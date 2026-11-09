// asm-bypass — ASM(macOS NAC agent) 协议重实现
// 逆向来源: ASM.app 5.2.6039 (Hopper decompile)，协议细节逐字节复刻。
//
// 流程（与原版一致）:
//   1. get_server_info     → 解析 serverip
//   2. getdeviceinfoprocess (devXml 注册) → devid / AscID
//   3. net_auth            → LDAP 认证 (type=User, authserver=AdDomain)
//   4. getmobileconfig     → data.isvpn (VPN 模式跳过 TTL 修改)
//   5. sysctl ttl=200 + 清 DNS + pf 防火墙白名单
//   6. TCP 长连接 (port 37527): ASM5 帧 + nibble-XOR("infogo") + zlib-9
//      - 每 30s 发 "HeartTest" 心跳
//      - 收帧按 TradeCode 分发 (IpRenew / firewall policy push / ...)
//   7. Darwin network_change 监听 → 路由快照对比 → 重新注册
//
// 兼容目标:
//   - WiFi ↔ 有线切换: route 快照 5 元组 (en/ip/mac/mark/is_main) 变化即重注册
//   - Clash TUN: utun* 不进入主路由与 *_ok 列表; pf 规则附加 utun pass;
//     主接口解析 fallback netstat -rn / scutil --nwi

mod args;
mod asm_id;
mod codec;
mod device;
mod http_api;
mod pf;
mod privesc;
mod socket;
mod state;
mod watch;

use anyhow::{Context, Result};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::Duration;

fn main() {
    if let Err(e) = run() {
        eprintln!("[!] 致命错误: {:#}", e);
        std::process::exit(1);
    }
}

/// 安检上报：所有检查项直接按"通过"提交。
///
/// 协议依据 (ASM 5.2.6039 /a/ajax.php?tradecode=mobileresult，实测 + plist 落盘值):
///   itemsid  = "99"（条目 id，来自 getcheckpolicy 的 PolicyBody）
///   checkres = XML，<Result>Yes</Result> + <Message>符合管理员要求</Message>
///   is_safecheck = 1
///
/// 这一步是"认证成功但网络仍然不通"的关键：net_auth 只拿到 RoleID/PolicyID，
/// 网关按 mobileresult 的结果把设备从"隔离域"挪到 PassIpRegion；
/// 不补这一步（或 itemsid/checkres 传空），ACL 就停在受限态，浏览器被 portal 劫持。
///
/// ReCheckTime=30（分钟）→ 调用方需周期性重跑本函数，否则 ACL 会过期收紧。
#[allow(clippy::too_many_arguments)]
fn safecheck(
    server: &str,
    devid: &str,
    policy_id: &str,
    role_id: &str,
    is_safe_check: i64,
    itemsid: &str,
    checkres: &str,
) {
    if let Ok(p) = http_api::get_check_policy(server, policy_id) {
        println!(
            "[*] 安检策略 {} 共 {} 项 → 全部按通过上报 (itemsid={})",
            policy_id,
            http_api::count_check_items(&p),
            itemsid
        );
    }
    match http_api::mobile_result(
        server,
        devid,
        policy_id,
        role_id,
        is_safe_check,
        itemsid,
        checkres,
    ) {
        Ok(v) => {
            let (ok, desc) = http_api::mobile_result_verdict(&v);
            if ok {
                let tail = if desc.is_empty() {
                    String::new()
                } else {
                    format!(": {desc}")
                };
                println!("[+] 安检通过{tail}");
            } else {
                eprintln!("[!] 安检未通过: {desc}");
            }
        }
        Err(e) => eprintln!("[*] 安检上报失败(继续): {e:#}"),
    }
}

/// 检测原版 ASM 客户端是否在运行。
///
/// 两者用同一个 DeviceID（105238）去认证，而服务器是单会话模型：
/// A 认证 → B 被踢 → B 重认证 → A 被踢，无限互踢。
/// 表现出来就是"用一会儿突然断网，过一会儿又自己好了"。
fn asm_client_running() -> bool {
    // -x 精确匹配进程名 "ASM"：用 -f 会匹配到命令行含该字符串的其他进程
    // （包括本程序启动瞬间的自身/残留），造成"其实没开也报警"的误报。
    std::process::Command::new("pgrep")
        .args(["-x", "ASM"])
        .output()
        .map(|o| o.status.success() && !o.stdout.trim_ascii().is_empty())
        .unwrap_or(false)
}

fn run() -> Result<()> {
    let cli = args::Cli::parse_args();

    let st = state::State::load(cli.state_dir.as_deref())?;
    st.apply_env_overrides(&cli);
    println!("[*] 工作目录 {}", st.dir.display());

    // osascript 管理员弹框兜底开关 (默认全静默)
    privesc::allow_prompt(cli.yes);

    // ─── 免密特权安装/卸载 (一次性, 不需要登录凭据) ───
    if cli.install {
        return privesc::install_privilege(&st);
    }
    if cli.uninstall {
        return privesc::uninstall_privilege(&st);
    }
    // 零网络诊断：只核对从 ASM plist 读到什么
    if cli.dump_id {
        let a = asm_id::read();
        println!("ASM 是否安装: {}", asm_id::asm_present());
        println!("devid      = {:?}", a.devid);
        println!("AscID      = {:?}", a.ascid);
        println!("UserName   = {:?}", a.username);
        println!("PolicyId   = {:?}", a.policy_id);
        println!("RoleID     = {:?}", a.role_id);
        println!("itemsid    = {:?}", a.itemsid);
        println!("rand_hard_ID = {:?}  ← DiskId 来源", a.rand_hard_id);
        println!("isSafeCheck= {:?}", a.is_safe_check);
        println!("IsNeedReg  = {:?}", a.is_need_reg);
        println!("ReCheck(min) = {:?}", a.recheck_minutes);
        println!("PassIpRegion = {:?}", a.pass_ip_region);
        println!("AuthTime   = {:?}", a.auth_time);
        match &a.checkres {
            Some(x) => println!("checkres   = ({} 字节) {}", x.len(), &x[..x.len().min(160)]),
            None => println!("checkres   = <缺失，将用内置兜底 XML>"),
        }
        // 顺便验证接口解析（纯本地命令，无网络）
        if let Ok(dev) = device::collect("172.29.92.2") {
            println!("--- 网络解析 ---");
            println!("主接口     = {} ip={} mac={}", dev.main_en, dev.main_ip, dev.main_mac);
            println!("网关       = {}", dev.gateway);
            println!("服务名     = {}", dev.service_name);
        }
        return Ok(());
    }
    // 只打印将要发送的 mobileresult query，不发送
    if cli.dump_query {
        let a = asm_id::read();
        let devid = a.devid.clone().unwrap_or_else(|| "<无 devid>".into());
        let pid = a.policy_id.clone().unwrap_or_else(|| "5".into());
        let rid = a.role_id.clone().unwrap_or_else(|| "9".into());
        let itemsid = a.itemsid.clone().unwrap_or_else(|| "99".into());
        let checkres = a
            .checkres
            .clone()
            .unwrap_or_else(http_api::default_checkres_xml);
        let flag = a.is_safe_check.unwrap_or(1);
        let q = http_api::build_mobile_result_query(&devid, &pid, &rid, flag, &itemsid, &checkres);
        println!("POST /a/ajax.php?{}", q);
        println!();
        println!("[解码后 checkres]");
        println!("{}", codec::decode_unicode_escapes(&checkres));
        return Ok(());
    }

    // ─── 凭据: CLI > SOUL_LDAP_* env > $USER (仅用户名兜底, 密码必须显式给) ───
    let username = cli
        .username
        .clone()
        .or_else(|| std::env::var("SOUL_LDAP_USERNAME").ok())
        .or_else(|| std::env::var("USER").ok())
        .filter(|s| !s.is_empty())
        .context("缺少用户名: 传 --username 或设置 SOUL_LDAP_USERNAME")?;
    // 密码来源: CLI > SOUL_LDAP_PASSWORD env > macOS Keychain (asm-bypass 条目)
    let (password, from_keychain) = cli
        .password
        .clone()
        .map(|p| (p, false))
        .or_else(|| std::env::var("SOUL_LDAP_PASSWORD").ok().map(|p| (p, false)))
        .or_else(|| keychain_get().map(|p| (p, true)))
        .filter(|(s, _)| !s.is_empty())
        .context("缺少密码: 传 --password、设置 SOUL_LDAP_PASSWORD，或先带一次 --password 让它写入 Keychain")?;

    // ─── Ctrl+C 清理钩子 ───
    let stop = Arc::new(AtomicBool::new(false));
    let stop2 = stop.clone();
    ctrlc::set_handler(move || {
        stop2.store(true, Ordering::SeqCst);
    })?;

    // 会话冲突预警：ASM 与本程序不能同时运行
    if asm_client_running() {
        eprintln!("[!] ═══════════════════════════════════════════════════");
        eprintln!("[!] 检测到原版 ASM 客户端正在运行");
        eprintln!("[!] 两者共用 DeviceID，服务器单会话互踢 → 会反复掉线");
        eprintln!("[!] 请完全退出 ASM 后再运行本程序（或从登录项移除）");
        eprintln!("[!] ═══════════════════════════════════════════════════");
    }

    // ─── 步骤 1: 服务器发现 ───
    let server = resolve_server(&st, &cli)?;
    println!("[+] serverip = {}", server);
    st.set("serverip", &server);

    // ─── 步骤 2: 设备身份（注册，由服务器按 DiskId 返回 DeviceID） ───
    // 先把上次缓存下来的指纹注入，ASM 卸载后也能保持同一个 DeviceID
    {
        let cached = st.get("disk_id");
        if !cached.is_empty() {
            device::set_cached_disk_id(cached);
        }
    }
    let dev = device::collect(&server)?;
    if dev.disk_id.starts_with("RAND:") {
        st.set("disk_id", &dev.disk_id);
    }
    println!(
        "[*] 主路由 {} ip={} mac={} mark={} gw={}",
        dev.main_en, dev.main_ip, dev.main_mac, dev.main_mark, dev.gateway
    );
    println!("[*] DiskId={} (设备指纹)", dev.disk_id);

    let asm = asm_id::read();

    // 必须每次注册，不是"复用本地存的 devid"。
    //
    // getdeviceinfoprocess 是幂等的：服务器按 <DiskId> 精确匹配设备记录
    // （DiskId=RAND:xxxx → DeviceID=105238，Registered=1 正规设备），
    // 同时把记录里的 IP/Mac/GateIP 更新成本次上报的值。
    //
    // 不注册就会出现：服务器仍按旧 IP/MAC 下发 ACL，而本机当前流量源地址
    // 已经变了（换网/DHCP/私有 WiFi MAC）→ 对不上 → 流量被 portal 劫持。
    let dev_xml = dev.build_dev_xml(true);
    let (devid, ascid) = match http_api::register_device(&server, &dev_xml) {
        Ok((d, a)) => {
            println!("[+] 注册 DeviceID={} AscID={} (服务器按 DiskId 匹配)", d, a);
            (d, a)
        }
        Err(e) => {
            eprintln!("[!] 注册失败: {e:#}");
            let cached = {
                let sx = st.get("devid");
                if !sx.is_empty() && sx != "0" {
                    Some(sx)
                } else {
                    asm.devid.clone()
                }
            };
            match cached {
                Some(d) => {
                    eprintln!("[*] 退回缓存 DeviceID={} (记录可能不是最新)", d);
                    (d, asm.ascid.clone().unwrap_or_default())
                }
                None => return Err(e.context("设备注册失败且无可用缓存 DeviceID")),
            }
        }
    };
    st.set("devid", &devid);
    if !ascid.is_empty() {
        st.set("AscID", &ascid);
    }
    println!("[*] 生效身份 DeviceID={} AscID={}", devid, ascid);

    // 认证请求必须从物理网卡发出：Clash TUN 会把到 NAC 的路由也劫持走 utun，
    // 源 IP 变成 198.18.0.1 → 服务器把 ACL 绑在虚拟地址上 → 真实流量被 portal 拦。
    let bind_ip = dev.main_ip.parse::<std::net::IpAddr>().ok();
    http_api::set_local_ip(bind_ip);
    if let Some(ip) = bind_ip {
        println!("[*] 绑定源 IP {} (绕过 Clash TUN)", ip);
    }

    // 安检素材：优先复用 ASM 已算好的 itemsid / checkres（等价于"所有检查按通过"）
    let sc_itemsid = asm.itemsid.clone().unwrap_or_else(|| "99".to_string());
    let sc_checkres = asm
        .checkres
        .clone()
        .unwrap_or_else(http_api::default_checkres_xml);

    // ─── 步骤 3: LDAP 认证 ───
    let auth = http_api::net_auth(&server, &username, &password, &devid)?;
    if !auth.ok {
        anyhow::bail!("认证失败: {}", auth.error_msg);
    }
    if let Some(r) = &auth.role_id {
        st.set("RoleID", r);
    }
    if let Some(p) = &auth.policy_id {
        st.set("PolicyId", p);
    }
    println!(
        "[+] 认证成功 RoleID={:?} PolicyID={:?}",
        auth.role_id, auth.policy_id
    );
    // 认证通过后把密码写入 Keychain（来源不是 Keychain 才需要落盘）
    if !from_keychain {
        keychain_set(&password);
    }

    // ─── 步骤 3.5: 安检上报（所有检查项按通过提交，放开服务端 ACL） ───
    if !cli.no_safecheck {
        if let (Some(pid), Some(rid)) = (auth.policy_id.as_deref(), auth.role_id.as_deref()) {
            let flag = auth.is_safe_check.or(asm.is_safe_check).unwrap_or(1);
            safecheck(
                &server,
                &devid,
                pid,
                rid,
                flag,
                &sc_itemsid,
                &sc_checkres,
            );
        } else {
            println!("[*] 无 PolicyID/RoleID，跳过安检上报");
        }
    }

    // ─── 步骤 3.6: 周期性重检线程（ReCheck=1, ReCheckTime=30 分钟） ───
    // 服务端 ReCheck=1 时 ACL 会按 ReCheckTime 过期收紧，必须定时重报 mobileresult。
    if !cli.no_safecheck {
        if let (Some(rid), Some(pid)) = (auth.role_id.clone(), auth.policy_id.clone()) {
            let stop4 = stop.clone();
            let srv = server.clone();
            let dv = devid.clone();
            let items = sc_itemsid.clone();
            let cr = sc_checkres.clone();
            let flag = auth.is_safe_check.or(asm.is_safe_check).unwrap_or(1);
            // ACL 实际失效比服务器声明的 ReCheckTime(30) 更早，
            // 用更短的强制周期兜底：不管有没有失效，到点就重认证一遍。
            let mins = cli
                .recheck_minutes
                .unwrap_or_else(|| asm.recheck_minutes.unwrap_or(30).min(5))
                .clamp(1, 60);
            let user4 = username.clone();
            let pass4 = password.clone();
            println!("[*] 周期重认证+重检 {} 分钟（强制兜底）", mins);
            thread::spawn(move || {
                let ticks = mins * 60 * 10; // 100ms 粒度
                loop {
                    for _ in 0..ticks {
                        if stop4.load(Ordering::SeqCst) {
                            return;
                        }
                        thread::sleep(Duration::from_millis(100));
                    }
                    println!("[*] 周期到点 ({} 分钟)：重认证 + 重报安检", mins);
                    // 先重认证：AuthInterval 到期后旧会话失效，只补 mobileresult 不够
                    match http_api::net_auth(&srv, &user4, &pass4, &dv) {
                        Ok(a) if a.ok => println!("[+] 周期重认证成功"),
                        Ok(a) => eprintln!("[!] 周期重认证被拒: {}", a.error_msg),
                        Err(e) => eprintln!("[!] 周期重认证失败: {e:#}"),
                    }
                    safecheck(&srv, &dv, &pid, &rid, flag, &items, &cr);
                }
            });
        }
    }

    // ─── 步骤 4: mobile config / isvpn ───
    let isvpn = http_api::get_mobile_config(&server, &ascid).unwrap_or(false);
    println!("[*] isvpn = {}", isvpn);
    st.set("isvpn", if isvpn { "1" } else { "0" });

    // ─── 步骤 5: 系统配置 (需要 root/setuid) ───
    if !cli.no_privilege {
        privesc::ensure_toolchain(&st)?;
        if !cli.no_ttl && !isvpn {
            privesc::set_ttl(200, &st);
        }
        if !cli.keep_dns {
            privesc::clear_dns(&dev.service_name, &st);
        }
    }

    // ─── 路由快照 (WiFi↔有线切换检测基线) ───
    st.set("main_en", &dev.main_en);
    st.save_route_snapshot(&dev.route_snapshot());
    st.flush()?;

    // ─── 步骤 6: socket 长连接线程 ───
    let (cmd_tx, cmd_rx) = mpsc::channel::<socket::SockCmd>();
    let pf_ctx = Arc::new(pf::PfCtx::new(
        &st,
        server.clone(),
        dev.gateway.clone(),
        cli.no_pf || cli.no_privilege,
    ));
    if !cli.no_socket {
        let stop3 = stop.clone();
        let st2 = st.clone_handle();
        let pf2 = pf_ctx.clone();
        let sock_host = server2_host(&server);
        thread::spawn(move || {
            socket::run(&st2, &sock_host, pf2, cmd_rx, stop3);
        });
    } else {
        // HTTP auto_auth 心跳兜底
        let stop3 = stop.clone();
        let srv = server.clone();
        let st2 = st.clone_handle();
        thread::spawn(move || {
            let devid = st2.get("devid");
            while !stop3.load(Ordering::SeqCst) {
                match http_api::auto_auth(&srv, &devid) {
                    Ok(true) => {}
                    _ => eprintln!("[!] auto_auth 心跳失败"),
                }
                for _ in 0..300 {
                    if stop3.load(Ordering::SeqCst) {
                        return;
                    }
                    thread::sleep(Duration::from_millis(100));
                }
            }
        });
    }

    // ─── 步骤 7: 网络变化监听主循环 ───
    println!("[*] 进入网络监听 (WiFi↔有线/Clash TUN 自动适配)...");
    let mut backoff = 0u32;
    while !stop.load(Ordering::SeqCst) {
        match watch::wait_network_change(&stop) {
            false => break,
            true => {}
        }
        // ASM: debounce ~3s (NSUserDefaults) + sleep(3)
        if watch::debounced(&stop, Duration::from_secs(3)) {
            break;
        }
        if watch::debounced(&stop, Duration::from_secs(3)) {
            break;
        }
        let dev2 = match device::collect(&server) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("[!] 重采路由失败: {:#}", e);
                continue;
            }
        };
        let snap = dev2.route_snapshot();
        if st.route_snapshot_eq(&snap) {
            continue; // 无实质变化
        }
        println!(
            "[*] 路由变化: {} {} → 重新注册",
            dev2.main_en, dev2.main_ip
        );
        // 注: 不调 cutoff_net —— 原版该接口仅用于"注销/被踢下线"语义
        // (recvComputerGetCutoffNetworkReason)，切换路径发它会直接砍掉
        // 服务器侧刚认证的会话 ACL，反而断网。
        // 换网后同样要重新注册：服务器记录里的 IP/Mac/GateIP 必须跟着更新，
        // 否则 ACL 仍按旧地址下发，当前流量对不上 → portal 劫持。
        // DiskId 不变 → 服务器返回同一个 DeviceID（105238）。
        let xml2 = dev2.build_dev_xml(true);
        let mut devid_now = String::new();
        match http_api::register_device(&server, &xml2) {
            Ok((d2, a2)) => {
                if !a2.is_empty() {
                    st.set("AscID", &a2);
                }
                println!("[+] 换网重注册 DeviceID={}", d2);
                devid_now = d2;
            }
            Err(e) => {
                eprintln!("[!] 换网重注册失败: {:#}", e);
                let fallback = st.get("devid");
                if !fallback.is_empty() && fallback != "0" {
                    eprintln!("[*] 退回已有 DeviceID={}", fallback);
                    devid_now = fallback;
                } else {
                    eprintln!("[!] 无可用 DeviceID，跳过本轮");
                    continue;
                }
            }
        }
        st.set("devid", &devid_now);
        st.set("main_en", &dev2.main_en);
        // 换网后源 IP 变了，认证请求要跟着换绑
        if let Ok(ip) = dev2.main_ip.parse::<std::net::IpAddr>() {
            http_api::set_local_ip(Some(ip));
            println!("[*] 重绑源 IP {}", ip);
        }
        // 重新认证 (换网卡后服务器侧 session 绑定旧 mac/ip)，失败重试一次
        for attempt in 0..2 {
            if attempt == 1 && watch::debounced(&stop, Duration::from_secs(2)) {
                break;
            }
            match http_api::net_auth(&server, &username, &password, &devid_now) {
                Ok(a) if a.ok => {
                    if let Some(r) = &a.role_id {
                        st.set("RoleID", r);
                    }
                    if let Some(p) = &a.policy_id {
                        st.set("PolicyId", p);
                    }
                    println!("[+] 重认证成功 RoleID={:?}", a.role_id);
                    // 换网卡后服务器侧 session 是新的，必须重跑安检，
                    // 否则 ACL 停在受限态 → 认证成功但流量不通。
                    if !cli.no_safecheck {
                        match (a.policy_id.as_deref(), a.role_id.as_deref()) {
                            (Some(pid), Some(rid)) => {
                                let flag = a.is_safe_check.or(asm.is_safe_check).unwrap_or(1);
                                safecheck(
                                    &server,
                                    &devid_now,
                                    pid,
                                    rid,
                                    flag,
                                    &sc_itemsid,
                                    &sc_checkres,
                                )
                            }
                            _ => println!("[*] 无 PolicyID/RoleID，跳过安检上报"),
                        }
                    }
                    break;
                }
                Ok(a) => eprintln!(
                    "[!] 重认证被拒{}{}: {}",
                    attempt + 1,
                    if attempt == 0 { "，重试" } else { "" },
                    a.error_msg
                ),
                Err(e) => eprintln!("[!] 重认证请求失败: {:#}", e),
            }
        }
        st.save_route_snapshot(&snap);
        let _ = st.flush();
        // 通知 socket 线程重连 + 刷新 pf 白名单网关
        pf_ctx.set_gateway(dev2.gateway.clone());
        let _ = cmd_tx.send(socket::SockCmd::Reconnect);
        let _ = cmd_tx.send(socket::SockCmd::IpRenew);
        backoff = 0;
    }

    // ─── 清理 ───
    stop.store(true, Ordering::SeqCst);
    if !cli.no_privilege {
        if pf_ctx.was_applied() {
            privesc::restore_pf(&st, true);
        }
        if !cli.no_ttl && !isvpn {
            privesc::set_ttl(64, &st);
        }
    }
    let _ = st.flush();
    let _ = backoff;
    println!("[*] 已退出，pf/TTL 已还原");
    Ok(())
}

// ─── Keychain 密码持久化 ───
// security CLI 读写 login keychain 中自己创建的条目不会弹授权框
// (ACL 记在 /usr/bin/security 上，我们 spawn 的正是它)。
const KC_SERVICE: &str = "asm-bypass";

fn keychain_get() -> Option<String> {
    let out = std::process::Command::new("security")
        .args(["find-generic-password", "-s", KC_SERVICE, "-w"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() { None } else { Some(s) }
}

fn keychain_set(pass: &str) {
    let ok = std::process::Command::new("security")
        .args([
            "add-generic-password",
            "-s", KC_SERVICE,
            "-a", "ldap",
            "-w", pass,
            "-U", // 已存在则更新
            "-T", "", // 允许所有应用读取 → 避免后续 find 弹框
        ])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if ok {
        println!("[*] 密码已写入 macOS Keychain (service={})", KC_SERVICE);
    }
}

/// host 可能带端口 "ip:port"，socket 连接时剥离
fn server2_host(server: &str) -> String {
    server.split(':').next().unwrap_or(server).to_string()
}

fn resolve_server(st: &state::StateHandle, cli: &args::Cli) -> Result<String> {
    if let Some(s) = &cli.server {
        return Ok(s.clone());
    }
    if let Ok(s) = std::env::var("SOUL_SERVER") {
        if !s.is_empty() {
            return Ok(s);
        }
    }
    let cached = st.get("serverip");
    if !cached.is_empty() {
        return Ok(cached);
    }
    // get_server_info 候选: env 列表 > 内建域名
    let mut cands: Vec<String> = std::env::var("SOUL_SERVER_CANDIDATES")
        .ok()
        .map(|s| s.split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect())
        .unwrap_or_default();
    cands.push("nac.soulapp-inc.cn".to_string());
    let mut errs = Vec::new();
    for c in &cands {
        match http_api::get_server_info(c) {
            Ok(ip) if !ip.is_empty() => return Ok(ip),
            Ok(_) => errs.push(format!("{}: 响应无 serverip", c)),
            Err(e) => errs.push(format!("{}: {:#}", c, e)),
        }
    }
    for e in &errs {
        eprintln!("[!] 候选失败 {}", e);
    }
    anyhow::bail!("服务器发现失败: 传 --server <IP或域名> 或设置 SOUL_SERVER")
}
