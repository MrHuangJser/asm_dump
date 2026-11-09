// 特权操作 —— 三级静默链，默认全程不弹框不输密码：
//   1. euid==0            → 直跑 (sudo -E ./asm-bypass 场景)
//   2. sudo -n            → /etc/sudoers.d/asm-bypass NOPASSWD 规则 (--install 写入)
//   3. cfg/ setuid 拷贝   → 仅 pfctl/sysctl 有效 (不带 restricted entitlement)
// osascript 管理员弹框仅在 --yes 下启用；否则特权操作静默降级打日志。
//
// 为什么 networksetup/ipconfig 不能做 setuid 拷贝: 两者带 restricted
// entitlement，复制后经 setuid exec 直接内核 CS_KILL (Killed: 9, rc=137)，
// 只能走 euid0 / sudo / osascript。pfctl/sysctl 无此限制，setuid 拷贝可用。
use anyhow::Result;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::state::StateHandle;

/// --yes: 允许 osascript 管理员授权弹框兜底 (默认关闭, 全自动无人值守)
static ALLOW_PROMPT: AtomicBool = AtomicBool::new(false);

pub fn allow_prompt(v: bool) {
    ALLOW_PROMPT.store(v, Ordering::SeqCst);
}

fn prompted() -> bool {
    ALLOW_PROMPT.load(Ordering::SeqCst)
}

/// setuid 拷贝工具链: 只保留无 restricted-entitlement 的二进制
const TOOLS: &[(&str, &str)] = &[
    ("/sbin/pfctl", "pfctl"),
    ("/usr/sbin/sysctl", "sysctl"),
];

fn cfg_dir(st: &StateHandle) -> PathBuf {
    st.dir.join("cfg")
}

fn tool_path(st: &StateHandle, name: &str) -> PathBuf {
    cfg_dir(st).join(name)
}

fn is_setuid(p: &PathBuf) -> bool {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(p)
        .map(|m| m.mode() & 0o4000 != 0 && m.uid() == 0)
        .unwrap_or(false)
}

fn euid0() -> bool {
    unsafe { libc::geteuid() == 0 }
}

// ─── 静默特权执行 ───
/// argv[0] 传二进制全路径。依次尝试 euid0 / sudo -n / setuid 拷贝。
/// 成功返回 true；全部静默失败返回 false（不弹框、不报错）。
fn exec_priv(argv: &[&str], st: &StateHandle) -> bool {
    if argv.is_empty() {
        return false;
    }
    let name = PathBuf::from(argv[0])
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    // 1) euid==0 直跑
    if euid0() {
        if Command::new(argv[0])
            .args(&argv[1..])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
        {
            return true;
        }
    }
    // 2) sudo -n: NOPASSWD 规则装好后无感放行；没装则立刻失败不阻塞
    if Command::new("sudo")
        .arg("-n")
        .args(argv)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
    {
        return true;
    }
    // 3) cfg/ setuid 拷贝 (pfctl/sysctl)
    let p = tool_path(st, &name);
    if is_setuid(&p) {
        return Command::new(&p)
            .args(&argv[1..])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
    }
    false
}

/// 多命令 shell 串 (恢复 pf.conf 备份等)，euid0 / sudo -n / osascript
fn exec_shell_priv(cmd: &str) -> bool {
    if euid0() {
        return Command::new("/bin/sh")
            .args(["-c", cmd])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
    }
    if Command::new("sudo")
        .args(["-n", "/bin/sh", "-c", cmd])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
    {
        return true;
    }
    if prompted() {
        return Command::new("osascript")
            .args([
                "-e",
                &format!(
                    "do shell script \"{}\" with administrator privileges",
                    cmd.replace('"', "\\\"")
                ),
            ])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
    }
    false
}

/// osascript 管理员弹框兜底 (仅 --yes 时 exec_shell_priv 会走到)

// ─── 安装/卸载免密特权 ───
const SUDOERS_PATH: &str = "/etc/sudoers.d/asm-bypass";

fn sudoers_body(user: &str) -> String {
    format!(
        "# asm-bypass 免密特权 (由 asm-bypass --install 生成, --uninstall 删除)\n\
         {u} ALL=(ALL) NOPASSWD: /sbin/pfctl, /usr/sbin/sysctl, \\\n\
         \x20   /usr/sbin/networksetup, /usr/sbin/ipconfig\n",
        u = user
    )
}

/// 写 sudoers 规则 + setuid 工具链。唯一一次需要系统管理员密码的操作。
pub fn install_privilege(st: &StateHandle) -> Result<()> {
    let user = std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| "admin".into());
    let tmp = std::env::temp_dir().join(format!("asm-sudoers-{}", std::process::id()));
    std::fs::write(&tmp, sudoers_body(&user))?;
    std::fs::create_dir_all(cfg_dir(st))?;

    let mut script = format!(
        "cp '{tmp}' {SP} && chown root:wheel {SP} && chmod 0440 {SP} && \
         (visudo -cf {SP} >/dev/null 2>&1 || (rm -f {SP}; exit 3)); ",
        tmp = tmp.display(),
        SP = SUDOERS_PATH
    );
    for (src, name) in TOOLS {
        let dst = tool_path(st, name);
        script.push_str(&format!(
            "cp {src} '{dst}' && chown root:wheel '{dst}' && chmod 4755 '{dst}'; ",
            src = src,
            dst = dst.display()
        ));
    }

    let ok = if euid0() {
        exec_shell_priv(&script)
    } else {
        // 这是唯一一次弹管理员授权框，装完终身免密
        Command::new("osascript")
            .args([
                "-e",
                &format!(
                    "do shell script \"{}\" with administrator privileges",
                    script.replace('"', "\\\"")
                ),
            ])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    };
    let _ = std::fs::remove_file(&tmp);

    if ok {
        println!("[+] 免密特权已安装: {}", SUDOERS_PATH);
        println!("    放行命令: pfctl / sysctl / networksetup / ipconfig (仅这四个)");
        println!("    撤销方式: ./asm-bypass --uninstall");
    } else {
        anyhow::bail!("授权被取消或 sudoers 写入失败");
    }
    Ok(())
}

/// 删除 sudoers 规则与 setuid 拷贝。
/// 卸载与安装一样是显式手动操作: 弹一次管理员框属预期
/// (NOPASSWD 不放行 /bin/sh，所以静默链必然失败，直接走 osascript)。
pub fn uninstall_privilege(st: &StateHandle) -> Result<()> {
    let files: Vec<String> = std::iter::once(SUDOERS_PATH.to_string())
        .chain(TOOLS.iter().map(|(_, n)| tool_path(st, n).to_string_lossy().into_owned()))
        .collect();
    let cmd = format!("rm -f {}", files.join(" "));
    let ok = if euid0() {
        exec_shell_priv(&cmd)
    } else {
        Command::new("osascript")
            .args([
                "-e",
                &format!(
                    "do shell script \"{}\" with administrator privileges",
                    cmd.replace('"', "\\\"")
                ),
            ])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    };
    if ok {
        println!("[+] 已卸载: {} + cfg/ setuid 工具链", SUDOERS_PATH);
    } else {
        eprintln!("[!] 卸载失败 (授权被取消); 可手动: sudo rm {}", SUDOERS_PATH);
    }
    Ok(())
}

// ─── 工具链 (setuid 拷贝) ───
/// euid0 直跑; 已装 sudoers 走 sudo -n; --yes 时 osascript; 否则提示 --install
pub fn ensure_toolchain(st: &StateHandle) -> Result<()> {
    let dir = cfg_dir(st);
    std::fs::create_dir_all(&dir)?;
    let mut script = String::new();
    for (src, name) in TOOLS {
        let dst = tool_path(st, name);
        if is_setuid(&dst) {
            continue;
        }
        script.push_str(&format!(
            "cp {src} '{dst}' && chown root:wheel '{dst}' && chmod 4755 '{dst}'; ",
            src = src,
            dst = dst.display()
        ));
    }
    if script.is_empty() {
        return Ok(());
    }
    if exec_shell_priv(&script) {
        return Ok(());
    }
    eprintln!("[*] 工具链未就绪 (特权操作静默降级); 执行一次 ./asm-bypass --install 可永久免密");
    Ok(())
}

// ─── 各特权动作 ───
/// sysctl -w net.inet.ip.ttl={v} （认证成功 200，退出还原 64，isvpn 跳过）
pub fn set_ttl(v: u32, st: &StateHandle) {
    if exec_priv(&["/usr/sbin/sysctl", "-w", &format!("net.inet.ip.ttl={}", v)], st) {
        println!("[+] TTL={}", v);
    } else {
        eprintln!("[*] TTL={} 设置跳过 (无免密特权, --install 可解决)", v);
    }
}

/// networksetup -setdnsservers {service} empty
/// networksetup 带 restricted entitlement → setuid 无效, 只走 euid0/sudo -n
pub fn clear_dns(service: &str, st: &StateHandle) {
    if service.is_empty() {
        return;
    }
    let _ = st;
    if exec_priv(&["/usr/sbin/networksetup", "-setdnsservers", service, "empty"], st) {
        println!("[+] DNS 已清空 ({})", service);
    } else {
        eprintln!("[*] DNS 清空跳过 ({}) (无免密特权)", service);
    }
}

/// pfctl -ef {conf}
pub fn load_pf(conf: &PathBuf, st: &StateHandle) -> Result<()> {
    if exec_priv(&["/sbin/pfctl", "-ef", &conf.to_string_lossy()], st) {
        Ok(())
    } else {
        anyhow::bail!("pfctl -ef 无特权执行通道")
    }
}

/// ipconfig set {en} DHCP —— 换网卡/服务器 IpRenew 指令后重取租约
/// restricted entitlement → 只有 euid0 / sudo -n 两条路；都不可用就跳过。
/// 跳过是安全的: 新接口租约由 macOS DHCP 客户端自行协商。
pub fn renew_dhcp(en: &str, st: &StateHandle) {
    if en.is_empty() {
        return;
    }
    if exec_priv(&["/usr/sbin/ipconfig", "set", en, "DHCP"], st) {
        println!("[+] DHCP 续约 {} 完成", en);
    } else {
        println!("[*] DHCP 续约跳过 (无免密特权，新接口租约由系统协商)");
    }
}

/// pfctl -F all -f /etc/pf.conf (+ 恢复备份的 /etc/pf.conf)
/// verbose=false 时静默 (IsOpen=0 等未实际应用过策略的场景)
pub fn restore_pf(st: &StateHandle, verbose: bool) {
    let back = st.dir.join("pf_back.conf");
    if back.exists() {
        let cmd = format!(
            "cp '{}' /etc/pf.conf && pfctl -F all -f /etc/pf.conf",
            back.display()
        );
        exec_shell_priv(&cmd);
    }
    let _ = exec_priv(&["/sbin/pfctl", "-F", "all", "-f", "/etc/pf.conf"], st);
    if verbose {
        println!("[*] pf 已恢复");
    }
}

/// 首次应用 pf 前备份 /etc/pf.conf
pub fn backup_pf_conf(st: &StateHandle) {
    let back = st.dir.join("pf_back.conf");
    if back.exists() {
        return;
    }
    if let Ok(c) = std::fs::read_to_string("/etc/pf.conf") {
        let _ = std::fs::write(&back, c);
    }
}
