// 设备/路由信息采集 —— 复刻 ASMDeviceInfo + ASMRouteInfo + setRouteInfoIPAndMarkByBSD
//
// MARK = netmask (ifa_netmask inet_ntoa)，不是网段地址。
// 主路由 = `route -n get {server}` 的 interface；
//   若指向 utun*(Clash TUN) → fallback netstat -rn -f inet default(非 utun) → scutil --nwi → en0。
// *_ok 列表只收“有效”网卡: 非虚拟前缀 + 有 MAC + ip 非 0.0.0.0/127.x。
use anyhow::Result;
use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::process::Command;

const VIRTUAL_PREFIXES: &[&str] = &[
    "utun", "lo", "awdl", "llw", "anpi", "ap", "bridge", "gif", "stf", "vmenet", "vboxnet",
    "ipsec", "ppp", "p2p", "tap", "tun", "enx", "fw",
];

#[derive(Debug, Clone)]
pub struct Iface {
    pub en: String,
    pub ip: String,
    pub mac: String,
    pub mark: String, // netmask "255.255.255.0"
    pub is_main: bool,
}

pub struct DevInfo {
    pub device_name: String,
    pub safari_version: String,
    pub disk_id: String, // IOPlatformUUID 大写无横杠
    pub gateway: String,
    pub service_name: String, // networksetup 服务名 (Wi-Fi / Ethernet)
    pub main_en: String,
    pub main_ip: String,
    pub main_mac: String,
    pub main_mark: String,
    pub ifaces: Vec<Iface>,
}

pub fn collect(server: &str) -> Result<DevInfo> {
    let main_en = resolve_main_en(server);
    let mut ifaces = collect_ifaces();
    for i in ifaces.iter_mut() {
        i.is_main = i.en == main_en;
    }
    let (main_ip, main_mac, main_mark) = ifaces
        .iter()
        .find(|i| i.is_main)
        .map(|i| (i.ip.clone(), i.mac.clone(), i.mark.clone()))
        .unwrap_or_default();
    let gateway = resolve_gateway(&main_en);
    Ok(DevInfo {
        device_name: device_name(),
        safari_version: safari_version(),
        disk_id: resolve_disk_id(),
        gateway,
        service_name: service_name(&main_en),
        main_en,
        main_ip,
        main_mac,
        main_mark,
        ifaces,
    })
}

impl DevInfo {
    /// devXml 精确模板 (getDevXml @0x10009d210, arg==0 → ASM-Base64)
    /// <?xml version="1.0" encoding="gb2312"?><MSAC> <DeviceName>..</DeviceName>
    /// <OS>MacOS</OS><Ip>..</Ip><Mac>..</Mac><Mark>..</Mark><GateWay>..</GateWay>
    /// <IeVersion>..</IeVersion><DiskId>..</DiskId><AllIp_Ok>..</AllIp_Ok>
    /// <AllMac_Ok>..</AllMac_Ok><AllIp>..</AllIp><AllMark>..</AllMark><AllMac>..</AllMac></MSAC>
    pub fn build_dev_xml(&self, encoded: bool) -> String {
        let ok: Vec<&Iface> = self.ifaces.iter().filter(|i| i.is_valid()).collect();
        let all_ip_ok = ok.iter().map(|i| i.ip.clone()).collect::<Vec<_>>().join(",");
        let all_mac_ok = ok.iter().map(|i| i.mac.clone()).collect::<Vec<_>>().join(",");
        let all_ip = self.ifaces.iter().map(|i| i.ip.clone()).collect::<Vec<_>>().join(",");
        let all_mark = self.ifaces.iter().map(|i| i.mark.clone()).collect::<Vec<_>>().join(",");
        let all_mac = self.ifaces.iter().map(|i| i.mac.clone()).collect::<Vec<_>>().join(",");
        let xml = format!(
            concat!(
                "<?xml version=\"1.0\" encoding=\"gb2312\"?><MSAC> ",
                "<DeviceName>{}</DeviceName><OS>MacOS</OS><Ip>{}</Ip><Mac>{}</Mac>",
                "<Mark>{}</Mark><GateWay>{}</GateWay><IeVersion>{}</IeVersion>",
                "<DiskId>{}</DiskId><AllIp_Ok>{}</AllIp_Ok><AllMac_Ok>{}</AllMac_Ok>",
                "<AllIp>{}</AllIp><AllMark>{}</AllMark><AllMac>{}</AllMac></MSAC>"
            ),
            self.device_name,
            self.main_ip,
            self.main_mac,
            self.main_mark,
            self.gateway,
            self.safari_version,
            self.disk_id,
            all_ip_ok,
            all_mac_ok,
            all_ip,
            all_mark,
            all_mac
        );
        if encoded {
            // ASMBase64StringFromText: GBK bytes → std base64 → =:/+, /. 
            crate::codec::encode_gbk(&xml)
        } else {
            xml
        }
    }

    /// 路由快照: 5 元组 {is_main,en,ip,mac,mark} —— RouteInfoCompare 语义
    /// JSON array of "en|ip|mac|mark|is_main" (排序后比较)
    pub fn route_snapshot(&self) -> String {
        let mut v: Vec<String> = self
            .ifaces
            .iter()
            .filter(|i| i.is_valid())
            .map(|i| format!("{}|{}|{}|{}|{}", i.en, i.ip, i.mac, i.mark, i.is_main as u8))
            .collect();
        v.sort();
        serde_json::to_string(&v).unwrap_or_else(|_| "[]".into())
    }
}

impl Iface {
    pub fn is_virtual(&self) -> bool {
        let n = self.en.as_str();
        VIRTUAL_PREFIXES.iter().any(|p| {
            n.starts_with(p)
                && (n.len() == p.len()
                    || n[p.len()..].chars().all(|c| c.is_ascii_digit()))
        })
    }
    /// 有效网卡 (进 *_ok): 非虚拟 + 有 MAC + IPv4 正常地址
    pub fn is_valid(&self) -> bool {
        if self.is_virtual() {
            return false;
        }
        if self.mac.is_empty() || self.mac == "00:00:00:00:00:00" {
            return false;
        }
        match self.ip.parse::<Ipv4Addr>() {
            Ok(a) => !a.is_unspecified() && !a.is_loopback(),
            Err(_) => false,
        }
    }
}

// ─── getifaddrs 采集 ───
fn collect_ifaces() -> Vec<Iface> {
    let mut addrs: BTreeMap<String, (String, String)> = BTreeMap::new(); // en -> (ip, mark)
    let mut macs: BTreeMap<String, String> = BTreeMap::new();
    unsafe {
        let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut ifap) != 0 {
            return Vec::new();
        }
        let mut cur = ifap;
        while !cur.is_null() {
            let ifa = &*cur;
            if !ifa.ifa_addr.is_null() {
                let name = std::ffi::CStr::from_ptr(ifa.ifa_name)
                    .to_string_lossy()
                    .to_string();
                let fam = (*ifa.ifa_addr).sa_family as i32;
                if fam == libc::AF_INET {
                    let ip = inet_ntoa(ifa.ifa_addr);
                    let mark = if !ifa.ifa_netmask.is_null() {
                        inet_ntoa(ifa.ifa_netmask)
                    } else {
                        String::new()
                    };
                    addrs.insert(name, (ip, mark));
                } else if fam == libc::AF_LINK {
                    if let Some(m) = link_mac(ifa.ifa_addr) {
                        macs.insert(name, m);
                    }
                }
            }
            cur = ifa.ifa_next;
        }
        libc::freeifaddrs(ifap);
    }
    addrs
        .into_iter()
        .map(|(en, (ip, mark))| Iface {
            mac: macs.get(&en).cloned().unwrap_or_default(),
            en,
            ip,
            mark,
            is_main: false,
        })
        .collect()
}

unsafe fn inet_ntoa(sa: *const libc::sockaddr) -> String {
    let sin = sa as *const libc::sockaddr_in;
    let a = (*sin).sin_addr.s_addr.to_be();
    Ipv4Addr::from(a).to_string()
}

/// AF_LINK sockaddr_dl → MAC (ENET 类型有 6 字节地址)
/// 布局: len,family,index u16, type u8, nlen u8, alen u8, selen u8, data[46]
unsafe fn link_mac(sa: *const libc::sockaddr) -> Option<String> {
    let p = sa as *const u8;
    let nlen = *p.add(5) as usize;
    let alen = *p.add(6) as usize;
    if alen != 6 {
        return None;
    }
    let base = 8usize + nlen;
    let b = std::slice::from_raw_parts(p.add(base), 6);
    Some(format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        b[0], b[1], b[2], b[3], b[4], b[5]
    ))
}

// ─── 主接口解析 ───
/// route -n get {server} → interface: enX
fn iface_to_host(host: &str) -> Option<String> {
    let out = Command::new("route")
        .args(["-n", "get", host])
        .output()
        .ok()?;
    let s = String::from_utf8_lossy(&out.stdout);
    parse_key(&s, "interface:")
}

/// netstat -rn -f inet → default 路由的 Netif (排除 utun)
fn default_underlay_iface() -> Option<String> {
    let out = Command::new("netstat")
        .args(["-rn", "-f", "inet"])
        .output()
        .ok()?;
    let s = String::from_utf8_lossy(&out.stdout);
    for line in s.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() >= 4 && cols[0] == "default" {
            let netif = cols[3];
            if !netif.starts_with("utun") && netif != "lo0" {
                return Some(netif.to_string());
            }
        }
    }
    None
}

/// 合法接口名: en0 / en12 / utun3 —— 必须严格匹配，否则 scutil 输出里的
/// `REACH : flags ...`、"Network interfaces: en0" 之类的行会被误当成接口名。
fn is_iface_name(s: &str) -> bool {
    let rest = match s.strip_prefix("en").or_else(|| s.strip_prefix("utun")) {
        Some(r) => r,
        None => return false,
    };
    !rest.is_empty() && rest.chars().all(|c| c.is_ascii_digit())
}

/// 接口是否真实存在（USB 网卡拔出后 en7 会从 ifconfig 列表消失）
fn iface_exists(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    Command::new("ifconfig")
        .arg(name)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// 找第一个有 IPv4 地址的真实 en* 接口（fallback 用）
fn first_live_en() -> Option<String> {
    let out = Command::new("ifconfig").arg("-l").output().ok()?;
    let list = String::from_utf8_lossy(&out.stdout);
    for name in list.split_whitespace() {
        if name.starts_with("en") && is_iface_name(name) {
            if let Ok(o) = Command::new("ipconfig").args(["getifaddr", name]).output() {
                if o.status.success() && !o.stdout.is_empty() {
                    return Some(name.to_string());
                }
            }
        }
    }
    None
}

/// scutil --nwi → 第一个非 utun IPv4 接口
fn scutil_ipv4_iface() -> Option<String> {
    let out = Command::new("scutil").arg("--nwi").output().ok()?;
    let s = String::from_utf8_lossy(&out.stdout);
    let mut in_v4 = false;
    for line in s.lines() {
        let t = line.trim();
        if t == "IPv4 network interface information" {
            in_v4 = true;
            continue;
        }
        if t.starts_with("IPv6 network") {
            break;
        }
        if in_v4 && t.contains(':') {
            if let Some(en) = t.split_whitespace().next() {
                // 只接受 en<N>/utun<N>；"REACH" 之类直接丢弃
                if is_iface_name(en) && !en.starts_with("utun") {
                    return Some(en.to_string());
                }
            }
        }
    }
    None
}

pub fn resolve_main_en(server: &str) -> String {
    let host = server.split(':').next().unwrap_or(server);
    let mut cand: Option<String> = None;
    if let Some(en) = iface_to_host(host) {
        if is_iface_name(&en) && !en.starts_with("utun") {
            cand = Some(en);
        }
    }
    if cand.is_none() {
        // Clash TUN: 到 server 的路由被劫持 → 找物理底层网卡
        cand = default_underlay_iface().filter(|e| is_iface_name(e));
    }
    if cand.is_none() {
        cand = scutil_ipv4_iface();
    }
    // 最后一道闸：接口必须真实存在，否则说明网卡被拔了 / 正在切换，
    // 拿一个不存在的名字去注册只会产生垃圾 devXml。
    match cand {
        Some(en) if iface_exists(&en) => en,
        _ => first_live_en().unwrap_or_else(|| {
            eprintln!("[!] 未找到可用物理网卡，暂用 en0");
            "en0".to_string()
        }),
    }
}

/// 网关: netstat -rn 里该接口的 default gateway；找不到 → "0.0.0.0"
fn resolve_gateway(main_en: &str) -> String {
    if main_en.is_empty() {
        return "0.0.0.0".into();
    }
    if let Ok(out) = Command::new("netstat").args(["-rn", "-f", "inet"]).output() {
        let s = String::from_utf8_lossy(&out.stdout);
        for line in s.lines() {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() >= 4 && cols[0] == "default" && cols[3] == main_en {
                return cols[1].to_string();
            }
        }
    }
    // route -n get default 兜底
    if let Ok(out) = Command::new("route").args(["-n", "get", "default"]).output() {
        let s = String::from_utf8_lossy(&out.stdout);
        if parse_key(&s, "interface:").as_deref() == Some(main_en) {
            if let Some(g) = parse_key(&s, "gateway:") {
                return g;
            }
        }
    }
    "0.0.0.0".into()
}

fn parse_key(text: &str, key: &str) -> Option<String> {
    for line in text.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix(key) {
            return Some(rest.trim().to_string());
        }
    }
    None
}

// ─── 其他采集 ───
fn device_name() -> String {
    for args in [
        ["--get", "ComputerName"],
        ["--get", "LocalHostName"],
    ] {
        if let Ok(out) = Command::new("scutil").args(args).output() {
            let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !s.is_empty() && !s.contains("not set") {
                return s;
            }
        }
    }
    Command::new("hostname")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|_| "Mac".into())
}

fn safari_version() -> String {
    if let Ok(out) = Command::new("plutil")
        .args([
            "-extract",
            "CFBundleShortVersionString",
            "raw",
            "-o",
            "-",
            "/Applications/Safari.app/Contents/Info.plist",
        ])
        .output()
    {
        let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if !s.is_empty() {
            return s;
        }
    }
    "0".into()
}

/// IOPlatformUUID → 大写无横杠 (DiskId)
/// DiskId —— 服务器识别设备的唯一依据。
///
/// 实测（/a/ajax.php?tradecode=getdeviceinfoprocess 按 <DiskId> 精确匹配）：
///   "RAND:9495F0BC-5B05-43C8-8442-B6A755345245" → DeviceID=105238, Registered=1（正规设备）
///   "b3ae2a06...（IOPlatformUUID 去横线大写）"   → DeviceID=208123, Registered=-2（自动发现设备）
/// 大小写/横线/前缀全部敏感。
///
/// 所以优先复用 ASM 的 rand_hard_ID；拿不到时退回 IOPlatformUUID，
/// 但会打日志提醒（那会拿到未受管的"自动发现"记录）。
fn resolve_disk_id() -> String {
    // 1) ASM plist（最权威：就是服务器上那条 105238 记录对应的值）
    if let Some(v) = crate::asm_id::disk_id() {
        if v.starts_with("RAND:") {
            return v;
        }
        eprintln!("[!] plist rand_hard_ID 格式异常({})，尝试本地缓存", v);
    }
    // 2) 本地缓存 state.json（ASM 卸载后仍然可用，保持 devid 不变）
    if let Some(v) = CACHED_DISK_ID.get() {
        if v.starts_with("RAND:") {
            return v.clone();
        }
    }
    // 3) 生成一个新的随机指纹并持久化（首次安装场景）
    //    服务器会据此新建一条"系统自动注册设备"记录
    let raw = format!("{:016X}{:016X}", fastrand::u64(..), fastrand::u64(..));
    let u = format!(
        "{}-{}-{}-{}-{}",
        &raw[0..8],
        &raw[8..12],
        &raw[12..16],
        &raw[16..20],
        &raw[20..32]
    );
    let id = format!("RAND:{}", u);
    eprintln!("[!] 未找到 rand_hard_ID，已生成新指纹 {}", id);
    id
}

static CACHED_DISK_ID: std::sync::OnceLock<String> = std::sync::OnceLock::new();

/// main 在 collect 之前注入 state.json 里缓存的 DiskId
pub fn set_cached_disk_id(s: String) {
    let _ = CACHED_DISK_ID.set(s);
}

fn platform_uuid() -> String {
    if let Ok(out) = Command::new("ioreg")
        .args(["-d2", "-c", "IOPlatformExpertDevice"])
        .output()
    {
        let s = String::from_utf8_lossy(&out.stdout);
        for line in s.lines() {
            if line.contains("IOPlatformUUID") {
                if let Some(uuid) = line.split('"').nth(3) {
                    return uuid.replace('-', "").to_uppercase();
                }
            }
        }
    }
    String::new()
}

/// networksetup -listallhardwareports → "Wi-Fi" / "Ethernet"
fn service_name(en: &str) -> String {
    if let Ok(out) = Command::new("networksetup")
        .arg("-listallhardwareports")
        .output()
    {
        let s = String::from_utf8_lossy(&out.stdout);
        let mut cur_name = String::new();
        for line in s.lines() {
            let t = line.trim();
            if let Some(rest) = t.strip_prefix("Hardware Port:") {
                cur_name = rest.trim().to_string();
            }
            if t == format!("Device: {}", en) && !cur_name.is_empty() {
                return cur_name;
            }
        }
    }
    if en.starts_with("en0") {
        "Wi-Fi".into()
    } else {
        String::new()
    }
}
