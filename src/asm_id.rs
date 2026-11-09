// 复用已安装 ASM 客户端的真实身份数据 (com.infogo.MAC3 plist)。
//
// 为什么必须复用：
//   原版 ASM 的 devid 是服务器**首次注册时分配并长期绑定**的设备 ID（IsNeedReg=0 时不重注册）。
//   每次自己调 getdeviceinfoprocess 都会拿到一个**全新 devid**，服务器把它当成
//   从未受管的设备 → net_auth 虽返回 RoleID，但网关按 devid 下发的 ACL 落不到这台机器上，
//   表现就是"认证成功但流量全被 portal 劫持"。
//
// 同理，安检结果 checkres 是 ASM 自己算好存在 plist 里的 XML，直接复用即等价于
// "所有检查项按通过提交"，不需要在 Rust 侧真跑任何检查。

use std::process::Command;

#[derive(Debug, Default, Clone)]
pub struct AsmIdentity {
    /// 服务器分配的真实设备 ID（最关键）
    pub devid: Option<String>,
    pub ascid: Option<String>,
    /// 完整登录名，如 huangjiangheng@soulapp.com
    pub username: Option<String>,
    pub policy_id: Option<String>,
    pub role_id: Option<String>,
    /// 安检条目 id，如 "99"
    pub itemsid: Option<String>,
    /// 安检结果 XML（含 <Result>Yes</Result>）
    pub checkres: Option<String>,
    /// 上次成功认证时间字符串
    pub auth_time: Option<String>,
    /// 重检间隔（分钟），plist 里 ReCheckTime
    pub recheck_minutes: Option<u64>,
    /// 是否要求安检
    pub is_safe_check: Option<i64>,
    /// 是否需要重新注册（1 时必须注册）
    pub is_need_reg: Option<i64>,
    /// 通过后可达域，如 "互联网,内网"
    pub pass_ip_region: Option<String>,
    /// ASM 自生成的硬件指纹，格式 "RAND:<UUID大写带横线>"。
    /// 这是服务器识别本机的唯一依据（注册时作为 <DiskId> 发送），
    /// 决定 DeviceID：RAND:xxxx → 105238 (Registered=1 正规设备)；
    /// 用 IOPlatformUUID 反而会得到 208123 (自动发现设备, Registered=-2)。
    pub rand_hard_id: Option<String>,
}

const DOMAIN: &str = "com.infogo.MAC3";

/// `defaults read com.infogo.MAC3 <key>`，返回去掉首尾引号/空白的值
fn read_key(key: &str) -> Option<String> {
    let out = Command::new("defaults")
        .args(["read", DOMAIN, key])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() {
        return None;
    }
    // defaults 对含空格/特殊字符的字符串会加双引号
    let s = s
        .strip_prefix('"')
        .and_then(|x| x.strip_suffix('"'))
        .unwrap_or(&s)
        .to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

/// 读 net_auth_callback 字典里的某个子键：
/// `defaults read com.infogo.MAC3 net_auth_callback` 输出是格式化的 plist 文本，
/// 这里按 "    Key = value;" 行来抽，够用且不引第三方 plist 库。
fn read_callback(key: &str) -> Option<String> {
    let out = Command::new("defaults")
        .args(["read", DOMAIN, "net_auth_callback"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let needle = format!("{} = ", key);
    for line in text.lines() {
        let l = line.trim();
        let Some(rest) = l.strip_prefix(&needle) else {
            continue;
        };
        let v = rest.trim_end_matches(';').trim().to_string();
        let v = v
            .strip_prefix('"')
            .and_then(|x| x.strip_suffix('"'))
            .unwrap_or(&v)
            .to_string();
        return if v.is_empty() { None } else { Some(v) };
    }
    None
}

fn num(s: Option<String>) -> Option<i64> {
    s.and_then(|x| x.trim().parse::<i64>().ok())
}

/// 探测 ASM 是否安装过（plist 是否存在）
pub fn asm_present() -> bool {
    Command::new("defaults")
        .args(["read", DOMAIN, "Registered"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

pub fn read() -> AsmIdentity {
    // devid 在主域是整数，defaults 输出不带引号
    let devid = read_key("devid").filter(|s| s.chars().all(|c| c.is_ascii_digit()));
    AsmIdentity {
        devid,
        ascid: read_key("AscID"),
        username: read_callback("UserName"),
        policy_id: read_key("PolicyId").or_else(|| read_callback("PolicyID")),
        role_id: read_key("RoleID").or_else(|| read_callback("RoleID")),
        itemsid: read_key("itemsid"),
        checkres: read_key("checkres"),
        auth_time: read_callback("AuthTime"),
        recheck_minutes: num(read_callback("ReCheckTime")).map(|n| n.max(0) as u64),
        is_safe_check: num(read_key("isSafeCheck")),
        is_need_reg: num(read_callback("IsNeedReg")),
        pass_ip_region: read_callback("PassIpRegion"),
        rand_hard_id: read_key("rand_hard_ID"),
    }
}

/// 供 device::build_dev_xml 直接取 DiskId 用
pub fn disk_id() -> Option<String> {
    read_key("rand_hard_ID")
}
