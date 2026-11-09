// HTTP API —— 复刻 -[Singleton *WithAddress:...] 系列
// 全部 POST http://{server}/a/ajax.php?... ，参数全部在 URL query。
// Headers: Content-Type: text/html;  Extend-Data: ostype=mac;  User-Agent: MERONG(0.9/;Macos)
use anyhow::{Context, Result};
use reqwest::blocking::Client;
use serde_json::Value;
use std::time::Duration;

use crate::codec;

/// 认证请求必须**绑定物理网卡源 IP**。
///
/// Clash TUN 会把到 NAC 内网地址的路由也劫持走 utun（`route get 172.29.92.2`
/// → `interface utun4`），于是 POST 的源 IP 变成 `198.18.0.1`。NAC 把 ACL
/// 绑在这个虚拟地址上，而用户真实流量从 `172.27.76.19` 出去 → 未认证 → portal 劫持。
/// 现象就是"net_auth 返回 RoleID 却上不了网"。
static LOCAL_IP: std::sync::RwLock<Option<std::net::IpAddr>> = std::sync::RwLock::new(None);
static CLIENT_CACHE: std::sync::RwLock<Option<(Option<std::net::IpAddr>, Client)>> =
    std::sync::RwLock::new(None);

pub fn set_local_ip(ip: Option<std::net::IpAddr>) {
    *LOCAL_IP.write().unwrap() = ip;
}

pub fn current_local_ip() -> Option<std::net::IpAddr> {
    *LOCAL_IP.read().unwrap()
}

/// 取与当前源 IP 匹配的 client（源 IP 变化时自动重建）
fn client() -> Client {
    let want = current_local_ip();
    if let Some((ip, c)) = CLIENT_CACHE.read().unwrap().as_ref() {
        if *ip == want {
            return c.clone();
        }
    }
    let c = build_client(want);
    *CLIENT_CACHE.write().unwrap() = Some((want, c.clone()));
    c
}

/// 清掉绑定重试用（绑定失败时退回不绑定，至少能拿到服务器响应）
fn client_unbound() -> Client {
    build_client(None)
}

pub fn build_client(local_ip: Option<std::net::IpAddr>) -> Client {
    let mut b = Client::builder()
        .timeout(Duration::from_secs(10))
        .danger_accept_invalid_certs(true)
        .default_headers({
            let mut h = reqwest::header::HeaderMap::new();
            h.insert(
                reqwest::header::CONTENT_TYPE,
                reqwest::header::HeaderValue::from_static("text/html;"),
            );
            h.insert(
                "Extend-Data",
                reqwest::header::HeaderValue::from_static("ostype=mac;"),
            );
            h.insert(
                reqwest::header::USER_AGENT,
                reqwest::header::HeaderValue::from_static("MERONG(0.9/;Macos)"),
            );
            h
        });
    if let Some(ip) = local_ip {
        b = b.local_address(ip);
    }
    b.build().unwrap_or_else(|_| Client::new())
}

/// POST 拿原始响应文本 (http 失败自动试 https —— 门户常把 http 重定向)
fn post_raw(server: &str, path: &str, query: &[(&str, &str)]) -> Result<String> {
    let bound = current_local_ip();
    let client = client();
    let mut last_err: Option<anyhow::Error> = None;
    for proto in ["http", "https"] {
        let url = format!("{}://{}{}", proto, server, path);
        match client.post(&url).query(query).send() {
            Ok(r) => return r.text().context("读响应体失败"),
            Err(e) => last_err = Some(anyhow::anyhow!("POST {} 失败: {}", url, e)),
        }
    }
    // 绑定源 IP 后失败（网卡刚切换 / IP 已失效）→ 退回不绑定再试一轮
    if bound.is_some() {
        let u = client_unbound();
        for proto in ["http", "https"] {
            let url = format!("{}://{}{}", proto, server, path);
            match u.post(&url).query(query).send() {
                Ok(r) => return r.text().context("读响应体失败"),
                Err(e) => last_err = Some(anyhow::anyhow!("POST {} 失败(未绑定重试): {}", url, e)),
            }
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("请求失败")))
}

/// 同 post_raw，但 query 已经是编好的字符串（用于需要 GBK 编码的字段）
fn post_raw_encoded(server: &str, path: &str, query_encoded: &str) -> Result<String> {
    let client = client();
    let mut last_err: Option<anyhow::Error> = None;
    for proto in ["http", "https"] {
        let url = format!("{}://{}{}?{}", proto, server, path, query_encoded);
        match client.post(&url).send() {
            Ok(r) => return r.text().context("读响应体失败"),
            Err(e) => last_err = Some(anyhow::anyhow!("POST {} 失败: {}", url, e)),
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("请求失败")))
}

/// POST 后解析 JSON，做 GBK mojibake 修复
fn post_json(server: &str, path: &str, query: &[(&str, &str)]) -> Result<Value> {
    let body = post_raw(server, path, query)?;
    let mut v: Value =
        serde_json::from_str(&body).with_context(|| format!("JSON 解析失败: {}", &body[..body.len().min(200)]))?;
    codec::fix_json_value(&mut v);
    Ok(v)
}

/// 在 "__res = {...}" JS 字面量里找 "KEY": "value" —— 兼容非标准 JSON
fn find_qstr(body: &str, key: &str) -> Option<String> {
    let pat = format!("\"{}\"", key);
    let start = body.find(&pat)? + pat.len();
    let rest = &body[start..];
    // 跳过 : 与空白
    let rest = rest.trim_start_matches(|c: char| c == ':' || c.is_whitespace());
    if !rest.starts_with('"') {
        return None;
    }
    let rest = &rest[1..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

/// data 层提取: 顶层 data 优先; code==200(0xc8) 时取根
fn data_layer(v: &Value) -> &Value {
    if let Some(d) = v.get("data") {
        if d.is_object() {
            // getdeviceinfoprocess 存在 data.data 嵌套
            if let Some(dd) = d.get("data") {
                if dd.is_object() {
                    return dd;
                }
            }
            return d;
        }
    }
    if v.get("code").and_then(|c| c.as_i64()) == Some(200) {
        return v;
    }
    v
}

// ─── get_server_info ───
/// 响应是 "__res = {...}" JS 字面量 (含 parseFloat / 裸数字 key / Boolean(false))，
/// 不是合法 JSON —— 直接字符串提取 "SERVERIP"，兜底 MANAGER_IP / RE_URL。
pub fn get_server_info(candidate: &str) -> Result<String> {
    let body = post_raw(
        candidate,
        "/a/ajax.php",
        &[
            ("tradecode", "get_server_info"),
            ("data_type", "json"),
            ("local_lguage_set", codec::lang()),
        ],
    )?;
    for key in ["SERVERIP", "serverip", "MANAGER_IP"] {
        if let Some(ip) = find_qstr(&body, key) {
            if !ip.is_empty() {
                return Ok(ip);
            }
        }
    }
    // RE_URL = "http://nac.xxx/" → 取 host 兜底
    if let Some(u) = find_qstr(&body, "RE_URL") {
        let host = u
            .trim_start_matches("http://")
            .trim_start_matches("https://")
            .trim_matches('/');
        if !host.is_empty() {
            return Ok(host.to_string());
        }
    }
    anyhow::bail!("get_server_info 响应无 SERVERIP: {}", &body[..body.len().min(120)])
}

// ─── getdeviceinfoprocess (注册) ───
/// dev_xml 在 URL query, ASM-Base64 编码 (encode=1)
/// 返回 (DeviceID, AscID)
pub fn register_device(server: &str, dev_xml_b64: &str) -> Result<(String, String)> {
    let v = post_json(
        server,
        "/a/ajax.php",
        &[
            ("tradecode", "getdeviceinfoprocess"),
            ("gettype", "control"),
            ("isopennet", "isopen"),
            ("depart_id", "0"),
            ("username", "iphone"),
            ("tel", ""),
            ("remark", "iosagent"),
            ("device_id", ""),
            ("positions", ""),
            ("is_mobile", "0"),
            ("is_guest", "0"),
            ("os_platform", "OS"),
            ("encode", "1"),
            ("data_type", "json"),
            ("dev_xml", dev_xml_b64),
        ],
    )?;
    let d = data_layer(&v);
    let devid = d.get("DeviceID").and_then(|x| x.as_str()).unwrap_or_default();
    let ascid = d.get("AscID").and_then(|x| x.as_str()).unwrap_or_default();
    if devid.is_empty() {
        anyhow::bail!("注册响应无 DeviceID: {}", v);
    }
    Ok((devid.to_string(), ascid.to_string()))
}

/// 服务器把数值字段全当**字符串**下发（"IsSafeCheck":"1"、"IsAgainReg":"0"），
/// serde 的 as_i64() 对 Value::String 返回 None，直接用会把 1 误判成 0。
fn int_flex(v: Option<&Value>) -> Option<i64> {
    let v = v?;
    if let Some(n) = v.as_i64() {
        return Some(n);
    }
    if let Some(f) = v.as_f64() {
        return Some(f as i64);
    }
    v.as_str().and_then(|s| s.trim().parse::<i64>().ok())
}

// ─── net_auth ───
pub struct AuthResult {
    pub ok: bool,
    pub role_id: Option<String>,
    pub policy_id: Option<String>,
    pub is_safe_check: Option<i64>,
    pub is_again_reg: Option<i64>,
    pub error_msg: String,
}

/// type=User user_name=GBK-b64 password=ASCII-b64 authserver=AdDomain(GBK-b64)
/// verify_code 默认空
pub fn net_auth(server: &str, user: &str, pass: &str, devid: &str) -> Result<AuthResult> {
    net_auth_ext(server, user, pass, devid, "", "AdDomain")
}

pub fn net_auth_ext(
    server: &str,
    user: &str,
    pass: &str,
    devid: &str,
    verify_code: &str,
    authserver: &str,
) -> Result<AuthResult> {
    let u = codec::encode_gbk(user);
    let p = codec::encode_ascii(pass);
    let a = codec::encode_gbk(authserver);
    let v = post_json(
        server,
        "/a/ajax.php",
        &[
            ("tradecode", "net_auth"),
            ("type", "User"),
            ("user_name", u.as_str()),
            ("password", p.as_str()),
            ("deviceid", devid),
            ("verify_code", verify_code),
            ("authserver", a.as_str()),
            ("data_type", "json"),
            ("local_lguage_set", codec::lang()),
        ],
    )?;
    let d = data_layer(&v);
    // dealWithJsonDict: RoleID→RoleID PolicyID→PolicyId IsSafeCheck→isSafeCheck IsAgainReg
    let role = d.get("RoleID").and_then(|x| x.as_str()).map(String::from);
    let pol = d.get("PolicyID").and_then(|x| x.as_str()).map(String::from);
    let ok = role.as_ref().map(|r| !r.is_empty()).unwrap_or(false);
    let error_msg = d
        .get("errorMsg")
        .or_else(|| v.get("errorMsg"))
        .and_then(|x| x.as_str())
        .unwrap_or_default()
        .to_string();
    Ok(AuthResult {
        ok,
        role_id: d.get("RoleID").and_then(|x| x.as_str()).map(String::from),
        policy_id: pol,
        is_safe_check: int_flex(d.get("IsSafeCheck")),
        is_again_reg: int_flex(d.get("IsAgainReg")),
        error_msg,
    })
}

// ─── get_authflag: data.res=="1" → 需要认证 ───
pub fn get_authflag(server: &str, devid: &str) -> Result<bool> {
    let v = post_json(
        server,
        "/a/ajax.php",
        &[
            ("tradecode", "get_authflag"),
            ("data_type", "json"),
            ("local_lguage_set", codec::lang()),
            ("deviceid", devid),
        ],
    )?;
    let d = data_layer(&v);
    match d.get("res").and_then(|x| x.as_str()) {
        Some("1") => Ok(true),
        Some("0") => Ok(false),
        _ => Ok(true), // res 空 → 默认需要认证
    }
}

// ─── getmobileconfig → data.isvpn ───
pub fn get_mobile_config(server: &str, ascid: &str) -> Result<bool> {
    let v = post_json(
        server,
        "/a/ajax.php",
        &[
            ("tradecode", "getmobileconfig"),
            ("data_type", "json"),
            ("ascid", ascid),
        ],
    )?;
    let d = data_layer(&v);
    let isvpn = d
        .get("isvpn")
        .map(|x| x.as_i64().map(|n| n != 0).unwrap_or_else(|| {
            x.as_str().map(|s| s == "1" || s.eq_ignore_ascii_case("true")).unwrap_or(false)
        }))
        .unwrap_or(false);
    Ok(isvpn)
}

// ─── 安检: getcheckpolicy ───
/// 拉取策略体（PolicyBody 为 GBK XML，仅用于日志/条目统计，失败不影响主流程）
pub fn get_check_policy(server: &str, policy_id: &str) -> Result<Value> {
    post_json(
        server,
        "/a/ajax.php",
        &[
            ("tradecode", "getcheckpolicy"),
            ("policy_id", policy_id),
            ("ostype", "mac"),
            ("local_lguage_set", codec::lang()),
            ("data_type", "json"),
        ],
    )
}

/// 从 PolicyBody XML 里数出 CheckItems 的条目数（仅供日志）
pub fn count_check_items(v: &Value) -> usize {
    let d = data_layer(v);
    d.get("PolicyBody")
        .and_then(|x| x.as_str())
        .map(|s| s.matches("<ItemID>").count())
        .unwrap_or(0)
}

// ─── 安检: mobileresult 上报 ───
/// 上报安检结果。正确姿势（复刻 ASM plist 里存的实际值）：
///   itemsid  = "99"                     ← 具体条目 id，不是空
///   checkres = 完整 XML，含 <Result>Yes</Result> + <Message>符合管理员要求</Message>
///   is_safecheck = 1
///
/// 空 itemsid/checkres 虽然服务端也回 success/Rate=100，但那是"无失败项"的空响应，
/// 并不真正下发 ACL（实测：认证成功但流量仍被 portal 劫持）。
/// 必须带真实条目结果，网关才把设备从"隔离域"挪到 PassIpRegion。
///
/// 注意：这是写操作，会刷新服务端该设备的安检 ACL 与会话状态。
pub fn mobile_result(
    server: &str,
    devid: &str,
    policy_id: &str,
    role_id: &str,
    is_safe_check: i64,
    itemsid: &str,
    checkres: &str,
) -> Result<Value> {
    let sc = is_safe_check.to_string();
    // checkres 是 GBK 声明的 XML，必须按 GBK 字节百分号编码后手工拼 query，
    // 走 .query() 只会编成 UTF-8，服务器解不出中文 → 判定结果不生效。
    let q = build_mobile_result_query(
        devid,
        policy_id,
        role_id,
        is_safe_check,
        itemsid,
        checkres,
    );
    let body = post_raw_encoded(server, "/a/ajax.php", &q)?;
    let mut v: Value = serde_json::from_str(&body).with_context(|| {
        format!("JSON 解析失败: {}", &body[..body.len().min(200)])
    })?;
    codec::fix_json_value(&mut v);
    Ok(v)
}

/// 构造 mobileresult 的 query（已百分号编码，checkres 走 GBK）
pub fn build_mobile_result_query(
    devid: &str,
    policy_id: &str,
    role_id: &str,
    is_safe_check: i64,
    itemsid: &str,
    checkres: &str,
) -> String {
    let sc = is_safe_check.to_string();
    let xml_real = codec::decode_unicode_escapes(checkres);
    format!(
        "tradecode=mobileresult&deviceid={}&policyid={}&roleid={}&is_safecheck={}&LastAuthID=0&itemsid={}&checkres={}&data_type=json",
        codec::percent_encode(devid),
        codec::percent_encode(policy_id),
        codec::percent_encode(role_id),
        codec::percent_encode(&sc),
        codec::percent_encode(itemsid),
        codec::gbk_percent_encode(&xml_real),
    )
}

/// 探测是否被 NAC portal 劫持。
///
/// 用绑定物理网卡源 IP 的 client 请求一个明文 HTTP 站点（不走 Clash），
/// 若响应 30x 且 Location 指向 NAC 域名/地址，说明 ACL 已失效、流量被劫持。
/// 这是"用着用着就断网"最可靠的信号 —— 比 get_authflag 靠谱
/// （后者实测恒返回 res="1"，无法区分已认证/未认证）。
pub fn probe_portal_redirect() -> Option<String> {
    let c = Client::builder()
        .timeout(Duration::from_secs(6))
        .redirect(reqwest::redirect::Policy::none());
    let c = match current_local_ip() {
        Some(ip) => c.local_address(ip),
        None => c,
    };
    let c = c.build().ok()?;
    for url in ["http://www.baidu.com", "http://www.bing.com"] {
        let Ok(r) = c.get(url).send() else { continue };
        let code = r.status().as_u16();
        let loc = r
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if (300..400).contains(&code)
            && (loc.contains("nac.") || loc.contains("172.29.92.2") || loc.contains("/a/index.html"))
        {
            return Some(loc.to_string());
        }
    }
    None
}

/// 兜底：ASM plist 里没有 checkres 时，用最小合法 XML（单条目、全通过）
pub fn default_checkres_xml() -> String {
    concat!(
        r#"<?xml version="1.0" encoding="gbk"?><Result><DllVersion></DllVersion><CheckType>"#,
        r#"<InsideName>CheckSoftForbidInstallStat_mac</InsideName>"#,
        r#"<OutsideName>禁止安装软件检查</OutsideName>"#,
        r#"<Desc>检查客户机是否安装了管理员要求禁止安装的软件。</Desc>"#,
        r#"<Key>Yes</Key><Result>Yes</Result><Message>符合管理员要求</Message>"#,
        r#"</CheckType></Result>"#
    )
    .to_string()
}

/// 剥出 CheckResult 的结论：返回 (通过?, 描述)
pub fn mobile_result_verdict(v: &Value) -> (bool, String) {
    let d = data_layer(v);
    let cr = d.get("CheckResult");
    let res = cr
        .and_then(|x| x.get("Res"))
        .and_then(|x| x.as_str())
        .unwrap_or("");
    // ErrItem 为空数组 / 空字符串 → 无失败项
    let err_empty = match d.get("ErrItem") {
        None => true,
        Some(Value::String(s)) => s.is_empty(),
        Some(Value::Array(a)) => a.is_empty(),
        _ => false,
    };
    let desc = cr
        .and_then(|x| x.get("Desc"))
        .and_then(|x| x.as_str())
        .unwrap_or("");
    // Desc 是 HTML，只取纯文本尾巴
    let plain: String = desc
        .split(['<', '>'])
        .filter(|s| !s.is_empty() && !s.contains('=') && !s.contains('/'))
        .last()
        .unwrap_or("")
        .trim()
        .to_string();
    (res == "success" && err_empty, plain)
}

// ─── check_device_illegal ───
#[allow(dead_code)]
pub fn check_device_illegal(server: &str, ip: &str, mac: &str, hard: &str) -> Result<Value> {
    post_json(
        server,
        "/a/ajax.php",
        &[
            ("tradecode", "check_device_illegal"),
            ("ip", ip),
            ("mac", mac),
            ("hard", hard),
            ("data_type", "json"),
        ],
    )
}

// ─── auto_auth 心跳兜底 ───
/// 需要 data.RoleID + data.DeviceID → true
pub fn auto_auth(server: &str, devid: &str) -> Result<bool> {
    let v = post_json(
        server,
        "/a/ajax.php",
        &[
            ("tradecode", "auto_auth"),
            ("deviceid", devid),
            ("from", "assistant"),
            ("type", "0"),
            ("data_type", "json"),
        ],
    )?;
    let d = data_layer(&v);
    let ok = d.get("RoleID").is_some() && d.get("DeviceID").is_some();
    Ok(ok)
}

// ─── cutoff_net ───
/// POST /phpdir/trade.php (encode=1 → msg 走 ASM-Base64 GBK 编码)
pub fn cutoff_net(server: &str, devid: &str, msg: &str) -> Result<()> {
    let m = codec::encode_gbk(msg);
    post_json(
        server,
        "/phpdir/trade.php",
        &[
            ("tradecode", "cutoff_net"),
            ("device_id", devid),
            ("tradetype", "authcheck"),
            ("data_type", "json"),
            ("mod", "a"),
            ("encode", "1"),
            ("msg", m.as_str()),
        ],
    )?;
    Ok(())
}
