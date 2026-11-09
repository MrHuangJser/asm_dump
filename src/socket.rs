// TCP 长连接协议 —— 复刻 initNetwork:andPort: / SocketSendUNRecv / sub_1000bd650
//
// 帧头 60B LE:
//   +0x00 u32 total_len = 0x3c + comp_body_len
//   +0x04 u32 magic 0x354d5341 ("ASM5")
//   +0x08 u32 cType (0=心跳, 1=业务)
//   +0x0c u32 flag_compressed = 1
//   +0x10 u32 flag_ciphered   = 1
//   +0x14 u8[32] tradecode (发送: rotl4(b^k); 接收: rotl4(b)^k)
//   +0x34 u32 nSNO
//   +0x38 u32 body_orig_len
// body: zlib-9 压缩后的密文 (rotl4(b^k) per byte, key="infogo")
//
// 端口 37527 (dword_1001bee10 静态初始化值)。心跳 30s "HeartTest" cType=0。
// 连接后顺序: UpdateAgentInfo → GetAgentPolicyList → GetHostFirewallPolicy → recv loop。
// 收帧按 TradeCode 分发; HeartTest 回包清空 pending SNO; 服务器推送含
// SecurityDomain/AccessDomains/IsOpen → 重新生成 pf.conf。
use anyhow::{Context, Result};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::pf::PfCtx;
use crate::state::StateHandle;

pub const DEFAULT_PORT: u16 = 37527; // dword_1001bee10
const MAGIC: u32 = 0x354d5341; // "ASM5"
const HDR_LEN: usize = 0x3c;
const TC_LEN: usize = 0x20;
const KEY: &[u8] = b"infogo";
const HEARTBEAT: Duration = Duration::from_secs(30);
const POLL_MS: i32 = 200;
const MAX_BODY: u32 = 0x100000;

pub enum SockCmd {
    Reconnect,
    IpRenew,
    Stop,
}

// ─── 加解密 (不对称: 发送先 xor 后换 nibble; 接收先换 nibble 后 xor) ───
fn cipher_send(buf: &mut [u8]) {
    for (i, b) in buf.iter_mut().enumerate() {
        *b = (*b ^ KEY[i % KEY.len()]).rotate_left(4);
    }
}
fn cipher_recv(buf: &mut [u8]) {
    for (i, b) in buf.iter_mut().enumerate() {
        *b = b.rotate_left(4) ^ KEY[i % KEY.len()];
    }
}

fn zlib_compress(src: &[u8]) -> Vec<u8> {
    use flate2::write::ZlibEncoder;
    let mut e = ZlibEncoder::new(Vec::new(), flate2::Compression::best());
    let _ = e.write_all(src);
    e.finish().unwrap_or_default()
}

fn zlib_decompress(src: &[u8], out_len: usize) -> Vec<u8> {
    use flate2::read::ZlibDecoder;
    let mut d = ZlibDecoder::new(src);
    let mut out = Vec::with_capacity(out_len + 16);
    let _ = d.read_to_end(&mut out);
    out
}

// ─── XML → 扁平 map ───
fn xml_flat_map(xml: &str) -> BTreeMap<String, String> {
    use quick_xml::events::Event;
    use quick_xml::Reader;
    let mut map = BTreeMap::new();
    let mut r = Reader::from_str(xml);
    r.trim_text(true);
    let mut path: Vec<String> = Vec::new();
    loop {
        match r.read_event() {
            Ok(Event::Start(e)) => {
                path.push(String::from_utf8_lossy(e.name().as_ref()).to_string());
            }
            Ok(Event::Text(e)) => {
                if let Some(k) = path.last() {
                    if let Ok(t) = e.unescape() {
                        map.insert(k.clone(), t.to_string());
                    }
                }
            }
            Ok(Event::Empty(_)) => {}
            Ok(Event::End(_)) => {
                path.pop();
            }
            Ok(Event::Eof) | Err(_) => break,
            _ => {}
        }
    }
    map
}

// ─── 帧收发 ───
fn send_frame(
    s: &mut TcpStream,
    tradecode: &str,
    body: &str,
    ctype: u32,
    sno: u32,
) -> Result<()> {
    let (gbk, _, _) = encoding_rs::GBK.encode(body);
    let mut payload = zlib_compress(&gbk);
    cipher_send(&mut payload);

    let mut hdr = vec![0u8; HDR_LEN];
    let total = (HDR_LEN + payload.len()) as u32;
    hdr[0x00..0x04].copy_from_slice(&total.to_le_bytes());
    hdr[0x04..0x08].copy_from_slice(&MAGIC.to_le_bytes());
    hdr[0x08..0x0c].copy_from_slice(&ctype.to_le_bytes());
    hdr[0x0c..0x10].copy_from_slice(&1u32.to_le_bytes()); // compressed
    hdr[0x10..0x14].copy_from_slice(&1u32.to_le_bytes()); // ciphered
    let mut tc = [0u8; TC_LEN];
    let n = tradecode.len().min(TC_LEN);
    tc[..n].copy_from_slice(&tradecode.as_bytes()[..n]);
    cipher_send(&mut tc);
    hdr[0x14..0x34].copy_from_slice(&tc);
    hdr[0x34..0x38].copy_from_slice(&sno.to_le_bytes());
    hdr[0x38..0x3c].copy_from_slice(&(gbk.len() as u32).to_le_bytes());

    s.write_all(&hdr)?;
    s.write_all(&payload)?;
    s.flush()?;
    Ok(())
}

struct Frame {
    tradecode: String,
    #[allow(dead_code)]
    sno: u32,
    body: String,
}

fn recv_frame(s: &mut TcpStream) -> Result<Frame> {
    let mut hdr = [0u8; HDR_LEN];
    s.read_exact(&mut hdr).context("recv headPacket")?;
    let total = u32::from_le_bytes(hdr[0x00..0x04].try_into().unwrap());
    let flag_comp = u32::from_le_bytes(hdr[0x0c..0x10].try_into().unwrap());
    let flag_enc = u32::from_le_bytes(hdr[0x10..0x14].try_into().unwrap());
    let sno = u32::from_le_bytes(hdr[0x34..0x38].try_into().unwrap());
    let orig_len = u32::from_le_bytes(hdr[0x38..0x3c].try_into().unwrap());
    let body_len = total.wrapping_sub(HDR_LEN as u32);
    if body_len < 1 || body_len > MAX_BODY || orig_len > MAX_BODY {
        anyhow::bail!("body len error {}!", body_len);
    }
    let mut body = vec![0u8; body_len as usize];
    s.read_exact(&mut body).context("recv body")?;

    let mut tc = [0u8; TC_LEN];
    tc.copy_from_slice(&hdr[0x14..0x34]);
    cipher_recv(&mut tc);
    let end = tc.iter().position(|&b| b == 0).unwrap_or(TC_LEN);
    let tradecode = String::from_utf8_lossy(&tc[..end]).to_string();

    if flag_enc != 0 {
        cipher_recv(&mut body);
    }
    let plain = if flag_comp != 0 {
        zlib_decompress(&body, orig_len as usize)
    } else {
        body
    };
    let (utf8, _, _) = encoding_rs::GBK.decode(&plain);
    Ok(Frame {
        tradecode,
        sno,
        body: utf8.into_owned(),
    })
}

/// poll(2) 等可读 —— 不阻塞在 read 上，帧一旦开始读就不会被 200ms 超时切断
fn wait_readable(s: &TcpStream, ms: i32) -> bool {
    let mut pfd = libc::pollfd {
        fd: s.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    let r = unsafe { libc::poll(&mut pfd, 1, ms) };
    r > 0 && (pfd.revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR)) != 0
}

// ─── 各业务发送 ───
fn send_update_agent_info(s: &mut TcpStream, devid: &str) -> Result<()> {
    let xml = format!(
        "<?xml version=\"1.0\" encoding=\"gbk\"?><ASM><TradeCode>UpdateAgentInfo</TradeCode><AgentID>{}</AgentID><requestClientType>mobile</requestClientType></ASM>",
        devid
    );
    send_frame(s, "UpdateAgentInfo", &xml, 1, fastrand::u32(0..0x100000))
}

fn send_get_agent_policy_list(s: &mut TcpStream, devid: &str) -> Result<()> {
    let xml = format!(
        "<?xml version=\"1.0\" encoding=\"gbk\"?><ASM><TradeCode>GetAgentPolicyList</TradeCode><AgentID>{}</AgentID></ASM>",
        devid
    );
    send_frame(s, "GetAgentPolicyList", &xml, 1, fastrand::u32(0..0xf4240))
}

fn send_get_host_firewall_policy(s: &mut TcpStream, devid: &str) -> Result<()> {
    let xml = format!(
        "<?xml version=\"1.0\" encoding=\"gbk\"?><ASM><TradeCode>GetHostFirewallPolicy</TradeCode><AgentID>{}</AgentID></ASM>",
        devid
    );
    send_frame(s, "GetHostFirewallPolicy", &xml, 1, fastrand::u32(0..0xf4240))
}

fn send_heartbeat(s: &mut TcpStream, devid: &str) -> Result<u32> {
    let sno = fastrand::u32(0..0x186a0);
    let xml = format!(
        "<?xml version=\"1.0\" encoding=\"gbk\"?><ASM><TradeCode>HeartTest</TradeCode><AgentID>{}</AgentID><requestClientType>mobile</requestClientType></ASM>",
        devid
    );
    send_frame(s, "HeartTest", &xml, 0, sno)?;
    Ok(sno)
}

// ─── 收包分发 ───
fn dispatch(frame: &Frame, st: &StateHandle, pf: &PfCtx) {
    let map = xml_flat_map(&frame.body);
    let tc = if frame.tradecode.is_empty() {
        map.get("TradeCode").cloned().unwrap_or_default()
    } else {
        frame.tradecode.clone()
    };
    match tc.as_str() {
        "HeartTest" => {
            st.set("SocketOffline", "0");
        }
        "UpdateAgentInfo" => {
            if let Some(v) = map.get("ServerID") {
                st.set("ServerID", v);
            }
            if let Some(v) = map.get("AgentID") {
                if !v.is_empty() {
                    st.set("devid", v);
                }
            }
        }
        "SvrMsgToAss" => {
            if map.get("WhatToDo").map(|s| s.as_str()) == Some("IpRenew") {
                crate::privesc::renew_dhcp(&st.get("main_en"), st);
            }
        }
        "UploadAgentLog" | "GetClientLog" => {}
        _ => {}
    }
    // 防火墙策略推送: 任何含 AccessDomains/SecurityDomain 的帧
    if map.contains_key("AccessDomains") || map.contains_key("SecurityDomain") {
        let is_open = map.get("IsOpen").map(|s| s == "1").unwrap_or(true);
        let is_offline_open = map.get("IsOfflineOpen").map(|s| s == "1").unwrap_or(false);
        let domains = map
            .get("AccessDomains")
            .or_else(|| map.get("SecurityDomain"))
            .cloned()
            .unwrap_or_default();
        let _ = pf.apply_policy(&domains, is_open, is_offline_open);
    }
}

fn connect(host: &str, port: u16) -> Result<TcpStream> {
    let addr = format!("{}:{}", host, port)
        .to_socket_addrs()?
        .next()
        .context("DNS 解析失败")?;
    // 绑物理网卡源 IP：否则到 NAC 的 TCP 也会走 Clash TUN（源 198.18.0.1），
    // 服务器据此判断设备在线地址，和 ACL 绑定的地址对不上。
    if let Some(local) = crate::http_api::current_local_ip() {
        if let Some(s) = connect_via(addr, local) {
            let _ = s.set_nodelay(true);
            return Ok(s);
        }
        eprintln!("[*] 绑定 {} 连接失败，退回默认路由", local);
    }
    let s = TcpStream::connect_timeout(&addr, Duration::from_millis(5000))?;
    s.set_nodelay(true)?;
    Ok(s)
}

/// bind(local) → connect(remote)，用于强制从指定源地址发起连接
fn connect_via(addr: std::net::SocketAddr, local: std::net::IpAddr) -> Option<TcpStream> {
    use std::os::unix::io::FromRawFd;
    let std::net::SocketAddr::V4(v4) = addr else {
        return None;
    };
    let std::net::IpAddr::V4(lip) = local else {
        return None;
    };
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
        if fd < 0 {
            return None;
        }
        let tv = libc::timeval { tv_sec: 5, tv_usec: 0 };
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_SNDTIMEO,
            &tv as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        );
        let mut sa: libc::sockaddr_in = std::mem::zeroed();
        sa.sin_family = libc::AF_INET as libc::sa_family_t;
        sa.sin_port = 0;
        sa.sin_addr.s_addr = u32::from_ne_bytes(lip.octets());
        if libc::bind(
            fd,
            &sa as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        ) != 0
        {
            libc::close(fd);
            return None;
        }
        let mut ra: libc::sockaddr_in = std::mem::zeroed();
        ra.sin_family = libc::AF_INET as libc::sa_family_t;
        ra.sin_port = v4.port().to_be();
        ra.sin_addr.s_addr = u32::from_ne_bytes(v4.ip().octets());
        if libc::connect(
            fd,
            &ra as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        ) != 0
        {
            libc::close(fd);
            return None;
        }
        Some(TcpStream::from_raw_fd(fd))
    }
}

/// socket 主循环: 连接 → 握手三连 → recv + 心跳 + 命令; 断线退避重连
pub fn run(
    st: &StateHandle,
    host: &str,
    pf: Arc<PfCtx>,
    cmd_rx: mpsc::Receiver<SockCmd>,
    stop: Arc<AtomicBool>,
) {
    let port = st
        .get("socket_port")
        .parse::<u16>()
        .unwrap_or(DEFAULT_PORT);
    let mut fails = 0u32;
    'outer: while !stop.load(Ordering::SeqCst) {
        let mut s = match connect(host, port) {
            Ok(s) => {
                println!("[+] socket 已连接 {}:{}", host, port);
                fails = 0;
                s
            }
            Err(e) => {
                fails += 1;
                eprintln!("[!] socket 连接失败({}): {:#}", fails, e);
                if fails >= 3 {
                    pf.restore_if_needed();
                    st.set("SocketOffline", "1");
                }
                if interruptible_sleep(&stop, Duration::from_secs((5 * fails.min(12)) as u64)) {
                    break 'outer;
                }
                continue 'outer;
            }
        };
        st.set("SocketOffline", "0");

        let devid = st.get("devid");
        let _ = send_update_agent_info(&mut s, &devid);
        let _ = send_get_agent_policy_list(&mut s, &devid);
        let _ = send_get_host_firewall_policy(&mut s, &devid);

        let mut last_hb = Instant::now();
        let mut reconnect = false;
        loop {
            while let Ok(cmd) = cmd_rx.try_recv() {
                match cmd {
                    SockCmd::Stop => break 'outer,
                    SockCmd::Reconnect => reconnect = true,
                    SockCmd::IpRenew => {
                        crate::privesc::renew_dhcp(&st.get("main_en"), st)
                    }
                }
            }
            if reconnect || stop.load(Ordering::SeqCst) {
                break;
            }
            if last_hb.elapsed() >= HEARTBEAT {
                if let Err(e) = send_heartbeat(&mut s, &st.get("devid")) {
                    eprintln!("[!] HeartTest 发送失败: {:#}", e);
                    break;
                }
                last_hb = Instant::now();
            }
            if !wait_readable(&s, POLL_MS) {
                continue;
            }
            match recv_frame(&mut s) {
                Ok(f) => dispatch(&f, st, &pf),
                Err(e) => {
                    eprintln!("[!] socket recv 断开: {:#}", e);
                    break;
                }
            }
        }
        if stop.load(Ordering::SeqCst) {
            break 'outer;
        }
        fails += 1;
        if fails >= 3 {
            pf.restore_if_needed();
            st.set("SocketOffline", "1");
        }
        if interruptible_sleep(&stop, Duration::from_secs((3 * fails.min(10)) as u64)) {
            break 'outer;
        }
    }
    println!("[*] socket 线程退出");
}

fn interruptible_sleep(stop: &Arc<AtomicBool>, d: Duration) -> bool {
    let deadline = Instant::now() + d;
    while Instant::now() < deadline {
        if stop.load(Ordering::SeqCst) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}
