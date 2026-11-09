// pf 防火墙 —— 复刻 ExecuteHostFirewallPolicy / createPfConfWithRules
//
// 原版模板逐行一致，<Blacklist> 表语义实为白名单（block all + 双向 pass 表内地址）。
// Clash TUN 兼容：附加 pass in/out quick on utunN。
// 白名单自动追加: serverip + 默认网关 + 系统 DNS + 代理端口。
use anyhow::Result;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use crate::state::StateHandle;

const PF_TEMPLATE: &str = r#"# PF Set
set block-policy drop
set fingerprints '/etc/pf.os'
set skip on lo0
scrub-anchor "com.apple/*"
# TABLES
table <Blacklist> { %BLACKLIST% } persist
# Blocks
block in all
block out all
pass in log quick from <Blacklist> to any label "BlackList_IN"
pass out log quick from any to <Blacklist> label "BlackList_OUT"
"#;

/// 当前活动的 utun 接口名（Clash TUN 通常是 utun4/utun9）
fn active_utuns() -> Vec<String> {
    if let Ok(out) = Command::new("ifconfig").arg("-l").output() {
        String::from_utf8_lossy(&out.stdout)
            .split_whitespace()
            .filter(|n| n.starts_with("utun"))
            .map(String::from)
            .collect()
    } else {
        Vec::new()
    }
}

fn system_dns() -> Vec<String> {
    if let Ok(out) = Command::new("scutil").arg("--dns").output() {
        let s = String::from_utf8_lossy(&out.stdout);
        s.lines()
            .filter_map(|l| {
                let t = l.trim();
                t.strip_prefix("nameserver[")
                    .and_then(|r| r.split(':').nth(1))
                    .map(|x| x.trim().to_string())
            })
            .collect()
    } else {
        Vec::new()
    }
}

/// AccessDomains CSV "startIP-endIP" → CIDR 聚合
fn ip_range_to_cidrs(start: Ipv4Addr, end: Ipv4Addr) -> Vec<String> {
    let mut out = Vec::new();
    let (mut lo, hi) = (u32::from(start), u32::from(end));
    while lo <= hi {
        let tz = lo.trailing_zeros();
        let max_len = 32 - (hi - lo + 1).leading_zeros();
        let len = tz.min(max_len);
        let prefix = 32 - len;
        out.push(format!("{}/{}", Ipv4Addr::from(lo & (u32::MAX << len.max(0))), prefix));
        lo = lo.wrapping_add(1 << len);
    }
    out
}

pub fn parse_access_domains(raw: &str, extra: &[String]) -> Vec<String> {
    use std::collections::BTreeSet;
    let mut set = BTreeSet::new();
    for e in extra {
        if !e.is_empty() && e != "0.0.0.0" {
            set.insert(e.clone());
        }
    }
    for r in raw.split(',') {
        let r = r.trim();
        if r.is_empty() {
            continue;
        }
        if let Some((s, e)) = r.split_once('-') {
            if let (Ok(a), Ok(b)) = (s.parse::<Ipv4Addr>(), e.parse::<Ipv4Addr>()) {
                set.extend(ip_range_to_cidrs(a, b));
            }
        } else {
            set.insert(r.to_string());
        }
    }
    set.into_iter().collect()
}

pub fn generate_pf_conf(whitelist: &[String], utuns: &[String]) -> String {
    let table = whitelist.join(", ");
    let mut conf = PF_TEMPLATE.replace("%BLACKLIST%", &table);
    for u in utuns {
        conf.push_str(&format!("pass in quick on {}\n", u));
        conf.push_str(&format!("pass out quick on {}\n", u));
    }
    conf
}

/// socket 线程与主线程共享的 pf 上下文
pub struct PfCtx {
    dir: PathBuf,
    server: String,
    gateway: Mutex<String>,
    applied: AtomicBool,
    is_open: AtomicBool,
    is_offline_open: AtomicBool,
    no_pf: bool,
}

impl PfCtx {
    pub fn new(st: &StateHandle, server: String, gateway: String, no_pf: bool) -> Self {
        Self {
            dir: st.dir.clone(),
            server,
            gateway: Mutex::new(gateway),
            applied: AtomicBool::new(false),
            is_open: AtomicBool::new(false),
            is_offline_open: AtomicBool::new(false),
            no_pf,
        }
    }

    pub fn set_gateway(&self, gw: String) {
        *self.gateway.lock().unwrap() = gw;
    }
    pub fn was_applied(&self) -> bool {
        self.applied.load(Ordering::SeqCst)
    }
    pub fn is_open(&self) -> bool {
        self.is_open.load(Ordering::SeqCst)
    }
    pub fn is_offline_open(&self) -> bool {
        self.is_offline_open.load(Ordering::SeqCst)
    }

    /// 应用服务器推送的防火墙策略 (IsOpen=1 → block all + 白名单; IsOpen=0 → 恢复)
    pub fn apply_policy(&self, access_domains: &str, is_open: bool, is_offline_open: bool) -> Result<()> {
        self.is_open.store(is_open, Ordering::SeqCst);
        self.is_offline_open
            .store(is_offline_open, Ordering::SeqCst);
        if self.no_pf {
            println!("[*] pf 禁用 (--no-pf/--no-privilege)，策略仅记录");
            return Ok(());
        }
        if !is_open {
            // 只有真的应用过才打日志，否则静默
            let was = self.applied.swap(false, Ordering::SeqCst);
            crate::privesc::restore_pf(&self.fake_state(), was);
            return Ok(());
        }
        crate::privesc::backup_pf_conf(&self.fake_state());
        let extra = {
            let gw = self.gateway.lock().unwrap().clone();
            let mut v = vec![self.server.split(':').next().unwrap_or(&self.server).to_string(), gw];
            v.extend(system_dns());
            // Clash 本地代理端口
            v.extend(["127.0.0.1".to_string(), "198.18.0.1".to_string()]);
            v
        };
        let wl = parse_access_domains(access_domains, &extra);
        let conf = generate_pf_conf(&wl, &active_utuns());
        let path = self.dir.join("cfg").join("pf.conf");
        std::fs::create_dir_all(path.parent().unwrap())?;
        std::fs::write(&path, &conf)?;
        crate::privesc::load_pf(&path, &self.fake_state())?;
        self.applied.store(true, Ordering::SeqCst);
        println!("[+] pf 策略已应用 (白名单 {} 条, utun pass {} 个)", wl.len(), active_utuns().len());
        Ok(())
    }

    /// socket 断线时按 ASM 语义恢复 pf
    pub fn restore_if_needed(&self) {
        if self.applied.load(Ordering::SeqCst)
            && self.is_open.load(Ordering::SeqCst)
            && !self.is_offline_open.load(Ordering::SeqCst)
        {
            crate::privesc::restore_pf(&self.fake_state(), true);
            self.applied.store(false, Ordering::SeqCst);
        }
    }

    /// PfCtx 需要 StateHandle 的几个方法只有 dir，做一个轻量副本
    fn fake_state(&self) -> StateHandle {
        crate::state::State::load(Some(self.dir.as_path()))
            .expect("state dir must exist")
    }
}
