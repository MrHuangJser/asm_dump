// 网络变化监听 —— 复刻 Darwin notify "com.apple.system.config.network_change"
// 原版: notify → ~3s debounce → sleep(3) → 对比路由快照 → getDevXml 重注册
// 这里用 `scutil` 交互进程订阅 State:/Network/* + Global/IPv4/DNS/Interface
// 事件去抖; scutil 不可用时轮询接口签名兜底; 主循环再用路由快照做权威判定。
use std::collections::BTreeSet;
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

/// scutil 交互会话: n.add + n.watch 一组 key, 变化时 stdout 逐行输出
struct ScutilWatch {
    child: Option<Child>,
    rx: Option<mpsc::Receiver<String>>,
}

impl ScutilWatch {
    fn start() -> Self {
        let mut child = match Command::new("scutil")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
        {
            Ok(c) => c,
            Err(_) => return Self { child: None, rx: None },
        };
        let (tx, rx) = mpsc::channel::<String>();
        if let Some(stdout) = child.stdout.take() {
            thread::spawn(move || {
                let rd = BufReader::new(stdout);
                for line in rd.lines().flatten() {
                    if tx.send(line).is_err() {
                        break;
                    }
                }
            });
        }
        if let Some(mut stdin) = child.stdin.take() {
            let keys = [
                "State:/Network/Global/IPv4",
                "State:/Network/Global/DNS",
                "State:/Network/Global/Proxies",
                "State:/Network/Interface",
                "State:/Network/Service",
            ];
            for k in keys {
                let _ = writeln!(stdin, "n.add {}", k);
            }
            let _ = writeln!(stdin, "n.watch");
            let _ = stdin.flush();
        }
        Self {
            child: Some(child),
            rx: Some(rx),
        }
    }

    /// 等一个事件; 返回 true=有事件
    fn wait_event(&mut self, timeout: Duration, stop: &Arc<AtomicBool>) -> bool {
        let deadline = Instant::now() + timeout;
        if let Some(rx) = &self.rx {
            loop {
                if stop.load(Ordering::SeqCst) {
                    return false;
                }
                if Instant::now() >= deadline {
                    return false;
                }
                match rx.recv_timeout(Duration::from_millis(200)) {
                    Ok(_) => return true,
                    Err(mpsc::RecvTimeoutError::Timeout) => {}
                    Err(mpsc::RecvTimeoutError::Disconnected) => {
                        self.rx = None;
                        return false;
                    }
                }
            }
        }
        false
    }
}

impl Drop for ScutilWatch {
    fn drop(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

/// 简易接口签名: en:inet 地址排序拼接 —— 轮询兜底用
fn quick_iface_sig() -> String {
    let out = match Command::new("ifconfig").output() {
        Ok(o) => String::from_utf8_lossy(&o.stdout).to_string(),
        Err(_) => return String::new(),
    };
    let mut cur_en = String::new();
    let mut set = BTreeSet::new();
    for line in out.lines() {
        if !line.starts_with('\t') && !line.starts_with(' ') {
            if let Some(colon) = line.find(':') {
                cur_en = line[..colon].to_string();
            }
        }
        let t = line.trim();
        if t.starts_with("inet ") && !cur_en.is_empty() {
            let addr = t.split_whitespace().nth(1).unwrap_or("");
            set.insert(format!("{}:{}", cur_en, addr));
        }
    }
    set.into_iter().collect::<Vec<_>>().join("|")
}

/// ASM network_change 等价物 —— 阻塞等待网络变化事件:
/// scutil 通知 → 排空积压 → 返回 true; scutil 挂了 → 每 3s 轮询 ifconfig 签名。
/// ASM 的 ~3s debounce + sleep(3) 由调用方执行 (main 循环)。
pub fn wait_network_change(stop: &Arc<AtomicBool>) -> bool {
    let mut watcher = ScutilWatch::start();
    let mut sig = quick_iface_sig();
    loop {
        if stop.load(Ordering::SeqCst) {
            return false;
        }
        if watcher.rx.is_some() {
            // scutil 活跃: 事件驱动
            if watcher.wait_event(Duration::from_secs(1), stop) {
                while watcher.wait_event(Duration::from_millis(200), stop) {}
                if stop.load(Ordering::SeqCst) {
                    return false;
                }
                if quick_iface_sig() != sig {
                    return true;
                }
                // DNS/代理等无关变化 → 继续等
            }
        } else {
            // scutil 不可用: 轮询签名
            if debounced(stop, Duration::from_secs(3)) {
                return false;
            }
            if quick_iface_sig() != sig {
                return true;
            }
        }
    }
}

/// 可被 stop 中断的睡眠 (ASM debounce/sleep(3) 语义)
pub fn debounced(stop: &Arc<AtomicBool>, d: Duration) -> bool {
    let deadline = Instant::now() + d;
    while Instant::now() < deadline {
        if stop.load(Ordering::SeqCst) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}
