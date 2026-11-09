// 持久化状态 —— 替代原版的 NSUserDefaults
// ASM 原版 plist keys: serverip / devid / AscID / RoleID / PolicyId /
//   route_info_data_1 / route_info_data_back_1 / last_domain_name_map_ip
use anyhow::Result;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

struct Inner {
    map: BTreeMap<String, String>,
    dirty: bool,
}

pub struct StateHandle {
    pub dir: PathBuf,
    file: PathBuf,
    inner: Arc<Mutex<Inner>>,
}

/// 加载入口: state::State::load(dir)
pub struct State;

impl State {
    pub fn load(dir: Option<&Path>) -> Result<StateHandle> {
        let dir = match dir {
            Some(d) => d.to_path_buf(),
            None => std::env::var("HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from("/tmp"))
                .join(".asm_bypass"),
        };
        std::fs::create_dir_all(dir.join("cfg"))?;
        let file = dir.join("state.json");
        let map = if file.exists() {
            serde_json::from_str(&std::fs::read_to_string(&file)?).unwrap_or_default()
        } else {
            BTreeMap::new()
        };
        Ok(StateHandle {
            dir,
            file,
            inner: Arc::new(Mutex::new(Inner { map, dirty: false })),
        })
    }
}

impl StateHandle {
    pub fn clone_handle(&self) -> StateHandle {
        StateHandle {
            dir: self.dir.clone(),
            file: self.file.clone(),
            inner: self.inner.clone(),
        }
    }

    pub fn get(&self, key: &str) -> String {
        self.inner
            .lock()
            .unwrap()
            .map
            .get(key)
            .cloned()
            .unwrap_or_default()
    }

    pub fn set(&self, key: &str, val: &str) {
        let mut g = self.inner.lock().unwrap();
        if g.map.get(key) != Some(&val.to_string()) {
            g.map.insert(key.to_string(), val.to_string());
            g.dirty = true;
        }
    }

    pub fn flush(&self) -> Result<()> {
        let mut g = self.inner.lock().unwrap();
        if !g.dirty {
            return Ok(());
        }
        let tmp = self.file.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_string_pretty(&g.map)?)?;
        std::fs::rename(&tmp, &self.file)?;
        g.dirty = false;
        Ok(())
    }

    /// CLI/env 覆盖写入（等价于命令行优先级最高）
    pub fn apply_env_overrides(&self, cli: &crate::args::Cli) {
        if let Some(s) = &cli.server {
            self.set("serverip", s);
        }
    }

    // ─── 路由快照 (route_info_data_1) ───
    pub fn save_route_snapshot(&self, snap: &str) {
        // 滚动备份: route_info_data_back_1
        let old = self.get("route_info_data_1");
        if !old.is_empty() && old != snap {
            self.set("route_info_data_back_1", &old);
        }
        self.set("route_info_data_1", snap);
    }

    pub fn route_snapshot_eq(&self, snap: &str) -> bool {
        // 快照比较：逐条 5 元组集合相等（乱序不敏感）
        let old: std::collections::BTreeSet<String> =
            serde_json::from_str(&self.get("route_info_data_1")).unwrap_or_default();
        let new: std::collections::BTreeSet<String> =
            serde_json::from_str(snap).unwrap_or_default();
        !new.is_empty() && old == new
    }
}
