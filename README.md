# asm-bypass

macOS NAC 客户端 `ASM.app`（`com.infogo.MAC3` 5.2.6039）协议的 Rust 重实现。
单二进制，**运行时不需要原版 ASM 参与**：自己发现服务器、注册设备、LDAP 认证、上报安检、
配置系统，并长连接保持在线；有线 ↔ WiFi 切换、Clash TUN 共存都能自动跟。

- 目标平台：macOS 12+
- 构建：Rust stable（`cargo build --release`）
- 产物：`target/release/asm-bypass`

## 快速开始

```bash
git clone <repo> && cd <repo>
cargo build --release

# 1) 一次性授权：写最小 sudoers + setuid 兜底，弹一次系统授权框
./target/release/asm-bypass --install

# 2) 零网络核对：设备指纹、网卡解析、将要发出的安检报文
./target/release/asm-bypass --dump-id
./target/release/asm-bypass --dump-query

# 3) 首次认证：带一次密码，成功后自动写入 Keychain
export SOUL_LDAP_USERNAME=someone@corp.example.com
export SOUL_LDAP_PASSWORD='...'
./target/release/asm-bypass --keep-dns

# 或者直接用参数给（密码会进 shell history，测完清掉）
./target/release/asm-bypass --username someone@corp.example.com --password '...' --keep-dns
```

常驻（登录自启 + 崩溃重启）：

```bash
scripts/launchd-install.sh someone@corp.example.com
tail -f ~/Library/Logs/asm-bypass.log
```

**接管前必须完全退出原版 ASM**（`pgrep -x ASM` 为空）。两者共用同一服务端设备记录，
同时运行会互相踢下线，表现为「用一会儿断网、过一会儿又好了」。

## 文档

| 文档 | 内容 |
|---|---|
| [docs/AI-SETUP.md](docs/AI-SETUP.md) | 完整安装与使用指南：前置条件 → 构建 → 免密授权 → 凭据 → 首次接管 → 验证 → 常驻 → 升级 → 卸载，每步带完成判据。也是给 AI agent 执行的操作单 |
| [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) | 排障手册：认证成功但上不了网、用一段时间就断、特权跳过、网卡消失、TTL/pf 残留、设备身份异常、Keychain 轮换 |
| [AGENTS.md](AGENTS.md) | AI agent 的仓库入口：硬规则 + 指针 + 常用命令 |
| [ANALYSIS.md](ANALYSIS.md) / [ASM_FULL_ANALYSIS.md](ASM_FULL_ANALYSIS.md) | 逆向来料：devXml 模板、认证参数、NSUserDefaults 键表、pf 策略、启动序列 |
| `scripts/doctor.sh` | 只读体检：系统、工具链、进程冲突、设备指纹、免密特权、网卡/TUN、日志异常 |
| `scripts/launchd-install.sh` | 装成登录自启的 launchd 任务（`--dry-run` 只预览 plist） |
| `scripts/launchd-uninstall.sh` | 停止并移除自启任务 |

想直接让 AI agent 装，把仓库 clone 下来后对它说一句：

> 读 AGENTS.md 和 docs/AI-SETUP.md，按里面的步骤在这台机器上安装并验证 asm-bypass，
> 每步先给完成判据的结论再进入下一步；出问题按 docs/TROUBLESHOOTING.md 查。

## 运行流程

```
get_server_info → getdeviceinfoprocess(devXml) → net_auth(AdDomain)
   → mobileresult(安检，全部按通过) → TTL/DNS/pf → TCP:37527 心跳
   → 路由快照监听（换网重注册+重认证+重安检）→ 每 5 分钟强制续期
```

关键设计点（都是踩坑换来的）：

| 点 | 说明 |
|---|---|
| 设备指纹 `DiskId` | 服务端按 `<DiskId>` 精确匹配设备记录，格式 `RAND:<UUID>` 才对应「正规设备」（`Registered=1`）；用 IOPlatformUUID 会注册成「自动发现设备」（`Registered=-2`），ACL 停在受限态 |
| 源 IP 绑定 | Clash TUN 会劫持到 NAC 的路由，认证请求源 IP 变成 `198.18.x.x`，ACL 绑错地址 → 认证成功但上不了网。所以 HTTP 与 37527 连接都强制绑物理网卡 |
| 安检上报 | `itemsid=99` + GBK 编码的 checkres XML；空壳提交只换回空 `success`，不触发 ACL 下发 |
| 周期续期 | 服务端 `ReCheckTime` 到期 ACL 会收紧，实测更早，故每 5 分钟无条件重认证 + 重报安检（`--recheck-minutes` 可调） |
| `cutoff_net` | 语义是「服务端踢下线」，换网时**不能**发，否则会砍掉刚认证的会话 |
| 特权 | 三级静默链：`euid==0` → `sudo -n`（`--install` 写的最小 sudoers） → `cfg/` setuid（仅 pfctl/sysctl 可行） |

## CLI

```
--server <HOST>            直连指定 NAC（默认自动发现）
--username / --password    覆盖凭据（正常走 Keychain，不需要）
--state-dir <DIR>          状态目录，默认 ~/.asm_bypass
--keep-dns                 不清空物理网卡 DNS（Clash 用户必带）
--no-pf / --no-ttl / --no-socket / --no-privilege   按需关闭对应动作
--no-safecheck             不报安检（ACL 会停在受限态）
--recheck-minutes <N>      续期间隔，默认 5，范围 1–60
--install / --uninstall    安装 / 撤销免密特权
--yes                      允许 osascript 授权弹框兜底（默认全静默）
--dump-id / --dump-query   零网络诊断：看身份 / 看将要发出的报文
```

完整说明见 `./target/release/asm-bypass --help`。

## 环境变量

| 变量 | 作用 |
|---|---|
| `SOUL_LDAP_USERNAME` | 域账号（建议完整邮箱） |
| `SOUL_LDAP_PASSWORD` | 密码（首次用，之后写 Keychain；优先级低于 `--password`） |
| `SOUL_SERVER` | 跳过发现，直连 NAC |
| `SOUL_SERVER_CANDIDATES` | 发现候选域，逗号分隔（仅在无 state 缓存时生效） |

## 排障三条命令

```bash
scripts/doctor.sh                              # 只读取证
tail -40 ~/Library/Logs/asm-bypass.log         # 或你 tee 的文件
./target/release/asm-bypass --dump-id          # 设备身份与网卡解析
```

判据口诀：有 `绑定源 IP` + `认证成功` + `安检通过` 但站点不通 → 查 `DiskId`；
有 `认证成功` 无 `安检通过` → 安检报文不对；周期日志缺失 → 续期线程没跑；
`[!]` 里出现「跳过」 → 免密特权没装。

干净退出用 `Ctrl-C` 或 `pkill -INT -f asm-bypass`：只有 SIGINT 会还原 pf 与
`net.inet.ip.ttl`，`kill`（SIGTERM）会留下 TTL=200。

## 卸载

```bash
pkill -INT -f asm-bypass
scripts/launchd-uninstall.sh
./target/release/asm-bypass --uninstall        # 删 sudoers + cfg/ 工具链
security delete-generic-password -s asm-bypass
rm -rf ~/.asm_bypass
```

细节与回滚核对见 [docs/AI-SETUP.md §7](docs/AI-SETUP.md#7-卸载与回滚)。
