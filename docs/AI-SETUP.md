# 安装与使用指南

从 `git clone` 到「机器上有网、且不再需要原版 ASM」，全程大约 10 分钟。
本文既是给人看的说明书，也是给 AI agent 执行的操作单：每一步都有**完成判据**，判据不成立就跳到
[docs/TROUBLESHOOTING.md](TROUBLESHOOTING.md) 对应条目，别靠猜继续往下走。

> 给 agent 的读法：按 §2 → §3 → §4 顺序执行，每步跑完先核判据再进入下一步；
> 只读诊断（`--dump-id`、`--dump-query`、`scripts/doctor.sh`）可以随时跑，
> 写操作（`--install`、真实认证、连通性验证）必须串行，且确认上一步已通过。

---

## 0. 它到底做了什么

`asm-bypass` 是一个单二进制，替代 ASM.app 的联网认证客户端。启动后按固定顺序跑：

| # | 阶段 | 行为 | 对应日志 |
|---|---|---|---|
| 1 | 服务器发现 | `get_server_info` 解析 NAC 地址，写入 state | `[+] serverip = ...` |
| 2 | 设备注册 | 用 `DiskId` 构造 devXml 注册，取回服务端绑定的 DeviceID | `[+] 注册 DeviceID=...` |
| 3 | 源地址绑定 | 认证请求强制从物理网卡发出（绕开 Clash TUN） | `[*] 绑定源 IP ...` |
| 4 | LDAP 认证 | `net_auth`（AD 域），拿 RoleID / PolicyID | `[+] 认证成功 ...` |
| 5 | 安检上报 | `mobileresult` 把检查项按「通过」提交，放开 ACL | `[+] 安检通过 ...` |
| 6 | 特权配置 | `net.inet.ip.ttl=200`、清 DNS（可选）、pf 白名单（服务端推送时） | `[+] TTL=200` |
| 7 | 长连接 | TCP 37527，30s 心跳 `HeartTest`，接收服务端推送 | `[+] socket 已连接 ...` |
| 8 | 切换监听 | 路由快照变化 → 重注册 → 重认证 → 重安检 → 重绑源 IP | `[*] 路由变化 ...` |
| 9 | 周期续期 | 每 5 分钟强制重认证 + 重报安检，兜住 ACL 过期 | `[*] 周期到点 ...` |

它**不读、不写、不启动 ASM 的任何进程**。只有在 ASM 装过的机器上会读一次
`com.infogo.MAC3` 的 `rand_hard_ID`（设备指纹）和安检结果，读过就落到
`~/.asm_bypass/state.json`，之后 ASM 卸载也不影响。

---

## 1. 前置条件

| 项 | 要求 | 检查命令 |
|---|---|---|
| 系统 | macOS 12+（Intel / Apple Silicon 均可） | `sw_vers -productVersion` |
| 编译 | Rust stable ≥ 1.75（`rustup` 装），Xcode Command Line Tools | `rustc -V`、`xcode-select -p` |
| 网络 | 能解析并访问内网 NAC（通常 `172.29.92.2`，TCP 80 + 37527） | `nc -z -w2 172.29.92.2 80` |
| 凭据 | 域账号，**建议用完整邮箱**（如 `someone@corp.example.com`），不是短名 | 问用户或读 ASM plist |
| 权限 | 一次管理员密码（写 sudoers），之后不再需要 | — |
| 冲突 | 本机没有第二份 `asm-bypass` 在跑 | `pgrep -fl asm-bypass` |

Rust 没装的话，agent 直接装：

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
. "$HOME/.cargo/env"
```

**完成判据**：`rustc -V` 有输出、`nc -z` 成功、`pgrep -x ASM` 为空。

---

## 2. 安装（一次性，4 步）

### 2.1 构建

```bash
cd <repo>
cargo build --release
```

**完成判据**：

```bash
./target/release/asm-bypass --version     # 打印 asm-bypass 0.2.0
```

编译警告（未使用字段之类）可以忽略；出现 `error[E…]` 才需要处理。

### 2.2 体检（零网络、零授权）

```bash
scripts/doctor.sh
```

它只读：系统版本、编译器、二进制、ASM 是否安装/在跑、设备指纹来源、state 缓存、
免密权限、当前 TTL、网卡/网关/TUN、Keychain 条目。不会发认证请求，不会弹框。

**完成判据**：输出里 `WARN` 项都能解释——典型可接受项是「未装 ASM」（说明走自生成指纹）、
「sudoers 未安装」（下一步解决）、「Keychain 无条目」（§2.4 解决）。

### 2.3 免密特权（唯一一次要管理员密码）

```bash
./target/release/asm-bypass --install
```

弹一次系统授权框，输入管理员密码。它会：

- 写 `/etc/sudoers.d/asm-bypass`（root:wheel 0440，`visudo -cf` 语法校验后才留下，
  校验失败自动删除），内容只放行四条绝对路径：
  `/sbin/pfctl`、`/usr/sbin/sysctl`、`/usr/sbin/networksetup`、`/usr/sbin/ipconfig`；
- 把 `pfctl`、`sysctl` 拷到 `~/.asm_bypass/cfg/` 并 `chmod 4755`（setuid 兜底）。
  `networksetup`/`ipconfig` 带 restricted entitlement，做 setuid 拷贝会被内核 `Killed: 9`，
  所以它们只走 `sudo -n`。

**完成判据**（三条都要过，任何一条失败都说明授权没成功）：

```bash
sudo -n /usr/sbin/sysctl -n net.inet.ip.ttl          # 不需要密码就打印 64 或 200
sudo -n /usr/sbin/networksetup -listallnetworkservices  # 不需要密码打印服务列表
ls -l /etc/sudoers.d/asm-bypass                       # 存在，权限 -r--r-----
```

之后程序内部按 `euid==0 → sudo -n → cfg/ setuid` 三级静默链执行特权动作，
默认**不弹框、不读 stdin**；某条链路全不通时只打一行 `[*] … 跳过 (无免密特权)` 降级。

### 2.4 凭据落 Keychain（一次性）

密码有两种给法，选一种：

```bash
# A. 环境变量（推荐，不落 shell history）
export SOUL_LDAP_USERNAME=someone@corp.example.com
export SOUL_LDAP_PASSWORD='...'          # 只在首次需要
./target/release/asm-bypass --keep-dns

# B. 命令行参数（会进 shell history，测完记得清）
./target/release/asm-bypass --username someone@corp.example.com --password '...' --keep-dns
```

首次认证成功后程序打印 `[*] 密码已写入 macOS Keychain (service=asm-bypass)`，
之后**任何启动都不再需要密码**，也不再用环境变量。用户名没有 Keychain 缓存，建议写进
launchd plist 或 shell profile（见 §5）。

**完成判据**：日志里出现 `密码已写入 macOS Keychain`，且下一次不带
`SOUL_LDAP_PASSWORD`/`--password` 也能认证成功。

---

## 3. 首次接管

### 3.1 让 ASM 退场

两者共用同一台设备的服务端记录，服务端单会话，同时跑会互踢（症状：用几分钟断一次，
过一会儿自己又好了）。接管前：

```bash
pgrep -x ASM                       # 必须为空
osascript -e 'tell application "System Events" to delete login item "ASM"' 2>/dev/null
```

ASM 每次被手动打开都可能把自己重新写回登录项，所以这条命令可以反复执行。

### 3.2 先跑零网络核对

```bash
./target/release/asm-bypass --dump-id
```

重点看三行：

```
devid      = Some("105238")                      ← 服务端分配过的设备 ID（可空，空则靠 DiskId 注册）
rand_hard_ID = Some("RAND:9495F0BC-...")         ← DiskId 来源，必须以 RAND: 开头
主接口     = en0 ip=172.27.76.19 mac=...
```

再核对报文（不发送）：

```bash
./target/release/asm-bypass --dump-query
```

**完成判据**：`checkres` 长度 > 100 字节、`/a/ajax.php?tradecode=mobileresult...` 里的
`itemsid=99`、`is_safecheck=1` 都在。若 `devid` 为 `None`（`--dump-query` 里显示 `<无 devid>`）
也没关系，§3.3 的注册会取回来。

`--dump-id` 和 `--dump-query` 都在读凭据之前返回，**不需要用户名密码**。

> 全新机器（没装过 ASM）的情况：`DiskId` 会是本次运行自生成的 `RAND:<UUID>`，
> 服务端会新建一条设备记录，策略与 ACL 取决于该记录被归到哪一类。
> 想在既有机器上保持「正规设备」身份，就先让 ASM 完成过一次登录（写入 `rand_hard_ID`），
> 再切到本工具；指纹随后会缓存进 `state.json`。

### 3.3 前台跑一次

```bash
cd <repo>
./target/release/asm-bypass --keep-dns 2>&1 | tee /tmp/asm-bypass.log
```

`--keep-dns` 是给 Clash / 自管 DNS 的用户用的（跳过清空物理网卡 DNS）。
如果不跑 Clash，去掉它也行，程序会把物理网卡 DNS 清成 DHCP 下发的值。

成功时日志长这样，**这 11 行是判据**：

```
[*] 工作目录 /Users/<you>/.asm_bypass
[+] serverip = 172.29.92.2
[*] 主路由 en0 ip=172.27.76.19 mac=... mark=255.255.254.0 gw=172.27.76.1
[*] DiskId=RAND:9495F0BC-5B05-43C8-8442-B6A755345245 (设备指纹)
[+] 注册 DeviceID=105238 AscID=11:11:11:11:11:11 (服务器按 DiskId 匹配)
[*] 绑定源 IP 172.27.76.19 (绕过 Clash TUN)
[+] 认证成功 RoleID=Some("9") PolicyID=Some("5")
[+] 安检通过: 您的设备完全符合检查规则，可以正常使用网络了！
[*] 周期重认证+重检 5 分钟（强制兜底）
[+] TTL=200
[+] socket 已连接 172.29.92.2:37527
```

### 3.4 验证网络

判据只看 HTTP(S) 真实出网，不看 ping（ping 通不代表 ACL 放开）：

```bash
for u in https://www.baidu.com https://www.bing.com https://github.com; do
  printf '%s -> ' "$u"
  curl -sS -o /dev/null -w '%{http_code}\n' --max-time 8 "$u"
done
```

**完成判据**：三个都是 `200`（或站点自身的 `301/302`，但 `Location` 不指向 NAC portal 页）。
出现 `000` 或跳到 portal：按 [TROUBLESHOOTING §1](TROUBLESHOOTING.md#1-认证成功但上不了网) 逐层查。

> 不要用 `curl --interface <物理网卡IP>` 当判据：Clash 的 fake-ip DNS 会让该绑定必然超时（返回 000），
> 那是预期行为，不是网络故障。

### 3.5 跑通后转后台

见 §5。前台进程用 `Ctrl-C` 退出（**必须用 Ctrl-C**，只有它触发清理：还原 pf、TTL 回 64）。

---

## 4. 日常使用

### 4.1 一条命令

```bash
./target/release/asm-bypass --keep-dns
```

程序会自己处理：换网（有线 ↔ WiFi）重注册重认证、Clash TUN 存在时绑物理网卡、
每 5 分钟强制续期、服务端推送 `IpRenew` 时续 DHCP。

### 4.2 常用参数

| 参数 | 用途 |
|---|---|
| `--keep-dns` | 不清空物理网卡 DNS（Clash / 自管 DNS 场景必带） |
| `--recheck-minutes N` | 续期间隔，默认 5，范围 1–60。断得勤就压到 2 |
| `--server IP` | 跳过自动发现，直连指定 NAC |
| `--username / --password` | 覆盖凭据（正常情况不需要，走 Keychain） |
| `--state-dir DIR` | 状态目录，默认 `~/.asm_bypass` |
| `--no-pf` | 不应用服务端推送的 pf 白名单 |
| `--no-ttl` | 不改 `net.inet.ip.ttl` |
| `--no-socket` | 不建 37527 长连接，改用 HTTP `auto_auth` 心跳 |
| `--no-privilege` | 完全不碰特权（pf/TTL/DNS/setuid 全跳过），纯协议模式 |
| `--no-safecheck` | 不报安检，仅当确定服务端不要求时使用（会导致 ACL 停在受限态） |
| `--yes` | 允许 osascript 授权弹框兜底；默认全静默 |
| `--dump-id` / `--dump-query` | 零网络诊断，见 §3.2 |
| `--install` / `--uninstall` | 安装 / 撤销免密特权 |

### 4.3 日志怎么读

三类前缀：`[+]` 是既成事实（成功），`[*]` 是流程信息，`[!]` 是要人看懂的异常。
最常见的正常噪音：

| 日志 | 含义 |
|---|---|
| `[*] 路由变化: en7 172.27.30.27 → 重新注册` | 检测到换网，正在重认证，几秒内恢复 |
| `[*] 周期到点 (5 分钟)：重认证 + 重报安检` | 正常续期，紧跟 `[+] 周期重认证成功` |
| `[*] DNS 清空跳过` / `[*] TTL=200 设置跳过` | 免密特权没装或没生效，按 §2.3 修 |
| `[*] DHCP 续约跳过` | 同上；新接口租约由系统自行协商，不致命 |

### 4.4 换网行为

路由快照 = 所有物理网卡的五元组 `{en, ip, mac, netmask, is_main}`。任一变化即触发：
重注册（服务端更新记录里的 IP/MAC/网关）→ 重绑定源 IP → 重认证 → 重报安检 → socket 重连。
所以 **USB 网卡拔掉再插回、WiFi 切换、DHCP 换租约都不用管**，程序自己跟。

---

## 5. 常驻（二选一）

### 5.1 launchd（推荐：开机自启 + 崩溃重启）

```bash
scripts/launchd-install.sh someone@corp.example.com --dry-run   # 先看生成的 plist
scripts/launchd-install.sh someone@corp.example.com             # 真正安装并启动
```

脚本生成 `~/Library/LaunchAgents/local.asm-bypass.plist`（内含 `SOUL_LDAP_USERNAME`，
不含密码），`bootstrap` 到当前用户会话，日志写 `~/Library/Logs/asm-bypass.log`。
`--no-keep-dns` 可去掉 `--keep-dns` 参数，`--binary PATH` 可指定别的产物路径。

**完成判据**：

```bash
launchctl print gui/$(id -u)/local.asm-bypass | head -20   # state = running
tail -20 ~/Library/Logs/asm-bypass.log                     # 有 §3.3 那 11 行
```

停止 / 卸载：

```bash
scripts/launchd-uninstall.sh
```

### 5.2 nohup（临时）

```bash
nohup ./target/release/asm-bypass --keep-dns > /tmp/asm-bypass.log 2>&1 &
```

注意：`kill <pid>` 是 SIGTERM，**不会**执行清理（pf 与 TTL 会残留）。要干净退出：

```bash
pkill -INT -f asm-bypass
```

---

## 6. 升级 / 重建

```bash
git pull
cargo build --release
launchctl kickstart -k gui/$(id -u)/local.asm-bypass    # 或 pkill -INT; 再手动起
```

状态不丢：`~/.asm_bypass/state.json` 里缓存着 `serverip` / `devid` / `disk_id`，
二进制替换后仍用同一设备身份。
`--install` 不需要重跑（sudoers 与 cfg/ 独立于二进制）。

想强制重新发现服务器（换了网段 / NAC 换地址）：

```bash
rm ~/.asm_bypass/state.json
```

注意这会同时丢掉 `disk_id` 缓存 —— 如果原版 ASM 已卸载，程序会生成新的
`RAND:` 指纹，服务端会当成新设备建记录。所以要重置的话，先确认 ASM 还在、
`rand_hard_ID` 还读得到。

---

## 7. 卸载与回滚

按顺序执行，每步都可单独回滚：

```bash
# 1. 停进程（SIGINT，触发 pf/TTL 还原）
pkill -INT -f asm-bypass
launchctl bootout gui/$(id -u)/local.asm-bypass 2>/dev/null

# 2. 撤销免密特权（弹一次管理员授权框）
./target/release/asm-bypass --uninstall

# 3. 删 Keychain 里的密码
security delete-generic-password -s asm-bypass >/dev/null 2>&1

# 4. 删状态目录（含 state.json / cfg/ / pf_back.conf）
rm -rf ~/.asm_bypass

# 5. 确认系统干净
sudo -n /usr/sbin/sysctl -n net.inet.ip.ttl     # 应为 64
sudo pfctl -s info | head -3                    # 可选确认：Status: Disabled 或原始规则
```

残留自查：`/etc/sudoers.d/asm-bypass` 不存在、`~/.asm_bypass` 不存在、
`pgrep -fl asm-bypass` 为空。之后要恢复原状就正常打开 ASM 登录即可。

---

## 8. agent 交付核对表

跑完必须能对每一项给出 yes/no 与证据（日志行或命令输出）：

1. `cargo build --release` 通过，`--version` 正常。
2. `scripts/doctor.sh` 的 WARN 项都能解释。
3. `sudo -n /usr/sbin/sysctl -n net.inet.ip.ttl` 免密成功（证明 sudoers 生效）。
4. `--dump-id` 里 `DiskId` 以 `RAND:` 开头。
5. `--dump-query` 里 `itemsid=99`、`is_safecheck=1`、`checkres` 非空。
6. 完整运行的日志含 `注册 DeviceID=` / `绑定源 IP` / `认证成功` / `安检通过` / `socket 已连接`。
7. 三个 https 站点返回 200，且没有 portal 跳转。
8. `pgrep -x ASM` 为空；ASM 不在登录项。

---

## 附录 A：文件与状态清单

| 路径 | 内容 | 删除后果 |
|---|---|---|
| `~/.asm_bypass/state.json` | `serverip`、`devid`、`AscID`、`disk_id`、`RoleID`、`PolicyId`、`main_en`、路由快照 | 重新发现服务器；`disk_id` 丢失后可能生成新指纹 |
| `~/.asm_bypass/cfg/pf.conf` | 服务端推送生成的 pf 规则 | 下次推送时重建 |
| `~/.asm_bypass/cfg/{pfctl,sysctl}` | setuid 兜底工具链 | 只影响 `sudo -n` 失效时的兜底 |
| `~/.asm_bypass/pf_back.conf` | 首次改 pf 前备份的 `/etc/pf.conf` | 退出时无法还原原始 pf.conf |
| `/etc/sudoers.d/asm-bypass` | NOPASSWD 规则（4 个二进制） | 特权操作全部降级为「跳过」 |
| Keychain `asm-bypass` / `ldap` | LDAP 密码 | 下次启动需要重新给一次密码 |
| `~/Library/LaunchAgents/local.asm-bypass.plist` | 自启任务（若装了） | 不再开机自启 |

## 附录 B：凭据

| 项 | 来源优先级 |
|---|---|
| 服务器 | `--server` > `SOUL_SERVER` > `state.json` 缓存 > `SOUL_SERVER_CANDIDATES`（逗号分隔）+ 内置 `nac.soulapp-inc.cn` |
| 用户名 | `--username` > `SOUL_LDAP_USERNAME` > `$USER`（短名可能被域拒绝，建议显式给完整邮箱） |
| 密码 | `--password` > `SOUL_LDAP_PASSWORD` > Keychain |

换密码 / 密码过期：

```bash
security delete-generic-password -s asm-bypass >/dev/null 2>&1
./target/release/asm-bypass --username you@corp.example.com --password '新密码' --keep-dns
```

## 附录 C：协议速查

| 环节 | 细节 |
|---|---|
| HTTP | 全部 `POST http://{server}/a/ajax.php?tradecode=…`，参数在 query；头 `Extend-Data: ostype=mac;`、`User-Agent: MERONG(0.9/;Macos)` |
| 设备注册 | `getdeviceinfoprocess` + devXml（GB2312，自定义 Base64）。服务端按 `<DiskId>` 精确匹配，大小写/横线/`RAND:` 前缀全敏感 |
| 认证 | `net_auth`，`type=User&authserver=AdDomain`，用户名 GBK-Base64、密码 ASCII-Base64 |
| 安检 | `getcheckpolicy` 取条目 → `mobileresult` 上报（`itemsid=99`，checkres 为 GBK XML，`<Result>Yes</Result>`） |
| 剔除语义 | `cutoff_net` 仅用于「服务端踢下线」，切换网卡时**不能**发，否则会把刚认证的 ACL 砍掉 |
| 长连接 | TCP 37527，60 字节小端头（`ASM5` @0x04、tradecode[32] @0x14），nibble-XOR("infogo") + zlib-9，30s 心跳 |
| 特权 | `sysctl net.inet.ip.ttl=200`（isvpn 跳过）；pf 仅在服务端推送 `IsOpen=1` 时应用 |
