# 排障手册

每条按「症状 → 先看哪一行日志 → 根因 → 处置」组织。动手前先跑一次只读体检：

```bash
scripts/doctor.sh
tail -40 /tmp/asm-bypass.log     # 或 ~/Library/Logs/asm-bypass.log
```

日志按前缀检索最快：`grep '^\[!\]' <log>` 只看异常。下文 `<log>` 指实际日志路径
（前台 `tee` 的 `/tmp/asm-bypass.log`，或 launchd 的 `~/Library/Logs/asm-bypass.log`）。

---

## 1. 认证成功但上不了网

**症状**：日志里 `[+] 认证成功 RoleID=Some("9")`、`[+] 安检通过` 都有，但浏览器跳到 NAC
认证页，或 https 请求超时（curl 返回 `000`）。

按下面三层依次排除，**顺序不能换**——越靠前的层出错，后面的证据全是假象。

### 1.1 层一：请求源地址被 Clash TUN 劫持

先确认：

```bash
grep '绑定源 IP' <log>      # 期望：[*] 绑定源 IP 172.27.76.19 (绕过 Clash TUN)
route -n get 172.29.92.2 | grep interface
```

`route get` 显示 `utun4` 是正常的（说明 TUN 在工作），**关键是日志里绑定的 IP 必须是物理网卡地址**
（`ipconfig getifaddr en0` / `en7` 的值），不能是 `198.18.x.x`、`127.x`。

根因：Clash TUN 把到 NAC 内网的路由也接管了，认证 POST 的源 IP 变成 Clash 的虚拟地址；
NAC 把 ACL 绑在这个地址上，而用户真实流量从物理网卡出去 → 对不上 → portal 劫持。
`net_auth` 照样返回 RoleID，所以看起来「认证成功」。

处置：程序自动处理，无需人工干预。若日志里确实出现 `198.18.`，说明 `resolve_main_en`
选错了网卡：

```bash
ifconfig -l | tr ' ' '\n' | grep '^en'
ipconfig getifaddr en0
route -n get default | grep interface
```

确认物理网卡有 IPv4 后重启程序；仍选错就带 `--server` 指定 NAC 再跑一次（`route get` 路径不同）。

### 1.2 层二：ACL 没放开（安检没报 / 报得不对）

```bash
grep -E '安检|itemsid|mobileresult' <log>
```

期望：

```
[*] 安检策略 5 共 3 项 → 全部按通过上报 (itemsid=99)
[+] 安检通过: 您的设备完全符合检查规则，可以正常使用网络了！
```

若看到 `[*] 无 PolicyID/RoleID，跳过安检上报`：`net_auth` 响应里没有策略信息，
说明认证其实没真正成功，去看 `RoleID` 那行的值。

若出现 `[!] 安检未通过` 或 `ErrItem` 非空：`itemsid` 必须是非空条目 id（本环境是 `99`），
`checkres` 必须是完整 XML。用零网络方式核对实际报文：

```bash
./target/release/asm-bypass --dump-query
```

注意：`itemsid=""` + `checkres=""` 的空提交只会换回一个空的 `success`，**不触发 ACL 下发**，
这是早期版本的主要坑。

### 1.3 层三：设备身份不是「正规设备」

```bash
./target/release/asm-bypass --dump-id | head -8
```

`DiskId` 必须以 `RAND:` 开头。服务端按 `<DiskId>` 精确匹配设备记录：

| DiskId | 服务端记录 | 结果 |
|---|---|---|
| `RAND:<UUID>`（ASM 生成的原值） | `系统自动注册设备`，`Registered=1` | 正规受管，策略正常下发 |
| IOPlatformUUID（大写去横线） | `自动发现设备`，`Registered=-2` | 未受管，ACL 停在受限态 |
| 少了 `RAND:` 前缀 / 大小写变了 | 新建第三条记录 | 同上 |

处置：确保原版 ASM 还装着（`defaults read com.infogo.MAC3 rand_hard_ID` 能读出值），
或者 `~/.asm_bypass/state.json` 里 `disk_id` 是正确值。两者都没有就只能力气活：
先装一次 ASM 并完成一次认证，让指纹落盘，再切回本工具。

---

## 2. 用一段时间就断，过一会儿自己又好了

**症状**：认证成功后稳定几分钟到几十分钟，突然全站不可用；重启程序或打开 ASM 又恢复。

### 2.1 先排除会话互踢

```bash
pgrep -x ASM; pgrep -fl asm-bypass
```

两个都有输出 = 互踢。两者共用同一个服务端设备记录，服务端单会话，A 认证踢 B、B 重认证踢 A，
无限循环。处置：

```bash
pkill -x ASM
osascript -e 'tell application "System Events" to delete login item "ASM"' 2>/dev/null
```

ASM 每次被手动打开都会尝试把自己写回登录项，所以这条要定期复查。

### 2.2 再看续期是否在跑

```bash
grep -E '周期到点|周期重认证' <log> | tail -6
```

期望每 5 分钟一组 `[*] 周期到点 (5 分钟)` + `[+] 周期重认证成功` + `[+] 安检通过`。
若断点间隔明显短于 5 分钟，把周期压到 1–2 分钟：

```bash
./target/release/asm-bypass --keep-dns --recheck-minutes 2
```

服务端 `ReCheck=1 / ReCheckTime=30` 时 ACL 会过期收紧，而实测失效比 30 分钟更早，
所以默认取 `min(30, 5) = 5` 分钟强制续期，不等它失效。

### 2.3 若日志停在 `socket 已连接` 之后

说明 37527 长连接线程卡住，续期线程可能也被同一个进程状态带偏。先看有没有
`[!] socket 重连` / `SocketOffline` 记录；没有就重启程序观察一轮。稳定复现时抓：

```bash
sample $(pgrep -f asm-bypass | head -1) 3 -file /tmp/asm-sample.txt
```

---

## 3. 认证直接失败

**症状**：`[!] 认证失败: …` 或 `[!] 致命错误: 认证失败`。

| 日志片段 | 根因 | 处置 |
|---|---|---|
| `缺少用户名` | 没给 `--username` 且无 `SOUL_LDAP_USERNAME` | 显式给完整邮箱 |
| `用户名或密码错误` / `密码错误` | 密码错或过期 | 删 Keychain 条目后用 `--password` 重跑一次（见 §8） |
| `认证失败` 但无细节 | 设备记录被服务端置为异常 | `--dump-id` 核对 `devid`；必要时删掉 `state.json` 里的 `devid` 键，下次启动会用同一 `DiskId` 重新注册 |
| `服务器发现失败` | NAC 域名解析不到 / 网段不同 | `--server <IP>` 或 `SOUL_SERVER_CANDIDATES` |

快速试一个候选：

```bash
nc -z -w2 172.29.92.2 80 && echo "NAC 可达"
curl -s -o /dev/null -w '%{http_code}\n' http://172.29.92.2/a/ajax.php
```

---

## 4. 特权类日志：TTL / DNS / DHCP 被「跳过」

**症状**：日志出现

```
[*] TTL=200 设置跳过 (无免密特权, --install 可解决)
[*] DNS 清空跳过 (Wi-Fi) (无免密特权)
[*] DHCP 续约跳过 (无免密特权，新接口租约由系统协商)
```

**根因**：三级静默链（`euid==0` → `sudo -n` → `cfg/` setuid）全不通。
最常见是 `--install` 没执行，或 sudoers 被系统更新/安全策略清掉了。

**处置**：

```bash
sudo -n /usr/sbin/sysctl -n net.inet.ip.ttl        # 不通 = sudoers 没了
./target/release/asm-bypass --install              # 重装（弹一次授权框）
```

说明：`DHCP 续约跳过` 不致命——换网后新接口的租约由 macOS 自己协商；`TTL 跳过` 也不影响认证，
只是不再伪装 TTL=200。真正影响的是 `pf` 相关（仅服务端推送 `IsOpen=1` 时才用）。

---

## 5. 网卡「消失」：`en7` 不存在 / `interface doesn't exist`

**症状**：`sudo ipconfig set en7 DHCP` 报接口不存在；`ifconfig -l` 里没有 en7；
`networksetup -listallhardwareports` 里该服务还指向 en7。

**根因**：USB 网卡被 `networksetup -setnetworkserviceenabled off/on`（或 USB 电源复位）
踢出总线后没重新枚举。**这是测试动作的副作用，不是程序 bug。**

**处置**：

1. 物理拔插 USB 网卡（或换口），确认重新出现：

```bash
ifconfig -l | tr ' ' '\n' | grep -E '^en'
system_profiler SPUSBDataType | grep -i -E -A3 'AX88|USB 10/100'
```

2. 不要再用 `networksetup ... off/on` 触发切换；要测切换就真实拔插网线。

程序侧对不存在的接口已有防护：接口名必须匹配 `en<N>`、且 `ifconfig <if>` 能取到才使用，
否则回退 `first_live_en()`，不会拿垃圾值去注册。

---

## 6. 退出后系统有残留

### 6.1 TTL 还是 200

`kill`（SIGTERM）不会触发清理钩子，只有 Ctrl-C（SIGINT）才会。手动还原：

```bash
sudo sysctl -w net.inet.ip.ttl=64
```

以后退出用：

```bash
pkill -INT -f asm-bypass
```

### 6.2 pf 规则还在 / 上不了网但认证正常

```bash
sudo pfctl -s info | head -3
sudo pfctl -s rules | head -20
```

程序只在服务端推送 `IsOpen=1` 时应用 pf 白名单，退出时会 `pfctl -F all -f /etc/pf.conf`
并从 `~/.asm_bypass/pf_back.conf` 还原原始配置。若残留：

```bash
sudo pfctl -F all -f /etc/pf.conf
sudo pfctl -d            # 若原本就是 disabled 状态
```

### 6.3 还有进程

```bash
pgrep -fl asm-bypass
launchctl bootout gui/$(id -u)/local.asm-bypass 2>/dev/null   # 装过 launchd 的话
```

---

## 7. 设备身份 / 注册异常

| 现象 | 含义 | 处置 |
|---|---|---|
| `[!] 未找到 rand_hard_ID，已生成新指纹 RAND:…` | 本机没有 ASM 指纹，生成新的 | 服务端会建新设备记录；策略可能不同，属预期 |
| `[!] 注册失败: …` + `[*] 退回缓存 DeviceID=…` | 网络/服务端暂时拒绝 | 记录可能不是最新，观察下一轮换网重注册是否修正 |
| `[+] 注册 DeviceID=` 每次都是**不同**数字 | `DiskId` 每次都变 | 检查 `state.json` 是否可写、`rand_hard_ID` 是否被 ASM 改写 |
| `[!] 未找到可用物理网卡，暂用 en0` | 网卡切换瞬间 | 等切换完成；持续出现说明网卡驱动异常 |

核对指纹：

```bash
defaults read com.infogo.MAC3 rand_hard_ID
python3 -c 'import json,os;print(json.load(open(os.path.expanduser("~/.asm_bypass/state.json"))).get("disk_id"))'
```

两个值应当一致。

---

## 8. 凭据：Keychain 与密码轮换

密码错了或换了密码，Keychain 里会一直用旧值，所以要删了重写：

```bash
security delete-generic-password -s asm-bypass >/dev/null 2>&1
./target/release/asm-bypass --username you@corp.example.com --password '新密码' --keep-dns
```

确认写进去了（只看是否存在，不打印密码）：

```bash
security find-generic-password -s asm-bypass >/dev/null 2>&1 && echo "Keychain 有条目"
```

优先级：`--password` > `SOUL_LDAP_PASSWORD` > Keychain。环境变量优先级高于 Keychain，
所以旧的环境变量会让新密码「不生效」——检查 `env | grep SOUL_LDAP`。

---

## 9. 编译与运行环境

| 现象 | 处置 |
|---|---|
| `cargo: command not found` | `. "$HOME/.cargo/env"`，没有就装 rustup |
| `error: linker not found` / `xcrun: error` | `xcode-select --install` |
| `Address already in use` / 端口相关 | 本机已有实例：`pgrep -fl asm-bypass` |
| `Killed: 9` 出现在 cfg/ 里的工具 | `networksetup`/`ipconfig` 不能做 setuid 拷贝（restricted entitlement），只会走 `sudo -n`；无视 |
| 二进制被 Gatekeeper 拦 | 本机编译产物不触发；从别处拷来的需要 `xattr -d com.apple.quarantine` |

---

## 10. 一键采集诊断信息

贴给别人看之前，先跑这三条，通常足够定位：

```bash
scripts/doctor.sh
tail -60 /tmp/asm-bypass.log 2>/dev/null || tail -60 ~/Library/Logs/asm-bypass.log
./target/release/asm-bypass --dump-id
```

判断口诀：

- 有 `绑定源 IP` + `认证成功` + `安检通过`，但站点不通 → 看 §1.3 的 DiskId
- 有 `认证成功` 无 `安检通过` → §1.2
- 周期日志缺失 → §2.2
- `[!]` 里出现 `特权`/`跳过` → §4
- 两个认证进程并存 → §2.1
