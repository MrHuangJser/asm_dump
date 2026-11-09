# asm-bypass — ASM NAC agent 协议重实现 (Rust)

逆向 ASM.app 5.2.6039 (com.infogo.MAC3) 的全协议 Rust 重写。
**运行时零 ASM 依赖**：不读/不写/不启动 ASM 任何文件，只做系统 BSD 工具调用。

## 运行

```bash
export SOUL_LDAP_USERNAME=你的工号
export SOUL_LDAP_PASSWORD=你的密码
cargo run --release
# 或
./target/release/asm-bypass
```

Clash TUN 开着也能跑：物理网卡走 `netstat`/`scutil` 兜底解析，
utun* 不进主路由、pf 附加 `pass on utunN`、`--keep-dns` 可保 Clash DNS。

## 协议复刻明细

| 阶段 | ASM 原版 | 本实现 |
|---|---|---|
| 服务器发现 | get_server_info | `SOUL_SERVER` > state > `nac.soulapp-inc.cn` |
| 设备注册 | getdeviceinfoprocess + devXml (GBK/自定义B64/URL) | `device.rs::build_dev_xml` 逐字节模板 |
| LDAP 认证 | net_auth type=User authserver=AdDomain | username=GBK-B64, password=ASCII-B64 |
| 心跳 | TCP:37527 ASM5 帧 + nibble-XOR("infogo") + zlib-9 | `socket.rs` 帧/加解密/压缩全自研 |
| pf 防火墙 | Blacklist 白名单模板 pfctl -ef | `pf.rs` 模板 + utun pass + 白名单自动补 |
| 网络监听 | Darwin notify + 3s debounce + sleep(3) 重注册 | `watch.rs` scutil watch + ifconfig 签名轮询 |
| TTL | sysctl ttl=200 (isvpn 跳过) | `privesc::set_ttl` |

## 环境变量

- `SOUL_LDAP_USERNAME` / `SOUL_LDAP_PASSWORD` — 凭据 (必需，或 `--username/--password`)
- `SOUL_SERVER` — 跳过 discovery 直连
- `SOUL_SERVER_CANDIDATES` — discovery 候选域 (逗号分隔)

## CLI

```
--server <HOST>         直连指定 NAC
--state-dir <DIR>       状态目录 (默认 ~/.asm_bypass)
--no-pf                 不应用服务器推送的 pf 白名单
--no-ttl                不改 net.inet.ip.ttl
--no-socket             跳过 37527 socket，用 HTTP auto_auth 心跳
--no-privilege          不碰 pf/TTL/DNS/setuid (最干净模式)
--keep-dns              不清空物理网卡 DNS (Clash 用户建议)
```

## 特权引导

首次需要 root 时弹 osascript 管理员授权一次：把
`/sbin/pfctl` `/usr/sbin/sysctl` `/usr/sbin/networksetup`
拷到 `~/.asm_bypass/cfg/` chown root + u+s，之后免密。

## 关键开关速查

```bash
# 最干净: 不碰任何特权, 只跑协议
./asm-bypass --no-privilege
# 跳过 socket 心跳 (服务器对端没开 37527 时)
./asm-bypass --no-socket
# Clash TUN + 保留 Clash DNS
./asm-bypass --keep-dns
```
