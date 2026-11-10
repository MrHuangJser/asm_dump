# AGENTS.md — 给 AI agent 的仓库入口

本仓库是 macOS NAC 客户端 `ASM.app`（`com.infogo.MAC3` 5.2.6039）协议的 Rust 重实现，
产物是一个单二进制 `asm-bypass`：自动完成「服务器发现 → 设备注册 → LDAP 认证 → 安检上报 →
特权配置（TTL/DNS/pf）→ 37527 长连接心跳 → 网络切换监听」，**运行时不需要原版 ASM 在跑**。

目标机器是 macOS。开始改动之前先读本文件，再按下面的指针取用详细材料。

## 铁律

1. **同一设备只能有一个认证客户端在跑。** 原版 `ASM` 与 `asm-bypass` 共用同一个服务器
   设备记录（DeviceID），服务端是单会话模型，两者同时跑会互踢，表现为「用一会儿断网、
   过一会儿又好了」。接管前先确认 `pgrep -x ASM` 为空。
2. **诊断先走零网络路径。** 核对身份用 `--dump-id`，核对报文用 `--dump-query`；两者都不发
   认证请求、不写服务端状态。不要在真机上用 `mobileresult` / 注册接口做「试探」——那些是
   写操作，会让服务端重算该设备的 ACL，把用户网络弄断。
3. **不动网络开关做验证。** `networksetup -setnetworkserviceenabled off/on` 会让 USB 网卡
   掉出 USB 总线（en7 消失），且没有任何验证价值。需要触发切换就用真实拔插或让监听逻辑自己发现。
4. **特权只走 `--install`。** 它写 `/etc/sudoers.d/asm-bypass`（仅放行 pfctl / sysctl /
   networksetup / ipconfig 四个绝对路径）并生成 `~/.asm_bypass/cfg/` setuid 拷贝。不要手写
   sudoers，也不要给 `/bin/sh` 开 NOPASSWD。
5. **密码不进仓库。** 凭据来源优先级 `--password` > `SOUL_LDAP_PASSWORD` > macOS Keychain；
   首次认证成功后程序自己写 Keychain（service `asm-bypass`）。日志、脚本、plist、提交里都不要出现明文。
6. **收尾用 SIGINT。** 只有 Ctrl-C 触发的清理会还原 pf 与 `net.inet.ip.ttl`；`kill`（SIGTERM）
   跳过清理，会留下 TTL=200。

## 指针

| 任务 | 读这里 |
|---|---|
| 从 clone 到跑通（安装 / 首次接管 / 常驻 / 卸载） | [docs/AI-SETUP.md](docs/AI-SETUP.md) |
| 认证成功但上不了网、用一段时间就断、TTL/pf 残留、网卡消失 | [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) |
| 机器现状体检（只读，无网络、无授权框） | `scripts/doctor.sh` |
| 协议与逆向往细节（tradecode、编码、pf 模板、plist 键表） | [ANALYSIS.md](ANALYSIS.md)、[ASM_FULL_ANALYSIS.md](ASM_FULL_ANALYSIS.md) |
| 全部命令行开关 | `./target/release/asm-bypass --help`（源码 `src/args.rs`） |

## 常用命令

```bash
cargo build --release                     # 产物 target/release/asm-bypass
./target/release/asm-bypass --dump-id     # 零网络：看 Read 到的身份/指纹/网卡解析
scripts/doctor.sh                         # 零网络：整机体检
./target/release/asm-bypass --install     # 一次性授权，之后特权操作全部静默
./target/release/asm-bypass --keep-dns    # 日常运行（Clash 用户必带）
```

## 代码约定

- 模块按协议阶段切分：`http_api`（HTTP tradecode）、`device`（网卡/指纹/devXml）、
  `codec`（GBK/自定义 Base64/转义）、`socket`（37527 帧）、`pf`、`privesc`、`watch`、`state`。
- 日志前缀固定：`[+]` 成功事实、`[*]` 流程信息、`[!]` 需要人看懂的异常。新增日志沿用前缀，
  因为文档和排障表按前缀检索。
- 改动涉及认证语义时，先用 `--dump-query` 打印实际报文比对，再上真机跑。
