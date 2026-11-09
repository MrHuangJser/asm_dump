# ASM_ORIGIN 逆向分析 — 绕过方案详细执行计划

## 一、设备注册 XML 模板

### getDevXml 生成格式

```
<?xml version="1.0" encoding="gb2312"?>
<MSAC>
  <DeviceName>%@</DeviceName>
  <OS>MacOS</OS>
  <Ip>%@</Ip>
  <Mac>%@</Mac>
  <Mark>%@</Mark>
  <GateWay>%@</GateWay>
  <IeVersion>%@</IeVersion>
  <DiskId>%@</DiskId>
  <AllIp_Ok>%@</AllIp_Ok>
  <AllMac_Ok>%@</AllMac_Ok>
  <AllIp>%@</AllIp>
  <AllMark>%@</AllMark>
  <AllMac>%@</AllMac>
</MSAC>
```

### XML 字段说明

| 字段 | 来源方法 | 说明 |
| ------ | ---------- | ------ |
| `DeviceName` | `SCDynamicStoreCopyLocalHostName()` | 本机计算机名 |
| `OS` | 硬编码 | 固定 "MacOS" |
| `Ip` | `getifaddrs` 遍历 `enX` 接口 | 主网卡 IPv4 地址 |
| `Mac` | `getifaddrs` 或 `ifconfig` | 主网卡 MAC（大写无分隔） |
| `Mark` | `getifaddrs` → `inet_ntoa(sockaddr_in->sin_addr.s_addr & netmask)` | 子网掩码 & IP 的结果 |
| `GateWay` | `route -n get default \| grep gateway` | 默认网关 IP |
| `IeVersion` | `/Applications/Safari.app/Contents/version.plist` → `CFBundleShortVersionString(CFBundleVersion)` | 如 `Safari 17.5(19618.2.12.11.6)` |
| `DiskId` | `ioreg -c IOPlatformExpertDevice \| grep IOPlatformUUID` → 去 `-` 大写 | 系统 UUID，如 `A1B2C3D4...` |
| `AllIp_Ok` | 拼接所有有效网卡 IP（逗号分隔，去除非 `0.0.0.0` / `127.0.0.1` 且 MAC ≠ `00:00:00:00:00:00`） | |
| `AllMac_Ok` | 拼接所有有效网卡 MAC | |
| `AllIp` | 拼接所有 MAC ≠ `00:00:00:00:00:00` 的网卡 IP | |
| `AllMark` | 同上网卡的 MARK | |
| `AllMac` | 同上网卡的 MAC | |

### XML 编码

- 设置参数 `getDevXml:NO`（不 Base64）→ 直接发 XML 字符串
- 设置参数 `getDevXml:YES` → 先 `CommonFunc.ASMBase64StringFromText:` 做 Base64，再发
- 编码 `encoding="gb2312"`，但实际输出为 UTF-8（iOS/ObjC 不强制转换）

---

## 二、pf.conf 防火墙模板

### 完整模板 (createPfConfWithRules:)

```
# PF Set
set block-policy drop
set fingerprints '/etc/pf.os'
set skip on lo0
scrub-anchor "com.apple/*"
# TABLES
table <Blacklist> { %@ } persist
# Blocks
block in all
block out all
pass in log quick from <Blacklist> to any label "BlackList_IN"
pass out log quick from any to <Blacklist> label "BlackList_OUT"
```

### 说明

- `%@` 替换为逗号分隔的 CIDR 列表
- Blacklist 名称虽叫“黑名单”，实际是**白名单**——只有列表中的 IP 段可以通过
- `set skip on lo0` — 跳过本地环回
- `set block-policy drop` — 不匹配的流量静默丢弃
- 规则：**阻止所有入站和出站**，仅放行 Blacklist 表中的地址

### CIDR 列表生成逻辑 (ExecuteHostFirewallPolicy → sub_1000f0f80)

1. 从服务器返回的 `SecurityDomain.AccessDomains` 取出 IP 范围字符串（逗号分隔）
2. 每个范围格式为 `{起始IP}-{结束IP}`（如 `10.0.0.1-10.0.0.100`）
3. `sub_1000f2240` 将 IP 转为 u32 整数
4. `sub_1000f0f80` 对范围做 CIDR 聚合（最小子网数量覆盖）
5. 追加 `serverip`（从 NSUserDefaults 读取 key `serverip`）到列表中
6. 写入 `{ASMPath}/cfg/pf.conf`
7. 通过 osascript 执行 `{binDir}/pfctl -ef {path}` 加载规则

### pf.conf 备份/恢复

- 备份：首次执行前将 `/etc/pf.conf` 拷贝到 `{ASMPath}/pf_back.conf`
- 恢复（退出/认证失败时）：`{binDir}/pfctl -F all -f /etc/pf.conf`

---

## 三、HTTP API 接口

### 1. 用户密码认证

```
POST http://{server}/a/ajax.php
参数:
  tradecode=net_auth
  type=User
  qrlogin=1
  deviceid={deviceId}
  local_lguage_set={lang}
  clientip=
  user_name={username}
  password={password}
  data_type=json
```

响应通过 `YGHttpServerManager.dealWithJsonDict:` 解析：

```json
{
  "data": {
    "RoleID": "...",
    "PolicyID": "...",
    "IsSafeCheck": "1/0",
    "IsAgainReg": "1/0"
  },
  "code": 200
}
```

### 2. 设备注册

```
GET http://{server}/a/ajax.php?tradecode=getdeviceinfoprocess&gettype=control&isopennet=isopen&depart_id=0&username=iphone&tel=&remark=iosagent&device_id=&positions=&is_mobile=0&is_guest=0&os_platform=OS&encode=1&data_type=json&dev_xml={devXml}
```

### 3. 获取移动配置

```
GET http://{server}/a/ajax.php?tradecode=getmobileconfig&data_type=json&ascid={ascid}
```

响应：

```json
{
  "data": {
    "isvpn": "1/0"
  }
}
```

### 4. 双因子认证（短信验证）

```
POST http://{server}/a/ajax.php?tradecode=...
  type=User
  twofactor=1
  username=...
  phoneNumber=...
  verifyCode=...
```

---

## 四、路由信息采集

### ASMRouteInfo 核心字段

| 属性 | 获取方式 | 说明 |
| ------ | ---------- | ------ |
| `en` | 接口 BSD 名 | 如 `en0` |
| `isMainRoute` | `route -n get default` | 是否为默认路由接口 |
| `IP` | `getifaddrs` → AF_INET | 接口 IPv4 地址 |
| `MAC` | `getifaddrs` → AF_LINK sockaddr_dl | MAC 大写无分隔 |
| `MARK` | `getifaddrs` → sockaddr_in & netmask | `inet_ntoa(ip & mask)` |
| `Gateway` | `route -n get default \| grep gateway` 解析 | 默认网关 |

---

## 五、详细执行计划

### Rust 项目结构

```
asm-bypass/
├── Cargo.toml
├── src/
│   ├── main.rs          # 入口 + 流程编排
│   ├── auth.rs          # HTTP 认证模块
│   ├── device.rs        # 设备信息 XML 生成
│   ├── network.rs       # 路由/网卡信息采集
│   ├── pf.rs            # pf.conf 生成与加载
│   ├── ttl.rs           # TTL 修改
│   └── config.rs        # 配置管理（serverip, prefs）
```

### 执行流程

```
1. 收集设备信息
   ├── 计算机名: SCDynamicStoreCopyLocalHostName()
   ├── UUID: ioreg -c IOPlatformExpertDevice | grep IOPlatformUUID
   ├── Safari 版本: /Applications/Safari.app/Contents/version.plist
   └── 路由信息: getifaddrs() 遍历所有 AF_INET + AF_LINK 接口
              route -n get default 获取主路由和网关

2. 用户登录认证
   ├── 读取或提示输入: serverip, username, password
   ├── HTTP POST → /a/ajax.php?tradecode=net_auth (用户名密码)
   └── 解析响应 → RoleID, PolicyID, IsSafeCheck, IsAgainReg

3. 获取移动配置
   ├── HTTP GET → /a/ajax.php?tradecode=getmobileconfig&ascid={ascid}
   └── 读取 isvpn 标志

4. 设备注册
   ├── 构造 devXml（含所有字段）
   ├── HTTP GET → /a/ajax.php?tradecode=getdeviceinfoprocess&dev_xml={xml}
   └── 解析响应 → DeviceID, AscID

5. 生成并加载 pf.conf
   ├── 从服务器响应 SecurityDomain.AccessDomains 获取 IP 范围列表
   ├── IP 范围 → CIDR 聚合 (sub_1000f0f80 算法)
   ├── 写入 {workdir}/cfg/pf.conf
   └── osascript 提权执行 pfctl -ef {cfg/pf.conf}

6. 修改系统 TTL
   ├── 读取当前 TTL: sysctl net.inet.ip.ttl
   ├── 如果 isvpn==0 且当前≠200: sudo sysctl net.inet.ip.ttl=200
   └── 如果 auth 失败或退出: sudo sysctl net.inet.ip.ttl=64

7. 维持网络连通
   ├── 监听网络变化: 检测路由表变动时重新注册
   ├── PingManager: 持续 ping 网关
   └── DNS 清空: networksetup -setdnsservers Wi-Fi empty (可选)
```

### 首次提权步骤（等价于 ASM 安装流程）

首次运行时需要 admin 密码，复制系统工具并设置 setuid：

```
osascript -e 'do shell script "
  cp /usr/sbin/arp {cfg_dir}/arp
  chown root {cfg_dir}/arp
  chmod u+s {cfg_dir}/arp
  cp /sbin/pfctl {cfg_dir}/pfctl
  chown root {cfg_dir}/pfctl
  chmod u+s {cfg_dir}/pfctl
  cp /usr/sbin/networksetup {cfg_dir}/networksetup
  chown root {cfg_dir}/networksetup
  chmod u+s {cfg_dir}/networksetup
  cp /usr/sbin/sysctl {cfg_dir}/sysctl
  chown root {cfg_dir}/sysctl
  chmod u+s {cfg_dir}/sysctl
" with administrator privileges'
```

后续再调用命令时直接用 setuid 二进制，无需重复输入密码：

```
echo "net.inet.ip.ttl=200" | {cfg_dir}/sysctl -w
```

### 退出/回收流程

```
1. pfctl -F all -f /etc/pf.conf           # 恢复原始 pf 规则
2. sysctl net.inet.ip.ttl=64              # 恢复默认 TTL
3. 删除 cfg/ 下的 setuid 工具（可选留）
4. 清理 pf.conf 备份 (可选)
```

---

## 六、关键技术点

### TTL 机制本质

- **TTL=200** 是非标准值（标准 64/128），网关设备可能以此为识别标记
- 同时配合 **pf 白名单防火墙**，未授权设备流量被直接 drop
- DNS 清空可能迫使应用使用硬编码 DNS 或通过 VPN 隧道解析

### 安全风险注意

- 该方案需要 **sudo / 管理员密码**
- setuid root 工具如果被利用可能造成提权漏洞
- 仅为逆向工程教育和研究用途
