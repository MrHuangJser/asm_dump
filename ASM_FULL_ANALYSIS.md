# ASM_ORIGIN 完整逆向分析文档

> 基于 Hopper 反编译深度分析，涵盖 5437 个函数，由 4 个并行 Agent 协作完成

---

## 目录

1. [启动初始化流程](#1-启动初始化流程)
2. [服务器发现机制](#2-服务器发现机制)
3. [登录认证流程](#3-登录认证流程)
4. [登录后网络连通机制](#4-登录后网络连通机制)
5. [关键数据编码](#5-关键数据编码)
6. [NSUserDefaults 键值全表](#6-nsuserdefaults-键值全表)
7. [Bypass 方案分析](#7-bypass-方案分析)

---

## 1. 启动初始化流程

### 1.1 AppDelegate 启动序列

```
applicationDidFinishLaunching:
├── YGLanguageTools.initUserLanguage          # 语言初始化
├── [self serveripChanaged]                   # 读取/验证 serverip
├── 代理检查                                   # YGTool.isUseProxy
├── 静默模式检查                               # silent_mode 偏好设置
├── 更新管理器 (Sparkle)                       # 自动更新检查
├── 注册 4 个 NSNotificationCenter 观察者
├── dispatch_async 后台任务
├── createHttpLocalService                    # ★ 启动端口 36600 HTTP 服务
├── createASMSocketManager                    # 创建 Socket 通信层
├── createStateBarItem                        # 创建状态栏图标
├── [NSApp hide:self]                         # 隐藏主窗口
└── (等待用户点击状态栏图标 → 弹出登录窗口)
```

### 1.2 ASMLoginViewController 通知注册 (createNotification)

注册了 **13 个通知观察者**，覆盖登录全生命周期：

| 通知名称 | 处理器 | 触发场景 |
| ---------- | -------- | ---------- |
| `sleepMethod` | sleepMethod: | 系统休眠/唤醒 |
| `asm_start_login` | startLogin: | 登录开始 |
| **`asm_end_login`** | endLogin: | **登录结束** |
| `serveripChanaged` | serveripChanaged | 服务器地址变化 |
| `IpRenewNotification` | IpRenewNotification: | DHCP IP 续租 |
| `stopVPN` | backToLiveByStopVPN: | VPN 断开 |
| `ShowUserOneMsg` | ShowUserOneMsg: | 显示提示消息 |
| `NetAuthCurrentSafetyInspectionProgress` | refreshNetAuthCurrentSafetyInspectionProgress: | 安检进度更新 |
| `ViolationHandling` | CheckViolationHandling: | 安全违规 |
| `RecvReportSendMsg` | aNotificationHandler: | 接收报告 |
| `WebToAgt_SetRegisterDeviceFinish` | WebToAgt_SetRegisterDeviceFinish: | 设备注册完成 |
| `webPort36600AuthEndNotification` | webPort36600AuthEndNotification: | 36600 认证结束 |
| `ASMLoginWindowController_windowDidBecomeMain_` | 窗口激活 |

### 1.3 HXNet 网络监控

```
HXNet.shareInstance (dispatch_once 单例)
└── HXNet.net
    ├── [[HXNet alloc] init]
    └── CFNotificationCenterAddObserver(
          CFNotificationCenterGetDarwinNotifyCenter(),
          "com.apple.system.config.network_change",  # Darwin 系统级网络变化
          sub_10001e890                               # ★ 回调：设备重注册
        )
```

**网络变化回调流程 (sub_10001e890 → sub_10001ec10):**

```
网络变化 (Darwin notification)
  → sleep(3) 等待网络稳定
  → GetLocalRouteInfoBack vs GetLocalRouteInfo 比较路由
  → 如果路由变化:
      → getAllRouteInfo → 比较新旧路由
      → 如果发生变化:
          → getDevXml:0 获取设备 XML
          → YGHttpServerManager.netRegDev6000WithAddress  ★ 注册设备
          → SaveRouteInfo 保存新路由
          → 更新 YGPolicyItem.wifiRecordModel
```

---

## 2. 服务器发现机制

### 2.1 发现流程

**时序：登录之前**

```
ASMLoginViewController 加载
  → _res_get_server_info 属性访问
  → HTTP GET: /a/ajax.php?tradecode=get_server_info&data_type=json&local_lguage_set=zh
  → 响应 JSON 解析
  → 提取 Address 字段 (如 ["soulapp.com"])
  → setObject:forKey: → NSUserDefaults["serverip"] = "nac.soulapp-inc.cn"
  → synchronize() 持久化
```

**关键 URL 字符串 (0x100148559):**

```
http://%@/a/ajax.php?tradecode=get_server_info&data_type=json&local_lguage_set=%@
```

### 2.2 实际存储值 (从 com.infogo.MAC3.plist 验证)

```json
{
  "serverip": "nac.soulapp-inc.cn",      // 主机名
  "SERVERIP": "172.29.92.2",             // 内网 IP
  "SERVERPORT": "80",                    // 端口
  "Address": ["soulapp.com"],            // 原始发现地址
  "RE_URL": "http://nac.soulapp-inc.cn/"
}
```

---

## 3. 登录认证流程

### 3.1 入口函数

```
loginWithUser_Pass: → saveLoginState:isGoon:1 → dispatch_async(global_queue, ^block)
                                                        ↓
                                               sub_100084760 (后台线程)
```

### 3.2 后台认证块 (sub_100084760)

```
1. 获取参数
   address  = sub_10002e010(*qword_1001bea88)  // 从 NSUserDefaults 读 "address"
   deviceId = sub_10002e010(@"devid")           // 从 NSUserDefaults 读 "devid"

2. 构建 URL
   YGHttpServerManager.netAuthWithUserPasswordWithAddress:
     address
     deviceId
     username   (gb2312 → 自定义 base64)
     password   (gb2312 → 自定义 base64)
     verifyCode (空字符串)
     authserver (登录界面下拉框选择的值，如 "AdDomain" → gb2312 → base64)
     → message, RoleID, PolicyID, IsSafeCheck, IsAgainReg, resInfo

3. 处理响应
   ├── message ≠ nil → 错误处理 (dispatch_async main)
   ├── FactorAuth == 1 → 短信验证码 (dispatch_async main)
   └── FactorAuth ≠ 1 → loadnetAuthEndViewAndAlert ★ 登录成功
```

### 3.3 认证 HTTP 请求

**URL 模板 (0x100147d6f):**

```
http://{address}/a/ajax.php?
  tradecode=net_auth
  &type=User
  &user_name={username_gb2312→b64}
  &password={password_gb2312→b64}
  &deviceid={devid}
  &verify_code={verifyCode}
  &authserver={authserver_gb2312→b64}
  &data_type=json
  &local_lguage_set={lang}
```

**HTTP 方法:** POST

**HTTP Headers (sub_1000f5160):**

```
Content-Type: text/html;
User-Agent: MERONG(0.9/;Macos)
Extend-Data: ostype=mac;
```

**超时:** `POST` 字符串值误用 setTimeoutInterval → 实际超时取决于系统默认值

**同步方式:** `dispatch_semaphore_wait` (信号量阻塞等待，非异步回调)

### 3.4 自定义 Base64 编码 (sub_10005c160)

用于用户名、密码、authserver 的编码：

| 操作 | 说明 |
| ------ | ------ |
| 输入编码 | 先 GB2312 (`CFStringConvertEncodingToNSStringEncoding(0x632)`) |
| 标准 Base64 | 对 GB2312 字节数组执行 Base64 编码 |
| `=` → `:` | 填充符替换 |
| `+` → `,` | 标准 Base64 的 + 替换 |
| `/` → `.` | 标准 Base64 的 / 替换 |

**示例:**

```
huangjiangheng (gb2312)
  → aHVhbmdqaWFuZ2hlbmc= (标准 Base64)
  → aHVhbmdqaWFuZ2hlbmc: (自定义 Base64)

FuckYou202606 (gb2312)
  → RnVja1lvdTIwMjYwNg== (标准 Base64)
  → RnVja1lvdTIwMjYwNg:: (自定义 Base64)
```

### 3.5 语言检测 (sub_100024dc0)

```
YGLanguageTools.shareInstance.defineUserLanguage
  → "zh-Hans" → "zh"
  → 其他     → "en"
```

### 3.6 服务端响应解析 (dealWithJsonDict)

```json
{
  "state": "0",
  "code": "200",
  "data": {
    "RoleID": "9",
    "PolicyID": "5",
    "IsSafeCheck": "1",
    "IsAgainReg": "0",
    "SecurityDomain": {
      "AccessDomains": "10.0.0.1-10.0.0.100,172.29.0.0-172.29.255.255"
    }
  }
}
```

提取字段存储到 NSUserDefaults:

- `RoleID` → @"RoleID"
- `PolicyID` → @"PolicyId"
- `IsSafeCheck` → @"isSafeCheck"
- 响应体缓存到 `@"net_auth_callback"`

### 3.7 其他认证方式

| 方法 | URL tradecode | 关键参数 |
| ------ | --------------- | ---------- |
| 无认证登录 | `net_auth&type=NoAuth` | clientip |
| 短信验证 | `net_auth&type=SMS&authtypes=TwoFactor` | mobile_phone, check_code |
| 访客码 | `net_auth&type=Guest` | net_code |
| 微信扫码 | `net_auth&type=User&qrlogin=1` | 额外 isRecord/hintOver/autoAuth |
| 企业微信 | `net_auth&type=User&weworkqrlogin=1` | 同微信扫码 |
| 自动认证 | `auto_authWithAddress:devId:type:` | (已注册设备) |

---

## 4. 登录后网络连通机制

### 4.1 认证成功后 (loadnetAuthEndViewAndAlert)

```
认证成功 → loadnetAuthEndViewAndAlert:
├── sub_10002dc20(@"1", *qword_1001bea70)   // 设置某种状态标记
├── 如果 netAuthMessage ≠ nil:
│   ├── dispatch_async(main): 显示错误
│   └── [var_10 RecordConfig]
├── 如果 netAuthMessage == nil (成功):
│   ├── [var_10 RecordConfig]
│   ├── [var_10 loadAppImageWithNetAuthInfo:0x0]
│   ├── YGHttpServerManager.getMobileConfig:withAscid:  ★ 获取移动配置
│   ├── PingManager.pingManagerDelegateObject:runWithHostName:   ★ 启动 Ping
│   └── [var_10 loadNextResultPage:address:devID:policyId:isSafeCheck:IsAgainReg:]
└── dispatch_async(main) → sub_100089e80  ★ 主结果处理块
```

### 4.2 主结果块 (sub_100089e80)

```
sub_100089e80:
├── 创建/获取 AuthResultWindowController
├── 设置 is_safecheck / repair 标志
├── 加载 WebView
├── 设置 clientState = 1
│
├── 如果 var_C0+0x50 ≠ 0 (需要修复):
│   ├── 如果 is_repair:
│   │   ├── 设置自动修复回调
│   │   └── 显示修复进度
│   │
│   ├── 如果修复完成且失败:
│   │   ├── NetTool.authFalseChangeTTL  ★ 恢复 TTL=64
│   │   └── 显示修复失败视图
│   │
│   └── 如果修复完成且成功:
│       ├── 检查 isVPN
│       └── 如果非 VPN: NetTool.authSuccessChangeTTL  ★ 设置 TTL=200
│
├── 如果 var_C0+0x50 == 0 (无需修复):
│   ├── 检查 isVPN
│   ├── 如果非 VPN: NetTool.authSuccessChangeTTL  ★ 设置 TTL=200
│   └── loadNetAuthSuccessView
│
└── sub_10002dc20(@"1", *qword_1001beab0)
```

### 4.3 防火墙规则 (ExecuteHostFirewallPolicy)

**触发时机:** 认证成功后，异步获取

```
ExecuteHostFirewallPolicy:
├── 读取 IsOpen / IsOfflineOpen 标志
├── 如果 IsOpen == 0:
│   ├── appleScriptRecoverPFConf   ★ 恢复原始 pf.conf
│   └── SaveHostFirewallPolicyToUDF
│
├── 如果 IsOpen == 1:
│   ├── 从 SecurityDomain.AccessDomains 取 IP 范围
│   ├── 解析逗号分隔的范围 (如 "10.0.0.1-10.0.0.100")
│   ├── IP 范围 → CIDR 聚合 (sub_1000f0f80)
│   ├── 追加 serverip 到白名单
│   ├── createPfConfWithRules   ★ 生成 pf.conf
│   └── SaveHostFirewallPolicyToUDF
│
└── 与缓存策略比较，仅在变化时重新加载
```

### 4.4 pf.conf 模板

```
# PF Set
set block-policy drop
set fingerprints '/etc/pf.os'
set skip on lo0
scrub-anchor "com.apple/*"
# TABLES
table <Blacklist> { {CIDR_LIST} } persist
# Blocks
block in all
block out all
pass in log quick from <Blacklist> to any label "BlackList_IN"
pass out log quick from any to <Blacklist> label "BlackList_OUT"
```

**加载方式:**

```
osascript -e 'do shell script "{cfg_dir}/pfctl -ef {cfg_dir}/pf.conf" with administrator privileges'
```

**备份/恢复:**

- 首次: 备份 `/etc/pf.conf` → `{ASMPath}/pf_back.conf`
- 退出或认证失败: `{cfg_dir}/pfctl -F all -f /etc/pf.conf`

---

## 5. 关键数据编码

### 5.1 设备注册 XML (getDevXml)

```xml
<?xml version="1.0" encoding="gb2312"?>
<MSAC>
  <DeviceName>MacBook-Pro-8</DeviceName>   <!-- SCDynamicStoreCopyLocalHostName() -->
  <OS>MacOS</OS>                             <!-- 硬编码 -->
  <Ip>172.27.40.3</Ip>                       <!-- 主网卡 IP -->
  <Mac>2C16DBA93445</Mac>                    <!-- 主网卡 MAC (大写无冒号) -->
  <Mark>172.27.40.0</Mark>                   <!-- IP & netmask -->
  <GateWay>172.27.40.1</GateWay>             <!-- route -n get default -->
  <IeVersion>Safari 17.5(xxx)</IeVersion>   <!-- Safari 版本 -->
  <DiskId>B3AE2A06...</DiskId>               <!-- IOPlatformUUID 去横线大写 -->
  <AllIp_Ok>172.27.40.3</AllIp_Ok>          <!-- 有效网卡 IP 列表 (MAC≠00..00, IP≠0.0.0.0/127.0.0.1) -->
  <AllMac_Ok>2C16DBA93445</AllMac_Ok>        <!-- 有效网卡 MAC 列表 -->
  <AllIp>198.18.0.1,172.27.40.3</AllIp>     <!-- 有 MAC 网卡的 IP 列表 -->
  <AllMark>198.18.0.0,172.27.40.0</AllMark>  <!-- 有 MAC 网卡的 Mark 列表 -->
  <AllMac>AEEF88...,2C16DBA9...</AllMac>     <!-- 有 MAC 网卡的 MAC 列表 -->
</MSAC>
```

### 5.2 默认网关提取

```
route -n get default → 解析 "gateway: x.x.x.x"
route -n get default → 解析 "interface: enX"  # 主接口名
```

### 5.3 IP 范围 → CIDR 聚合 (sub_1000f0f80)

- 输入: 两个 IP 字符串 (起始-结束)
- 标准 CIDR 聚合算法 (最小前缀覆盖)
- 输出: "/" 格式的 CIDR 数组

### 5.4 提权工具链

**安装目录:** `{ASMPath}/cfg/`
**工具列表:**

| 系统路径 | 安装路径 | 说明 |
| ---------- | ---------- | ------ |
| /usr/sbin/arp | {cfg_dir}/arp | ARP 表操作 (setuid root) |
| /sbin/pfctl | {cfg_dir}/pfctl | 防火墙控制 (setuid root) |
| /usr/sbin/networksetup | {cfg_dir}/networksetup | 网络设置 (setuid root) |
| /usr/sbin/sysctl | {cfg_dir}/sysctl | 内核参数 (setuid root) |

**安装方式:**

```bash
osascript -e 'do shell script "
  cp /usr/sbin/arp {cfg_dir}/arp && chown root {cfg_dir}/arp && chmod u+s {cfg_dir}/arp
  cp /sbin/pfctl {cfg_dir}/pfctl && chown root {cfg_dir}/pfctl && chmod u+s {cfg_dir}/pfctl
  cp /usr/sbin/networksetup {cfg_dir}/networksetup && chown root {cfg_dir}/networksetup && chmod u+s {cfg_dir}/networksetup
  cp /usr/sbin/sysctl {cfg_dir}/sysctl && chown root {cfg_dir}/sysctl && chmod u+s {cfg_dir}/sysctl
" with administrator privileges'
```

### 5.5 TTL 修改机制

| 方法 | TTL 值 | 触发时机 |
| ------ | -------- | ---------- |
| authSuccessChangeTTL | **200** (0xc8) | 认证成功，非 VPN 模式 |
| authFalseChangeTTL | **64** (0x40) | 认证失败、退出、VPN 模式 |
| getCurTTLValue | 读取当前值 | 每次修改前检查 |

**执行命令:**

```bash
sudo {cfg_dir}/sysctl net.inet.ip.ttl=200
```

---

## 6. NSUserDefaults 键值全表

### 认证相关

| Key | 值示例 | 说明 |
| ----- | -------- | ------ |
| `devid` | `"105238"` | 设备 ID (服务器分配) |
| `AscID` | `"11:11:11:11:11:11"` | 应用会话 ID (默认 MAC 地址) |
| `Registered` | `"1"` | 设备注册状态 |
| `last_Registered` | `"0"` | 上次注册时间戳 |
| `RoleID` | `"9"` | 用户角色 |
| `PolicyId` | `"5"` | 策略 ID |
| `isSafeCheck` | `"1"` | 安全检查标志 |
| `user` | `"huangjiangheng"` | 用户名 |
| `pass` | `"RnVja1lvdTIwMjYwNg=="` | 密码 (Base64) |
| `LoginState` | `"0"` | 登录状态 |

### 服务器相关

| Key | 值示例 | 说明 |
| ----- | -------- | ------ |
| `serverip` | `"nac.soulapp-inc.cn"` | 服务器主机名 |
| `SERVERIP` | `"172.29.92.2"` | 服务器 IP |
| `SERVERPORT` | `"80"` | 服务器端口 |
| `ServerID` | `"3c6baa0a-..."` | 服务器唯一 ID |
| `res_get_server_info` | `{...}` | get_server_info 完整响应 (大 JSON) |
| `net_auth_callback` | `{...}` | 认证回调数据 |
| `SUFeedURL` | `"http://nac.soulapp-inc.cn/download/appupdate.xml"` | 更新 URL |

### 策略相关

| Key | 值示例 | 说明 |
| ----- | -------- | ------ |
| `getcheckpolicy` | `{...}` | 检查策略 JSON |
| `INFOGOPOLICY` | {binary plist} | 策略二进制数据 |
| `FirewallPolicyTime` | `"1783401187..."` | 防火墙策略更新时间 |
| `GetHostFirewallPolicy` | {binary plist} | 防火墙策略二进制 |
| `WebAuthConfigTmp` | `{...}` | Web 认证临时配置 |
| `WebAuthTypeTmp` | `"VXNlcg::###..."` | 认证类型编码 (包含令牌) |

### 网络相关

| Key | 值示例 | 说明 |
| ----- | -------- | ------ |
| `route_info_data_1` | {binary plist} | 路由信息快照 |
| `route_info_data_back_1` | {binary plist} | 路由信息备份 |
| `com.apple.system.config.network_change` | `"1783397971..."` | 上次网络变化时间戳 |
| `last_domain_name_map_ip` | `"198.18.0.17"` | DNS 解析结果 |
| `gethostbyname` | `"198.18.0.17"` | 主机名解析缓存 |
| `defalutMac` | `"AC:07:75:0F:A4:1E"` | 默认 MAC 地址 |

---

## 7. Bypass 方案分析

### 7.1 ASM 通信架构总结

```
┌──────────────────────────────────────────────────┐
│                    ASM 客户端                      │
│                                                   │
│  ┌─────────┐   ┌──────────────┐  ┌────────────┐  │
│  │ 登录 UI │ → │ 认证模块     │→│ 后处理模块  │  │
│  │         │   │ net_auth     │  │ TTL+pf+注册 │  │
│  └─────────┘   └──────┬───────┘  └─────┬──────┘  │
│                       │                │         │
│              ┌────────▼────────────────▼───────┐  │
│              │        HTTP 请求发送              │  │
│              │  Content-Type: text/html;        │  │
│              │  User-Agent: MERONG(0.9/;Macos) │  │
│              │  Extend-Data: ostype=mac;        │  │
│              └────────┬────────────────────────┘  │
│                       │                           │
│              ┌────────▼────────┐                  │
│              │ 本地 HTTP 代理   │  ← 端口 36600    │
│              │ (localhost)     │                  │
│              └────────┬────────┘                  │
│                       │                           │
└───────────────────────┼───────────────────────────┘
                        │
                        ▼
              ┌─────────────────┐
              │   NAC 服务器     │
              │  172.29.92.2:80 │
              │ nac.soulapp...  │
              └─────────────────┘
```

### 7.2 Bypass 必要条件

要绕过 ASM 客户端实现网络连通，必须完成以下 **三个层面** 的操作：

| 层面 | 操作 | 依赖条件 |
| ------ | ------ | ---------- |
| **1. 认证层面** | POST `/a/ajax.php` 用户名密码认证 | ASM 客户端运行中 (提供 36600 代理) |
| **2. 防火墙层面** | 生成并加载 `pf.conf` 白名单 | 系统 root 权限 (首次需弹窗) |
| **3. 网络层面** | 修改系统 TTL=200 | 系统 root 权限 |

### 7.3 Rust Bypass 方案修正

**核心发现: 认证必须通过 ASM 客户端的 36600 端口代理，无法直接连接 NAC 服务器**

#### 方案 A: 依赖 ASM 客户端 (推荐)

```
前提: ASM 客户端已登录，36600 端口代理运行中

asm-bypass (Rust):
  ├── 配置 reqwest Proxy: http://127.0.0.1:36600
  ├── POST 认证请求 (通过 36600 转发到 NAC)
  ├── 获取 AccessDomains → 生成 pf.conf
  ├── sudo 加载 pf.conf
  └── sudo sysctl TTL=200
```

#### 方案 B: 完全独立 (需额外工作)

需要 ASM 客户端已完成首次登录并建立了到 NAC 的连接隧道。之后可以：

1. 复用 ASM 的本地代理 (36600)
2. 或复制 ASM 的认证令牌/session

### 7.4 已验证的 HTTP 参数

**认证请求 (POST):**

```
URL:    http://172.29.92.2/a/ajax.php
Method: POST
Headers:
  Content-Type: text/html;
  User-Agent: MERONG(0.9/;Macos)
  Extend-Data: ostype=mac;
Body (form-urlencoded):
  tradecode=net_auth
  type=User
  user_name={username-gb2312→custom-base64}
  password={password-gb2312→custom-base64}
  deviceid={devid}
  authserver=AdDomain               # ← 明文 "AdDomain"
  verify_code=                      # ← 空字符串
  data_type=json
  local_lguage_set=zh               # ← 直接传 "zh"
```

**关键纠正:**

- `authserver` 传**明文** `"AdDomain"`（不是编码后的）
- `local_lguage_set` 传 **`"zh"`**（不是 `"zh_CN"`）
- 密码要传 plist 中存储的 **Base64 值** `"RnVja1lvdTIwMjYwNg=="`（不是重新编码）
- 设备注册需要先获取 serverip: `tradecode=get_server_info`

---

## 附录: 函数地址速查表

| 地址 | 函数 | 说明 |
| ------ | ------ | ------ |
| 0x100010940 | EntryPoint | 程序入口 |
| 0x100062dc0 | AppDelegate.applicationDidFinishLaunching: | 启动初始化 |
| 0x1000636c0 | AppDelegate.applicationWillTerminate: | 退出清理 |
| 0x100064330 | AppDelegate.serveripChanaged | 服务器 IP 变化处理 |
| 0x10001e730 | +[HXNet shareInstance] | HXNet 单例 |
| 0x10001e800 | +[HXNet net] | 创建 HXNet + 注册网络通知 |
| 0x10001e890 | sub_10001e890 | 网络变化回调 |
| 0x10001ec10 | sub_10001ec10 | 设备重注册 |
| 0x100078810 | -[ASMLoginViewController createNotification] | 注册通知 |
| 0x100083ed0 | -[ASMLoginViewController loginWithUser_Pass:] | 登录入口 |
| 0x100084760 | sub_100084760 | 后台认证块 |
| 0x100070ca0 | +[YGHttpServerManager netAuthWithUserPasswordWithAddress:...] | 构建认证请求 |
| 0x10005c160 | sub_10005c160 | 自定义 Base64 编码 |
| 0x100024dc0 | sub_100024dc0 | 语言检测 (zh/en) |
| 0x1000f5160 | sub_1000f5160 | HTTP POST 请求 |
| 0x100073a10 | +[YGHttpServerManager dealWithJsonDict:...] | 响应解析 |
| 0x100087960 | loadnetAuthEndViewAndAlert:... | 认证后处理 |
| 0x100087f40 | loadNextResultPage:... | 状态路由 |
| 0x100089e80 | sub_100089e80 | 主结果块 |
| 0x1000f0550 | +[GetHostFirewallPolicy ExecuteHostFirewallPolicy:] | 防火墙策略 |
| 0x1000f11f0 | createPfConfWithRules: | pf.conf 生成 |
| 0x10010c1b0 | +[NetTool runWithAdminShellCommand:binPath:] | 提权执行 |
| 0x10010be00 | +[NetTool authSuccessChangeTTL] | TTL=200 |
| 0x10010be50 | +[NetTool authFalseChangeTTL] | TTL=64 |
| 0x10009d210 | -[ASMDeviceInfo getDevXml:] | 设备 XML 生成 |
| 0x1000705e0 | +[YGHttpServerManager netRegDev6000WithAddress:...] | 设备注册 |
| 0x100072d20 | +[YGHttpServerManager getMobileConfig:withAscid:] | 移动配置 |
| 0x1000cbb10 | +[ASMRouteInfo getNetworkCardDictionary] | 网卡信息获取 |
| 0x1000cb3b0 | +[ASMRouteInfo getAllRouteInfo] | 路由信息 |
