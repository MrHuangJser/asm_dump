use clap::Parser;

/// ASM NAC agent 协议重实现 —— 自动认证 + 网络切换适配 + Clash TUN 兼容
#[derive(Parser, Debug, Clone)]
#[command(name = "asm-bypass", version, about)]
pub struct Cli {
    /// 认证服务器 (默认自动发现: SOUL_SERVER > state > 候选域名 get_server_info)
    #[arg(long)]
    pub server: Option<String>,

    /// LDAP 用户名 (默认读环境变量 SOUL_LDAP_USERNAME)
    #[arg(long)]
    pub username: Option<String>,

    /// LDAP 密码 (默认读环境变量 SOUL_LDAP_PASSWORD)
    #[arg(long)]
    pub password: Option<String>,

    /// 状态目录 (默认 ~/.asm_bypass)
    #[arg(long)]
    pub state_dir: Option<std::path::PathBuf>,

    /// 跳过 pf 防火墙策略应用
    #[arg(long)]
    pub no_pf: bool,

    /// 跳过 sysctl net.inet.ip.ttl=200
    #[arg(long)]
    pub no_ttl: bool,

    /// 跳过 TCP 长连接 (用 HTTP auto_auth 心跳兜底)
    #[arg(long)]
    pub no_socket: bool,

    /// 不执行任何特权操作 (pf/TTL/DNS/setuid 全部跳过)
    #[arg(long)]
    pub no_privilege: bool,

    /// 认证成功后不清空物理网卡 DNS (Clash 管理 DNS 时建议开启)
    #[arg(long)]
    pub keep_dns: bool,

    /// 安装免密特权 (一次性): 写 /etc/sudoers.d/asm-bypass NOPASSWD 规则
    /// (仅放行 pfctl/sysctl/networksetup/ipconfig 四个二进制) + setuid 工具链。
    /// 仅此一次需要系统管理员密码，之后任何路径都不再要密码。
    #[arg(long)]
    pub install: bool,

    /// 卸载免密特权: 删除 /etc/sudoers.d/asm-bypass 与 cfg/ 工具链
    #[arg(long)]
    pub uninstall: bool,

    /// 允许 osascript 管理员授权弹框兜底 (默认禁止: 特权操作静默降级)
    #[arg(long)]
    pub yes: bool,

    /// 跳过安检上报 (mobileresult)。默认认证后把所有检查项按"通过"提交，
    /// 让服务端放开该设备的完整 ACL；跳过会停留在受限访问状态。
    #[arg(long)]
    pub no_safecheck: bool,

    /// 只打印从 ASM plist 读到的身份数据后退出（零网络请求，用于核对 devid/checkres）
    #[arg(long)]
    pub dump_id: bool,

    /// 打印安检上报的 query 后退出，不真正发送 mobileresult（零写操作）
    #[arg(long)]
    pub dump_query: bool,

    /// 覆盖周期重认证间隔（分钟，默认 5）。调试用，如 --recheck-minutes 1
    #[arg(long)]
    pub recheck_minutes: Option<u64>,
}

impl Cli {
    pub fn parse_args() -> Self {
        <Self as Parser>::parse()
    }
}
