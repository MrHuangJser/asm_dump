#!/bin/bash
# doctor.sh — asm-bypass 只读环境体检
#
# 只做读取与判断：不发认证请求、不改任何配置、不弹管理员授权框
# （特权相关检查一律用 `sudo -n`，拿不到权限就报 WARN，不阻塞）。
#
# 用法：
#   scripts/doctor.sh                # 体检
#   scripts/doctor.sh --log FILE     # 额外分析指定日志
#
# 退出码：0 = 无 FAIL；1 = 有 FAIL 项

set -u

LOG=""
SERVER_HINT="172.29.92.2"
while [ $# -gt 0 ]; do
  case "$1" in
    --log) LOG="${2:-}"; shift 2 ;;
    -h|--help) sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "未知参数: $1" >&2; exit 2 ;;
  esac
done

FAIL=0
WARN=0
if [ -t 1 ]; then
  C_G=$'\033[32m'; C_Y=$'\033[33m'; C_R=$'\033[31m'; C_D=$'\033[2m'; C_0=$'\033[0m'
else
  C_G=""; C_Y=""; C_R=""; C_D=""; C_0=""
fi

ok()   { printf '%sPASS%s  %s\n' "$C_G" "$C_0" "$*"; }
warn() { printf '%sWARN%s  %s\n' "$C_Y" "$C_0" "$*"; WARN=$((WARN + 1)); }
bad()  { printf '%sFAIL%s  %s\n' "$C_R" "$C_0" "$*"; FAIL=$((FAIL + 1)); }
info() { printf '%sINFO%s  %s\n' "$C_D" "$C_0" "$*"; }
sec()  { printf '\n%s── %s ──%s\n' "$C_D" "$*" "$C_0"; }

REPO="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$REPO/target/release/asm-bypass"
STATE="${HOME}/.asm_bypass"
STATE_JSON="$STATE/state.json"

# ── 1. 系统与工具链 ─────────────────────────────────────────────
sec "系统与工具链"
printf 'macOS %s  arch=%s  kernel=%s\n' \
  "$(sw_vers -productVersion 2>/dev/null || echo '?')" \
  "$(uname -m)" "$(uname -r)"

if command -v rustc >/dev/null 2>&1; then
  ok "rustc $(rustc -V 2>/dev/null | cut -d' ' -f2)"
else
  warn "未找到 rustc（源码构建才需要；已有二进制可忽略）"
fi
if xcode-select -p >/dev/null 2>&1; then
  info "Command Line Tools: $(xcode-select -p)"
else
  warn "未安装 Command Line Tools（xcode-select --install）"
fi

if [ -x "$BIN" ]; then
  ok "二进制 $BIN ($(du -h "$BIN" | cut -f1))"
  info "版本：$("$BIN" --version 2>/dev/null || echo '执行失败')"
else
  warn "未找到 ${BIN}（先 cargo build --release）"
fi

# ── 2. 进程与会话冲突 ──────────────────────────────────────────
sec "进程与会话冲突"
ASM_PID="$(pgrep -x ASM 2>/dev/null | tr '\n' ' ' | sed 's/ *$//')"
BY_PIDS="$(pgrep -f '[a]sm-bypass' 2>/dev/null | tr '\n' ' ' | sed 's/ *$//')"
if [ -n "$ASM_PID" ]; then
  bad "原版 ASM 正在运行 (pid $ASM_PID) —— 与本工具互踢，必须完全退出"
else
  ok "原版 ASM 未运行"
fi
if [ -n "$BY_PIDS" ]; then
  COUNT="$(echo "$BY_PIDS" | wc -w | tr -d ' ')"
  if [ "$COUNT" -gt 1 ]; then
    warn "asm-bypass 有 $COUNT 个实例 (pid $BY_PIDS)，只应有一个"
  else
    ok "asm-bypass 运行中 (pid $BY_PIDS)"
  fi
else
  info "asm-bypass 未运行"
fi
if [ -f "$HOME/Library/LaunchAgents/local.asm-bypass.plist" ]; then
  info "已安装 launchd 任务 local.asm-bypass"
fi

# ── 3. 设备身份 ────────────────────────────────────────────────
sec "设备身份"
if [ -d /Applications/ASM.app ]; then
  info "ASM.app 已安装"
else
  warn "ASM.app 未安装（指纹将走 state 缓存或自生成）"
fi
RAND="$(defaults read com.infogo.MAC3 rand_hard_ID 2>/dev/null || true)"
if [ -n "$RAND" ]; then
  case "$RAND" in
    RAND:*) ok "plist rand_hard_ID = $RAND" ;;
    *)      bad "plist rand_hard_ID 格式异常（缺 RAND: 前缀）: $RAND" ;;
  esac
else
  warn "读不到 rand_hard_ID（ASM 未认证过 / 未安装）"
fi

jget() { # jget <file> <key>
  [ -f "$1" ] || { echo ""; return; }
  if command -v python3 >/dev/null 2>&1; then
    python3 - "$1" "$2" <<'PY' 2>/dev/null
import json, sys
try:
    d = json.load(open(sys.argv[1]))
except Exception:
    print(""); raise SystemExit
print(d.get(sys.argv[2], ""))
PY
  else
    grep -o "\"$2\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" "$1" 2>/dev/null | head -1 | sed 's/.*:[[:space:]]*"//;s/"$//'
  fi
}

if [ -f "$STATE_JSON" ]; then
  ok "state.json 存在 ($(wc -c <"$STATE_JSON" | tr -d ' ') 字节)"
  S_DEVID="$(jget "$STATE_JSON" devid)"
  S_DISK="$(jget "$STATE_JSON" disk_id)"
  S_SRV="$(jget "$STATE_JSON" serverip)"
  info "devid    = ${S_DEVID:-<空>}"
  info "disk_id  = ${S_DISK:-<空>}"
  info "serverip = ${S_SRV:-<空>}"
  [ -n "$S_SRV" ] && SERVER_HINT="$S_SRV"
  if [ -n "$S_DISK" ]; then
    case "$S_DISK" in
      RAND:*) [ "$S_DISK" = "$RAND" ] || [ -z "$RAND" ] || warn "缓存 disk_id 与 plist 不一致" ;;
      *) warn "缓存 disk_id 缺 RAND: 前缀（会注册成未受管设备）" ;;
    esac
  fi
else
  info "无 state.json（首次运行会创建）"
fi

# ── 4. 免密特权 ────────────────────────────────────────────────
sec "免密特权"
if [ -f /etc/sudoers.d/asm-bypass ]; then
  ok "sudoers 规则存在: $(ls -l /etc/sudoers.d/asm-bypass 2>/dev/null | awk '{print $1, $3":"$4}')"
else
  warn "未安装 /etc/sudoers.d/asm-bypass（跑一次 --install 解决）"
fi
if sudo -n /usr/sbin/sysctl -n net.inet.ip.ttl >/dev/null 2>&1; then
  TTL_NOW="$(sudo -n /usr/sbin/sysctl -n net.inet.ip.ttl 2>/dev/null)"
  ok "sudo -n 可用（当前 TTL=${TTL_NOW}）"
  [ "$TTL_NOW" = "200" ] && info "TTL=200：认证已生效，或是上次非 SIGINT 退出的残留"
else
  warn "sudo -n 不可用：特权操作会静默降级为「跳过」"
fi
if [ -x "$STATE/cfg/pfctl" ] && [ -x "$STATE/cfg/sysctl" ]; then
  ok "cfg/ setuid 兜底工具链就绪（pfctl, sysctl）"
else
  info "cfg/ 兜底工具链未生成（sudo -n 可用时不重要）"
fi
if security find-generic-password -s asm-bypass >/dev/null 2>&1; then
  ok "Keychain 已存 LDAP 密码 (service=asm-bypass)"
else
  warn "Keychain 无密码：首次运行需要 --password 或 SOUL_LDAP_PASSWORD"
fi

# ── 5. 网络与 TUN ─────────────────────────────────────────────
sec "网络与 TUN"
printf 'networksetup 服务:\n'
networksetup -listallnetworkservices 2>/dev/null | sed 's/^/    /' || info "读取失败"

printf '硬件端口:\n'
networksetup -listallhardwareports 2>/dev/null \
  | awk '/Hardware Port|Device/ {printf "    %s\n", $0}' || true

LIVE=""
for en in $(ifconfig -l 2>/dev/null); do
  case "$en" in
    en[0-9]*) ip="$(ipconfig getifaddr "$en" 2>/dev/null || true)"; [ -n "$ip" ] && LIVE="$LIVE $en=$ip" ;;
  esac
done
[ -n "$LIVE" ] && ok "在线物理网卡:$LIVE" || warn "没有拿到 IPv4 的物理网卡"

UTUN="$(ifconfig -l 2>/dev/null | tr ' ' '\n' | grep -c '^utun' || true)"
[ "${UTUN:-0}" -gt 0 ] && info "存在 $UTUN 个 utun 接口（Clash/TUN 场景）" || info "无 utun 接口"

if command -v route >/dev/null 2>&1 && [ -n "$SERVER_HINT" ]; then
  ROUTE="$(route -n get "$SERVER_HINT" 2>/dev/null | awk '/interface:/{print $2}' | head -1)"
  info "到 NAC($SERVER_HINT) 的出口接口: ${ROUTE:-<解析失败>}"
  case "$ROUTE" in
    utun*) info "  走 TUN：认证依赖「绑定源 IP」绕开，日志里必须有该行" ;;
  esac
fi

CLASH="$(pgrep -i -x 'clash.*|xray|mihomo|sing-box|surge' 2>/dev/null | tr '\n' ' ' | sed 's/ *$//')"
[ -n "$CLASH" ] && info "代理进程: ${CLASH}（建议 --keep-dns）" || info "未检测到 Clash/mihomo/sing-box"

# ── 6. 日志 ───────────────────────────────────────────────────
sec "日志"
if [ -z "$LOG" ]; then
  for cand in /tmp/asm-bypass.log /tmp/asm_clean.log /tmp/asm_live.log /tmp/asm_last.log \
              "$HOME/Library/Logs/asm-bypass.log"; do
    [ -f "$cand" ] && { LOG="$cand"; break; }
  done
fi
if [ -n "$LOG" ] && [ -f "$LOG" ]; then
  ok "日志 $LOG ($(wc -l <"$LOG" | tr -d ' ') 行)"
  printf '    最近关键事件:\n'
  grep -E '^\[' "$LOG" 2>/dev/null | tail -8 | sed 's/^/      /'
  ERR="$(grep -c '^\[!\]' "$LOG" 2>/dev/null || true)"
  [ "${ERR:-0}" -gt 0 ] && warn "日志里有 $ERR 条 [!] 异常（看最后一次运行段）" || ok "日志无 [!] 异常"
else
  info "未找到日志（前台运行时用 tee 落盘，或 launchd 装好后在 ~/Library/Logs）"
fi

# ── 汇总 ─────────────────────────────────────────────────────
printf '\n%s── 汇总 ──%s\n' "$C_D" "$C_0"
printf 'FAIL=%d  WARN=%d\n' "$FAIL" "$WARN"
if [ "$FAIL" -gt 0 ]; then
  echo "先处理 FAIL，再看 docs/TROUBLESHOOTING.md"
  exit 1
fi
[ "$WARN" -gt 0 ] && echo "WARN 项按 docs/AI-SETUP.md 对应步骤处置"
exit 0
