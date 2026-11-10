#!/bin/bash
# launchd-install.sh — 把 asm-bypass 装成登录自启的 launchd 任务
#
# 生成 ~/Library/LaunchAgents/local.asm-bypass.plist：
#   ProgramArguments   <binary> --keep-dns
#   EnvironmentVariables SOUL_LDAP_USERNAME=<你给的账号>
#   日志               ~/Library/Logs/asm-bypass.log
#   KeepAlive          常驻（崩溃/退出后自动拉起，节流 30s）
#
# 不含密码：密码走 macOS Keychain（首次 --password 认证后自动写入）。
#
# 用法：
#   scripts/launchd-install.sh <LDAP_USERNAME> [--binary PATH] [--no-keep-dns] [--dry-run]
#
# 卸载：scripts/launchd-uninstall.sh

set -eu

usage() { sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'; exit 2; }

[ $# -ge 1 ] || usage
USERNAME_ARG="$1"; shift

REPO="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$REPO/target/release/asm-bypass"
EXTRA="--keep-dns"
DRY_RUN=0

while [ $# -gt 0 ]; do
  case "$1" in
    --binary)      BIN="${2:-}"; shift 2 ;;
    --no-keep-dns) EXTRA=""; shift ;;
    --dry-run)     DRY_RUN=1; shift ;;
    -h|--help)     usage ;;
    *) echo "未知参数: $1" >&2; exit 2 ;;
  esac
done

[ -x "$BIN" ] || { echo "找不到可执行文件: ${BIN}（先 cargo build --release）" >&2; exit 1; }
[ -n "$USERNAME_ARG" ] || { echo "用户名不能为空" >&2; exit 1; }

LABEL="local.asm-bypass"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
LOGDIR="$HOME/Library/Logs"
LOGFILE="$LOGDIR/asm-bypass.log"
UID_NUM="$(id -u)"

xml_escape() { printf '%s' "$1" | sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g'; }

mkdir -p "$HOME/Library/LaunchAgents" "$LOGDIR"

if [ -n "$EXTRA" ]; then
  EXTRA_XML="        <string>$(xml_escape "$EXTRA")</string>"
else
  EXTRA_XML=""
fi

TMP="$(mktemp "${TMPDIR:-/tmp}/asm-launchd.XXXXXX")"
cat >"$TMP" <<PLISTEOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>$LABEL</string>
    <key>ProgramArguments</key>
    <array>
        <string>$(xml_escape "$BIN")</string>
$EXTRA_XML
    </array>
    <key>EnvironmentVariables</key>
    <dict>
        <key>SOUL_LDAP_USERNAME</key>
        <string>$(xml_escape "$USERNAME_ARG")</string>
    </dict>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>ThrottleInterval</key>
    <integer>30</integer>
    <key>ProcessType</key>
    <string>Background</string>
    <key>StandardOutPath</key>
    <string>$(xml_escape "$LOGFILE")</string>
    <key>StandardErrorPath</key>
    <string>$(xml_escape "$LOGFILE")</string>
</dict>
</plist>
PLISTEOF

# 去掉 --no-keep-dns 时留下的空行（array 里的空元素）
awk 'NF' "$TMP" > "$TMP.clean" && mv "$TMP.clean" "$TMP"

if ! plutil -lint "$TMP" >/dev/null 2>&1; then
  echo "生成的 plist 语法不合法，已中止" >&2
  rm -f "$TMP"
  exit 1
fi

if [ "$DRY_RUN" -eq 1 ]; then
  cat "$TMP"
  rm -f "$TMP"
  echo "[*] --dry-run：未写入、未加载（去掉该参数才真正安装）" >&2
  exit 0
fi

cp "$TMP" "$PLIST"
rm -f "$TMP"

# 先停掉已存在的同名任务（忽略不存在的情况）
launchctl bootout "gui/$UID_NUM/$LABEL" >/dev/null 2>&1 || true
pkill -INT -f '[a]sm-bypass --keep-dns' >/dev/null 2>&1 || true
sleep 1

launchctl bootstrap "gui/$UID_NUM" "$PLIST"
launchctl enable "gui/$UID_NUM/$LABEL" >/dev/null 2>&1 || true

echo "[+] 已安装 launchd 任务: $LABEL"
echo "    plist : $PLIST"
echo "    二进制: $BIN $EXTRA"
echo "    账号  : $USERNAME_ARG"
echo "    日志  : $LOGFILE"
echo
echo "核对:"
echo "    launchctl print gui/$UID_NUM/$LABEL | head -20"
echo "    sleep 8; tail -20 $LOGFILE"
echo
echo "卸载: scripts/launchd-uninstall.sh"
