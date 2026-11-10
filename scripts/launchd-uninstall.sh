#!/bin/bash
# launchd-uninstall.sh — 停止并移除 asm-bypass 的 launchd 任务
#
# 只处理自启项与进程；sudoers / Keychain / 状态目录用 `asm-bypass --uninstall`
# 和 docs/AI-SETUP.md §7 的步骤清理。

set -u

LABEL="local.asm-bypass"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
UID_NUM="$(id -u)"

launchctl bootout "gui/$UID_NUM/$LABEL" >/dev/null 2>&1 || true
launchctl disable "gui/$UID_NUM/$LABEL" >/dev/null 2>&1 || true

if [ -f "$PLIST" ]; then
  rm -f "$PLIST"
  echo "[+] 已删除 $PLIST"
else
  echo "[*] 没有找到 ${PLIST}（可能本来就没装）"
fi

# SIGINT 让进程走清理路径（还原 pf / TTL）
pkill -INT -f '[a]sm-bypass' >/dev/null 2>&1 || true
sleep 1
LEFT="$(pgrep -f '[a]sm-bypass' 2>/dev/null | tr '\n' ' ' | sed 's/ *$//')"
if [ -n "$LEFT" ]; then
  echo "[!] 仍有进程在: $LEFT"
else
  echo "[+] asm-bypass 已停止"
fi
