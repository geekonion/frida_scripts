#!/bin/bash
# 卸载 /usr/local/bin/frida-buddy（只删除链接，不删除源脚本）
set -e

DEST="/usr/local/bin/frida-buddy"

if [ ! -e "$DEST" ] && [ ! -L "$DEST" ]; then
  echo "[!] 未找到已安装项: $DEST"
  exit 0
fi

if [ ! -L "$DEST" ]; then
  echo "[!] $DEST 不是软链接，为避免误删真实文件，已跳过" >&2
  exit 1
fi

if [ -w "$(dirname "$DEST")" ]; then
  rm -f "$DEST"
else
  echo "[*] 需要管理员权限删除 $DEST"
  sudo rm -f "$DEST"
fi

echo "[+] 已卸载: $DEST"
