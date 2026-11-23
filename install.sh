#!/bin/bash
# 将同目录下的 frida-buddy 以软链接方式安装到 /usr/local/bin
# 用软链接而非复制，保证脚本能按真实路径找到同目录的 .js 脚本
set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
SRC="$DIR/frida-buddy"
DEST_DIR="/usr/local/bin"
DEST="$DEST_DIR/frida-buddy"

if [ ! -f "$SRC" ]; then
  echo "[!] 找不到源文件: $SRC" >&2
  exit 1
fi

if [ ! -d "$DEST_DIR" ]; then
  echo "[*] 创建目标目录: $DEST_DIR"
  mkdir -p "$DEST_DIR" 2>/dev/null || sudo mkdir -p "$DEST_DIR"
fi

if [ -w "$DEST_DIR" ]; then
  ln -sfn "$SRC" "$DEST"
else
  echo "[*] 需要管理员权限写入 $DEST_DIR"
  sudo ln -sfn "$SRC" "$DEST"
fi

echo "[+] 已安装软链接: $DEST -> $SRC"
ls -l "$DEST"
