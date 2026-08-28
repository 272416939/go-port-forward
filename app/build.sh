#!/usr/bin/env bash
# app/build.sh — 隧道组件构建脚本（产物输出到 app/bin/）
# Usage: bash app/build.sh [client]
set -euo pipefail

cd "$(dirname "$0")"

VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
OUT="bin"
# -H=windowsgui：不分配控制台窗口。界面由本机浏览器承载，留一个空白 cmd
# 窗口只会让用户以为程序卡住。
LDFLAGS="-s -w -H=windowsgui"

log() { echo -e "\033[1;36m==>\033[0m $*"; }

build_server() {
    log "Building pf-server (linux/amd64)..."
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
        go build -trimpath -ldflags "-s -w" -o "$OUT/pf-server" ./cmd/server
    log "Done: $OUT/pf-server"
}

build_client() {
    log "Building pf-client (windows/amd64)..."
    CGO_ENABLED=0 GOOS=windows GOARCH=amd64 \
        go build -trimpath -ldflags "$LDFLAGS" -o "$OUT/pf-client.exe" ./cmd/client
    # wintun.dll 必须与 exe 同目录（WireGuard 官方签名 DLL，允许随软件分发）
    mkdir -p "$OUT"
    cp vendor-wintun/amd64/wintun.dll "$OUT/wintun.dll"
    log "Done: $OUT/pf-client.exe + wintun.dll"
}

mkdir -p "$OUT"
target="${1:-client}"
case "$target" in
    client) build_client ;;
    *) echo "usage: $0 [client]"; exit 1 ;;
esac

log "版本: $VERSION；产物在 app/$OUT/"
