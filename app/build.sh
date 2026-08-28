#!/usr/bin/env bash
# app/build.sh — 隧道组件构建脚本（产物输出到 app/bin/）
# Usage: bash app/build.sh [all|server|client]
set -euo pipefail

cd "$(dirname "$0")"

VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
OUT="bin"
LDFLAGS="-s -w"

log() { echo -e "\033[1;36m==>\033[0m $*"; }

build_server() {
    log "Building pf-server (linux/amd64)..."
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
        go build -trimpath -ldflags "$LDFLAGS" -o "$OUT/pf-server" ./cmd/server
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
target="${1:-all}"
case "$target" in
    server) build_server ;;
    client) build_client ;;
    all)    build_server; build_client ;;
    *) echo "usage: $0 [all|server|client]"; exit 1 ;;
esac

log "版本: $VERSION；产物在 app/$OUT/"
