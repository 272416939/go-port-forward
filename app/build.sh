#!/usr/bin/env bash
# app/build.sh — 隧道客户端构建脚本（产物输出到 app/bin/）
#
# 隧道服务端已集成进 go-port-forward 主程序（tunnel.enabled），这里只构建
# Windows 客户端。
#
# Usage: bash app/build.sh
set -euo pipefail

cd "$(dirname "$0")"

VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
OUT="bin"
# -H=windowsgui：不分配控制台窗口。界面是 WebView2 原生窗口，留一个空白 cmd
# 窗口只会让用户以为程序卡住。
LDFLAGS="-s -w -H=windowsgui"

log() { echo -e "\033[1;36m==>\033[0m $*"; }

build_client() {
    log "Building pf-client (windows/amd64)..."
    CGO_ENABLED=0 GOOS=windows GOARCH=amd64 \
        go build -trimpath -ldflags "$LDFLAGS" -o "$OUT/pf-client.exe" ./cmd/client
    # wintun.dll 必须与 exe 同目录（WireGuard 官方签名 DLL，允许随软件分发）
    mkdir -p "$OUT"
    cp vendor-wintun/amd64/wintun.dll "$OUT/wintun.dll"
    # 清掉 `go build ./cmd/client/` 直接留在包目录下的产物：那种方式没有
    # -H=windowsgui，跑起来会多一个黑色控制台窗口，和正式产物混在一起容易发错。
    rm -f client.exe cmd/client/client.exe
    log "Done: $OUT/pf-client.exe + wintun.dll"
}

mkdir -p "$OUT"
build_client

log "版本: $VERSION；产物在 app/$OUT/"
