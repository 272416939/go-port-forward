# pf-client 资源文件说明

## assets/icon.ico
窗口标题栏与托盘图标，由 `//go:embed` 打进二进制（见 `window_windows.go`）。
源文件是 `internal/web/static/images/favicon.ico` 的副本——`go:embed` 无法引用
包目录之外的路径，所以必须复制而不是软链。更新图标时两处都要改。

## rsrc_windows_amd64.syso
exe 的 Win32 资源段（Explorer / 任务栏图标 + 版本信息 + GUI manifest），由
go-winres 生成后提交进仓库，这样 `build.sh` 保持纯 `go build`，无需额外工具。

重新生成（改图标或版本信息后）：

```bash
go install github.com/tc-hib/go-winres@latest
cd app/cmd/client
go-winres simply --arch amd64 --icon assets/icon.ico --manifest gui \
  --out rsrc --file-description "Port Forward 隧道客户端" \
  --product-name "Port Forward" --original-filename "pf-client.exe"
```

注意 `--manifest gui`：`cli` 会让 exe 申请控制台，与 `-H=windowsgui` 冲突。
