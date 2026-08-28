# pf-client 资源文件说明

品牌图标源图在仓库里：[`assets/brand/logo.png`](../../../assets/brand/logo.png)
（48×48 RGBA PNG）。换 LOGO 时替换它，然后跑一次生成脚本：

```bash
python assets/brand/generate.py
```

脚本会一次性刷新客户端图标、界面顶栏 LOGO 与 Web 面板 favicon。**exe 的资源
图标不在脚本范围内**，需要另外跑下面的 go-winres。

## assets/icon.ico
窗口标题栏与托盘图标，由 `//go:embed` 打进二进制（见 `window_windows.go`）。

**必须是多尺寸未压缩 DIB**：`CreateIconFromResourceEx` 不认 PNG 压缩的 ICO
条目，而 PIL 的 ICO 导出对较大尺寸会自动改用 PNG——踩到的表现是窗口和托盘
静默地没有图标，没有任何报错。生成脚本因此自己拼 DIB（16/24/32/48 四档），
`TestEmbeddedIconIsUncompressedDIB` 守住这条。

## ui/logo.png
界面顶栏的品牌标记（96px，供 34px 显示位在 HiDPI 下取样）。

## rsrc_windows_amd64.syso
exe 的 Win32 资源段（Explorer / 任务栏图标 + 版本信息 + GUI manifest），由
go-winres 生成后提交进仓库，这样 `build.sh` 保持纯 `go build`，无需额外工具。

```bash
go install github.com/tc-hib/go-winres@latest
cd app/cmd/client
go-winres simply --arch amd64 --icon assets/icon.ico --manifest gui \
  --out rsrc --file-description "Port Forward 隧道客户端" \
  --product-name "Port Forward" --original-filename "pf-client.exe"
```

注意 `--manifest gui`：`cli`（默认值）会让 exe 申请控制台，与 `-H=windowsgui` 冲突。
