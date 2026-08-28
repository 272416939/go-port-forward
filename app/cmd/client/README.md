# pf-client 资源文件说明

统一的品牌图标源文件是 `G:\图片\头像LOGO\favicon.ico`（实为 48×48 RGBA **PNG**，
扩展名有误导性）。下面三处都由它派生，换 LOGO 时全部要重新生成。

## assets/icon.ico
窗口标题栏与托盘图标，由 `//go:embed` 打进二进制（见 `window_windows.go`）。

**必须是多尺寸未压缩 DIB**：`CreateIconFromResourceEx` 不认 PNG 压缩的 ICO
条目，而 PIL 与多数在线转换工具默认就输出 PNG 条目——踩到的表现是窗口和托盘
静默地没有图标。`TestEmbeddedIconIsUncompressedDIB` 会守住这条。

生成（16/24/32/48 四档，逐条写 BITMAPINFOHEADER + BGRA + AND 掩码）：

```python
from PIL import Image
import struct
img = Image.open(r"G:\图片\头像LOGO\favicon.ico").convert("RGBA")

def dib(im, n):
    r = im.resize((n, n), Image.LANCZOS); px = r.load()
    hdr = struct.pack('<IiiHHIIiiII', 40, n, n*2, 1, 32, 0, 0, 0, 0, 0, 0)
    body = bytearray()
    for y in range(n-1, -1, -1):             # DIB 自底向上
        for x in range(n):
            rr, gg, bb, aa = px[x, y]
            body += bytes((bb, gg, rr, aa))  # BGRA
    body += bytes(((n + 31) // 32) * 4 * n)  # AND 掩码（32bpp 下留空）
    return hdr + bytes(body)

sizes = [16, 24, 32, 48]
entries, blobs, off = [], [], 6 + 16 * len(sizes)
for n in sizes:
    d = dib(img, n)
    entries.append(struct.pack('<BBBBHHII', n, n, 0, 0, 1, 32, len(d), off))
    blobs.append(d); off += len(d)
open("assets/icon.ico", "wb").write(
    struct.pack('<HHH', 0, 1, len(sizes)) + b''.join(entries) + b''.join(blobs))
```

## ui/logo.png
界面顶栏的品牌标记（96px，供 34px 显示位在 HiDPI 下取样）。

```python
img.resize((96, 96), Image.LANCZOS).save("ui/logo.png", optimize=True)
```

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

## 主项目 Web 面板
`internal/web/static/images/` 下的 `favicon.ico`、`favicon_256x256.ico`、`logo.png`
同源同 LOGO，但那里由浏览器加载，PIL 默认输出的 PNG 条目即可，无需 DIB 处理。
