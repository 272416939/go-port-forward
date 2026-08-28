#!/usr/bin/env python3
"""从品牌源图生成项目各处需要的图标。

源图：assets/brand/logo.png（48×48 RGBA）。改 LOGO 时只替换它，然后跑一次本脚本，
最后按 app/cmd/client/README.md 重新生成 .syso。

用法：
    python assets/brand/generate.py
"""

import os
import struct
import sys

try:
    from PIL import Image
except ImportError:
    sys.exit("需要 Pillow：pip install pillow")

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SRC = os.path.join(ROOT, "assets", "brand", "logo.png")


def dib_entry(img, n):
    """把图像渲染成 n×n 的未压缩 DIB（BITMAPINFOHEADER + BGRA + AND 掩码）。

    Windows 的 CreateIconFromResourceEx 不认 PNG 压缩的 ICO 条目，而 PIL 的
    ICO 导出对较大尺寸会自动改用 PNG——所以客户端用的 icon.ico 必须自己拼。
    踩到的表现是窗口和托盘静默地没有图标，没有任何报错。
    """
    resized = img.resize((n, n), Image.LANCZOS)
    px = resized.load()
    # 高度写 2n：DIB 里颜色位图与掩码位图叠在一起。
    header = struct.pack("<IiiHHIIiiII", 40, n, n * 2, 1, 32, 0, 0, 0, 0, 0, 0)
    body = bytearray()
    for y in range(n - 1, -1, -1):  # DIB 自底向上
        for x in range(n):
            r, g, b, a = px[x, y]
            body += bytes((b, g, r, a))  # BGRA
    # AND 掩码：32bpp 下透明度由 alpha 决定，掩码留空，但每行需 4 字节对齐。
    body += bytes(((n + 31) // 32) * 4 * n)
    return header + bytes(body)


def write_dib_ico(img, path, sizes):
    entries, blobs = [], []
    offset = 6 + 16 * len(sizes)
    for n in sizes:
        data = dib_entry(img, n)
        entries.append(struct.pack("<BBBBHHII", n, n, 0, 0, 1, 32, len(data), offset))
        blobs.append(data)
        offset += len(data)
    payload = struct.pack("<HHH", 0, 1, len(sizes)) + b"".join(entries) + b"".join(blobs)
    with open(path, "wb") as f:
        f.write(payload)
    return len(payload)


def main():
    if not os.path.exists(SRC):
        sys.exit(f"找不到源图：{SRC}")
    img = Image.open(SRC).convert("RGBA")

    targets = []

    # 1) 客户端窗口 + 托盘：必须是多尺寸未压缩 DIB。
    p = os.path.join(ROOT, "app", "cmd", "client", "assets", "icon.ico")
    targets.append((p, write_dib_ico(img, p, [16, 24, 32, 48])))

    # 2) 客户端界面顶栏：96px 供 34px 显示位在 HiDPI 下取样。
    p = os.path.join(ROOT, "app", "cmd", "client", "ui", "logo.png")
    img.resize((96, 96), Image.LANCZOS).save(p, format="PNG", optimize=True)
    targets.append((p, os.path.getsize(p)))

    # 3) Web 面板：浏览器加载，PIL 默认的 PNG 条目即可。
    web = os.path.join(ROOT, "internal", "web", "static", "images")
    p = os.path.join(web, "favicon.ico")
    img.save(p, format="ICO", sizes=[(16, 16), (32, 32), (48, 48)])
    targets.append((p, os.path.getsize(p)))

    p = os.path.join(web, "favicon_256x256.ico")
    img.resize((256, 256), Image.LANCZOS).save(p, format="ICO", sizes=[(256, 256)])
    targets.append((p, os.path.getsize(p)))

    p = os.path.join(web, "logo.png")
    img.save(p, format="PNG", optimize=True)
    targets.append((p, os.path.getsize(p)))

    for path, size in targets:
        print(f"  {os.path.relpath(path, ROOT)}  {size} bytes")
    print("\n完成。exe 资源图标还需重新生成 .syso，见 app/cmd/client/README.md。")


if __name__ == "__main__":
    main()
