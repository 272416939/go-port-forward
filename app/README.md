# Port Forward 隧道组件（pf-server / pf-client）

自研迷你加密隧道（UDP + PSK 握手 + X25519 密钥协商 + NaCl 每包加密），
为「中转 Linux VPS → 海外 Windows 游戏服务器」拓扑提供回程路径，配合
go-port-forward 的规则级**透明模式**实现后端零插件看到玩家真实 IP。

```
玩家P ──► [中转 Linux VPS]                        [Windows / BDS]
          go-port-forward（透明模式：                 ▲ pf-client
            源地址=P真实IP）──► 路由进 TUN ══加密隧道══╝ (10.66.0.2)
          pf-server (TUN 10.66.0.1)
          MASQUERADE：回包源改写为公网IP ──► 玩家P ◄──┘
```

## 构建（任意装有 Go 的机器）

```bash
bash app/build.sh            # 全部：app/bin/pf-server + pf-client.exe + wintun.dll
bash app/build.sh server     # 仅服务端
bash app/build.sh client     # 仅客户端
```

产物输出在 `app/bin/`。`pf-client.exe` 需与 `wintun.dll` 同目录分发
（WireGuard 官方签名 DLL，许可证允许随软件再分发），目标机器**无需 Go 环境**。

## 服务端（Linux 中转机，root）

```bash
sudo ./pf-server -c config.yaml     # 配置见 configs/server.example.yaml
```

- 自动完成：TUN(10.66.0.1/24)、ip_forward=1、隧道网段 MASQUERADE
- `sessions.url` 指向本机 go-port-forward（默认 `http://127.0.0.1:8989/api/sessions`，
  面板若启用 Basic Auth 请在配置中填写账号密码）
- 建议注册为 systemd 服务（`Restart=always`）

## 客户端（Windows 游戏服务器，管理员）

1. `pf-client.exe` 与 `wintun.dll` 放同一目录，右键"以管理员身份运行"
2. 按提示输入 **Port Forward 代理地址**（中转机 IP:7947，回车沿用上次）
3. 看到「✔ 隧道已建立」即可；Ctrl+C 自动清理回程路由并退出

回程路由为**动态 /32**：仅"正在经过中转的玩家 IP"走隧道返回，
Windows 机器的其它上网/RDP 流量完全不受影响。

## 与 go-port-forward 的配合

中转机上转发规则的目标地址填 **10.66.0.2:BDS端口**，并在规则上开启
**透明模式**（`transparent`，仅 Linux+root 可用）——转发器以玩家真实
IP:端口 为源地址经隧道送达 BDS，BDS 零插件看到真实玩家 IP。

排查清单：两端防火墙放行 UDP 7947；`ping 10.66.0.2`（中转机侧）验证隧道；
BDS 侧确认回程路由已下发（`route print 1.2.3.4`）；时钟偏差需小于 10 分钟。
