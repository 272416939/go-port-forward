# Port Forward 隧道客户端（pf-client）

自研迷你加密隧道（UDP + PSK 握手 + X25519 密钥协商 + NaCl 每包加密），
为「中转 Linux VPS → 海外 Windows 游戏服务器」拓扑提供回程路径，配合
go-port-forward 的规则级**透明模式**实现后端零插件看到玩家真实 IP。

```
玩家P ──► [中转 Linux VPS]                        [Windows / BDS]
          go-port-forward（透明模式：                 ▲ pf-client
            源地址=P真实IP）──► 路由进 TUN ══加密隧道══╝ (10.66.0.2)
          内置隧道服务端 (TUN 10.66.0.1)
          策略路由把回包交回透明 socket ──► 玩家P ◄──┘
```

隧道服务端已集成进 go-port-forward 主程序（`tunnel.enabled: true`），
**没有独立的服务端进程**，本目录只构建 Windows 客户端。

## 构建

```bash
bash app/build.sh
```

产物是 `app/bin/` 下的两个文件：`pf-client.exe` + `wintun.dll`
（后者是 WireGuard 官方签名 DLL，许可证允许随软件再分发）。两个文件同目录分发，
目标机器**无需 Go 环境**。

> 只有 `app/bin/pf-client.exe` 是正式产物。直接跑 `go build ./cmd/client/` 会在包目录
> 留一个同名程序，但它缺少 `-H=windowsgui`，运行时会多弹一个黑色控制台窗口。
> `build.sh` 每次都会清掉它，`.gitignore` 也拦着，别拿它去分发。

## 中转机（Linux，root）

在 go-port-forward 的 `config.yaml` 里开启：

```yaml
tunnel:
  enabled: true
  listen: ":7947"
  psk: "改掉默认值"
  nat: true        # 自动配 ip_forward + 策略路由 + FORWARD/INPUT 放行
```

启动主程序即可，防火墙放行 UDP 7947。注意这里**不使用 MASQUERADE**——透明模式下
正向首包走 OUTPUT 不匹配任何 NAT 规则，conntrack 会判定整条流不做 NAT，反向包即使
命中 MASQUERADE 也不会改写。回程靠 fwmark + 专用路由表把包交回透明 socket。

## 客户端（Windows 游戏服务器）

1. `pf-client.exe` 与 `wintun.dll` 放同一目录，双击运行
2. 程序自动请求管理员权限（虚拟网卡、路由表、防火墙规则都需要）
3. 界面里填中转机地址（`IP:7947`，会记住，下次启动自动连接）
4. 状态变「已连接」即可。关闭窗口会**收进右下角托盘继续运行**，托盘右键菜单可
   显示界面 / 断开连接 / 退出程序；只有「退出程序」才会清理路由与防火墙规则

界面是原生窗口，由系统自带的 Edge WebView2 渲染（Win11 与近年更新过的 Win10 均已
预装，缺失时程序会给出下载指引）。界面显示连接状态、双向字节数与实时速率、每个
玩家 IP 的流量，以及运行日志。

回程路由为**动态 /32**：只有正在经过中转的玩家 IP 走隧道返回，Windows 机器的其它
上网 / RDP 流量完全不受影响。路由在收到玩家入站包时即时安装（探测器这类"一来一回"
的交互等不到服务端的 10 秒周期推送），空闲超过 5 分钟才回收。

## 与 go-port-forward 的配合

中转机上转发规则的目标地址填 **10.66.0.2:BDS端口**，并在规则上开启**透明模式**
（`transparent`，仅 Linux+root 可用，且仅支持 UDP）——转发器以玩家真实 IP:端口
为源地址经隧道送达 BDS，BDS 零插件看到真实玩家 IP。

## 排查

| 现象 | 检查 |
|------|------|
| 握手一直失败 | 两端放行 UDP 7947；中转机 `tunnel.enabled` 是否开启；PSK 是否一致 |
| 隧道已连接但业务不通 | 界面「活跃玩家流量」是否出现玩家 IP，上下行字节是否**同时**增长；只有一个方向说明回程路径有问题 |
| 能进游戏但列表探测失败 | 客户端版本过旧（入站首包即时补路由是后来才加的） |
| 时间相关的握手失败 | 两端时钟偏差需小于 10 分钟 |

资源文件（图标）的生成方式见 [cmd/client/README.md](cmd/client/README.md)。
