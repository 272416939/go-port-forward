# Go Port Forward

高性能跨平台 TCP/UDP/Both 端口转发工具，内置 Web 管理界面。

A high-performance cross-platform TCP/UDP port forwarder with a built-in Web UI.

## 源码地址 | Source Code

| 平台           | 地址                                           |
|--------------|----------------------------------------------|
| 🌐 Github 主站 | https://github.com/shibingli/go-port-forward |
| 🪞 Gitee 镜像站 | https://gitee.com/shibingli/go-port-forward  |

## 下载 | Download

[点击下载](https://github.com/shibingli/go-port-forward/releases)

## 📸 截图 | Screenshots

### 首页 | Dashboard
![首页](docs/images/首页.png)

### 转发列表 | Rule List
![转发列表](docs/images/转发列表.png)

### 添加转发 | Add Rule
![添加转发](docs/images/添加转发.png)

### WSL2 端口导入 | WSL2 Import
![WSL2导入](docs/images/WSL2导入.png)

### 诊断工具 | Diagnostics
![诊断工具](docs/images/诊断工具.png)

## ✨ 功能特性 | Features

- **TCP / UDP / Both** 端口转发，支持同时转发双协议
  Port forwarding with dual-protocol support
- **Web 管理界面** — 基于 Alpine.js + Bootstrap 5 的现代化单页应用
  Built-in Web UI — a modern SPA built with Alpine.js + Bootstrap 5
- **运行诊断面板** — 实时查看 runtime / goroutine pool / rule health / 热点规则，并支持一键定位异常规则
  Diagnostics panel — real-time runtime / goroutine pool / rule health / hot rules with one-click navigation to problematic rules
- **WSL2 端口导入** — 自动发现 WSL2 发行版监听端口并一键导入转发规则
  WSL2 port import — auto-discover listening ports in WSL2 distros and import forwarding rules in one click
- **跨平台防火墙管理** — Windows (netsh)、Linux (iptables)、macOS (pfctl) 自动添加/删除防火墙规则
  Cross-platform firewall management — automatically add/remove firewall rules on Windows (netsh), Linux (iptables), macOS (pfctl)
- **系统服务支持** — 可注册为 Windows Service / Linux systemd / macOS launchd 后台服务
  System service support — register as Windows Service / Linux systemd / macOS launchd
- **高性能并发** — 基于 [ants](https://github.com/panjf2000/ants) 协程池，支持高并发连接
  High-performance concurrency — powered by [ants](https://github.com/panjf2000/ants) goroutine pool
- **嵌入式存储** — 使用 [bbolt](https://go.etcd.io/bbolt) 嵌入式 KV 数据库，零依赖部署
  Embedded storage — [bbolt](https://go.etcd.io/bbolt) KV database, zero-dependency deployment
- **自动 GC 管理** — 内存阈值触发 + 定时 GC，多种回收策略可选
  Automatic GC management — memory-threshold-triggered + scheduled GC with multiple strategies
- **YAML 配置** — 首次运行自动生成默认配置文件
  YAML configuration — auto-generated default config on first run
- **真实 IP 透传（PROXY Protocol v2）** — 向目标服务器注入携带客户端真实 IP 的 PROXY v2 头（TCP 流首部 / UDP 会话首包）
  Real IP passthrough (PROXY Protocol v2) — prepends a PROXY v2 header carrying the real client IP toward the target (TCP stream prefix / UDP session first datagram)
- **访问控制** — 按 IP/CIDR 黑白名单、连接日志、活跃会话实时视图（TCP/UDP 通用）
  Access control — IP/CIDR black/whitelist, connection logs and a live session view (works for any TCP/UDP service)
- **隧道组件与透明模式** — 自研迷你加密隧道（app/，Linux 服务端 + Windows 客户端）配合规则级透明模式，跨公网实现后端零插件看到玩家真实 IP
  Tunnel app & transparent mode — a mini encrypted tunnel (app/) plus per-rule transparent mode delivers real client IPs across the public internet with zero backend plugins

## 🎯 痛点分析 | Pain Points

| 痛点 Pain Point | 传统方案 Traditional Approach | Go Port Forward 解决方式 Solution |
|----------------|---------------------------|-------------------------------|
| **WSL2 端口不可达** WSL2 ports unreachable | 每次重启后手动执行 `netsh interface portproxy` 命令，IP 地址经常变化 Manually run `netsh interface portproxy` after every reboot; IP changes frequently | 自动发现 WSL2 发行版 IP 与监听端口，一键导入转发规则，重启后自动恢复 Auto-discover WSL2 distro IPs & listening ports, one-click import, auto-restore on restart |
| **防火墙规则繁琐** Tedious firewall rules | 需要在 Windows/Linux/macOS 上分别记忆 netsh / iptables / pfctl 命令语法 Must memorize netsh / iptables / pfctl syntax for each OS | 跨平台统一 API，创建转发规则时自动添加防火墙放行，删除时自动清理 Unified cross-platform API; auto-add firewall allow on create, auto-clean on delete |
| **缺少可视化管理** No visual management | SSH 隧道、socat、rinetd 等工具均为命令行操作，难以一目了然查看所有规则状态 SSH tunnels, socat, rinetd are all CLI-only, hard to overview all rules | 内置 Web UI，实时查看规则状态、连接数与流量统计，支持增删改查与一键启停 Built-in Web UI with real-time rule status, connection count & traffic stats, full CRUD & one-click toggle |
| **进程退出规则丢失** Rules lost on exit | iptables 转发规则或 socat 进程重启后消失，需手写 systemd 脚本保持持久化 iptables rules or socat processes vanish on restart; requires manual systemd scripts | 基于 bbolt 嵌入式数据库持久化所有规则，服务启动时自动恢复所有活跃转发 All rules persisted in bbolt; active forwarders auto-restored on startup |
| **高并发性能不足** Poor concurrency | socat 每连接 fork 进程，rinetd 单线程阻塞模型，面对大量连接时资源消耗大 socat forks per connection, rinetd is single-threaded blocking | 基于 Go 协程 + ants 协程池，高并发连接下内存占用可控 Go goroutines + ants pool, controlled memory under high concurrency |
| **部署依赖复杂** Complex deployment | 需要安装 Python/Node.js 运行时或依赖外部数据库 Requires Python/Node.js runtime or external database | 单个二进制文件零依赖部署，内嵌 Web 资源与 KV 存储，开箱即用 Single binary, zero-dependency, embedded Web assets & KV store |
| **跨平台不统一** Inconsistent cross-platform | 不同工具在 Windows/Linux/macOS 上配置方式完全不同 Different tools have completely different configs on each OS | 同一份代码与配置，三大平台行为一致，支持注册为系统服务 Same code & config across all three platforms, supports system service registration |

## 🏗️ 应用场景 | Use Cases

### 1. WSL2 开发环境端口暴露 | WSL2 Dev Environment Port Exposure

在 Windows 上使用 WSL2 进行开发时，WSL2 内部的服务（如 Nginx、MySQL、Redis）默认无法被局域网其他设备访问。Go Port Forward 可自动发现 WSL2 中的监听端口并创建转发规则，让同事的手机或其他电脑直接访问你的开发环境。

When developing with WSL2 on Windows, services inside WSL2 (e.g., Nginx, MySQL, Redis) are not accessible from the LAN by default. Go Port Forward auto-discovers listening ports in WSL2 and creates forwarding rules so that colleagues' phones or other computers can directly access your dev environment.

### 2. 内网服务统一转发网关 | Intranet Unified Forwarding Gateway

在企业内网中，多台服务器上运行着不同端口的服务。通过在一台网关机器上部署 Go Port Forward，可将所有服务端口集中转发和管理，Web UI 提供清晰的规则总览与流量监控。

In an enterprise intranet, multiple servers run services on different ports. By deploying Go Port Forward on a gateway machine, you can centrally forward and manage all service ports, with the Web UI providing a clear rule overview and traffic monitoring.

### 3. 容器 / 虚拟机端口映射 | Container / VM Port Mapping

Docker 容器、VMware/VirtualBox 虚拟机的网络模式（NAT、Host-Only）经常导致端口不可达。使用 Go Port Forward 在宿主机上建立转发规则，无需修改容器或虚拟机网络配置即可对外提供服务。

Docker containers and VMware/VirtualBox VMs with NAT or Host-Only networking often have unreachable ports. Use Go Port Forward on the host to set up forwarding rules without modifying container or VM network configurations.

### 4. 远程调试与测试 | Remote Debugging & Testing

后端开发人员需要将本地运行的 API 服务暴露给前端/测试同事访问。通过 Go Port Forward 将 `127.0.0.1:3000` 转发到 `0.0.0.0:3000`，配合自动防火墙放行，一键完成端口对外开放。

Backend developers need to expose locally running API services to frontend/QA colleagues. Use Go Port Forward to forward `127.0.0.1:3000` to `0.0.0.0:3000` with automatic firewall allow rules — one click to open the port externally.

### 5. UDP 游戏/音视频服务转发 | UDP Game / Audio-Video Forwarding

游戏服务器、VoIP、视频流等场景需要 UDP 转发能力。Go Port Forward 同时支持 TCP 和 UDP 协议转发，并可选择 `both` 模式双协议同时转发，无需部署两套工具。

Game servers, VoIP, and video streaming scenarios require UDP forwarding. Go Port Forward supports both TCP and UDP forwarding, with a `both` mode for dual-protocol forwarding — no need to deploy two separate tools.

### 6. 轻量级生产环境端口网关 | Lightweight Production Port Gateway

在不需要 Nginx/HAProxy 完整反向代理功能的场景下（如纯 TCP 数据库代理、IoT 设备通信网关），Go Port Forward 可作为轻量级的四层端口网关，单二进制部署、资源占用极低。

When full Nginx/HAProxy reverse proxy features are not needed (e.g., pure TCP database proxy, IoT device communication gateway), Go Port Forward serves as a lightweight Layer-4 port gateway with single-binary deployment and minimal resource usage.

## 📦 项目结构 | Project Structure

```
go-port-forward/
├── main.go                  # 程序入口 | Entry point
├── config.yaml              # 配置文件 | Configuration
├── internal/
│   ├── config/              # 配置加载 (Viper) | Config loading
│   ├── firewall/            # 跨平台防火墙管理 | Cross-platform firewall
│   │   ├── firewall.go      # 接口定义 | Interface
│   │   ├── firewall_windows.go
│   │   ├── firewall_linux.go
│   │   └── firewall_darwin.go
│   ├── forward/             # 转发核心 | Forwarding core
│   │   ├── manager.go       # 规则生命周期管理 | Rule lifecycle
│   │   ├── tcp.go           # TCP 转发器 | TCP forwarder
│   │   └── udp.go           # UDP 转发器 | UDP forwarder
│   ├── logger/              # 日志初始化 | Logger init
│   ├── models/              # 数据模型 | Data models
│   ├── storage/             # bbolt 持久化 | bbolt persistence
│   ├── svc/                 # 系统服务封装 | System service wrapper
│   └── web/                 # Web 服务 + 嵌入式静态资源 | Web server + embedded static
│       ├── server.go
│       ├── handlers.go
│       ├── handlers_wsl.go
│       └── static/          # 前端资源 (Alpine.js, Bootstrap, HTMX)
├── pkg/
│   ├── gc/                  # GC 管理服务 | GC management
│   ├── pool/                # 协程池封装 (ants) | Goroutine pool
│   ├── retry/               # 重试机制 | Retry utilities
│   ├── logger/              # 全局日志桥接 | Global logger bridge
│   ├── serializer/          # JSON 序列化 (sonic/jsoniter) | JSON serialization
│   └── os/                  # OS 工具 (WSL 发现等) | OS utilities
└── data/
    └── rules.db             # bbolt 数据库文件 | Database file
```

## 🚀 快速开始 | Quick Start

### 编译 | Build

项目提供了跨平台构建脚本，支持一键编译所有平台（Windows / Linux / macOS，amd64 / arm64 / arm）并自动打包。

Cross-platform build scripts are provided for one-click compilation of all platforms (Windows / Linux / macOS, amd64 / arm64 / arm) with automatic packaging.

```bash
# Linux / macOS
bash build.sh              # 构建所有平台 | Build all platforms
bash build.sh windows      # 仅构建 Windows | Build Windows only
bash build.sh linux        # 仅构建 Linux | Build Linux only
bash build.sh darwin       # 仅构建 macOS | Build macOS only
```

```powershell
# Windows (PowerShell)
.\build.ps1                # 构建所有平台 | Build all platforms
.\build.ps1 -Target windows   # 仅构建 Windows | Build Windows only
.\build.ps1 -Target linux     # 仅构建 Linux | Build Linux only
.\build.ps1 -Target darwin    # 仅构建 macOS | Build macOS only
```

构建产物输出到 `dist/` 目录，包含可执行文件、配置示例和 SHA256 校验文件。

Build artifacts are output to the `dist/` directory, including executables, config samples, and SHA256 checksum files.

> 也可通过环境变量指定版本号 | You can also specify the version via environment variable: `VERSION=v1.0.0 bash build.sh`

### CI/CD 自动发布 | Automated Release

项目集成了 GitHub Actions，推送符合格式的 tag 后会自动触发全平台构建并创建 GitHub Release。

The project integrates GitHub Actions. Pushing a properly formatted tag automatically triggers cross-platform builds and creates a GitHub Release.

```bash
# 正式版本发布 | Stable release
git tag v1.0.0
git push origin v1.0.0

# 预发布版本（带后缀自动标记为 Pre-release）| Pre-release (suffix auto-marked as Pre-release)
git tag v1.0.0-beta.1
git push origin v1.0.0-beta.1
```

**触发规则 | Trigger rule:** tag 格式为 `v{major}.{minor}.{patch}` 或 `v{major}.{minor}.{patch}-{suffix}`。

**自动完成 | Automated steps:** 7 个平台产物编译 → 打包归档 → 生成 SHA256 校验 → 创建 Release 并上传。
7 platform artifacts compiled → archived → SHA256 checksums generated → Release created & uploaded.

### 运行 | Run

```bash
# 前台运行 | Foreground
./go-port-forward

# 指定配置文件 | With custom config
./go-port-forward -config /path/to/config.yaml
```

启动后访问 `http://127.0.0.1:8989` 打开 Web 管理界面。

After startup, visit `http://127.0.0.1:8989` to open the Web management UI.

### 系统服务 | System Service

```bash
# 安装为系统服务 | Install as system service
./go-port-forward -service install

# 以服务方式运行 | Run as service
./go-port-forward -service run

# 卸载服务 | Uninstall service
./go-port-forward -service uninstall
```

## ⚙️ 配置 | Configuration

首次运行时会在可执行文件同目录自动生成 `config.yaml`。

A default `config.yaml` is auto-generated in the same directory as the executable on first run.

```yaml
web:
  host: 127.0.0.1          # Web UI 监听地址 | Listen address
  port: 8989                # Web UI 端口 | Port
  # username: admin         # Basic Auth 用户名 (留空禁用) | Username (leave empty to disable)
  # password: secret        # Basic Auth 密码 | Password

storage:
  path: data/rules.db       # 数据库路径 | Database path

log:
  level: info               # 日志级别 | Log level: debug | info | warn | error
  path: logs/app.log        # 日志文件路径 | Log file path
  max_size_mb: 50           # 单文件最大 MB | Max size per file (MB)
  max_backups: 5            # 保留备份数 | Max backup count
  max_age_days: 30          # 保留天数 | Max retention days
  compress: true            # 压缩归档 | Compress archived logs

forward:
  buffer_size: 32768        # I/O 缓冲区大小 (bytes) | I/O buffer size
  dial_timeout: 10          # 出站连接超时 (秒) | Outbound dial timeout (seconds)
  udp_timeout: 30           # UDP 会话空闲超时 (秒) | UDP session idle timeout (seconds)
  pool_size: 0              # 协程池大小 (0 = 自动) | Goroutine pool size (0 = auto)

gc:
  enabled: true
  interval_seconds: 300     # GC 间隔 (秒) | GC interval (seconds)
  strategy: standard        # GC 策略 | GC strategy: standard | aggressive | conservative
  memory_threshold_mb: 100  # 内存阈值 (MB) | Memory threshold (MB)
  enable_monitoring: true
```

## 🩺 运行诊断 | Diagnostics

Web UI 右上角或侧边栏提供 **「运行诊断」** 入口，用于快速排查转发规则、资源占用和运行状态问题。

The **Diagnostics** entry is available in the top-right corner or sidebar of the Web UI for quickly troubleshooting forwarding rules, resource usage, and runtime status.

### 面板内容 | Panel Contents

- **Runtime**：goroutines、heap alloc / inuse、GC 次数与暂停时间、线程数量
  goroutines, heap alloc / inuse, GC count & pause time, thread count
- **Goroutine Pool**：运行中协程数、空闲数、容量
  Running goroutines, free count, capacity
- **Manager / Rule Health**：缓存规则数、活跃 forwarder 数、规则状态分布、总连接数与流量
  Cached rules, active forwarders, rule status distribution, total connections & traffic
- **协议统计 Protocol Stats**：分别展示 TCP / UDP 的规则数、活跃 forwarder、流量和连接数
  TCP / UDP rule count, active forwarders, traffic, and connections
- **热点规则 Hot Rules**：按活跃连接 / 流量 / 总连接综合排序的 Top 规则
  Top rules ranked by active connections / traffic / total connections
- **Top Active / Traffic / Error Rules**：分别按连接数、流量、错误次数拆分的榜单
  Leaderboards split by connection count, traffic, and error count
- **错误规则摘要 Error Rule Summary**：显示当前错误信息、错误次数、最近报错时间、最近状态变化时间
  Current error message, error count, last error time, last status change time

### 诊断交互能力 | Interactive Capabilities

- **自动刷新 Auto-refresh**：诊断弹窗打开后会自动轮询刷新，关闭后停止刷新
  Auto-polls while the diagnostics modal is open; stops when closed
- **手动刷新 Manual refresh**：支持按钮即时拉取最新 diagnostics 数据
  Button to instantly fetch the latest diagnostics data
- **规则 drill-down Rule drill-down**：点击热点规则或错误规则，可直接定位到规则表并打开对应规则编辑弹窗
  Click a hot rule or error rule to navigate to the rule table and open its edit modal
- **仅定位模式 Locate-only mode**：启用后点击诊断规则项只滚动并高亮对应规则，不自动打开编辑弹窗
  When enabled, clicking a diagnostic rule item only scrolls and highlights the rule without opening the edit modal
- **快照导出 Snapshot export**：支持 **复制 JSON** 与 **下载 JSON**，方便排障留档或提交 issue
  Supports **Copy JSON** and **Download JSON** for troubleshooting records or issue attachments

### diagnostics JSON 示例 | diagnostics JSON Example

实际返回值会随运行时状态变化，下面是一个精简示例。

The actual response varies with runtime state. Below is a simplified example:

```json
{
  "success": true,
  "data": {
    "timestamp": "2026-03-22T11:11:56+08:00",
    "runtime": { "goroutines": 12, "heap_alloc_bytes": 1766160 },
    "pool": { "running": 0, "free": 128, "cap": 128 },
    "manager": {
      "cached_rules": 2,
      "rule_health": { "active": 1, "inactive": 0, "error": 1 },
      "hot_rules": [
        { "id": "rule-1", "name": "api-tcp", "total_bytes": 1048576, "active_conns": 3 }
      ],
      "top_error_rules": [
        {
          "id": "rule-2",
          "name": "mysql-udp",
          "error": "dial tcp 127.0.0.1:3306: connectex: connection refused",
          "error_count": 4,
          "last_error_at": "2026-03-22T11:10:01+08:00",
          "last_status_change_at": "2026-03-22T11:10:01+08:00"
        }
      ],
      "errors": []
    }
  }
}
```

常用字段说明 | Common Fields：

- `runtime`：Go 运行时与 GC 快照 | Go runtime & GC snapshot
- `pool`：goroutine pool 的运行状态 | Goroutine pool status
- `manager.hot_rules`：综合热点规则 | Composite hot rules
- `manager.top_active_rules`：按活跃连接排序的规则榜单 | Rules ranked by active connections
- `manager.top_traffic_rules`：按总流量排序的规则榜单 | Rules ranked by total traffic
- `manager.top_error_rules`：按错误次数排序的规则榜单 | Rules ranked by error count
- `manager.errors`：当前处于错误状态的规则摘要 | Summary of rules currently in error state

### 适用场景 | When to Use

- 规则显示异常但不确定是配置问题、端口占用还是运行时错误
  A rule shows abnormal status but you're unsure if it's a config issue, port conflict, or runtime error
- 想快速判断当前瓶颈在连接数、流量还是错误热点
  You want to quickly identify whether the bottleneck is in connections, traffic, or error hotspots
- 需要导出一份运行快照给同事、测试或 issue 附件
  You need to export a runtime snapshot for colleagues, QA, or issue attachments

## 🌐 真实 IP 透传 | Real IP Passthrough (PROXY Protocol v2)

在“添加/编辑规则”对话框开启 **启用真实IP透传** 后，转发器会按 [PROXY Protocol v2](https://www.haproxy.org/download/3.4/doc/proxy-protocol.txt) 规范，把客户端真实地址编码进发往目标服务器的数据中：

With **Real IP Passthrough** enabled in the add/edit rule dialog, the forwarder encodes the client's real address into the data sent to the target server per the [PROXY Protocol v2](https://www.haproxy.org/download/3.4/doc/proxy-protocol.txt) spec:

| 协议 Protocol | 注入方式 Injection |
|--------------|-------------------|
| TCP | 建立到目标的连接后，先写入一次 PROXY v2 头，再开始双向数据转发 Written once to the target connection before relaying |
| UDP | 每个客户端会话的**首个数据报**与头合并为单个数据报发送，后续数据报原样透传 Header + payload sent as a single datagram on the first packet of each client session; subsequent datagrams pass through untouched |

### 注意事项 | Notes

- **目标服务器必须支持 PROXY Protocol v2**，否则会把头当作应用数据导致连接失败。例如 Minecraft 基岩版（BDS）需安装支持 PROXY Protocol 的插件（如 LL3 生态相关插件）后才可开启。
  **The target server must support PROXY Protocol v2**, otherwise it treats the header as application data and the connection fails. For example, Minecraft BDS requires a PROXY-Protocol-aware plugin before enabling this.
- 开关变更保存后会自动重启该规则的转发器生效。
  Saving the toggle automatically restarts the rule's forwarders to take effect.
- UDP 无连接，会话按“客户端地址”区分并带超时（默认 30s 空闲后重建，头随新会话重新发送）；理论上首包并发存在极小概率的乱序竞态，与同类实现（docker-proxy 等）行为一致。
  UDP is connectionless: sessions are keyed by client address with a timeout (default 30s idle; header is re-sent with a new session). A theoretical first-packet reordering race exists, consistent with similar implementations (docker-proxy, etc.).

## 🛡️ 访问控制与活跃会话 | Access Control & Active Sessions

侧边栏「访问控制」提供两块面板，所有变更实时生效（自动重载转发器内的匹配快照）：

The **Access Control** sidebar panel offers two tabs; every change takes effect immediately (compiled match snapshots are reloaded into live forwarders automatically):

| 面板 Panel | 能力 Capability |
|-----------|----------------|
| IP 黑白名单 | 添加单 IP 或 CIDR（IPv4/IPv6）的“拒绝/放行”条目，可作用于全部规则或单条规则。判定顺序：命中任一 deny → 拒绝；作用域内存在 allow 且未命中 → 隐式拒绝；否则放行。Add per-IP/CIDR deny/allow entries scoped to all or one rule. A hit on any Deny rejects; if scoped Allow entries exist and none match, access is implicitly denied. |
| 连接日志 | 记录加入/离开/拒绝事件（时间、协议、规则、来源、流量），保留条数由 `forward.connlog_max_entries` 控制（默认 2000），支持一键“封此 IP”。Join/leave/denied events with one-click IP ban actions. |

侧边栏「活跃会话」展示当前所有客户端会话（协议 / 来源 / 规则 / 建立时间 / 实时流量），TCP 与 UDP 通用，conntrack 风格；每 5 秒自动刷新。

The **Active Sessions** panel lists all current client sessions (protocol / source / rule / uptime / live traffic) for both TCP and UDP, conntrack style, auto-refreshed every 5 seconds.

## 🔍 真实 IP 方案调研结论 | Why Relay-side Control (Research Notes)

围绕“后端零改动拿到真实玩家 IP”做过系统调研，结论存档如下，避免重复踩坑：

- **透明代理（TPROXY / IP_TRANSPARENT 源地址伪装）**：受网络拓扑硬约束——后端回包必须原路经过转发机才能被改写回服务器地址，否则客户端直接丢弃。同机 / 可控内网 / WireGuard 隧道拓扑可行；跨公网两台独立 VPS（常见中转架构）物理上不可行，且伪装源地址还可能被运营商 uRPF 丢弃。
  Transparent proxying requires the backend's replies to route back through the forwarder. Feasible on the same host, a controlled LAN, or over a WireGuard tunnel; physically impossible across two unrelated public VPSes (and spoofed sources may be dropped by uRPF anyway).
- **基岩版（BDS）解析端生态**：BDS 原生不支持 PROXY Protocol；目前没有可用的主流解析插件（基岩主流代理 WaterdogPE 的真实 IP 下传仍是 open issue [#212](https://github.com/WaterdogPE/WaterdogPE/issues/212)）。成熟方案（frp / SakuraFrp / HAProxyDetector 等）均属 Java 版生态。
  Bedrock (BDS) has no native PROXY Protocol support and no mature parsing plugin exists today; the mature solutions all belong to the Java Edition ecosystem.
- 因此本项目把真实 IP 的价值放在**中转机侧变现**（本节访问控制/连接日志/会话视图），同时保留 PROXY v2 注入开关，供未来出现解析端、或后端本身支持该协议（Java 版/面板类）时直接使用。
  Hence this project realizes the value of real IPs relay-side (this section), while keeping the PROXY v2 injection toggle for future parsing-capable backends.

## 🌉 透明模式与隧道组件 | Transparent Mode & Tunnel App

上一节的结论是“跨公网独立 VPS 无法直接透明”。**隧道组件（`app/`）正是补齐这一前提的官方方案**：自研迷你加密隧道把两端“缝”成一个虚拟内网，随后规则级**透明模式**让后端零插件看到玩家真实 IP。

```
玩家P ──► [中转 Linux VPS]                          [Windows / BDS]
          go-port-forward（透明模式：                    ▲ pf-client
            源地址=P真实IP）──► 路由进 TUN ══加密隧道═════╝ (10.66.0.2)
          内置隧道服务端 (TUN 10.66.0.1)
          策略路由把回包交回透明 socket ──► 玩家P ◄──────┘
```

### 部署步骤 | Deployment

1. **构建**：`bash app/build.sh` → 产物在 `app/bin/`，只有两个文件：`pf-client.exe` + `wintun.dll`。
   客户端目标机**无需 Go 环境**，两个文件同目录分发即可。
   （中转机侧不需要单独进程，隧道服务端已内置在主程序里。）
2. **中转机（Linux，root）**：`config.yaml` 里开 `tunnel.enabled: true`，启动主程序即可；
   防火墙放行 UDP 7947。
3. **后端机（Windows）**：双击 `pf-client.exe` → 自动请求管理员权限 → 打开图形界面 →
   填中转机地址（IP:7947，会记住，下次自动连接）→ 自动创建虚拟网卡（10.66.0.2）
   并按会话动态维护回程路由。关闭窗口收进右下角托盘继续运行，托盘菜单可退出。
4. **go-port-forward**：添加/编辑规则，目标地址填 **10.66.0.2**（客户端虚拟 IP），开启 **透明模式** 开关。
   仅 Linux+root 可用；Windows 上该开关的规则会启动失败并给出明确原因（fail-closed）。

> `app/bin/pf-client.exe` 是唯一的正式客户端产物。若你直接跑过 `go build ./cmd/client/`，
> 包目录下会留一个同名程序，但它缺少 `-H=windowsgui`，运行时会多弹一个黑色控制台
> 窗口——那不是发布产物，`build.sh` 会自动清掉它。

### 回程路由原理（不影响其它流量）| Dynamic Return Routing

服务端每 10 秒把 go-port-forward 活跃会话的来源 IP 经加密控制通道推给客户端；
客户端另外在收到玩家入站包时即时补齐路由（探测器这类"一来一回"的交互等不到下一次推送）。
**只对这些 IP 添加 /32 路由**进隧道，空闲超过 5 分钟才回收。
Windows 机器的其它上网/RDP 流量、以及"通过后端公网 IP 直接访问"的流量完全不经过隧道。

### 注意事项 | Notes

- 透明模式与 PROXY 协议透传互斥（二选一）；两者都保留，按拓扑任选。
- 透明模式**仅支持 UDP 规则**（TCP 的回包无法送达透明 socket），协议含 TCP 时开关会被拒绝；UDP 场景（如基岩版 19132/58618）完全覆盖。
- 隧道为 UDP 传输（对游戏 UDP 最友好）；两端时钟偏差需 < 10 分钟；PSK 建议修改默认值。
- Windows 端需要管理员权限（wintun 驱动 + 路由管理），未提权时程序会主动弹 UAC。
- 客户端界面由系统自带的 Edge WebView2 渲染；Win11 与近年更新过的 Win10 均已预装，缺失时程序会给出下载指引。
- 服务端 `tunnel.enabled: true` 即随主程序常驻，自动配 ip_forward + 策略路由 + FORWARD/INPUT 放行，**不使用 MASQUERADE**（透明模式下正向首包走 OUTPUT 不匹配 NAT，conntrack 会判定整流不改写）。

### 排查清单 | Troubleshooting

| 现象 | 检查 |
|------|------|
| pf-client 一直握手失败 | 中转机 `tunnel.enabled` 是否开启、UDP 7947 是否放行、psk 是否与服务端一致 |
| 隧道已建立但业务不通 | 客户端界面「活跃玩家流量」是否出现玩家 IP，上下行字节是否同时增长；只有一个方向说明回程路由或策略路由有问题 |
| 规则开启透明模式变红 | 非 Linux 或非 root 运行（需 root 或给进程 CAP_NET_ADMIN） |
| 能进游戏但服务器列表探测失败 | 客户端版本过旧：入站首包即时补路由是后来才加的，旧版只靠 10 秒周期推送，短交互赶不上 |
| 中转机日志刷屏 | 例行推送已降为 debug；仍刷屏说明 `log.level` 设成了 debug |

## 🔌 REST API

| 方法 Method | 路径 Path | 描述 Description |
|----------|---------------------------|----------------|
| `GET`    | `/api/rules`              | 列出所有转发规则 List all forwarding rules |
| `POST`   | `/api/rules`              | 创建转发规则 Create a forwarding rule |
| `GET`    | `/api/rules/{id}`         | 获取单条规则 Get a single rule |
| `PUT`    | `/api/rules/{id}`         | 更新规则 Update a rule |
| `DELETE` | `/api/rules/{id}`         | 删除规则 Delete a rule |
| `PUT`    | `/api/rules/{id}/toggle`  | 启用/禁用规则 Enable/disable a rule |
| `GET`    | `/api/dashboard`          | 获取规则列表与聚合统计 Get rule list & aggregated stats |
| `GET`    | `/api/acl`                | 列出访问控制条目 List IP access-control entries |
| `POST`   | `/api/acl`                | 添加 IP 黑白名单条目 Add an IP allow/deny entry |
| `DELETE` | `/api/acl/{id}`           | 删除访问控制条目 Delete an access-control entry |
| `GET`    | `/api/logs`               | 查询连接日志 Query connection logs |
| `GET`    | `/api/sessions`           | 活跃会话（TCP/UDP 通用）Active client sessions |
| `GET`    | `/api/stats`              | 获取全局统计 Get global statistics |
| `GET`    | `/api/diagnostics`        | 获取运行诊断快照 Get runtime diagnostics snapshot |
| `GET`    | `/api/wsl/capability`     | 获取 WSL2 能力探测结果 Get WSL2 capability probe result |
| `GET`    | `/api/wsl/distros`        | 列出 WSL2 发行版 List WSL2 distros |
| `GET`    | `/api/wsl/ports/{distro}` | 列出发行版监听端口 List distro listening ports |
| `POST`   | `/api/wsl/import`         | 批量导入 WSL2 端口 Batch import WSL2 ports |

> 说明：WSL 相关接口仅在 Windows 上可用；在 Linux/macOS 上会返回 `501 Not Implemented`。
> Note: WSL-related APIs are only available on Windows; on Linux/macOS they return `501 Not Implemented`.

> 说明：`/api/diagnostics` 为只读诊断接口，适合接入前端面板、排障脚本或采样快照工具。
> Note: `/api/diagnostics` is a read-only diagnostic endpoint, suitable for frontend panels, troubleshooting scripts, or snapshot sampling tools.

## 📋 系统要求 | Requirements

- **Go** 1.26+
- **Windows** / **Linux** / **macOS**
- 防火墙管理需要管理员/root 权限 | Firewall management requires administrator/root privileges

## 📄 License

本项目基于 [Apache License 2.0](LICENSE) 许可证开源。

Licensed under the [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0).

