# xSight 快速开始

本指南带第一次部署的运维人员从源码走到「controller 与 node 都在运行、能看到流量」。这是唯一的安装指南；检测与响应的细节见[用户指南](docs/user-guide.zh.md)，内部机制见[架构指南](docs/architecture.zh.md)。

xSight 由两个程序组成：

- **Controller**——中心服务：Web UI、REST API、接收 node 的 gRPC 上报、检测、攻击跟踪与响应动作。数据存放在带 TimescaleDB 的 PostgreSQL 中。
- **Node**——部署在每个观测点的代理，二选一的模式：
  - **XDP 模式**——eBPF/XDP 程序在镜像（SPAN）或 ERSPAN 接口上计数报文。
  - **Flow 模式**——接收路由器、交换机发来的 sFlow / NetFlow v5 / NetFlow v9 / IPFIX。

步骤顺序：前置条件 → 构建 → 数据库 → controller 首次启动 → 注册节点 → node 配置与启动 → 验证 → 让 xDrop 动作执行（`auto`）。

示例使用文档专用地址：controller 为 `192.0.2.10`，被监控网络为 `198.51.100.0/24` 和 `2001:db8::/32`。

---

## 1. 前置条件

| 项目 | 要求 |
|---|---|
| CPU 架构（node，XDP 模式） | 仅 x86_64：BPF 绑定由 `bpf2go -target amd64` 生成 |
| Linux 内核（node，XDP 模式） | 5.18 及以上，且带 BTF（存在 `/sys/kernel/btf/vmlinux`）。XDP 程序使用 `bpf_xdp_load_bytes` 辅助函数。已在 Debian 13、内核 6.12 上验证。 |
| Go | 1.25 及以上（controller 模块要求 1.25，node 模块要求 1.24） |
| Node.js | 22.12+（构建）；跑控制台测试需 22.22.2+ 或 24.15+ |
| BPF 构建工具（node） | `clang`、`llvm`、libbpf 头文件和 `bpftool`（Debian 包名：`clang llvm libbpf-dev bpftool`） |
| 数据库 | PostgreSQL 15+，配合 TimescaleDB 2.x 扩展。**不支持** SQLite：`driver: sqlite` 能通过配置校验，但 controller 启动即以 `SQLite driver not yet implemented` 退出。 |
| 权限（node） | root。挂载 XDP 需要 `CAP_NET_ADMIN` 和 `CAP_BPF`；`scripts/node.sh` 在两种模式下都要求 root，否则拒绝启动。 |
| 可选 | BGP 动作需要带 `bgpd` 的 FRR；xDrop 动作需要 XDrop v3 |

两种模式下 node 都是 Linux 程序。Flow 模式不挂载 XDP，但 node 仍然引用 BPF 包，所以在 Linux 上构建 node 时，即使只用 Flow 模式也需要先生成 BPF 绑定（见 §2.2）。

---

## 2. 构建

### 2.1 Controller

Web UI 嵌入在 controller 二进制里（`//go:embed all:console/dist`），所以要先构建前端；没有 `controller/console/dist` 时 `go build` 会失败。

```bash
cd controller/console
npm ci
npm run build
cd ..
go build -o bin/xsight-controller .
cd ..
```

非 git 检出环境须在 `npm run build` 前设置 `XSIGHT_VERSION`；`./scripts/build-controller.sh` 先构建控制台，再用 `-buildvcs=false -trimpath` 编译 Go，并在无法取得 Git 版本时使用 `unknown`。

### 2.2 Node

BPF 程序引用的 `vmlinux.h` 已随仓库提供（在 Debian 13 / kernel 6.12 上生成）。仅当在带 BTF 的不同内核上编译时才需重新生成，然后再生成 Go 绑定并编译：

```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > node/bpf/vmlinux.h

cd node
go generate ./internal/bpf/    # bpf2go：编译 bpf/xsight.c，生成 internal/bpf/xsight_x86_bpfel.*
go build -o bin/xsight-node .
cd ..
```

在 `node/` 下执行 `make build` 会先跑 `go generate` 再 `go build`。`./scripts/build-node.sh` 做同样的事，并检查是否在装有 clang 的 Linux 上运行。

**两种模式**都要在 Linux 上执行以上步骤。缺少生成文件时 Linux 构建会失败，因为只在 Linux 下编译的 `internal/bpf/loader.go` 引用了它们。只有非 Linux 构建（例如在 macOS 上做开发）才使用桩代码、跳过 BPF。

---

## 3. 数据库

用发行版或 Timescale 官方的软件包安装 PostgreSQL 和 TimescaleDB，然后创建用户、数据库和扩展：

```bash
sudo -u postgres psql -c "CREATE USER xsight WITH PASSWORD 'YOUR_DB_PASSWORD';"
sudo -u postgres createdb -O xsight xsight
sudo -u postgres psql -d xsight -c "CREATE EXTENSION IF NOT EXISTS timescaledb;"
```

请按上面的方式由 `postgres` 超级用户创建扩展。controller 启动时也会执行 `CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE`；若失败，会记录 `WARNING: TimescaleDB not available` 并退回普通表继续运行，这不是受支持的部署方式。

表、hypertable、压缩策略和保留策略都在 controller 首次启动时自动创建。`xsight-controller -config <文件> -migrate` 只执行迁移然后退出。

**可选的 PostgreSQL 调优。** xSight 持续写入时序数据。对专用数据库主机，下列 `postgresql.conf` 设置可以降低写入负担（内存值按主机调整）：

```ini
synchronous_commit = off      # 崩溃时可能丢失最后片刻的统计数据
shared_buffers = 4GB          # 约为内存的 25%
effective_cache_size = 12GB   # 约为内存的 75%
wal_buffers = 64MB
max_wal_size = 4GB
min_wal_size = 1GB
wal_compression = on
wal_level = minimal           # 仅在不对此库做复制时使用
max_wal_senders = 0           # 与 wal_level = minimal 配套必需
```

修改后重启 PostgreSQL。

---

## 4. Controller：配置与首次启动

```bash
cp controller/config.example.yaml controller/config.yaml
```

至少修改以下键：

```yaml
database:
  driver: "postgres"
  dsn: "postgres://xsight:YOUR_DB_PASSWORD@localhost:5432/xsight?sslmode=disable"

auth:
  api_key: "REPLACE_WITH_RANDOM_SECRET"        # 例如 openssl rand -hex 32
  initial_admin_password: "REPLACE_WITH_STRONG_PASSWORD"

action_engine:
  mode: "observe"        # 缺省值：xDrop 动作只记为跳过；见 §8
```

| 键 | 必填 | 规则 |
|---|---|---|
| `database.dsn` | 是 | 不能为空 |
| `auth.api_key` | 是 | 不能为空或 `CHANGE_ME`。它是 REST API 密钥（请求头 `X-API-Key`，拥有完整管理员权限），同时是会话签名密钥的来源，修改它会让所有用户退出登录。 |
| `auth.initial_admin_password` | 首次启动时 | 8–72 字节，且不能是 `admin`。用户表为空且未设置此项时，controller 拒绝启动（`no users exist; set auth.initial_admin_password to create the first admin`）；设置后，controller 用此密码创建用户 **`admin`**。首次启动成功后删除此键。 |
| `listen.http` / `listen.grpc` | 否 | 缺省 `:8080`（Web UI + REST API + `/metrics`）和 `:50051`（node gRPC） |

升级旧数据库：若仍有管理员角色账号使用旧的默认密码，启动会被拒绝，直到设置了 `auth.initial_admin_password`；设置后 controller 替换该密码。这类升级之后所有用户都需要重新登录。

未知或拼错的键会被静默忽略、没有任何警告，请仔细核对拼写。完整键列表见 `controller/config.example.yaml`。

启动 controller：

```bash
./controller/bin/xsight-controller -config controller/config.yaml
```

启动成功会记录 `xsight-controller running (mode=observe)`。打开 `http://192.0.2.10:8080`，用 `admin` 和配置的密码登录。

---

## 5. 在 Web UI 中注册节点

controller 只接受事先注册过的节点。在 Web UI 打开 **节点 → 添加节点**，填写：

- **节点 ID**——唯一名称，例如 `node-a`。
- **API 密钥**——该节点专用的密钥（例如 `openssl rand -hex 32`）。它**不是** controller 的 `auth.api_key`。
- **模式**——XDP 或 Flow（节点连接时会上报自己的实际模式）。

---

## 6. Node：配置与启动

```bash
cp node/config.example.yaml node/config.yaml
```

XDP 模式：

```yaml
node_id: "node-a"                 # 与 §5 注册的 Node ID 完全一致
interfaces:
  - name: "eth1"                  # 镜像 / ERSPAN 接口
    mode: "mirror"                # mirror | erspan
controller:
  address: "192.0.2.10:50051"
auth:
  node_api_key: "THE_KEY_REGISTERED_FOR_node-a"
```

Flow 模式：

```yaml
node_id: "node-b"
mode: "flow"                      # 不写 = xdp
controller:
  address: "192.0.2.10:50051"
auth:
  node_api_key: "THE_KEY_REGISTERED_FOR_node-b"
```

`auth.node_api_key` 必须等于为该 `node_id` 注册的 API Key。否则 controller 以 `node not found` 或 `invalid api_key` 拒绝握手，node 记录 `reporter: handshake rejected: ...` 并不断重试。

以 root 启动 node：

```bash
sudo ./node/bin/xsight-node -config node/config.yaml
# 或：sudo ./scripts/node.sh start
```

Flow 节点在 Web UI 里为它添加 Listener 和数据源（**Flow** 页）之前收不到任何数据；见用户指南。

---

## 7. 验证

1. node 日志出现 `reporter: handshake accepted`。
2. **节点** 页显示该节点 **在线**（最近 10 秒内收到过上报）。
3. 添加一个监控前缀（**前缀 → 添加前缀**，例如 `198.51.100.0/24`）。controller 把它推送给节点；**节点** 页的配置状态显示为已同步。
4. 几秒内 **流量** 和 **总览** 显示该前缀的流量。
5. 可选的 API 检查：`curl -H "X-API-Key: YOUR_API_KEY" http://192.0.2.10:8080/api/stats/summary` 返回 JSON。
6. 可选的指标检查：`curl -s http://192.0.2.10:8080/metrics | grep ^xsight_`。`/metrics` 没有认证，请在网络层限制 8080 端口。

要检测攻击，还需要给前缀绑定阈值模板；用户指南的快速上手一节逐步说明。

---

## 8. 让 xDrop 动作执行（`observe` → `auto`）

`action_engine.mode` 缺省为 `observe`，它**只管 xDrop 动作**。在 `observe` 下，BGP、Webhook、Shell 动作**照常执行**；所有 xDrop 动作都被跳过并以 `skip_reason=mode_observe` 记录，不会创建任何 XDrop 规则。用真实流量核对检测效果期间保持 `observe`（BGP 动作只在你希望它执行时再绑定）。要让 xDrop 动作真正下发规则，设置：

```yaml
action_engine:
  mode: "auto"
```

并重启 controller。Web UI 中的人工强制移除（Force Remove）在两种模式下都可用。

---

## 9. 以服务方式运行（systemd）

`deploy/` 下有 unit 模板。它们假定目录布局为 `/opt/xsight/controller/` 和 `/opt/xsight/node/`（二进制在 `bin/`，`config.yaml` 在旁边）；布局不同时修改 `ExecStart` 和 `WorkingDirectory`。

```bash
# controller 的 unit 以用户 xsight 运行，只有 /opt/xsight/controller 可写。
sudo useradd --system --home /opt/xsight --shell /usr/sbin/nologin xsight
sudo cp deploy/xsight-controller.service deploy/xsight-node.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now xsight-controller
sudo systemctl enable --now xsight-node      # 以 root 运行，LimitMEMLOCK=infinity
```

日志写入 journal：`journalctl -u xsight-controller -f`、`journalctl -u xsight-node -f`。

若使用 BGP 动作，controller 的运行用户必须有权执行 `vtysh`（路径在每个 BGP 连接器里设置，缺省 `/usr/bin/vtysh`）。

---

## 10. 网络与安全提示

| 端口 | 谁来连接 | 说明 |
|---|---|---|
| TCP 8080 | 浏览器、API 客户端、Prometheus | Web UI、REST API、无认证的 `/metrics` |
| TCP 50051 | 各 node | node gRPC。默认明文——在两端设置 `tls.enabled: true` 可升级为 TLS 1.3 双向认证 mTLS，节点身份来自证书（见 [docs/MTLS.md](docs/MTLS.md)）。不启用 TLS 时只能在可信网络内或 VPN / 隧道中使用。 |
| 127.0.0.1:6060 | 仅本机 | controller 的 pprof，始终开启 |
| 127.0.0.1:6061 | 仅本机 | node 的 pprof，仅在 `pprof: true` 时开启 |

---

## 11. 快速排障

| 现象 | 可能原因 |
|---|---|
| 构建 controller 时 `go build` 报 `pattern all:console/dist: no matching files found` | 先构建 Web UI（§2.1） |
| `go generate` 找不到 `vmlinux.h` | 用 `bpftool` 生成（§2.2） |
| `go generate` 找不到 `bpf/bpf_helpers.h` | 安装 libbpf 头文件（`libbpf-dev`） |
| 在 Linux 上构建 node 报未定义 `xsightObjects` / `loadXsight` | 没有执行 `go generate ./internal/bpf/`（Flow 模式也需要） |
| controller 退出：`auth.api_key is empty or still the default "CHANGE_ME"` | 设置唯一的 `auth.api_key` |
| controller 退出：`initial admin: no users exist; ...` | 设置 `auth.initial_admin_password`（§4） |
| controller 退出：`SQLite driver not yet implemented` | 改用 PostgreSQL |
| node：`Failed to load BPF` / `Failed to attach XDP to <iface>` | 不是 root、内核低于 5.18，或接口名错误 |
| node：`handshake rejected: node not found` / `invalid api_key` / `node disabled` | 注册节点；使用该节点自己的密钥；启用节点（§5、§6） |
| node 连不上 controller | 检查 `controller.address`，以及 TCP 50051 是否放通 |

更多现象见用户指南的排障一章。
