# xSight Node

xSight DDoS 检测系统的数据平面代理。Node 通过 XDP/eBPF 从镜像/ERSPAN 端口抓包，或接收 sFlow/NetFlow/IPFIX 流数据，将聚合统计信息通过 gRPC 上报给 Controller。

## 双模式架构

### XDP 模式（默认）

将 XDP/eBPF 程序挂载到镜像或 ERSPAN 接口上，在内核中以线速捕获数据包。BPF 程序解析每个数据包，按解码器类型分类，更新 per-IP 和 per-prefix 统计 map，并将采样包发送到用户态 ring buffer。

**XDP 处理流程：**

```
数据包进入（mirror/ERSPAN）
  -> 解析 Ethernet/IP/Transport 头部
  -> 提取五元组（src_ip, dst_ip, src_port, dst_port, protocol）
  -> 分类解码器（TCP / TCP_SYN / UDP / ICMP / FRAG / ...）
  -> LPM trie 查找（watch_trie_a/b）：匹配 dst_ip（入向）/ src_ip（出向）
  -> 更新 ip_stats_a/b 或 src_stats_a/b（per-IP 计数器）
  -> 更新 prefix_stats_map / src_prefix_stats_map（per-prefix 计数器）
  -> 更新 global_stats（全局计数器）
  -> 概率采样 -> ring buffer (samples)
  -> XDP_DROP（镜像口，不转发；ARP/NDP 例外见下）
```

ARP 和 IPv6 NDP（ICMPv6 133–137，含单层 VLAN）走 `XDP_PASS`。

**BPF Maps：**

| Map | 类型 | 说明 |
|-----|------|------|
| `global_stats` | Array | 全局统计：total_pkts, total_bytes, matched_pkts, matched_bytes, 各解码器细分（入向与出向） |
| `watch_trie_a` / `watch_trie_b` | LPM Trie | Controller 下发的前缀列表。A/B 成对：新列表先写入非活动一侧再切换。用于快速路径中 dst_ip / src_ip 匹配 |
| `prefix_stats_map` | Hash | 按前缀的入向统计：pkt_count, byte_count, 解码器计数, active_ips, overflow_count |
| `ip_stats_a` / `ip_stats_b` | Hash | 按目的 IP 的入向统计（大小由 `bpf.max_entries` 决定）。A/B 成对，与 watch trie 一起切换 |
| `src_stats_a` / `src_stats_b` | Hash | 按源 IP 的出向统计，A/B 成对，同 `ip_stats_*` |
| `src_prefix_stats_map` | Hash | 按前缀的出向统计 |
| `active_slot` | Array | 当前生效的是哪一组 A/B（trie 与 IP map） |
| `xsight_config` | Array | 用户态写入的运行时设置（如采样率） |
| `samples` | Ring buffer（`BPF_MAP_TYPE_RINGBUF`） | 采样包头，发送到用户态 |

### Flow 模式

通过 UDP 接收 sFlow、NetFlow v5/v9 或 IPFIX 流记录，使用 [goflow2](https://github.com/netsampler/goflow2) 解码。Node 解码流协议消息，提取五元组 + TCP flags，按解码器类型分类，聚合 per-IP 统计后上报给 Controller。

**Flow 处理流程：**

```
流记录进入（sFlow/NetFlow/IPFIX over UDP）
  -> goflow2 自动检测协议 + 解码
  -> 从 FlowMessage 提取五元组 + TCP flags
  -> 分类解码器（TCP / TCP_SYN / UDP / ICMP / FRAG / ...）
  -> 前缀 trie 查找：将 dst_ip（入向）/ src_ip（出向）与 watch_prefixes 匹配
  -> 聚合到 per-IP + per-prefix 统计（RecordTable）
  -> 每 1 秒：刷新统计 -> gRPC StatsReport
```

在 Controller Web UI 的「检测 → Flow」页（「Flow 配置」）用「添加 Listener」和「添加数据源」配置采集，需要 admin；不在本地配置文件设置。

## gRPC 数据流

Node 是 **gRPC 客户端**，主动连接 Controller。不暴露 REST API；除可选 pprof 外，Flow 模式还按 controller 下发的配置绑定 UDP Flow 监听端口。实际使用三条数据流；`CriticalEventStream` 在协议中保留但不打开：

| 数据流 | 方向 | 频率 | 用途 |
|--------|------|------|------|
| `StatsStream` | Node -> Controller | 1 秒 | 聚合的 per-IP/prefix 统计、健康指标、Top 流 |
| `SampleStream` | Node -> Controller | 批量发送 | BPF ring buffer 中的原始包头采样（仅 XDP 模式） |
| `CriticalEventStream` | Node -> Controller | — | 保留，未使用。Node 从不打开 |
| `ControlStream` | 双向 | 按需 | Controller 下发 WatchConfig（前缀列表、Flow 监听器配置；硬阈值只保存不使用）；Node 以 delivery_version 确认 |

完整 gRPC 消息类型文档见 [API.zh.md](API.zh.md)。

**安全：** gRPC 链路为明文，且某节点首次握手成功后，Controller 按每条消息里的 `node_id` 接收统计，因此 Node 与 Controller 只应部署在可信网络内或加密隧道中。详见 [API.zh.md — 安全说明](API.zh.md#安全说明)。

## 编译

两种模式的 Node 都按 **Linux x86_64** 编译（bpf2go 以 `-target amd64` 运行）。要求：

- 运行 XDP 模式需要 Linux 5.18+（XDP 程序使用 `bpf_xdp_load_bytes`）；在 Debian 13 / kernel 6.12 上验证
- Go 1.24+、`clang`、`llvm-strip`、`bpftool` 与 libbpf 头文件（如 `libbpf-dev`）
- `bpf/vmlinux.h` — 已随仓库提供（在 Debian 13 / kernel 6.12 上生成）。仅当在带 BTF 的不同内核上编译时才需要重新生成：

```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h
```

然后：

```bash
# 生成 BPF Go 绑定（bpf2go）
go generate ./internal/bpf/

# 编译二进制
go build -o bin/xsight-node .
```

或使用 Makefile：

```bash
make all        # generate + build
make generate   # 仅 bpf2go
make build      # generate + go build
make clean      # 清理构建产物
```

### Flow 模式

Flow 模式使用同一个二进制，而 Linux 构建总会编译 BPF 加载器，因此为 Flow 模式编译 Linux 二进制同样需要 `go generate` 和上述工具链，从 macOS 交叉编译也一样。只有在非 Linux 平台本机编译（例如在 macOS 上开发）时才会用桩文件 `internal/bpf/stub_notlinux.go`、跳过 BPF 生成。

## 配置

同一节点的所有 XDP 接口在补齐缺省值后，`mode`、`sample_bytes` 和
`upstream_sample_rate` 必须完全相同。异构设置在启动及重载时均会被拒绝；
不同设置请使用独立节点。`sample_bytes` 可以省略，缺省值为 256。

XDP 模式下，SIGHUP 可热改 `sample_bytes` 和 `upstream_sample_rate`。新上游
倍率绑定到后续采集拍；已排队的报告保留各自拍的倍率。样本批次跟随 reporter
最近处理的 Stats 报告。修改接口 mode、网卡集合或名称、采集模式（`xdp`/`flow`）、
`node_id`、controller 地址、`parse_workers`、`bpf.max_entries`、
`auth.node_api_key` 或 `pprof` 都需要重启。SIGHUP 改 mode 会被拒绝。
网卡集合和名称的变化不会被应用：追加同构网卡后，HUP 可能报告重载成功，
但不会为新增网卡挂载 XDP。

flow 模式节点收到 SIGHUP 会直接退出，不支持此重载路径。随附 systemd unit
使用 `Restart=on-failure`，不会在 SIGHUP 导致退出后拉起节点。
修改 flow 模式配置后，请显式重启服务。

`erspan` 模式下，ERSPAN Type II 样本按解封装后的第一层 IP 归属，包括外层 IPv4、
内层 IPv6 的情况。Type I、Type III 的样本归属尚未验证。采集 mode 在进程生命期内固定。

首次启动前，先在 Controller 上注册该节点（Web UI **节点 → 添加节点** 或 `POST /api/nodes`；Flow 节点模式须选 Flow），填写 `node_id` 和一个 API 密钥。`auth.node_api_key` 必须就是这个密钥；它不是 Controller REST 接口的 `auth.api_key`。未注册的节点以 `node not found` 被拒，密钥不符以 `invalid api_key` 被拒。

XDP 模式下，超过 32 核的主机须显式设置 `parse_workers`（1–16）。

复制 `config.example.yaml` 并编辑：

```yaml
# XDP 模式（默认）
mode: xdp
node_id: "my-node-01"

interfaces:
  - name: "eth1"
    mode: "mirror"              # mirror | erspan
    upstream_sample_rate: 1     # 1 = 无上游采样
    sample_bytes: 128           # 捕获长度（128-512）

bpf:
  max_entries: 1000000          # ip_stats map 大小

controller:
  address: "controller:50051"

auth:
  node_api_key: "CHANGE_ME"    # Controller 上为该 node_id 注册的密钥

# 可选调优（仅 xdp 模式）
# parse_workers: 4             # 默认 = NumCPU/2，范围 1-16
# pprof: false                 # pprof 监听 127.0.0.1:6061
```

```yaml
# Flow 模式
mode: flow
node_id: "my-flow-node-01"

controller:
  address: "controller:50051"

auth:
  node_api_key: "CHANGE_ME"
```

Flow 模式下不需要 `interfaces` 和 `bpf` 配置段。Listener 和数据源由 admin 在「检测 → Flow」页管理，经 `ControlStream` 下发到 Node。

## 权限要求

- **XDP 模式**需要 root 或 `CAP_BPF` + `CAP_NET_ADMIN` 权限。BPF 程序需挂载到网络接口。
- **Flow 模式**需要 UDP 端口绑定权限（绑定 < 1024 的特权端口时需额外权限）。注意 `scripts/node.sh` 在两种模式下都要求 root；不想用 root 可直接运行二进制。

## 目录结构

```
node/
  main.go                     # XDP 模式入口
  flow_main.go                # Flow 模式入口
  config.example.yaml
  Makefile
  bpf/
    xsight.c                  # XDP/eBPF C 程序
    xsight.h                  # BPF 结构体定义
  internal/
    bpf/                      # BPF 加载器、Go 类型映射、bpf2go 生成代码
      gen.go                  # go:generate 指令（bpf2go）
      loader.go               # 加载 + 挂载 XDP 程序，map 操作
      types.go                # 映射 BPF C 结构体的 Go 类型
      stub_notlinux.go        # 非 Linux 平台编译桩
    config/                   # YAML 配置加载 + 校验
      config.go               # Config 结构体、Load()、validate()
      snapshot.go             # WatchConfig 快照持久化（重启恢复）
    collector/                # 定时读取 BPF map（XDP 模式）
      collector.go            # 每秒读取当前生效的统计 map 与 global_stats
    sampler/                  # 包采样流水线（XDP 模式）
      sampler.go              # BPF ring buffer 读取器
      batcher.go              # 批量打包样本用于 gRPC SampleStream
      packet.go               # 包头解析器（五元组提取）
      flowtable.go            # 每 tick 的 Top-N 流跟踪
      worker_pool.go          # 并行包解析工作池
    flow/                     # Flow 接收流水线（Flow 模式）
      listener.go             # 使用 goflow2 的 UDP 监听器
      decoder.go              # FlowMessage -> 五元组 + 解码器分类
      aggregator.go           # Per-IP/prefix 统计聚合 + 1 秒刷新
      record.go               # 流记录类型
      recordtable.go          # Per-IP 记录表（聚合用）
      prefixtrie.go           # 内存中的前缀 trie（watch_prefixes 匹配）
    reporter/                 # gRPC 客户端：握手 + 数据流
      reporter.go             # 流生命周期管理、重连、退避
      convert.go              # Collector Report -> protobuf StatsReport 转换
    watchdog/                 # 健康监控
      watchdog.go             # 检测降级状态（ring 溢出、map 满）
    pb/                       # 生成的 protobuf + gRPC 桩代码
      xsight.pb.go
      xsight_grpc.pb.go
```
