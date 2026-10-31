# xSight Node gRPC 接口文档

Node **不**对外暴露 REST API。它是 gRPC **客户端**，主动连接 Controller 的 gRPC 服务（默认端口 50051）。所有通信通过 `xsight.proto` 中定义的 `XSightService` 进行。

## 服务：`xsight.XSightService`

### RPC 列表

| RPC | 类型 | 方向 | 说明 |
|-----|------|------|------|
| `Handshake` | 一元调用 | Node -> Controller | 初始认证与配置交换 |
| `StatsStream` | 客户端流 | Node -> Controller | 周期性聚合流量统计 |
| `SampleStream` | 客户端流 | Node -> Controller | BPF ring buffer 中的包头采样 |
| `CriticalEventStream` | 客户端流 | Node -> Controller | 保留；当前 Node 不打开（见第 4 节） |
| `ControlStream` | 双向流 | Node <-> Controller | 配置下发/确认通道 |

---

## 1. Handshake（一元调用）

TCP 连接建立后的第一个调用。Node 进行身份认证并上报自身信息。Controller 返回接受状态和当前 `WatchConfig`。

**请求：`NodeHandshake`**

| 字段 | 类型 | 说明 |
|------|------|------|
| `node_id` | string | 唯一节点标识（来自 config.yaml） |
| `api_key` | string | 认证密钥（来自 config.yaml `auth.node_api_key`） |
| `interfaces` | string[] | 正在监控的接口名称列表 |
| `agent_version` | string | 按模式固定的字符串：XDP 为 `0.7.0`，Flow 为 `3.0.0`；不是发行版本号，controller 不使用该字段 |
| `delivery_version_applied` | uint64 | 本地快照中最后应用的配置版本（0 = 无） |
| `mode` | string | `"xdp"` 或 `"flow"` |

**响应：`HandshakeResponse`**

| 字段 | 类型 | 说明 |
|------|------|------|
| `accepted` | bool | Controller 是否接受此节点 |
| `reject_reason` | string | 拒绝原因（接受时为空） |
| `watch_config` | WatchConfig | 初始配置 |
| `delivery_version_current` | uint64 | Controller 上的当前配置版本 |

接受时 Controller 总是返回当前完整的 `watch_config`，与 `delivery_version_applied` 无关。全局前缀（IPv4 与 IPv6 缺省路由）从不下发给 Node。若该节点在 Controller 上的 `delivery_version_current` 仍为 0，先把它追平到全体节点中的最大版本。

拒绝原因（`accepted=false`）：`node not found`（`node_id` 未注册）、`invalid api_key`（密钥与该节点注册时的不一致）、`node disabled`、`invalid mode: ...`、`internal error: ...`。

---

## 2. StatsStream（客户端流）

Node 名义上每秒发送一条 `StatsReport` 消息；覆盖更长采集拍的那份上报带的是每秒均值。flow 模式下，连接期间若至少 1 秒没发过、也没有待发的上报，Node 发一份心跳 `StatsReport`，只带身份、`health` 和 `sampling_metrics`（无 `global_stats`，无 IP / 前缀条目）；断连期间不发。Controller 使用这些数据进行 DDoS 检测（基线比较、阈值评估、异常检测）。

**消息：`StatsReport`**

| 字段 | 类型 | 说明 |
|------|------|------|
| `node_id` | string | 节点标识 |
| `interface_name` | string | 来源接口名称 |
| `upstream_sample_rate` | uint32 | 该拍采集时生效的上游倍率（1 = 无采样） |
| `local_sample_rate` | uint32 | Node 最近一次成功写进 BPF map 的采样率（通常即实际生效值；若复用已有 BPF map 时启动复位为 1 失败，可能与实际生效值不符） |
| `timestamp` | int64 | Unix 时间戳（秒） |
| `ip_stats` | IPStats[] | 按目的 IP 的入向统计 |
| `prefix_stats` | PrefixStatsMsg[] | 按前缀的入向聚合统计 |
| `global_stats` | GlobalStatsMsg | 全局入向流量计数器 |
| `health` | NodeHealth | 代理健康状态 |
| `sampling_metrics` | SamplingMetrics | Ring buffer 和采样健康信息 |
| `gap_seconds` | uint32 | 重连后的数据间隔时长 |
| `ip_stats_truncated` | bool | ip_stats 是否被截断（IP 数过多） |
| `total_active_ips` | uint32 | 截断前的活跃目的 IP 总数 |
| `top_flows` | FlowSample[] | 本 tick 的 Top-N 流（按包数排序） |
| `src_ip_stats` | IPStats[] | 按源 IP 的出向统计 |
| `src_prefix_stats` | PrefixStatsMsg[] | 按前缀的出向聚合统计 |
| `src_ip_stats_truncated` | bool | src_ip_stats 是否被截断 |
| `total_active_src_ips` | uint32 | 截断前的活跃源 IP 总数 |

流关闭时返回 `google.protobuf.Empty`。

---

## 3. SampleStream（客户端流）

Node 发送 `SampleBatch` 消息，包含从 BPF ring buffer 中读取的原始包头采样。Controller 用于流指纹识别和深度检查。仅 XDP 模式使用。

**消息：`SampleBatch`**

| 字段 | 类型 | 说明 |
|------|------|------|
| `node_id` | string | 节点标识 |
| `interface_name` | string | 来源接口名称 |
| `upstream_sample_rate` | uint32 | 最近已处理 Stats 的该拍采集时生效的上游倍率；首份 Stats 之前使用启动倍率 |
| `local_sample_rate` | uint32 | BPF 层采样率 |
| `timestamp` | int64 | Unix 时间戳（秒） |
| `samples` | PacketSample[] | 采样包头数组 |

流关闭时返回 `google.protobuf.Empty`。

---

## 4. CriticalEventStream（客户端流）

协议中为紧急事件保留的通道，**目前未使用**。当前 Node 从不打开这条流，也不构造 `CriticalEvent`。Controller 收到时只记日志。此处列出消息结构仅供参考。

**消息：`CriticalEvent`**

| 字段 | 类型 | 说明 |
|------|------|------|
| `node_id` | string | 节点标识 |
| `interface_name` | string | 来源接口名称 |
| `timestamp` | int64 | Unix 时间戳（秒） |
| `dst_ip` | bytes | 涉及的目的 IP（4 或 16 字节），如适用 |
| `event_type` | string | 事件类别（如 `"hard_threshold_exceeded"`、`"map_full"`、`"interface_down"`） |
| `counters` | map<string, uint64> | 触发时的计数器快照（键值对） |

流关闭时返回 `google.protobuf.Empty`。

---

## 5. ControlStream（双向流）

用于运行时配置更新的双向流。Controller 在监控配置变更时发送 `ConfigPush` 消息（前缀列表、阈值、Flow 监听器配置）。Node 应用配置后回复 `ConfigAck`。

**消息：`ControlMessage`**

使用 `oneof payload` 字段：

| 变体 | 类型 | 发送方 | 说明 |
|------|------|--------|------|
| `config_push` | ConfigPush | Controller | 需要应用的新配置 |
| `config_ack` | ConfigAck | Node | 配置应用确认 |

---

## 共享消息类型

### IPStats

per-IP 流量计数器，出现在 `StatsReport.ip_stats` 和 `StatsReport.src_ip_stats` 中。

| 字段 | 类型 | 说明 |
|------|------|------|
| `dst_ip` | bytes | IP 地址（IPv4 为 4 字节，IPv6 为 16 字节） |
| `pkt_count` | uint64 | 总包数 |
| `byte_count` | uint64 | 总字节数 |
| `decoder_counts` | uint32[] | 按解码器 ID 索引的包计数。槽位 0-4：TCP / TCP_SYN / UDP / ICMP / FRAGMENT。槽位 5-13：TCP_ACK / TCP_RST / TCP_FIN / GRE / ESP / IGMP / IP_OTHER / BAD_FRAGMENT / INVALID。权威注册表见 [`shared/decoder/decoder.go`](../shared/decoder/decoder.go)。 |
| `decoder_byte_counts` | uint64[] | 按解码器 ID 索引的字节计数 |
| `small_pkt` | uint32 | < 128 字节的包数 |
| `medium_pkt` | uint32 | 128-512 字节的包数 |
| `large_pkt` | uint32 | > 512 字节的包数 |

### PrefixStatsMsg

per-prefix 流量计数器，出现在 `StatsReport.prefix_stats` 和 `StatsReport.src_prefix_stats` 中。

| 字段 | 类型 | 说明 |
|------|------|------|
| `prefix` | bytes | 网络地址（4 或 16 字节） |
| `prefix_len` | uint32 | CIDR 前缀长度 |
| `pkt_count` | uint64 | 总包数 |
| `byte_count` | uint64 | 总字节数 |
| `active_ips` | uint32 | 此前缀内的唯一 IP 数 |
| `overflow_count` | uint32 | 超出 per-IP map 容量的 IP 数 |
| `decoder_counts` | uint32[] | 按解码器 ID 索引的包计数 |
| `decoder_byte_counts` | uint64[] | 按解码器 ID 索引的字节计数 |

### GlobalStatsMsg

全局流量计数器，出现在 `StatsReport.global_stats` 中。

| 字段 | 类型 | 说明 |
|------|------|------|
| `total_pkts` | uint64 | 接口上的总包数 |
| `total_bytes` | uint64 | 接口上的总字节数 |
| `matched_pkts` | uint64 | 匹配 watch_prefixes 的入向包数 |
| `matched_bytes` | uint64 | 匹配 watch_prefixes 的入向字节数 |
| `decoder_counts` | uint32[] | 入向按解码器细分的 PPS |
| `decoder_byte_counts` | uint64[] | 入向按解码器细分的 BPS |
| `src_matched_pkts` | uint64 | 匹配 watch_prefixes 的出向包数 |
| `src_matched_bytes` | uint64 | 匹配 watch_prefixes 的出向字节数 |
| `src_decoder_counts` | uint32[] | 出向按解码器细分的 PPS |
| `src_decoder_byte_counts` | uint64[] | 出向按解码器细分的 BPS |

### FlowSample

单个聚合流（五元组），来自一个 tick 内，出现在 `StatsReport.top_flows` 中。

| 字段 | 类型 | 说明 |
|------|------|------|
| `src_ip` | bytes | 源 IP（4 或 16 字节） |
| `dst_ip` | bytes | 目的 IP（4 或 16 字节） |
| `src_port` | uint32 | 源端口 |
| `dst_port` | uint32 | 目的端口 |
| `protocol` | uint32 | IP 协议号（6=TCP, 17=UDP, 1=ICMP） |
| `tcp_flags` | uint32 | 此流中所有 TCP flags 的累积 OR |
| `packets` | uint64 | 包数 |
| `bytes_total` | uint64 | 字节数 |

### PacketSample

单个采样包头，出现在 `SampleBatch.samples` 中。

| 字段 | 类型 | 说明 |
|------|------|------|
| `raw_header` | bytes | 原始捕获的包头字节 |
| `src_ip` | bytes | 解析后的源 IP |
| `dst_ip` | bytes | 解析后的目的 IP |
| `ip_protocol` | uint32 | IP 协议号 |
| `src_port` | uint32 | 源端口（TCP/UDP） |
| `dst_port` | uint32 | 目的端口（TCP/UDP） |
| `packet_length` | uint32 | 原始包在线路上的长度 |
| `tcp_flags` | uint32 | TCP flags（如果是 TCP） |
| `ip_ttl` | uint32 | IP TTL 值 |
| `fragment_offset` | uint32 | IP 分片偏移 |
| `icmp_type` | uint32 | ICMP 类型（如果是 ICMP） |
| `icmp_code` | uint32 | ICMP 代码（如果是 ICMP） |

### NodeHealth

代理健康状态，出现在 `StatsReport.health` 中。

| 字段 | 类型 | 说明 |
|------|------|------|
| `status` | string | `"healthy"`、`"degraded"` 或 `"unhealthy"` |
| `message` | string | 可读的状态描述 |

### SamplingMetrics

Ring buffer 和采样健康信息，出现在 `StatsReport.sampling_metrics` 中。

| 字段 | 类型 | 说明 |
|------|------|------|
| `ring_fill_ratio` | float | 当前 ring buffer 填充率（0.0 - 1.0） |
| `dropped_kernel` | uint64 | 内核侧 ring buffer 丢包数 |
| `dropped_user` | uint64 | 用户态侧丢包数 |
| `decode_error` | uint64 | 包解码错误数 |
| `batch_send_latency_ms` | float | 批量 gRPC 发送的 P50 延迟 |
| `effective_sample_rate` | float | 自适应调整后、最近一次成功写进 BPF map 的采样率（启动时的例外同 `local_sample_rate`） |

### WatchConfig

Controller 下发给 Node 的配置（通过 Handshake 响应或 ControlStream ConfigPush）。

| 字段 | 类型 | 说明 |
|------|------|------|
| `prefixes` | WatchPrefix[] | 监控的 IP 前缀列表 |
| `hard_thresholds` | HardThresholds | per-IP 硬阈值（Node 只保存，目前不使用） |
| `flow_listeners` | FlowListenerConfig[] | Flow 监听器配置（仅 flow 模式，XDP 节点忽略） |

### WatchPrefix

监控列表中的单个 IP 前缀。

| 字段 | 类型 | 说明 |
|------|------|------|
| `prefix` | bytes | 网络地址（4 或 16 字节） |
| `prefix_len` | uint32 | CIDR 前缀长度 |
| `name` | string | 可读标签 |

### HardThresholds

Controller 下发所有已启用、`over`、domain 为 `internal_ip` 的规则中最小的值，`pps` 与 `bps` 分别取（没有时为 1,000,000 pps / 10,000,000,000 bps）。当前 Node 只把它存进本地快照，不据此动作。

| 字段 | 类型 | 说明 |
|------|------|------|
| `pps` | uint64 | per-IP 包/秒阈值 |
| `bps` | uint64 | per-IP 比特/秒阈值 |

### ConfigPush

Controller 通过 ControlStream 发送给 Node。

| 字段 | 类型 | 说明 |
|------|------|------|
| `watch_config` | WatchConfig | 需要应用的新配置 |
| `delivery_version_current` | uint64 | 配置版本号 |

### ConfigAck

Node 应用 ConfigPush 后通过 ControlStream 发送给 Controller。

| 字段 | 类型 | 说明 |
|------|------|------|
| `delivery_version_applied` | uint64 | 已应用的版本号 |
| `success` | bool | 配置是否成功应用 |
| `error_message` | string | 如果 success=false，错误详情 |

### FlowListenerConfig

下发给 flow 模式 Node 的 Flow 监听器配置。

| 字段 | 类型 | 说明 |
|------|------|------|
| `listen_address` | string | UDP 绑定地址（如 `":6343"`、`":2055"`） |
| `protocol_mode` | string | `"auto"`、`"sflow"`、`"netflow"` 或 `"ipfix"` |
| `sources` | FlowSourceConfig[] | 已注册的导出器设备 |
| `enabled` | bool | 此监听器是否启用 |

### FlowSourceConfig

监听器上的单个流导出器设备。

| 字段 | 类型 | 说明 |
|------|------|------|
| `device_ip` | string | 导出器 IP 地址（与 UDP 源地址匹配） |
| `sample_mode` | string | `"auto"`（使用记录中的采样率）、`"force"`（覆盖）或 `"none"`（rate=1） |
| `sample_rate` | int32 | 覆盖采样率（sample_mode=`"force"` 时使用） |
| `name` | string | 可读显示名称 |
| `enabled` | bool | 此源是否启用 |

---

## 连接生命周期

```
Node 启动
  -> 加载 config.yaml
  -> 加载 WatchConfig 快照（如果存在）
  -> 拨号 Controller gRPC（带重连退避）
  -> Handshake（发送 node_id、api_key、delivery_version_applied）
  -> 如果被接受：
       -> 应用 HandshakeResponse 中的 WatchConfig（非空时应用）
       -> 打开 StatsStream（每秒发送）
       -> 打开 SampleStream（XDP 模式，批量发送）
       -> （CriticalEventStream 为保留通道，不打开）
       -> 打开 ControlStream（接收 ConfigPush，发送 ConfigAck）
  -> 断连时：退避 + 重连 + 重新 Handshake
```
一次连接尝试持续至少 30 秒后，重连退避重置为 1 秒。

## 认证

Node 在 `Handshake` 消息中带上 `api_key`。Controller 按 `node_id` 查已注册的节点，并与该节点注册时填写的 `api_key`（`POST /api/nodes`）比较。它不是 Controller REST 接口的 `auth.api_key`。因此节点必须先在 Controller 上注册才能接入。

流式 RPC 本身不带凭证：

- `StatsStream`、`SampleStream`、`CriticalEventStream` 逐条检查消息里自报的 `node_id`：只要该节点自本 Controller 进程启动以来任何时候完成过一次 Handshake，即放行。检查与 TCP 连接无关；节点断开或之后被停用，这条记录也不会清除。否则流以 `Unauthenticated` `handshake required` 结束。
- `ControlStream` 按 Handshake 时记录的对端地址映射到节点。来自未知地址的流会被接受，但收不到配置下发。

### 安全说明

- **明文传输。** Node 以 insecure 凭证拨号，Controller 的 gRPC 服务未启用 TLS。`api_key`、统计和采样都以明文过网，密钥按普通字符串比较。
- **身份靠自报。** 某个 `node_id` 握手成功一次后，任何能连到 gRPC 端口的客户端都能以该 `node_id` 发送统计或采样。
- **只在可信网络内部署。** Controller 与 Node 之间的链路应放在可信的管理网或加密隧道（如 WireGuard、IPsec）内，并用防火墙把 gRPC 端口（缺省 50051）限制为只对节点地址开放。不要暴露到公网。
