# xSight 架构指南

> 说明 xSight 的内部工作方式：组件、数据流、状态机、存储与安全模型。面向贡献者，以及需要推断系统行为的运维人员。安装见[快速开始](../GETTING_STARTED.zh.md)；配置与日常运维见[用户指南](user-guide.zh.md)。

---

## 目录

1. [组件与数据流](#1-组件与数据流)
2. [Node](#2-node)
3. [Controller 检测流水线](#3-controller-检测流水线)
4. [动作引擎](#4-动作引擎)
5. [状态与存储](#5-状态与存储)
6. [安全模型](#6-安全模型)
7. [已知限制](#7-已知限制)

---

## 1. 组件与数据流

### 概览

```
  Node (XDP)  ──┐                    Controller
                │ gRPC   ┌──────────────────────────────────────────────────────────┐
  Node (Flow) ──┼──────▶ │ ingestion ─▶ ring buffers ─▶ detection ─▶ tracker         │
                │        │     │                       (static +      │            │
                │        │     ▼                        dynamic)      ▼            │
                │        │ ts_stats / flow_logs                  action engine     │
                │ ◀───── │ config publisher                  BGP · xDrop · webhook │
                │  push  │ REST API + Web UI + /metrics            · shell       │
                │        └──────────────────────────────────────────────────────────┘
```

1. **Node** 按目的 IP、源 IP 和被监控前缀计数流量（XDP 模式），或聚合 flow 记录（Flow 模式），每秒通过 gRPC 发送一份统计报告。
2. Controller 的 **ingestion（摄取）** 层把每份报告写入内存中的 **ring buffer（环形缓冲）**（用于实时检测），并批量写入 `ts_stats` 表（用于图表与基线）。flow 摘要写入 `flow_logs`。
3. **检测** 每秒把 ring 数据与静态阈值规则比较；启用时还与动态基线画像比较。
4. 超阈事件经告警去重后送入 **攻击跟踪器（tracker）**，由它确认、维持和结束攻击。
5. 跟踪器事件排队交给 **动作引擎**，它解析响应、依次过分派闸门，执行 BGP（FRR `vtysh`）、xDrop（XDrop v3 REST API）、Webhook 和 Shell 动作。
6. 前缀、阈值或 flow 监听器变化时，**配置发布器** 把新的监控配置推送给各 node。

### Node ↔ Controller 协议

Node 连接 controller 的 gRPC 端口（缺省 `:50051`）。服务包含五个 RPC：

| RPC | 类型 | 用途 |
|---|---|---|
| `Handshake` | 一元调用 | 核对 Node ID 与该节点专用 API Key；返回完整监控配置 |
| `StatsStream` | 客户端流 | 每秒一份统计报告（检测输入） |
| `SampleStream` | 客户端流 | XDP 模式的报文样本，用于攻击分类和 flow 摘要 |
| `CriticalEventStream` | 客户端流 | 协议中定义但**未使用**：node 从不在此流上发送；controller 收到也只记日志 |
| `ControlStream` | 双向流 | 配置推送（controller → node）与确认（node → controller） |

完整消息说明见 [node/API.zh.md](../node/API.zh.md)。

### 代码地图

| 领域 | Controller（`controller/internal/`） | Node（`node/internal/`） |
|---|---|---|
| 传输 | `ingestion`（gRPC 服务端、上报队列） | `reporter`（gRPC 客户端、带退避的重连） |
| 数据 | `store/ring`、`store/postgres`、`retention` | `collector`（读取 BPF map）、`sampler`、`flow` |
| 逻辑 | `engine/threshold`、`engine/baseline`、`engine/classifier`、`engine/dedup`、`tracker`、`action` | `bpf`（生成的绑定 + 加载器） |
| 接口 | `api`（REST + 内嵌 Web UI）、`configpub`、`metrics` | `config`（YAML + 最近一次配置的快照） |

两个程序通过 `shared/decoder/decoder.go` 共用 decoder 名称与编号。

---

## 2. Node

### XDP 模式

XDP 程序（`node/bpf/xsight.c`）挂载在每个配置的接口上。同一 node 的所有接口共用一份 BPF 配置，因此 `mode`、`sample_bytes` 和 `upstream_sample_rate` 必须在各接口间一致。`erspan` 模式下程序解封装 GRE/ERSPAN，统计内层报文。

对每个报文，程序：

1. 解析以太网头（含一层 VLAN 标签）、IPv4/IPv6 头和 L4 头。
2. 在被监控前缀的 LPM trie 中查找目的地址（入向）和源地址（出向）。不属于任何被监控前缀的报文只更新全局计数。
3. 更新按 IP、按源 IP 和按前缀的计数：报文数、字节数，以及固定 16 个 decoder 计数（即 `shared/decoder/decoder.go` 的槽位）。
4. 把被采样报文的前 `sample_bytes` 字节复制到 ring buffer，供用户态 sampler 读取。

BPF map（见 `node/bpf/xsight.h`）：`global_stats`（array）、`watch_trie_a/b`（LPM trie）、`ip_stats_a/b` 和 `src_stats_a/b`（hash）、`prefix_stats_map` 和 `src_prefix_stats_map`（hash）、`active_slot` 和 `xsight_config`（array）以及 `samples`（ring buffer）。`_a/_b` 成对出现，是配置变更用的双缓冲：新的监控前缀集先写入空闲的 trie 和 map，再切换 `active_slot`，报文永远不会看到写了一半的前缀集。collector 每秒读取累计计数并上报差值。

停止 node 时，XDP 程序及其固定（pin）在 `/sys/fs/bpf/xsight/` 下的 map 保留不动，重启后继续计数。`xsight-node -config <文件> -unload` 卸下 XDP 并删除这些 pin。`SIGHUP` 重新加载 `sample_bytes` 和 `upstream_sample_rate`；修改模式或接口需要重启。

### Flow 模式

Node 在 UDP 监听器上接收 sFlow v5、NetFlow v5/v9 和 IPFIX；监听器在 controller 中配置（Web UI **Flow**），不写在 node 的配置文件里。监听器与数据源随监控配置下发。只采用已注册且启用的数据源发来的记录，其余计为未知导出方。每个数据源有采样模式：`auto`（用记录里的采样率）、`force`（用配置的采样率）或 `none`（采样率按 1）。Flow 模式产生同样的每秒统计，但没有报文样本，所以基于样本的攻击分类器不运行。空闲的 Flow 节点每秒发送一次心跳报告，保持在线。

### 上报

Node 每秒发送一份 `StatsReport`，包含按目的 IP、按源 IP、按前缀的统计，全局计数，top flow 以及健康 / 采样指标。Node 把最近一次应用的监控配置保存在 `/var/lib/xsight/<node_id>/last_config.json`，启动时加载，因此在连上 controller 之前就能开始计数。

---

## 3. Controller 检测流水线

### 摄取

gRPC 处理器只接受已完成握手的 Node ID 发来的报告（见 §6）。报告在每条流的小队列中等待，队列满时丢弃最旧的报告。ring 写入器为每个键每秒存一个数据点；非法前缀或地址被丢弃，并输出限频的告警日志。数据库写入器每 5 秒把 `ts_stats` 刷盘一次；flow 摘要写入 `flow_logs`。节点最近一次上报距今不到 10 秒即视为在线。

### 静态阈值

阈值树把每个被监控前缀映射到它的有效规则（模板规则加上从父前缀继承的规则）。每个 tick 内，按节点、按方向（`receives` = 目的，`sends` = 源），`subnet` 规则与前缀聚合值比较，`internal_ip` 规则与前缀内每个 IP 比较。超阈事件经过去重：同一 IP 与方向上，更具体 decoder 的活跃攻击会抑制新的更宽泛攻击（例如活跃的 `tcp` 攻击抑制新的 `ip` 攻击）。

### 动态检测

动态检测只在前缀级、只看入向，缺省关闭（`dynamic_detection_config.enabled`）。

- **画像。** 每个（节点，前缀）有 168 个周槽位（一周中的小时，UTC）。每小时把刚结束的那一小时的 PPS、BPS 第 95 百分位数，按 EWMA（`ewma_alpha`）并入该槽位；每个槽位每个 ISO 周最多取一个样本。
- **阈值。** `expected × (100 + deviation) / 100`，其中 `deviation`（百分比）随该槽位的样本数从 0 增长到 `stable_weeks`，由 `deviation_max` 线性收窄到 `deviation_min`。槽位有第一个样本后即开始使用。
- **下限。** 只有 PPS < `min_pps` **且** BPS < `min_bps` 时才忽略流量。高于下限后，PPS 或 BPS 任一超过阈值即为超阈。
- **确认。** 动态超阈事件按 `ip` / `subnet` / `receives` 处理，需要连续 `dynamic_threshold_confirm_seconds` 个数据点确认。

另外，基线计算器为每个前缀计算最近一小时的 P95 × 3。这个值只作为**推荐的静态阈值**展示（`GET /api/baseline`），不参与检测。

### 攻击跟踪器

```
 (no attack) ──breach──▶ Confirming ──N consecutive points──▶ Active ◀──re-breach──┐
      ▲                       │ point missing: discard              │               │
      │                                                   no breach │               │
      │                                                             ▼               │
      └──────────────────────── Expired ◀──expiry timer ends── Expiring ────────────┘
```

| 状态 | 含义 |
|---|---|
| Confirming | 已看到超阈。连续 N 个超阈的每秒数据点即确认，N = `hard_threshold_confirm_seconds`（静态）或 `dynamic_threshold_confirm_seconds`（动态）；容忍缺一秒。 |
| Active | 已确认。写入 `attacks`，执行 `on_detected` 动作。每 5 分钟发出一次 `updated` 事件（供周期动作使用）。 |
| Expiring | 流量回落到阈值以下。计时 = `expiry_interval_seconds`；若 `expiry_function: dynamic`，则为该值 × clamp(攻击持续时长 / `expiry_scale_base_seconds`, 1, `expiry_max_scale`)。再次超阈回到 Active，并取消待执行的 BGP 撤回延迟。 |
| Expired | 已结束；写入 `ended_at`，执行 `on_expired` 动作。 |

严重度在确认时按峰值确定：critical（> 1 Mpps 或 > 10 Gbps）、high（> 100 kpps 或 > 1 Gbps）、medium（> 10 kpps 或 > 100 Mbps），其余为 low。

达到 `max_active_attacks` 时，新攻击只有在严格高于优先级最低的 Active 或 Expiring 攻击时才替换它（先比严重度；严重度相同时 Expiring 攻击排在后面；再比峰值 PPS）；被替换的攻击被**驱逐**，若它处于 Expiring，会提前执行 `on_expired` 动作。否则新攻击保持 Confirming，并计为被抑制。ring 容量（`max_ips_per_prefix`、`max_global_keys`）不得不丢弃键时，会保护 Active 和 Confirming 攻击的键。

人工结束攻击（`POST /api/attacks/:id/expire`）可能对同一目标、decoder 和方向留下内存中的保持期（`manual_expire_hold_seconds`）；controller 重启会清除它。

XDP 模式下，分类器根据报文样本细化入向 UDP 攻击的类型（例如源端口 53 占主导时为 `dns_reflection`）。

### 配置下发

1. 除用户、节点走直接审计外，响应、动作、前置条件、模板、前缀、阈值、连接器、Flow 配置及强制移除/孤立路由操作走发布路径，递增启用节点的**下发版本号**并重新推送。
2. Controller 组装 `WatchConfig`（前缀、按 IP 的硬阈值、Flow 节点的 flow 监听器），通过各节点的 `ControlStream` 推送。全局前缀从不下发给节点，它由全局计数计算。
3. 节点应用后返回 `ConfigAck`。
4. 每个节点有 `config_status`（`synced`、`pending` 或 `failed`）和**漂移**（当前版本 − 已应用版本）。`failed` 表示节点报告应用当前版本失败；推送未能发出时节点保持 `pending`。

---

## 4. 动作引擎

### 响应解析

跟踪器事件进入 FIFO 队列，由一个分派器按顺序处理。

- **入向（`receives`）**：取触发规则的 `response_id`，没有则取前缀所绑模板的默认响应。
- **出向（`sends`）**：只取规则自己的 `response_id`；不回落到模板默认响应，因为默认响应通常含有面向入向流量的阻断动作。
- 没有响应或响应已停用：只通知全局 Webhook。每次分派之后也都会通知全局 Webhook。

### 分派闸门

动作按 `(trigger_phase, priority)` 排序，依次通过以下闸门。会写执行日志行的闸门使用 `status=skipped` 和 `skip_reason`。

1. **启用与阶段。** `on_detected` 匹配 `confirmed`、`type_upgrade` 和 `updated` 事件（运行方式 `once` 忽略 `updated`）；`on_expired` 匹配 `expired` 和 `evicted`。
2. **运行方式。** `once` 每个攻击每个阶段只运行一次；`retry_until_success` 在后续事件上重试，直到有一次成功；两者被跳过时都记 `already_executed`。`periodic` 还会在每次 `updated` 事件（约每 5 分钟）时运行。
3. **前置条件。** 全部满足才通过（`precondition_not_matched`）。
4. **模式。** `action_engine.mode: observe` 时跳过所有 xDrop 动作（`mode_observe`）。BGP、Webhook、Shell 不受此闸门约束，两种模式下都会执行。
5. **执行方式 = 手动。** 静默跳过（不写日志行）；目前没有触发手动动作的入口。
6. **出向保护。** 出向攻击未结束时，跳过 xDrop 和 BGP（`outbound_block_forbidden`）。
7. **首个匹配。** 对 xDrop、BGP、Shell，每种类型只运行走到这一步的第一个动作（`first_match_suppressed`）；Webhook 全部运行。
8. **xDrop decoder 闸门。** `ip` 和 `ip_other` 攻击的 xDrop 动作被跳过（`decoder_not_xdrop_compatible`）。

### 自动配对动作

以 `trigger_phase: on_detected` 创建 xDrop 或 BGP 动作时，系统同时创建配套的 `on_expired` 子动作（xDrop 解封 / BGP 撤回）。父动作保存 `paired_with = child.id`；子动作 `auto_generated = true`，不能直接编辑。父动作的修改、启停和删除会同步到子动作；子动作操作失败时在应用层做补偿回滚。

### BGP 执行

BGP 路由是共享、带引用计数的资源，在 `bgp_announcements` 中以 `(prefix, route_map, connector_id)` 为键，每个挂载的攻击在 `bgp_announcement_attacks` 中占一行。

- **挂载**（`on_detected`）：在行锁内，第一个攻击插入公告（`announcing`）并执行 `vtysh`：`configure terminal` → `router bgp <ASN>` → `address-family ipv4|ipv6 unicast`（按前缀选择）→ `network <prefix> route-map <name>`；成功后变为 `active`。后来的攻击只增加 `refcount`，不调用 `vtysh`。单主机攻击按 /32 或 /128 宣告；子网攻击按其前缀宣告。
- **解绑**（`on_expired`）：减少 `refcount`。降到 0 时公告变为 `delayed`（延迟 > 0）或 `withdrawing`，随后 `no network …` 使其变为 `withdrawn`。延迟取本轮宣告周期内所有挂载攻击的 `bgp_withdraw_delay_minutes` 的**最大值**。
- **日志中的业务键**：`external_rule_id = <prefix>|<route_map>`。
- **孤儿路由**：启动时 controller 列出已启用连接器的 BGP 表；没有对应公告的路由记为 `orphan`，由运维在 Web UI 中撤回或忽略。
- **对账**：`announcing` 行两分钟后用只读命令向 FRR 核对；卡在 `withdrawing` 的行、以及已无挂载的 failed 行，在公告锁内重试。每次 `vtysh` 调用有 60 秒期限。

### xDrop 执行

- **认证与持有：** xDrop v3 使用 Bearer 机器凭证（每台 xSight 一个）。每次创建都带 `claim_ref = a<attack>.x<action>`；同一规则身份的持有方共用规则号。xSight 不发送 `expires_in`；它只释放自己的持有，最后一个持有方释放后，xDrop 才删除规则。
- **创建**（`on_detected`，`filter_l4` / `rate_limit`）：只有 HTTP 200/201 且返回非空 `id` 才算成功，该值作为 `external_rule_id` 写入 `action_execution_log` 与 `xdrop_active_rules`。其他结果记为 failed，使用合成号 `failed-create-<attack>-<action>`，它不是远端规则号。
- **载荷归一化：** 只发送 v3 规则字段；空值与未知字段被丢弃。协议由攻击的 decoder 决定（见下表）。异常类规则使用 `match_anomaly`，不带协议字段。未提供 TCP 标志时，TCP 标志类 decoder 补上对应的规范标志。
- **收窄与兜底：** 模板字段 `{src_ip}`、`{dominant_dst_port}`、`{dominant_src_port}`（即勾选 Src IP / Dst Port / Src Port）只表示**允许**收窄。flow 样本先按攻击的协议和 TCP 标志过滤。只有样本数不少于 `xdrop_min_sample_packets`、且该字段的头号取值占样本至少 `xdrop_narrow_pct` % 时，才保留该字段；两个端口都达标时只保留源端口。若没有任何字段收窄规则、也没有留下字面条件、动作为 `drop`、且 decoder 不是 `fragment` 或异常类，规则改为按触发规则的 PPS 值做 `rate_limit`；没有这样的 PPS 规则时（例如 BPS 规则或动态检测产生的攻击），按不收窄的 drop 下发。
- **前 K 名多规则：** 允许收窄的端口，其头号取值占比低于 `xdrop_narrow_pct`，但前 2..K 个端口（K ≤ `xdrop_topk_max`）合计达到样本的 `xdrop_topk_pct` % 时，一次分派创建 K 条规则，每个端口一条，共用同一个 `claim_ref`。先尝试源端口；源端口需要的规则数更少（或相同）时选源端口。`xdrop_topk_max: 1` 关闭此功能。
- **整形说明：** 决策写入成功执行日志的 `error_message`，不改变状态，例如 `shape: kept src_port=92%`、`shape: samples 120 < 1000`、`shape: fallback rate_limit=500000`、`shape: topk dst_port=3 84%`、`shape: item 1/3 dst_port=443`，以及归一化产生的 `dropped:`、`protocol pinned:` 说明。
- **释放**（`on_expired`，解封）：逐条释放本地持有。只有 HTTP 204 算远端释放成功；404、200、3xx 均为失败。同一条本地持有记录（攻击 + 动作 + 连接器 + 规则号）上的释放串行执行。
- **创建失败与迟到结果：** 攻击结束后，可恢复的创建失败依据经只读 `POST /rules/batch?validate=1` 核对（不重发创建）；找到对应远端规则则释放。依据无法恢复时可能只关闭本地记录、不向远端释放。成功的创建结果在本地撤销之后才返回时，会补发一次释放；失败计为 `late_create_leak`。
- **对账：** 启动恢复后立即执行一轮，此后每 2 分钟一轮，重新检查处于 `active` / `delayed` / `withdrawing` / `failed` 的记录和到期的 `xdrop_unblock` 调度。活攻击、未到期调度、人工覆盖和停用的连接器被跳过。释放失败后按 2 / 4 / 8 / 16 分钟退避。结果计入 `xsight_xdrop_reconcile_total`。
- **收下与下发：** `active` 表示 XDrop 控制器已收下规则。各节点的下发状态按需现查，描述已配置的规则代次，不是实测命中。

### xDrop Decoder 映射

| Decoder | xDrop | 规则匹配 |
|---|---|---|
| `tcp` | 是 | `protocol=tcp` |
| `tcp_syn` | 是 | `protocol=tcp` + `tcp_flags=SYN,!ACK` |
| `tcp_ack` | 是 | `protocol=tcp` + `tcp_flags=ACK,!SYN` |
| `tcp_rst` | 是 | `protocol=tcp` + `tcp_flags=RST` |
| `tcp_fin` | 是 | `protocol=tcp` + `tcp_flags=FIN` |
| `udp` | 是 | `protocol=udp` |
| `icmp` | 是 | IPv4 `protocol=icmp`；IPv6 `protocol=icmpv6` |
| `fragment` | 是 | `protocol=all`；IPv4 未提供分片条件时补 `fragment=frag` |
| `gre` | 是 | `protocol=gre` |
| `esp` | 是 | `protocol=esp` |
| `igmp` | 是 | `protocol=igmp` |
| `bad_fragment` | 是 | `match_anomaly`；drop 或 rate_limit；xDrop 拒绝 IPv6 |
| `invalid` | 是 | `match_anomaly`；drop 或 rate_limit |
| `ip` | 否 | L3 聚合——改用 BGP |
| `ip_other` | 否 | L3 兜底类——改用 BGP |

对没有端口的 decoder，下发前删除端口和 TCP 标志；异常类规则还不带协议字段。

### 延迟执行（持久化）

延迟的 BGP 撤回和 xDrop 释放持久化在 `scheduled_actions` 中，能跨重启保留。

1. `on_expired` 动作的延迟 > 0 时，写入一行 `pending`，`scheduled_for = now + delay`，并带业务键 `(attack_id, action_id, connector_id, external_rule_id)`；BGP 行还带 `announcement_id`。
2. 计时器触发时，该行变为 `executing`，执行移除，通常以 `completed` 或 `failed` 结束。对 xDrop，旧调度没有对应规则行、且这次释放没有成功时，调度保持 `executing`，交给运行期对账；有规则行时，释放失败通常使调度以 `failed` 结束。
3. 对 BGP，延迟期间再次超阈会取消 pending 行（`cancel_reason=rebreach`）。xDrop 只在攻击结束后才安排释放；之后再次超阈会形成新攻击，不会取消这次延迟释放。
4. 强制移除只取消该制品自己的行（`cancel_reason=force_remove`）。
5. 启动时，pending 行重新计时（未到期）或立即执行（已过期），停留在 `executing` 的行被重试；结果计入 `xsight_scheduled_actions_recovered_total`。

### 人工覆盖（强制移除）

1. BGP 强制移除先提交全部挂载攻击的解绑，再写入这些攻击的 manual override 和审计日志，最后执行 vtysh 撤回。所有挂载攻击都会失去共享路由的保护；撤回失败不会撤销已记录的 override。
2. 对 xDrop，强制解除释放本攻击这个动作的持有；最后一个持有方释放后，xDrop 才删除规则。若有进行中的自动释放，可能先等待最多一个连接器超时。创建失败记录先做只读核对，再释放或只做本地收尾；本地收尾成功不代表释放一定到达了 xDrop。
3. 之后的自动 `on_expired` 处理按制品检查 `action_manual_overrides`，只跳过被人工覆盖的那个制品。

**停用的 BGP 连接器：** 连接器停用期间结束的攻击，其路由留着不撤。重新启用该连接器、或编辑一个已启用的连接器时，后台对该连接器的 active 公告扫一遍，把挂载攻击都已结束的路由撤掉。

**停用的 xDrop 连接器：** 自动释放在连接器停用期间等待，启用后由下一轮对账重新处理。新建规则时以 `connector_disabled` 跳过停用的目标；显式选择的目标全部停用时，不回落到全局连接器。连接器停用时拒绝强制解除。

---

## 5. 状态与存储

### 状态机

每种外部制品有一张状态表，它是 Web UI 和 API 的真相源。`action_execution_log` 是只追加的审计记录，不用于推导状态。

| 表 | 状态 |
|---|---|
| `bgp_announcements` | `announcing` → `active` → `delayed` / `withdrawing` → `withdrawn`；另有 `failed`、`orphan`、`dismissed`、`dismissed_on_upgrade` |
| `xdrop_active_rules` | `active` → `delayed` / `withdrawing` → `withdrawn`；另有 `failed` |
| `scheduled_actions` | `pending` → `executing` → `completed` / `cancelled` / `failed` |

相关表：`bgp_announcement_attacks`（挂载关系，含每个攻击的延迟）、`bgp_announcement_events`（BGP 时间线）、`action_manual_overrides`（强制移除记录）。

### UI 状态派生

「缓解」页面直接读取状态表：

- **BGP 分区**：`bgp_announcements` 中状态为 `active`、`delayed` 或 `failed` 的行；`orphan` 行在独立横幅显示（查询也会返回 `announcing` 和 `withdrawing`，API 把它们当作过渡状态隐藏）。
- **xDrop 分区**：`xdrop_active_rules WHERE status IN ('active', 'delayed', 'failed')`。
- **详情时间线**：BGP 取 `bgp_announcement_events`；xDrop 取执行日志条目加 `action_manual_overrides`。

对于攻击动作日志中的 BGP 行，API 附加 `bgp_role`：`triggered`（该攻击引发了 `vtysh` 宣告）或 `attached_shared`（它加入了已有的公告）。

### 启动恢复

启动时，在接收工作之前，controller 按以下顺序执行：

1. 把 `active` / `delayed` 的 BGP 公告重新写入 FRR。
2. 对调度中的工作做快照，完成中断的 BGP 宣告 / 撤回和 xDrop 释放工作，并恢复 `scheduled_actions`（重新计时、执行已过期的、重试 `executing`）。
3. 释放在 controller 停机期间结束的攻击的 BGP 挂载和 xDrop 持有（`xsight_startup_cleanup_total`）。
4. 从数据库把活跃攻击恢复到跟踪器。
5. 扫描 FRR 中的孤儿路由。

随后启动 xDrop、BGP withdrawing 和 BGP announcing 三个对账器。每个攻击结束后，还会对该攻击的制品做一次补扫（`xsight_ended_sweep_total`）。

### 存储与保留期

| 数据 | 表 | 缺省保留期 |
|---|---|---|
| 5 秒统计 | `ts_stats`（hypertable，`ts_stats_compress_days` 后压缩） | `ts_stats_days`：7 |
| 5 分钟聚合（6H / 24H 图表） | `ts_stats_5min`（连续聚合） | `ts_stats_cagg_days`：90 |
| Flow 摘要 | `flow_logs`（hypertable） | `flow_logs_days`：7 |
| 已结束的攻击 | `attacks` | `attacks_days`：90（活跃攻击永不删除） |
| 配置审计 | `config_audit_log` | `audit_log_days`：180 |

`0` 表示永久保留。hypertable 由 TimescaleDB 的保留和压缩策略处理；内置清理器每 `interval_hours`（缺省 24）运行一次，处理其他表。配置类表（前缀、模板、阈值、响应、动作、前置条件、连接器、节点、用户、flow 监听器 / 数据源、动态检测配置与画像）不受保留期影响。

从 v7 升级时会重建 `ts_stats_5min`（v8，新增 `avg_tcp_syn_bps`）：7 天以前的 5 分钟聚合被删除，启动时同步从现存原始数据回填最近 7 天（固定 7 天，与 `ts_stats_days` 无关）；原始数据保留期更短时，可恢复的历史也更少。旧原始行的 `tcp_syn_bps` 为 0。详见 [CHANGELOG](../CHANGELOG.zh.md)。

删除过期已结束攻击时，同时删除其执行日志和相关状态行；仍有未完结状态的攻击保留。

### 可观测性

`GET /metrics` 暴露 23 个 `xsight_*` 指标，以及 Go 运行时和进程指标。完整目录（含标签与告警建议）见[用户指南](user-guide.zh.md#51-指标)；其中 `xsight_xdrop_reconcile_total` 统计 xDrop 释放与对账。从状态表读取的指标在抓取时采集，超时 5 秒；查询出错时，本次抓取不包含该指标。

---

## 6. 安全模型

- **REST 认证。** 除 `POST /api/login` 外，所有 `/api` 路由都需要 `X-API-Key: <auth.api_key>` 或 `Authorization: Bearer <JWT>`。API Key 视为管理员。
- **只有管理员能写。** 任何已登录用户都可以发 GET 请求。其他方法都要求角色 `admin`；`viewer` 和旧的 `operator` 角色只读（403）。
- **最后一个管理员。** 最后一个启用的 admin 不能被删除、降级或停用（409）。
- **每次请求复核。** 每个 JWT 请求都会重新加载用户，并把用户的最后修改时间与令牌比对。被删除、停用或修改过的用户立即得到 401。令牌最长有效 24 小时。签名密钥由 `auth.api_key` 派生，修改该键会使所有令牌失效。
- **登录限速。** 内存中按 15 分钟窗口计：每个「用户名 + 来源地址」5 次，每个来源地址 20 次，最多跟踪 10,000 个键；超出返回 429 并带 `Retry-After`。来源取 TCP 对端地址，不信任代理头，因此同一 NAT 或反向代理后的客户端共用额度。
- **审计。** 配置变更及强制移除、孤立路由操作尽力写入 `config_audit_log`；发布路径组装配置或读取节点列表失败时不写，审计写入失败只记日志。手动结束攻击不写审计。Webhook header 值在 API 输出和审计 diff 中遮蔽；xDrop 密钥显示为 `***` 加末 4 位（长度不超过 4 时只显示 `***`）。密码、密码哈希和节点 API 密钥不写入审计。
- **`/metrics` 不认证**，与其他 Prometheus exporter 相同。请在网络层限制 HTTP 端口。
- **gRPC 为明文。** Node 不使用 TLS 连接，API Key 以明文发送。握手核对 Node ID + 密钥；之后，统计、样本和事件流只要消息里携带的 Node ID 自 controller 启动以来完成过握手，就会被接受，与连接无关。`ControlStream` 按握手时记录的对端地址识别节点。因此 gRPC 端口只能对可信网络开放，或经 VPN / 隧道访问。
- **本机调试端口。** Controller 的 pprof 始终开在 `127.0.0.1:6060`；node 的 pprof 只在 `pprof: true` 时开在 `127.0.0.1:6061`。

---

## 7. 已知限制

- **手动执行永不运行。** 执行方式为 Manual 的动作被静默跳过；UI 和 API 都没有手动触发入口。
- **配置键不做严格校验。** 未知或拼错的 YAML 键被静默忽略。`log.level`、`action_engine.xdrop_api`、`action_engine.xdrop_api_key` 和 `bpf.path` 会被读取，但不起作用。
- **Node 未实现 `CriticalEventStream`。** 下发给节点的按 IP 硬阈值只被保存、不在节点上使用；所有检测都在 controller 中进行。
- **gRPC 没有 TLS**，上报流信任每条消息中的 Node ID（见 §6）。
- **未实现 SQLite**，尽管 `database.driver: sqlite` 能通过校验。
- **XDP 模式只支持 x86_64**，需要 Linux 5.18 及以上。
- **xDrop 期限。** xSight 从不给 xDrop 规则设置期限。xDrop 尚未提供按持有方的期限时，与其他系统共持同一条规则，可能使对方设置的期限失效。
- **没有 xDrop 孤儿扫描。** xSight 不扫描 xDrop 上它已失去记录的规则；这类规则请在 xDrop 界面删除。
