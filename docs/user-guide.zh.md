# xSight 用户指南

> 介绍如何配置检测与响应，以及日常如何运行 xSight。安装见[快速开始](../GETTING_STARTED.zh.md)；内部机制见[架构指南](architecture.zh.md)；REST API 见 [controller/API.zh.md](../controller/API.zh.md)。

---

## 目录

1. [概念](#1-概念)
2. [检测](#2-检测)
3. [响应](#3-响应)
4. [按功能介绍 Web UI](#4-按功能介绍-web-ui)
5. [运维](#5-运维)
6. [排障](#6-排障)
7. [典型场景](#7-典型场景)
8. [已知限制](#8-已知限制)

---

## 1. 概念

### 1.1 组件与要求

| 组件 | 作用 | 要求 |
|---|---|---|
| Controller | Web UI、REST API、检测、攻击跟踪、响应动作 | PostgreSQL + TimescaleDB 2.x |
| Node（XDP 模式） | 在镜像 / ERSPAN 接口上计数报文 | Linux 5.18+、x86_64、root |
| Node（Flow 模式） | 接收 sFlow / NetFlow v5 / NetFlow v9 / IPFIX | Linux、root（服务脚本要求） |
| FRR（可选） | 为 BGP 动作宣告和撤回 BGP 路由 | 启用 `bgpd`，controller 的运行用户能使用 `vtysh` |
| XDrop（可选） | 为 xDrop 动作过滤或限速流量 | XDrop v3；在 XDrop 上为每台 xSight 建一个独立的机器凭证 |

### 1.2 配置对象

| 对象 | 是什么 |
|---|---|
| 节点（Node） | 已注册的观测点：Node ID、节点专用 API 密钥、模式（XDP / Flow） |
| 监控前缀（Watch prefix） | xSight 监控的 IPv4 或 IPv6 CIDR；可以有父前缀和阈值模板 |
| 阈值模板（Threshold template） | 一组检测规则，外加一个默认响应 |
| 规则（Rule） | 一个条件：作用域、方向、decoder、单位、比较方式、阈值；可覆盖响应 |
| 响应（Response） | 一组动作，分为「攻击检测时」和「攻击结束时」两部分 |
| 动作（Action） | 一个步骤：Webhook、Shell、BGP 或 xDrop，带运行方式、优先级和前置条件 |
| 连接器（Connector） | 动作发往哪里：Webhook URL、Shell 命令、BGP（FRR）实例或 XDrop 控制器 |

绑定链：前缀 → 模板 → 规则；攻击 → 规则的响应（或模板的默认响应）→ 动作 → 连接器。

### 1.3 攻击生命周期

| 状态 | 含义 |
|---|---|
| Confirming | 规则超阈，等待连续 N 秒超阈（缺省 3；动态检测为 5）。容忍缺一秒。 |
| Active | 已确认。攻击被保存，执行「攻击检测时」动作。 |
| Expiring | 流量低于阈值，开始倒计时（缺省 300 秒）。再次超阈则回到 Active。 |
| Expired | 已结束。执行「攻击结束时」动作（包括自动的 BGP 撤回 / xDrop 释放）。 |

### 1.4 快速上手

完成[快速开始](../GETTING_STARTED.zh.md)（controller 与 node 在线）之后：

1. **前缀 → 添加前缀**：`198.51.100.0/24`。
2. **阈值 → 创建** 新建模板，再 **添加规则**：域 `subnet`、方向「入向」、解码器 `ip`、单位 `pps`、比较「超过」、阈值 `100000`、可继承打开。
3. **前缀**：编辑该前缀，选择这个模板。
4. 之后流量连续 3 秒超过 100,000 pps，就会在 **攻击** 页产生攻击。
5. 要做缓解：在 **连接器** 下添加连接器，在 **响应** 下建响应和动作，把它选为模板的默认响应；使用 xDrop 时设置 `action_engine.mode: auto`。

---

## 2. 检测

### 2.1 监控前缀

监控前缀是监控的单位。节点只为被监控前缀内的地址计数（其他流量只更新全局计数）。前缀可以有父前缀：父前缀模板中标为 **可继承** 的规则也作用于子前缀。停用父前缀只停止对父前缀本身的监控；其模板规则和按前缀覆盖仍会被子前缀继承。

字段：前缀 (CIDR)、名称、IP 分组、父级前缀、阈值模板、状态。示例：`198.51.100.0/24` 和 `2001:db8::/32`。新前缀恒为启用；状态开关只在编辑时出现，已有 CIDR 不能在控制台修改。删除前缀会连带删除其单独规则，子前缀变为顶级前缀。IPv4 映射的 IPv6 前缀会被拒绝，请用 IPv4 写法。

**全局前缀。** 一个特殊前缀，覆盖每个节点看到的全部流量。它由节点的全局计数计算，从不下发到 BPF 前缀表。

- 使用 `0.0.0.0/0` 作为全局前缀 — 它同时覆盖 IPv4 和 IPv6 流量。`::/0` 不受支持，API 会拒绝。
- 只允许 `subnet` 规则。
- 不能绑定包含 xDrop 或 BGP 动作的 Response（防止意外全局黑洞）。绑定模板时也一样：模板的默认响应或任一规则响应含这类动作就会被拒。已经有这种绑定的全局前缀，只要改完仍是全局前缀且仍绑着这个模板，编辑就会被拒（改名也不行）；解绑模板或改掉那些响应即可。

### 2.2 阈值模板与规则

模板包含规则和一个 **默认响应**。每条规则可以选择自己的响应，对该规则触发的攻击覆盖默认响应。

| 字段 | 取值 | 含义 |
|---|---|---|
| 域 | `subnet` / `internal_ip` | `subnet`：前缀总量。`internal_ip`：逐个 IP（攻击目标为 /32 或 /128）。 |
| 方向 | `receives` / `sends` | `receives`：发往前缀的流量（入向攻击）。`sends`：从前缀发出的流量（失陷主机、出向攻击）。 |
| 解码器 | 见 §2.3 | 统计哪类流量。选择 `ip` 表示全部 IP 流量；下拉框没有空选项。 |
| 单位 | `pps` / `bps` / `pct` | 包/秒、比特/秒，或该 decoder 占总流量的百分比（1–100；不能与 `ip` 搭配）。 |
| 比较 | `over` / `under` | 高于 / 低于阈值即超阈。 |
| 阈值 | 数值 | 阈值。 |
| 可继承 | 开 / 关 | 子前缀是否继承该规则。 |
| 响应 | 可选 | 覆盖模板的默认响应。 |

出向（`sends`）攻击只使用规则自己的响应，从不回落到模板默认响应；攻击活跃期间其 xDrop / BGP 动作会被跳过（`outbound_block_forbidden`）。请给出向规则配置只含 Webhook 的响应。

阈值页分「模板」和「全部规则」视图。在模板详情表的「响应」列设置规则响应，添加规则抽屉没有该字段；「—（使用默认）」沿用模板的「默认响应」，默认响应中的「无」清除绑定。模板支持「复制」，被前缀使用时不能删除。「全部规则」中新建的是入向、按前缀的 `pps` 或 `bps` 规则，这类规则在控制台只能删除。

### 2.3 Decoder

decoder 列表来自 `shared/decoder/decoder.go`；`ip` 是聚合项，没有自己的计数槽位。

| Decoder | 统计内容 | xDrop |
|---|---|---|
| `ip` | 全部 IP 流量 | 否 |
| `tcp` | 全部 TCP | 是 |
| `tcp_syn` | 置 SYN 且未置 ACK 的 TCP | 是 |
| `tcp_ack` | 置 ACK 且未置 SYN 的 TCP（已建连接的大部分流量） | 是 |
| `tcp_rst` | 置 RST 的 TCP | 是 |
| `tcp_fin` | 置 FIN 的 TCP | 是 |
| `udp` | 全部 UDP | 是 |
| `icmp` | ICMP 与 ICMPv6 | 是 |
| `fragment` | 任何 IP 分片 | 是 |
| `gre` | IP 协议号 47 | 是 |
| `esp` | IP 协议号 50 | 是 |
| `igmp` | IP 协议号 2 | 是 |
| `ip_other` | 上面未列出的 IP 协议 | 否 |
| `bad_fragment` | 死亡之 Ping 类分片（偏移 × 8 + 载荷 > 65535），以及小到放不下 L4 头的首片 | 是 |
| `invalid` | IPv4 IHL < 5、IP 总长度 < 头长度、TCP 数据偏移 < 5 | 是 |

说明：SYN+ACK 报文只计入 `tcp`。异常分片同时计入其协议、`fragment` 和 `bad_fragment`。TCP 标志异常（NULL、XMAS、SYN+FIN）不是 decoder，请用 XDrop 规则匹配。反射攻击（DNS、NTP、memcached 等）也不是 decoder：用 `udp` 加「主源端口」前置条件（§3.3）。同一 IP 已有更具体 decoder 的活跃攻击时，更宽泛 decoder（例如 `ip`）的新攻击会被抑制。

### 2.4 确认、过期与严重度

| 设置（controller 配置中的 `detection.`） | 缺省 | 含义 |
|---|---|---|
| `hard_threshold_confirm_seconds` | 3 | 静态规则攻击确认所需的连续超阈秒数 |
| `dynamic_threshold_confirm_seconds` | 5 | 动态检测的同类设置 |
| `expiry_interval_seconds` | 300 | 流量回落后的倒计时 |
| `expiry_function` | `static` | `dynamic`：倒计时 × (攻击持续时长 / `expiry_scale_base_seconds`)，取值在 1 与 `expiry_max_scale`（缺省 4）之间 |
| `manual_expire_hold_seconds` | 跟随 `expiry_interval_seconds`，最大 86400 | 人工结束攻击后，对同一目标、decoder 和方向压制新告警的时长（0 = 不压制） |
| `max_active_attacks` | 10000 | Active + Expiring 攻击数上限（0 = 不限） |
| `dry_run` | false | 只记录检测结果（`DRY-RUN: would trigger ...`），不创建攻击 |

严重度在攻击确认时按峰值确定：

| 严重度 | 条件 |
|---|---|
| critical | > 1,000,000 pps 或 > 10 Gbps |
| high | > 100,000 pps 或 > 1 Gbps |
| medium | > 10,000 pps 或 > 100 Mbps |
| low | 其他 |

达到 `max_active_attacks` 时，新攻击只有在优先级严格更高时才替换优先级最低的攻击；被替换的攻击计为被驱逐（若它处于 Expiring，会提前执行「攻击结束时」动作）。否则新攻击等待，并计为被抑制。

### 2.5 动态检测

动态检测按节点和前缀学习每周的流量画像，偏离画像时告警。缺省关闭，在 **基线** 页打开。它作用于入向前缀总量（产生 `ip` / `subnet` / `receives` 攻击）。

- **画像：** 168 个槽位，一周中每小时一个（UTC）。每过一小时，把该小时 PPS 和 BPS 的第 95 百分位数用 EWMA（`ewma_alpha`，缺省 0.3）并入该槽位。每个槽位每周最多学习一次。
- **阈值：** 期望值 × (100 + 偏差) / 100。偏差是百分比，从 `deviation_max`（缺省 200，即 3 倍期望值）开始，在 `stable_weeks`（缺省 4）周的样本内线性收窄到 `deviation_min`（缺省 100，即 2 倍期望值）。
- **启用时机：** 槽位学到一个样本后即被使用，因此学满一整周后所有槽位都会生效。此前显示为学习中。
- **下限：** 只有 PPS < `min_pps` **且** BPS < `min_bps`（缺省 100,000 pps 和 1 Gbps）时才忽略流量。高于下限后，PPS 或 BPS 任一超过阈值即算超阈。

状态视图显示每个前缀当前的槽位、期望值、阈值和学习进度。其中的「超限」标记只比较当前流量与阈值，不考虑下限和确认时长。

画像表只显示 PPS，每 30 秒刷新，也可点击 **↻ 刷新**。控制台取值范围：**最大偏差 (%)** 50–500、**最小偏差 (%)** 10–500、**稳定周数** 1–12、**EWMA Alpha** 0.01–0.99。

### 2.6 推荐阈值

与动态检测无关，controller 按最近 1 小时的 P95 × 2 为已启用前缀推荐阈值（`GET /api/baseline`），至少需要 60 个数据点。前缀页显示推荐值；模板详情仅对入向 `ip` 规则（含旧数据中的空 decoder）显示推荐，多个前缀有可用基线时显示区间。推荐值是设置静态规则的起点，不参与检测。

### 2.7 容量上限

| 设置（`ring.`） | 缺省 | 范围 | 含义 |
|---|---|---|---|
| `max_points_per_ip` | 120 | 10–600 | 每个键保留的历史秒数；必须 ≥ 两个确认设置 |
| `max_ips_per_prefix` | 10000 | 100–50000 | 每个前缀跟踪的 IP 数 |
| `max_global_keys` | 100000 | 1000–500000 | 跟踪的 IP 总数 |

达到上限时，新 IP 先替换空闲 5 秒以上的键，否则在新 IP 流量更大时替换最轻的键；Active 和 Confirming 攻击的键受保护。估算内存通过 `xsight_ring_estimated_memory_bytes` 导出。

---

## 3. 响应

### 3.1 响应与动作

响应分为两部分：**攻击检测时**（`on_detected`）和 **攻击结束时**（`on_expired`）。入向攻击使用触发规则的响应，没有则用模板的默认响应；出向攻击只用规则自己的响应。没有响应或响应已停用时，只通知全局 Webhook。

| 动作字段 | 取值 | 说明 |
|---|---|---|
| 动作类型 | Webhook / Shell / BGP / xDrop | BGP 和 xDrop 只在「攻击检测时」下提供；对应的「攻击结束时」动作自动创建（§3.2） |
| 连接器 | 按类型 | xDrop 改用 目标节点（§3.6） |
| 优先级 | 1–10 | 数字小的先执行；决定首个匹配 |
| 运行模式 | 单次 / 周期 / 重试直到成功 | 「攻击结束时」动作只提供 单次 |
| 执行方式 | 自动 / 手动 | **手动 动作永不执行**（§8） |
| 已启用 | 开 / 关 | |
| 前置条件 | 见 §3.3 | 全部满足才执行 |

自动生成的解除/撤回动作不在「攻击结束时」区块列出。动作创建后不能换类型，需要删除后重建。非 Webhook 动作带「首个命中」徽标。

### 3.2 动作何时执行

- **「攻击检测时」**动作在攻击确认时和攻击类型升级时执行。**周期** 动作还会随每次攻击更新执行，约每 5 分钟一次。**重试直到成功** 在后续事件上重试，直到有一次成功。**单次** 每个攻击执行一次。
- **「攻击结束时」**动作在攻击结束、或因容量上限被驱逐时执行。
- **首个匹配：** 对 xDrop、BGP、Shell，每种类型只执行（按优先级）第一个通过全部检查的动作；之后的记为 `first_match_suppressed`。Webhook 动作全部执行。例如：优先级 1 的 xDrop 带前置条件 decoder = `tcp_syn`，优先级 2 的 xDrop 不带前置条件；SYN 洪水用优先级 1，UDP 洪水落到优先级 2。
- **observe / auto：** `action_engine.mode: observe`（缺省）时，所有 xDrop 动作都以 `skip_reason=mode_observe` 跳过。BGP、Webhook、Shell 动作不受这个开关约束：两种模式下都会执行。设为 `auto` 并重启后，xDrop 动作才会创建规则。
- **自动配对：** 在「攻击检测时」下创建 BGP 或 xDrop 动作时，会在「攻击结束时」下创建对应的 BGP 撤回 / xDrop 解封动作。它复制连接器、延迟和目标，随父动作的修改同步，随父动作一起删除，不能直接编辑。
- 每个被跳过的动作都以 `skip_reason` 写入该攻击的动作日志，所以 攻击详情 页能看到某个动作为什么没有执行。

### 3.3 前置条件

| 属性 | 比较对象 | 示例 |
|---|---|---|
| `decoder` | 攻击的 decoder | `eq udp` |
| `attack_type` | 攻击类型（例如 `syn_flood`、`udp_flood`、`dns_reflection`） | `eq syn_flood` |
| `severity` | `critical` / `high` / `medium` / `low` | `in critical,high` |
| `pps` / `bps` | 峰值 | `gt 100000` |
| `domain` | `internal_ip`（单主机）或 `subnet` | `eq internal_ip` |
| `cidr` | 攻击目标的前缀长度 | `eq 32` |
| `node` | 上报该攻击的节点 ID | `in node-a,node-b` |
| `dominant_src_port` / `dominant_dst_port` | flow 样本中出现最多的端口 | `eq 53` |
| `dominant_src_port_pct` / `dominant_dst_port_pct` | 该端口的占比（%） | `gte 80` |
| `unique_src_ips` | 样本中不同源 IP 的个数 | `gt 1000` |

运算符：`eq`、`neq`、`gt`、`gte`、`lt`、`lte`、`in`、`not_in`。基于 flow 的属性需要 flow 样本，没有样本时条件不成立。未知属性一律不成立。

上表使用 API 属性和运算符名；控制台显示「主源端口」等标签，运算符显示为 `=`、`≠`、`>`、`≥`、`<`、`≤`、`in`、`not in`。`carpet_bomb`、`peak_pps`、`peak_bps` 仅 API 可设；`carpet_bomb` 在子网攻击时为 true，只接受 `eq` / `neq`。

### 3.4 Webhook 与 Shell

**Webhook 连接器：** 名称、URL、方法、Headers（JSON 对象）、超时（ms）（1–10000 毫秒；一次调用最多等待 10 秒）、全局、已启用。**全局** Webhook 不必加入响应，就会收到所有攻击事件。请求头的值读回时被遮蔽；编辑时保持遮蔽值不变即可保留原值。**测试** 发送一次测试请求。

**Shell 连接器：** 名称、命令（以 `/` 开头的绝对路径）、默认参数、超时（ms）（1–30000；每个动作约 30 秒封顶）、已启用。动作的「额外参数」追加到默认参数后；支持 `{ip}`、`{prefix}`、`{decoder}`、`{severity}`、`{peak_pps}`、`{attack_id}`、`{dominant_src_port}` 等占位符，未知占位符保存时被拒绝。`pass_stdin`（为 true 时把事件以 JSON 写入脚本标准输入）仅 API 可设；控制台新建为 `false`，编辑时保留原值。Shell 没有「测试」按钮。

Webhook 的「方法」只接受 POST / PUT / PATCH；修改 URL 后须重填所有 header 值，清空整个 Headers 框会删除全部 header。新建 Webhook、XDrop、Shell 连接器恒为启用，只有 BGP 在新建时提供「已启用」开关。连接器页另有「旧版 Webhook（只读）」区块。

### 3.5 BGP（FRR）

**BGP 连接器：** 名称、BGP ASN、vtysh 路径（缺省 `/usr/bin/vtysh`）、描述、已启用。一个连接器同时服务 IPv4 和 IPv6：地址族按每个前缀选择。**测试** 检查能否访问 FRR；**路由表** 显示当前 BGP 表。使用前先在 FRR 中配置好 ASN 和 route-map。

**BGP 动作：** 路由映射（例如 `RTBH`）和 路由保持（分钟）（0–1440 分钟）。

- Controller 在 `router bgp <ASN>` 的对应地址族下执行 `network <目标> route-map <名称>`。单主机攻击按 /32 或 /128 宣告，子网攻击按其前缀宣告。
- 解析到相同前缀、route-map 和连接器的攻击**共用一条路由**。只有最后一个挂载的攻击结束后才撤回路由，延迟取该次宣告期间挂载过的攻击中最长的撤回延迟。
- 延迟期间攻击再次超阈，延迟被取消，路由保留。
- 启动扫描发现的孤立 BGP 路由显示在「缓解」页独立横幅；admin 可用「强制撤回」或「忽略」。
- 全局前缀的攻击从不触发 BGP（没有具体目标）。

### 3.6 xDrop

**xDrop 连接器：** 名称、API 地址（最终的基础 URL，含 API 路径，例如 `https://xdrop.example.com:8000/api/v1`；请求不跟随重定向）、API 密钥（本台 xSight 独立使用的 XDrop v3 机器凭证密钥）、超时（ms）、已启用。

- 超时（ms）：每次请求 XDrop 的等待上限，1–30000 毫秒（缺省 10000）。创建、撤销、强制解除、下发现查都按它等待；越大，强制解除和现查越慢。
- **测试** 核验机器凭证，成功时显示凭证名。
- 仍被动作引用，或名下还有 active / delayed / withdrawing / failed 规则记录的连接器不能删除。
- 连接器已停用：撤销等启用后再做，强制解除会被拒绝。

修改「API 地址」须重填「API 密钥」；地址未变时，密钥留空沿用原值。系统会在基础 URL 后拼接 `/rules`。

**xDrop 动作字段：**

| 字段 | 含义 |
|---|---|
| xDrop 动作 | `Filter L4`（丢弃）/ `Rate Limit`（限速）/ `Unblock`（解封） |
| 匹配字段 | 勾选且适用于该攻击类型的字段作为规则条件；空值不下发。 |
| 协议 | 协议由攻击类型确定，勾选与否结果相同；异常类规则不带协议字段。 |
| 限速 (PPS) | 仅用于 Rate Limit |
| 目标节点 | 使用哪些 XDrop 连接器（空 = 所有已启用连接器）。停用的连接器被跳过；所选全部停用时不下发，也不回落到全部连接器。 |
| 规则保持（分钟） | 攻击结束后本 xSight 继续持有规则的时长。0 = 立即释放。最后一个持有方释放后，XDrop 才删除规则。 |

**下发内容。** 目的 IP 为攻击目标。协议，以及 TCP 标志类 decoder 的 TCP 标志，由攻击的 decoder 决定（例如 `tcp_syn` → `protocol=tcp`、`tcp_flags=SYN,!ACK`；IPv6 ICMP → `icmpv6`）；`bad_fragment` 和 `invalid` 使用 XDrop 的异常匹配。`ip` 和 `ip_other` 攻击被跳过（`decoder_not_xdrop_compatible`）——这类攻击请用 BGP。

**源 IP / 目的端口 / 源端口 只表示允许收窄。** 勾选后，xSight 可以把攻击的头号源 IP、头号目的端口或头号源端口加入规则；这些值取自按攻击协议和标志过滤后的 flow 样本。只有同时满足以下条件，字段才会加入：

- 样本至少 `xdrop_min_sample_packets` 个（缺省 1000；0 关闭此项检查），且
- 该字段的头号取值至少占样本的 `xdrop_narrow_pct` %（缺省 80）。

两个端口都达标时只用源端口。勾选的字段都用不上时，规则不收窄。此时 **Filter L4（丢弃）** 动作会改为**按触发规则的 PPS 阈值做 rate_limit**，让宽泛的规则限速，而不是把发往目标的流量全部丢弃。触发规则不是 PPS 规则时（例如 BPS 规则或动态检测产生的攻击），按宽泛的丢弃规则下发。此兜底不适用于 Rate Limit 动作、`fragment` 和异常类攻击。

**端口分散时拆成多条规则（前 K 名）。** 勾选的端口没有单一主导值，但其前 2..K 个取值合计达到样本的 `xdrop_topk_pct` %（缺省 80；K 最大为 `xdrop_topk_max`，缺省 8）时，xSight 为每个端口建一条规则——一个动作最多 K 条。`xdrop_topk_max: 1` 关闭此功能。每个决定都以 `shape: ...` 说明写在执行日志条目上，例如 `shape: dropped dst_port=35%` 或 `shape: topk dst_port=3 84%`。

**持有与持有方。** XDrop 可以为多个持有方共同保有一条规则。每个创建或加入规则的 xSight「攻击 + 动作」就是一个持有方。xSight 从不给规则设置期限；攻击结束（并过了解封延迟）后，xSight 释放自己的持有，最后一个持有方释放后，XDrop 才删除规则。

**创建失败。** XDrop 没有确认创建时，记录以合成规则号（`failed-create-…`）保留，显示为 **创建失败**。攻击结束后，xSight 只读地向 XDrop 查找对应规则，找到则释放，然后关闭该记录。

admin 也可对创建失败行点击「强制解除」，再确认「收尾」。这只保证 xSight 记录关闭，XDrop 上可能仍有对应规则。

**重试与对账。** 启动后立即、以及之后每 2 分钟，xSight 重试未完成的释放，失败后按 2 / 4 / 8 / 16 分钟退避。活攻击、未到期的延迟、人工覆盖和停用的连接器会被跳过。结果计入 `xsight_xdrop_reconcile_total`。

### 3.7 延迟与强制移除

- **路由保持（分钟）**（BGP）和 **规则保持（分钟）**（xDrop）让缓解在攻击结束后再保持 N 分钟，因为保护一撤攻击往往卷土重来。延迟能跨 controller 重启保留。
- 延迟期间，缓解 显示 **延迟撤回** 和倒计时。对 BGP，再次超阈会取消延迟。对 xDrop，释放在攻击结束后才安排；之后再次超阈会形成新攻击，不会取消旧的延迟释放。
- **强制撤回**（BGP）解绑全部挂载攻击并撤回整条共享路由。「攻击详情」里的「强制移除」只对 admin 显示，要求攻击未结束，日志行为成功的 `on_detected` BGP/xDrop 动作，且有外部规则号和连接器 ID：BGP 撤回整条共用路由，xDrop 则释放本攻击这个动作的持有（确认按钮为「释放」）。
- **强制解除**（xDrop）释放本攻击这个动作的持有；只要还有其他持有方（本 xSight 内或其他系统）持有，规则就保留。要为所有持有方删除规则，请在 XDrop 界面操作。若有进行中的自动释放，可能先等待最多一个连接器超时。
- 强制移除成功后，该制品的自动清理被跳过。

---

## 4. 按功能介绍 Web UI

控制台提供自动 / 浅 / 深三档外观，以及英文 / 中文语言选项。非 admin 用户看到只读页面，写操作控件隐藏或禁用，不能使用连接器「测试」；BGP「路由表」仍可查看。

侧栏可以收起，底部显示「动作」的自动 / 观察模式及说明；活动攻击数与离线节点数徽标每 30 秒刷新。「关于」页显示版本、项目链接和第三方许可证。

| 页面 | 用途 |
|---|---|
| 总览 | 入向流量、活动攻击、在线 / 总节点数；BGP / XDrop 指标包含生效中与延迟撤回项；「攻击 · 24 h 内」包含已结束攻击，另有流量图、前缀排行和节点列表 |
| 流量 | 按节点、前缀、方向与时间范围看曲线；6h / 24h 使用 5 分钟聚合，每桶关闭后数分钟才出现 |
| 攻击 | 进行中与历史攻击；列表用「结束」，详情用「结束攻击」，仅 admin 可结束未结束的攻击 |
| 攻击详情 | 摘要、动作日志、强制移除、流量样本；点击动作日志行打开详情，查看跳过原因和说明 |
| 缓解 | BGP 与 XDrop 两个分区，含状态、倒计时、详情抽屉、执行时间线与 XDrop 下发状态；每 5 秒刷新 |
| 节点 | 添加与删除节点、查看在线和配置状态；每 5 秒刷新；控制台不能编辑描述、模式或启停节点 |
| Flow | 按 Flow 节点配置 Listener 和数据源，查看健康与在线状态；状态每 10 秒刷新 |
| 前缀 | 前缀、父级前缀和阈值模板绑定 |
| 阈值 | 模板、全部规则及默认响应 |
| 响应 | 响应、动作、前置条件与 xDrop / BGP 设置 |
| 基线 | 动态检测参数与画像状态 |
| 连接器 | Webhook / XDrop / Shell / BGP；可用时提供「测试」 |
| 用户 | 账号与角色；修改、停用或删除用户会使其旧令牌失效，修改或删除自己的账号后退出登录 |
| 审计 | 配置变更、强制移除、孤立路由的撤回/忽略/重新提示；手动结束攻击不写审计；每页 50 条 |

**总览布局。** 时间范围可选 15m / 1h / 6h / 24h；可拖动面板换位、用分隔条调整宽度，也可点击「恢复默认布局」。

**流量操作。** 方向可选入向 / 出向 / 双向，时间范围为 1h / 6h / 24h，可切换 PPS / BPS。前缀只筛曲线，卡片与 Top 表不按前缀筛选；Top 表可选 10 / 20 / 50 / 100 条并排序，点击一行按该前缀筛选。筛选条件保存在 URL 中。只有此页可拖选放大、按半窗平移和「重置缩放」。

**键盘读图。** Tab 聚焦图表后，普通图表的读屏提示原文为：「左右方向键逐点读数，Home / End 跳到首末点，Esc 清空读数。」流量页的读屏提示原文为：「左右方向键逐点读数，Home / End 跳到首末点；按 Enter 开始选区，再按 Enter 放大，Esc 取消选区或清空读数。」

**攻击列表。** 每页 50 条，每 5 秒刷新；「进行中 / 已结束 / 全部」带计数，并支持方向、目标 IP 或网段包含匹配；「已结束」可选 24h / 7d / 30d。默认显示进行中，没有进行中攻击时回落到全部。进行中按峰值 PPS 降序，其余按开始时间降序。「压制秒数」可留空用配置默认值，或填 0–86400 的整数，0 表示不压制；检测不再看到攻击时提前解除，controller 重启也清除压制。

**节点操作。** 「添加节点」填写节点 ID、模式、描述、API 密钥；ID 不能含 `/`，也不能是 `.` 或 `..`。可「生成」和「复制」密钥，抽屉提供 `config.yaml` 片段，保存后不再显示密钥。节点详情显示 XDP 采集口和采样率、最近 15 分钟流量；删除节点连带删除其 Flow Listener 和数据源，已入库流量保留。配置状态为「已同步 / 失败 / 待下发 · 落后 {n}」。

**Flow 操作。** Listener 地址格式为 `:port` 或 `host:port`；协议为 `auto` / `sflow` / `netflow` / `ipfix`。数据源的设备 IP 不接受 CIDR，采样模式为 `auto` / `force` / `none`；60 秒无记录时显示「离线」。健康指标有「解码错误 / 未注册设备 / 模板缺失」；「数据源 {count}」打开数据源抽屉。admin 可用行内开关启停，删除 Listener 会连带删除其数据源。

**用户与审计。** 控制台不能修改已有用户名；新用户恒为启用，默认角色 viewer。最后一个启用的 admin 不能删除、降级或停用，后端返回 409 `at least one enabled admin is required`，前端也有相应保护。审计可按实体类型、用户和本地起止时间筛选（例如 `2026-10-27 08:00`），点击行打开详情；每页请求 51 条、偏移步长 50，以判断是否还有下一页。

**缓解状态：**

| 状态 | 含义 |
|---|---|
| 生效中 | BGP 已宣告；XDrop 已接受规则，各节点状态需打开「下发」查看 |
| 延迟撤回 | 攻击已结束，等待路由或规则保持期结束 |
| 失败 | BGP 移除失败或 XDrop 释放未完成、将重试；「创建失败」记录可在攻击结束后自动关闭，admin 也可手动「收尾」 |

孤立 BGP 路由不在状态表中，单列在顶部「发现 {count} 条孤立 BGP 路由」横幅，可「强制撤回」或「忽略」。展开「已忽略的孤立路由 {count}」后可「重新提示」。除创建失败的合成记录外，XDrop「下发」在打开抽屉时现查一次，也可「刷新」；连接器停用时「强制解除」不可用。

在「XDrop 规则」中，「共用」表示本 xSight 为多个攻击与动作持有该规则。「强制解除」的确认文案为：

- 共用规则：“释放本攻击这个动作的持有？本 xSight 还有 {n} 个其他持有方，规则保留。”
- 其他规则：“释放本攻击这个动作的持有？其他系统可能仍持有该规则。”

---

## 5. 运维

### 5.1 指标

HTTP 端口上的 `GET /metrics`（无认证；请在网络层限制）。Prometheus 任务示例：

```yaml
scrape_configs:
  - job_name: xsight-controller
    static_configs:
      - targets: ["192.0.2.10:8080"]
```

全部 23 个 xSight 指标（`controller/internal/metrics/metrics.go`）：

| 指标 | 类型 | 标签 | 含义 / 告警建议 |
|---|---|---|---|
| `xsight_attacks_active` | gauge | — | 当前跟踪的攻击数 |
| `xsight_attacks_created_total` | counter | — | 已创建的攻击数 |
| `xsight_attacks_suppressed_total` | counter | — | 因 `max_active_attacks` 被压制的新攻击；非零 → 调高上限 |
| `xsight_attacks_evicted_total` | counter | — | 因 `max_active_attacks` 被驱逐的攻击；非零 → 调高上限 |
| `xsight_action_executions_total` | counter | `action_type`, `status` | 动作结果（`success`、`failed`、`timeout`、`skipped`、`scheduled`）；对 `failed` 告警 |
| `xsight_action_skip_total` | counter | `skip_reason` | 被跳过的动作；`mode_observe` 表示 xDrop 未开启，`decoder_not_xdrop_compatible` 表示 xDrop 被用在 `ip` 攻击上 |
| `xsight_action_precondition_lookup_errors_total` | counter | — | 查询前置条件失败的次数；应保持 0 |
| `xsight_action_queue_total` | counter | `outcome` | `full`（事件队列背压）或 `drain_timeout` |
| `xsight_scheduled_actions_recovered_total` | counter | `outcome` | 启动时恢复的延迟任务；`executing_retried` > 0 表示有任务曾被中断 |
| `xsight_scheduled_actions` | gauge | `status` | 按状态统计的延迟任务 |
| `xsight_vtysh_ops_total` | counter | `operation`, `result` | FRR 宣告 / 撤回结果；对 `failed` 告警 |
| `xsight_bgp_announcements` | gauge | `status` | 按状态统计的 BGP 路由；`orphan` > 0 需要查看 |
| `xsight_bgp_withdrawing_reconcile_total` | counter | `outcome` | 卡住的 BGP 撤回的重试；对 `list_error` 告警 |
| `xsight_bgp_announcing_reconcile_total` | counter | `outcome` | 对待确认宣告的 FRR 核对；对 `absent`、`probe_error`、`state_write_error` 告警 |
| `xsight_bgp_stale_writes_total` | counter | `op` | 因公告已有更新代次或已到终态而未生效的 BGP 状态写入 |
| `xsight_xdrop_rules` | gauge | `status` | 按状态统计的 xDrop 规则记录 |
| `xsight_xdrop_reconcile_total` | counter | `outcome` | xDrop 释放重试；对 `failed`、`list_error`、`state_write_error` 上升，以及任何 `synthetic_unrecoverable`、`synthetic_identity_not_found`、`late_create_leak`（XDrop 上可能残留规则）告警 |
| `xsight_state_write_failures_total` | counter | `op` | 重试后仍失败的状态写入；应保持 0 |
| `xsight_startup_cleanup_total` | counter | `kind`, `outcome` | 清理 controller 停机期间结束的攻击；对 `failed` 告警 |
| `xsight_ended_sweep_total` | counter | `kind`, `outcome` | 每个攻击结束后的补查；对 `failed` 告警 |
| `xsight_config_publish_failures_total` | counter | `stage` | 配置已保存，但重建或推送到节点失败 |
| `xsight_grpc_identity_rejects_total` | counter | `stream` | 因节点未完成握手而被拒的上报 |
| `xsight_ring_estimated_memory_bytes` | gauge | — | ring buffer 的估算内存 |

从数据库读取的 gauge 在抓取时采集，超时 5 秒；数据库慢时，这次抓取中会缺少它们。

### 5.2 日志

两个程序都把日志写到标准输出（systemd 下进入 journal）。没有日志级别设置。常用日志行：

| 日志行 | 含义 |
|---|---|
| `xsight-controller running (mode=...)` | controller 已启动；显示 observe / auto |
| `reporter: handshake accepted` / `handshake rejected: <原因>` | 节点注册与密钥核对 |
| `reporter: received ConfigPush version=...` | 节点收到新的监控配置 |
| `tracker: attack ... expiring` / `back to active` | 攻击状态变化 |
| `DRY-RUN: would trigger ...` | `dry_run: true` 下的检测结果 |
| `WARNING: TimescaleDB not available` | 数据库缺少 TimescaleDB |

### 5.3 数据保留

| 键（`retention.`） | 代码缺省 | 数据 |
|---|---|---|
| `ts_stats_days` | 7 | 每秒统计 |
| `ts_stats_compress_days` | 1 | 压缩早于此天数的统计 |
| `ts_stats_cagg_days` | 90 | 5 分钟聚合（6H / 24H 图表） |
| `flow_logs_days` | 7 | flow 样本（「流量样本」、基于 flow 的前置条件） |
| `flow_logs_compress_days` | 1 | 压缩早于此天数的 flow 样本 |
| `attacks_days` | 90 | 已结束的攻击 |
| `audit_log_days` | 180 | 审计日志 |
| `interval_hours` | 24 | 内置清理器的运行间隔 |

`0` 表示永久保留。`ts_stats` 是最大的表；缩短保留期可减少磁盘占用。块大小（`ts_stats_chunk_days`、`flow_logs_chunk_days`，0 = 自动）决定旧数据删除的精细程度。

### 5.4 重启与升级

- 重启 controller 不会丢失攻击、延迟和缓解：延迟任务重新计时，中断的工作被完成，期间结束的攻击被清理，活跃攻击被恢复。
- 请同时升级 controller 和各节点。
- 升级时若仍有管理员账号使用旧的默认密码，启动会停下，直到设置 `auth.initial_admin_password`；之后所有用户需重新登录。
- 修改 `auth.api_key` 会让所有用户退出登录。
- `xsight-controller -config <文件> -migrate` 执行数据库迁移后退出。
- 停止 node 后 XDP 仍挂载、BPF map 仍固定，重启即可继续；`xsight-node -config <文件> -unload` 卸下 XDP。`SIGHUP` 重新加载 `sample_bytes` 和 `upstream_sample_rate`；node 的其他修改需要重启。

### 5.5 用户与审计

角色：`admin` 可以修改一切；`viewer` 和 `operator` 只读。所有登录失败返回同一个错误；连续失败会被限速（每 15 分钟内每用户 + 来源 5 次、每来源 20 次），返回 429。审计日志记录配置变更、强制移除及孤立路由撤回/忽略/重新提示的用户与时间；手动结束攻击不写审计。密码和节点 API 密钥不写入审计。最后一个启用的 admin 不能删除、降级或停用（409）。

---

## 6. 排障

### 6.1 节点

| 现象 | 原因 | 检查 |
|---|---|---|
| `handshake rejected: node not found` | Node ID 未注册 | **节点**：用完全相同的 ID 添加节点 |
| `handshake rejected: invalid api_key` | `auth.node_api_key` 与为该节点注册的密钥不同 | 使用节点专用密钥，而不是 controller 的 `auth.api_key` |
| `handshake rejected: node disabled` | 节点被停用 | 用 `PUT /api/nodes/<id>` 和 `{"enabled":true}` 重新启用；控制台无启停控件 |
| 节点离线 | 最近 10 秒没有上报 | node 服务是否运行、TCP 50051 是否可达、node 日志 |
| 配置状态「待下发 · 落后 {n}」/ 漂移增大 | 推送到不了节点 | 到 50051 的网络、node 日志中的 `apply ConfigPush failed` |
| 在线但没有流量（XDP） | 没有被监控前缀，或镜像没有送到 | 添加前缀；确认接口收到镜像流量 |
| 在线但没有流量（Flow） | 没有 Listener 或数据源，或导出方地址与注册的设备 IP 不同 | **Flow**；未注册的导出方会被忽略 |

### 6.2 检测

| 现象 | 原因 | 检查 |
|---|---|---|
| 没有攻击 | 没有绑定模板、阈值过高、方向或 decoder 不对 | 前缀 → 模板绑定；规则阈值；流量 |
| 流量超阈却没有攻击 | `dry_run: true`，或达到 `max_active_attacks` | controller 日志、`xsight_attacks_suppressed_total` |
| 预期的 `ip` 攻击没出现 | 该 IP 上已有更具体 decoder 的活跃攻击 | 攻击页 |
| 动态检测从不触发 | 未启用、槽位仍在学习，或同时低于 `min_pps` 和 `min_bps` | 基线 状态 |

### 6.3 动作

| 现象 | 原因 | 检查 |
|---|---|---|
| 动作日志里什么都没有 | 没有绑定响应、响应已停用，或 执行方式 = 手动 | 模板默认响应 / 规则响应；动作的 执行方式 |
| `mode_observe` | `action_engine.mode` 为 `observe` | 设为 `auto` 并重启 |
| `precondition_not_matched` | 某个前置条件不成立（说明中写明是哪个） | 前置条件；基于 flow 的条件需要样本 |
| `first_match_suppressed` | 同类型更靠前的动作已执行 | 优先级 |
| `outbound_block_forbidden` | 对出向攻击使用 xDrop / BGP | 出向规则请用 Webhook / Shell |
| `decoder_not_xdrop_compatible` | 对 `ip` / `ip_other` 攻击使用 xDrop | 改用 BGP，或使用具体 decoder 的规则 |
| `connector_disabled` / `no_connector` | 连接器停用或未设置 | 连接器 |

### 6.4 BGP

| 现象 | 原因 | 检查 |
|---|---|---|
| 宣告失败 | FRR 未运行、`bgpd` 未开、route-map 不存在、无权执行 vtysh | `vtysh -c "show route-map"`；执行日志文字；`xsight_vtysh_ops_total` |
| 攻击结束后路由还在 | 仍有其他攻击挂载、延迟未到，或连接器已停用 | 缓解 抽屉；启用连接器 |
| 孤立 BGP 路由 | FRR 中发现未受跟踪的路由，可能是遗留状态或由其他系统管理 | 在 缓解 撤回或忽略 |

### 6.5 xDrop

| 现象 | 原因 | 检查 |
|---|---|---|
| 没有创建规则 | observe 模式、decoder 闸门、目标全部停用、URL 或密钥错误 | 动作日志；连接器 **测试**；API 地址 必须包含 API 路径 |
| 规则比预期宽 / 是 rate_limit 而不是 drop | 样本不够或没有主导取值 | 动作日志中的 `shape:` 说明；§3.6 |
| 一个动作产生多条规则 | 前 K 名拆分 | `shape: topk` 说明；`xdrop_topk_max` |
| 规则没有删除 | 延迟未到、还有其他持有方、连接器停用、释放失败 | **共用** 标记、连接器状态、`deferred N: …` 说明、`xsight_xdrop_reconcile_total` |
| 创建失败 | 创建结果未知 | 攻击结束后自动关闭；admin 也可手动「收尾」，但 XDrop 上可能仍有规则 |

### 6.6 Controller 与指标

| 现象 | 原因 | 检查 |
|---|---|---|
| controller 启动即退出 | 配置值非法、API 密钥 为 `CHANGE_ME`、空库未设管理员密码、SQLite、数据库不可达 | 最后一行日志会写明是哪个键 |
| 某个设置不起作用 | 键拼错（被静默忽略），或属于不起作用的键 | 对照 `controller/config.example.yaml` |
| `/metrics` 缺少 gauge | 抓取时数据库查询超时 | PostgreSQL 负载 |

---

## 7. 典型场景

### 7.1 UDP 反射

规则：`subnet`、入向、`udp`、`pps`，例如 1,000,000。响应：BGP 动作（route-map `DIVERT`，路由保持（分钟）5），加一个勾选 目的 IP 和 源端口、前置条件为 `domain eq internal_ip` 的 xDrop Filter L4 动作。要只针对某类反射，加上 `dominant_src_port eq 53`（DNS）、`123`（NTP）、`11211`（memcached）、`1900`（SSDP）、`389`（CLDAP）或 `19`（chargen）。如果你自己运行这类服务，优先用 Rate Limit 而不是 Filter L4。

### 7.2 SYN 洪水

规则：`tcp_syn`、`pps`，按服务器能力设定。xDrop 规则自动带上 `tcp_flags=SYN,!ACK`。先用一个 xDrop Rate Limit 动作压住洪水；可再加一个优先级数字更大的 BGP RTBH 动作，配上 `severity eq critical` 之类的前置条件。服务器上保持 `net.ipv4.tcp_syncookies=1`。

### 7.3 地毯式轰炸

`subnet` 规则能抓到分散在大量地址上的攻击。BGP 动作不加前置条件（宣告整个前缀），xDrop 动作加 `domain eq internal_ip`，使 xDrop 只处理单主机攻击；在控制台用「域 = subnet」（API：`domain eq subnet`）可显式选中子网攻击。

### 7.4 出向攻击

规则：方向 `sends`、decoder `ip`、`bps`，并为它配置只含 Webhook 的专用响应。xDrop 和 BGP 从不作用于活跃的出向攻击。

### 7.5 误报处理

打开 **缓解**，选中条目，使用 **强制撤回**（BGP）或 **强制解除**（xDrop）。然后调高规则阈值或加上前置条件。

---

## 8. 已知限制

- **手动执行不会运行。** 动作编辑器选择「执行方式 = 手动」时提示：「手动动作不会执行（尚无手动触发）。」
- **未知配置键被忽略。** 两个 YAML 文件中拼错的键都会被接受、没有警告。`log.level`、`action_engine.xdrop_api`、`action_engine.xdrop_api_key` 和 `bpf.path` 会被读取，但不起作用。
- **节点与 controller 之间没有 TLS。** gRPC 为明文，握手之后按 Node ID 接受上报；请把 50051 端口限制在可信网络或隧道内。
- **Node 未实现 `CriticalEventStream`。**
- **未实现 SQLite。**
- **XDP 模式需要 x86_64 和 Linux 5.18+。**
- **xDrop 期限。** xDrop 尚未提供按持有方的期限时，与其他系统共持同一条规则，可能使对方设置的期限失效。
- **没有 xDrop 孤儿扫描。** 本地记录已丢失的规则需要在 XDrop 界面中删除。
