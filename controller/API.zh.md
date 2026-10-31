# xSight Controller API 参考手册

基础 URL: `http://<host>:8080/api`

## 认证

除 `/api/login` 外，所有 `/api/*` 端点都需要以下认证方式之一：

- **API Key**: `X-API-Key: <key>` 请求头（在 `config.yaml` 的 `auth.api_key` 中配置）
- **JWT Bearer**: `Authorization: Bearer <token>` 请求头（通过 `/api/login` 获取）

REST API key 是管理员机器身份。JWT 用户中只有 `admin` 可发送非 GET 请求；`viewer`、旧值 `operator` 及其他角色均只读。被拒绝的写请求在进入业务 handler 前返回 403 `{"error":"admin role required"}`。

非空 `X-API-Key` 优先于 JWT；即使同时带有效 JWT，错误的 key 仍返回 401 `invalid API key`。两个认证头都没有时返回 401 `missing authentication`。

JWT 有效期上限为 24 小时。每个 JWT 认证请求都查库，并使用当前用户名和角色。任何用户更新（包括密码、角色、启停状态或用户名）、停用或删除都会立即使旧令牌失效。查库故障返回 503 `authentication backend unavailable`；用户不存在、停用或修订号过期返回 401 `invalid token`。

### `GET /metrics` — Prometheus 抓取端点（无需认证）

暴露所有 v1.2 / v1.2.1 埋点指标（vtysh 操作、动作执行、动作跳过、调度动作恢复结果、当前 BGP 公告 / xDrop 规则 / 调度动作按状态的 gauge、攻击追踪计数器），以及默认的 Go runtime 与 process 指标。

**按惯例不做认证**（与 kube-apiserver / etcd / Prometheus 自身一致）——依赖网络层隔离。完整指标目录见 [用户指南 § 5.1 指标](../docs/user-guide.zh.md#51-指标)。

---

## 登录

### POST /api/login

用户认证，获取 JWT 令牌。

JSON 无效或缺少必填登录字段时返回 400 `username and password required`；令牌生成失败返回 500 `token generation failed`。

未知用户、停用账号、错误密码及登录查库错误均返回相同的 401 `{"error":"invalid credentials"}`。登录采用两个固定的 15 分钟窗口：（用户名，来源地址）最多 5 次，来源地址总计最多 20 次。只使用连接的远端地址，忽略代理头。超限返回 429 `{"error":"too many login attempts"}`，`Retry-After` 给出剩余秒数。成功登录清除用户名/地址桶并返还地址额度。限速仅在单个 Controller 实例内生效；NAT 和反向代理后的客户端共享地址桶。

| 字段 | 类型 | 说明 |
|------|------|------|
| `username` | string | **必填。** |
| `password` | string | **必填。** |

**响应：**

```json
{
  "token": "eyJhbG...",
  "user": { "id": 1, "username": "admin", "role": "admin" }
}
```

---

## 用户管理

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/users` | 列出所有用户 |
| POST | `/api/users` | 创建用户 |
| PUT | `/api/users/:id` | 更新用户 |
| DELETE | `/api/users/:id` | 删除用户 |

PUT 降级或停用最后一个启用的 `admin`，或 DELETE 删除该账号，返回 409 `at least one enabled admin is required`。被拒请求不写入、不产生审计，现有令牌不失效；创建用户不做此检查。

### 创建用户 -- POST /api/users

| 字段 | 类型 | 说明 |
|------|------|------|
| `username` | string | **必填。** |
| `password` | string | **必填。** |
| `role` | string | `admin` 或 `viewer`（默认：`viewer`）。取值不校验：其他字符串照样入库，除 `admin` 外的角色一律只读。 |

创建时不接收 `enabled`，新用户恒为启用。

### 更新用户 -- PUT /api/users/:id

| 字段 | 类型 | 说明 |
|------|------|------|
| `username` | string | 新用户名 |
| `password` | string | 新密码。修改后该用户已有令牌立即失效；审计记录 `password_changed`。 |
| `role` | string | `admin` 或 `viewer`（与创建时一样不校验） |
| `enabled` | bool | 启用/禁用账号 |

空或省略的 `username`、`role`、`password` 沿用旧值；密码先去除首尾空白再哈希。每次成功 PUT（包括 `{}`）都会更新 `updated_at`，使现有令牌失效。

---

## 节点管理

<!-- fe-q0:B9 -->
`GET /api/nodes` 新增 `last_stats_at`（RFC3339 时间戳）；尚未收到统计时省略。

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/nodes` | 列出所有节点（包含 `online` 在线状态） |
| POST | `/api/nodes` | 注册节点 |
| GET | `/api/nodes/:id` | 获取节点详情 |
| PUT | `/api/nodes/:id` | 更新节点 |
| DELETE | `/api/nodes/:id` | 删除节点（级联删除 Flow Listener/Source） |
| GET | `/api/nodes/:id/status` | 节点详细状态（在线、配置漂移、Flow 指标） |

### 创建节点 -- POST /api/nodes

| 字段 | 类型 | 说明 |
|------|------|------|
| `id` | string | **必填。** 节点标识符（如 `hk-mirror-01`） |
| `api_key` | string | **必填。** gRPC 认证共享密钥 |
| `description` | string | 可读描述 |
| `mode` | string | `xdp`（默认）或 `flow` |

新节点恒为启用；创建时忽略 `enabled`。

### 更新节点 -- PUT /api/nodes/:id

| 字段 | 类型 | 说明 |
|------|------|------|
| `description` | string | 空串或省略沿用旧值，不能用空串清空。 |
| `mode` | string | `xdp` 或 `flow` |
| `enabled` | bool | |

### 节点状态 -- GET /api/nodes/:id/status

<!-- fe-q0:B7 -->
可选 `interfaces` 列出最近一次已接受握手的网口名；可选 `capture: [{interface, upstream_sample_rate}]` 按网口名升序列出最近上报的采样率；整数 `upstream_sample_rate` 为节点上报值。空网口名不记录。握手接受时整组覆盖 interfaces 并清空 capture；离线后旧值保留到下次握手。空集合省略。

**响应**包含：`id`, `mode`, `online`, `config_status`, `delivery_version_current`, `delivery_version_applied`, `drift`, `last_ack_at`, `last_stats_at`, `stats_age_seconds`, `connected_at`, `uptime_seconds`, `flow_metrics`, `source_statuses`, `listener_statuses`。

节点最近一次统计上报在 10 秒内即 `online`。空闲的 flow 节点每秒发一次心跳上报，没有流量也保持在线。`source_statuses` 里，flow 来源 60 秒收不到记录即显示为不活跃。只有节点报告「应用当前、尚未应用的版本失败」时 `config_status` 才是 `failed`；推送发不出去时保持 `pending`。`last_ack_at` 是最后一次成功应用的时间。

---

## 前缀管理

监控的 IP 前缀（子网），用于流量监控和阈值检测。

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/prefixes` | 列出所有前缀（包含父子层级关系） |
| POST | `/api/prefixes` | 创建监控前缀 |
| GET | `/api/prefixes/:id` | 获取前缀详情 |
| PUT | `/api/prefixes/:id` | 更新前缀 |
| DELETE | `/api/prefixes/:id` | 删除前缀 |

### 创建前缀 -- POST /api/prefixes

| 字段 | 类型 | 说明 |
|------|------|------|
| `prefix` | string | **必填。** CIDR 格式（如 `198.51.100.0/24`）。全局用 `0.0.0.0/0`，不允许 `::/0`。 |
| `parent_id` | int | 父前缀 ID，用于层级结构 |
| `threshold_template_id` | int | 关联阈值模板 |
| `name` | string | 显示名称 |
| `ip_group` | string | IP 分组标签 |

IPv6 缺省路由会被拒绝（400，提示改用全局 IPv4 前缀）；IPv4 映射的 IPv6 前缀返回 **400** `Use IPv4 notation for IPv4-mapped prefixes`。两项检查在更新时同样适用。

### 更新前缀 -- PUT /api/prefixes/:id

所有字段可选。支持 `prefix`, `name`, `ip_group`, `parent_id`, `threshold_template_id`, `enabled`。将 `parent_id` 或 `threshold_template_id` 设为 `null` 可清除关联。

创建和更新时，`0.0.0.0/0` 绑定的模板若其默认响应或任一规则响应含 xDrop / BGP 动作，返回 **400**。更新时按改完之后的结果检查：改完仍是 `0.0.0.0/0`、且仍绑定这种模板，更新就被拒，只改名也不行。已经存在这种绑定的全局前缀，可以解绑模板（`threshold_template_id` 设为 `null`）或改掉模板里那些响应。

创建和更新时，非 null 的 `parent_id` 若造成环或指向已有环，返回 **400**，错误为 `parent_id would create a cycle`。创建和更新时父 ID 不存在也返回 **400**，错误为 `parent_id not found`。被拒绝的请求不写入、不发布配置、不产生审计记录。省略 `parent_id` 或设为 null 时不进行父链预检。

---

## 阈值模板

可复用的阈值规则集，可分配给多个前缀。

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/threshold-templates` | 列出所有模板 |
| POST | `/api/threshold-templates` | 创建模板 |
| GET | `/api/threshold-templates/:id` | 获取模板详情（含规则和关联前缀）：`{template, rules, prefixes_using}` |
| PUT | `/api/threshold-templates/:id` | 更新模板 |
| DELETE | `/api/threshold-templates/:id` | 删除模板（若被前缀使用则失败） |
| POST | `/api/threshold-templates/:id/duplicate` | 复制模板（含所有规则） |
| GET | `/api/threshold-templates/:id/rules` | 列出模板中的规则 |
| POST | `/api/threshold-templates/:id/rules` | 在模板中创建规则 |

### 创建模板 -- POST /api/threshold-templates

| 字段 | 类型 | 说明 |
|------|------|------|
| `name` | string | **必填。** |
| `description` | string | |
| `response_id` | int | 可选，模板默认响应策略 |

### 更新模板 -- PUT /api/threshold-templates/:id

| 字段 | 类型 | 说明 |
|------|------|------|
| `name` | string | |
| `description` | string | |
| `response_id` | int/null | 模板默认响应策略。设为 `null` 清除。全局前缀不能使用含 xDrop/BGP 的响应。 |

省略的字段沿用原值。请求体不是合法 JSON 时返回 **400**。

模板含 `sends` 规则时，把含 xDrop/BGP 动作的响应设为默认响应会返回 400 `Template has outbound (sends) rules — cannot use responses containing xDrop/BGP actions as default`。PUT 不拒绝空 `name`。

### 复制模板 -- POST /api/threshold-templates/:id/duplicate

| 字段 | 类型 | 说明 |
|------|------|------|
| `name` | string | 副本名称（默认：原名 + " (Copy)"） |

复制在同一事务内保留默认响应以及每条规则的响应覆盖、方向、阈值和启用状态；不复制前缀绑定，也不复制响应对象本身。返回 HTTP 201 `{id, name}`。

### 创建模板规则 -- POST /api/threshold-templates/:id/rules

| 字段 | 类型 | 说明 |
|------|------|------|
| `domain` | string | `internal_ip` 或 `subnet`（默认：`internal_ip`） |
| `direction` | string | `receives` 或 `sends`（默认：`receives`） |
| `decoder` | string | 协议过滤。可用：`ip`（L3 聚合）、`tcp`、`tcp_syn`、`udp`、`icmp`、`fragment`、`tcp_ack`、`tcp_rst`、`tcp_fin`、`gre`、`esp`、`igmp`、`ip_other`、`bad_fragment`、`invalid`。缺省：`""`（全部流量）。语义见用户指南。 |
| `unit` | string | `pps`（默认）、`bps` 或 `pct`（占比百分比）。`pct` 需指定具体 decoder。 |
| `comparison` | string | `over` 或 `under`（默认：`over`） |
| `value` | int | `pps`/`bps` 时 >= 0；`pct` 时范围 1-100。模板规则 `comparison=over` 且 `value=0` 表示 over 0，不是取消继承；只有逐前缀覆盖的 0 才表示取消继承。此接口对小数静默截断（1.5 存为 1），而 `POST /api/thresholds` 对同样的值返回 400。 |
| `inheritable` | bool | 子前缀是否继承此规则（默认：`true`） |
| `response_id` | int | 可选，此规则的覆盖响应策略 |

创建时不接收 `enabled`，新规则恒为启用。

---

## 阈值规则（逐前缀覆盖）

逐前缀的阈值规则，覆盖或补充模板规则。

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/thresholds` | 列出所有阈值规则。过滤：`?prefix_id=N` |
| POST | `/api/thresholds` | 创建逐前缀阈值 |
| GET | `/api/thresholds/:id` | 获取阈值详情 |
| PUT | `/api/thresholds/:id` | 更新阈值 |
| DELETE | `/api/thresholds/:id` | 删除阈值 |
| PUT | `/api/threshold-rules/:id` | 更新模板规则（同一处理器） |
| DELETE | `/api/threshold-rules/:id` | 删除模板规则（同一处理器） |

### 创建阈值 -- POST /api/thresholds

使用模板规则的字段，但 `POST /api/thresholds` 的 `unit`、`comparison`、`domain` 三字段必填，在此接口没有缺省值。另有两处缺省与模板规则不同：省略 `inheritable` 即为 `false`；省略 `direction` 会存成空串而不是 `receives`，请显式传 `direction`。另有：

| 字段 | 类型 | 说明 |
|------|------|------|
| `prefix_id` | int | 目标前缀。`prefix_id` 与 `template_id` 必须且只能设一个（数据库约束）；逐前缀规则传 `prefix_id`。 |
| `response_id` | int/null | 此规则的覆盖响应策略 |

所有模板规则的校验同样适用（枚举、数值范围、方向、decoder/unit 组合、全局前缀约束）。两个阈值 PUT 路由均合并更新，省略字段沿用旧值；校验作用于合并后的整行，含存量坏值。规则归属（`template_id` / `prefix_id`）不能改：PUT 里传了也会被忽略，保留原值。

对于 `PUT /api/thresholds/:id` 和 `PUT /api/threshold-rules/:id`，省略 `response_id` 保留已有绑定，显式 `null` 清除绑定，整数 ID 替换绑定。

---

## 响应策略

响应策略定义攻击检测或过期时执行的动作。

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/responses` | 列出所有响应策略 |
| POST | `/api/responses` | 创建响应策略 |
| GET | `/api/responses/:id` | 获取响应策略（含丰富的动作信息）：`{response, actions}`；每个动作另带 `connector_name`、`connector_id`、`target_node_ids`、`xdrop_fields`、`xdrop_rate_limit` |
| PUT | `/api/responses/:id` | 更新响应策略 |
| DELETE | `/api/responses/:id` | 删除响应策略（被模板或阈值引用时失败） |

### 创建响应策略 -- POST /api/responses

| 字段 | 类型 | 说明 |
|------|------|------|
| `name` | string | **必填。** |
| `description` | string | |
| `enabled` | bool | 默认：`true` |

### 更新响应策略 -- PUT /api/responses/:id

合并更新：省略的字段和 `null` 都沿用原值。`name` 为空返回 **400** `name is required`；`description` 传空串即清空。

---

## 响应动作

响应策略中的动作。每个动作有类型、触发阶段和运行模式。

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/responses/:id/actions` | 列出响应策略的动作 |
| POST | `/api/responses/:id/actions` | 创建动作 |
| PUT | `/api/actions/:id` | 更新动作 |
| DELETE | `/api/actions/:id` | 删除动作 |

### 创建/更新动作

只要任一 `sends` 规则显式引用该响应，创建或编辑 xDrop/BGP 动作均返回 HTTP 400，包括停用规则和未绑定前缀的模板规则。PUT 停用动作也执行此检查。全局前缀校验优先；Webhook 和 Shell 不受影响。整改历史组合时，可先清除规则的 `response_id` 或将方向改回 `receives`。

| 字段 | 类型 | 说明 |
|------|------|------|
| `action_type` | string | **必填。** `xdrop`、`bgp`、`webhook` 或 `shell`；拒收已弃用的 `xdrop_api`。 |
| `trigger_phase` | string | **必填。** `on_detected` 或 `on_expired`（否则返回 400 `trigger_phase must be on_detected or on_expired`）。`on_expired` 仅接受 `run_mode=once` 或空运行模式。 |
| `run_mode` | string | 可省略：`once`、`periodic`、`retry_until_success` 或 `""`。创建时省略会存为 `""`；在 `on_detected` 上，每次 confirmed/type_upgrade/updated 事件均执行、不按 once 去重（类似 periodic）；在 `on_expired` 上视同 once。PUT 省略沿用旧值。 |
| `period_seconds` | int | `periodic` 运行模式的间隔秒数 |
| `execution` | string | `automatic` 或 `manual`。设为 `manual` 的动作永远不会执行（目前没有手动触发入口）；其他值（含省略）都自动执行。 |
| `priority` | int | 数值越小优先级越高 |
| `enabled` | bool | 默认：`true` |
| `connector_id` | int | **webhook/shell/bgp 必填。** 使用的连接器 |
| `target_node_ids` | []int | xDrop 连接器 ID 列表（仅 xDrop 类型） |
| `xdrop_action` | string | **xDrop 必填：** `filter_l4`, `rate_limit` 或 `unblock` |
| `xdrop_custom_payload` | object | 仅 xDrop：v3 规则字段，包括匹配字段及 `rate_limit`。`filter_l4` / `rate_limit` 至少要有一个匹配字段（`dst_ip`、`src_ip`、`dst_port`、`src_port` 或 `protocol`）；`rate_limit` 还要有正的 `rate_limit`。`{变量}` 必须是支持的模板变量，未知名字会被拒。`claim_ref` 由 xSight 写入；`source`、`expires_in`、未知字段及空值被丢弃。协议由攻击类型确定。归一化说明（`dropped:` / `protocol pinned:` / `shape:`）写入成功执行日志的 `error_message`，不改变其状态。 |
| `shell_extra_args` | string | 仅 Shell：传递给命令的附加参数。`{变量}` 的校验同 `xdrop_custom_payload`。 |
| `unblock_delay_minutes` | int | 仅 xDrop filter_l4/rate_limit：N 分钟后自动解封（0-1440） |
| `bgp_route_map` | string | 仅 BGP：**on_detected 必填。** 黑洞注入使用的 route-map 名称 |
| `bgp_withdraw_delay_minutes` | int | 仅 BGP：攻击结束后延迟 N 分钟才撤回（0-1440）。多个共享同一公告的攻击下，单次 announce cycle 的有效延迟 = 所有攻击 `delay_minutes` 的 MAX——详见 [architecture.zh.md § BGP 执行](../docs/architecture.zh.md#bgp-执行) |

PUT 不能修改 `action_type`，否则返回 400 `cannot change action_type via PUT — delete this action and create a new one instead`。`bgp_route_map` 只接受字母、数字、`_`、`-`、`.`。直接删除自动生成的子动作返回 400；删除父动作会连带删除配对子动作。

> **xDrop decoder 兼容性：** 攻击 decoder 在兼容名单（`tcp`、`tcp_syn`、`tcp_ack`、`tcp_rst`、`tcp_fin`、`udp`、`icmp`、`fragment`、`gre`、`esp`、`igmp`、`bad_fragment`、`invalid`，共 13 个）中时，xDrop 动作才会下发。decoder 为 `ip` 或 `ip_other` 的攻击会以 `skip_reason=decoder_not_xdrop_compatible` 跳过——L3 聚合攻击应使用 BGP。异常类（`bad_fragment` / `invalid`）经 xDrop v3 异常位匹配，`drop` 与 `rate_limit` 均可；IPv6 `bad_fragment` 由 xDrop 拒绝。

> **自动配对动作：** 创建任何 xDrop `on_detected` 动作（所有 `xdrop_action`，含 `unblock`）或 BGP `on_detected` 动作时，系统会自动创建对应的 `on_expired` 子动作（`unblock` / withdraw）。子动作不可直接编辑，需通过父动作修改。在 `trigger_phase=on_expired` 下手动创建 `xdrop` 或 `bgp` 动作会被拒绝（HTTP 400）。

> **xDrop 规则收窄与前 K 名多规则：** 占位符 `{dominant_dst_port}`、`{dominant_src_port}`、`{src_ip}` 表示「允许收窄」，不保证成为规则条件。只有攻击样本不少于 `action_engine.xdrop_min_sample_packets` 个包（缺省 1000）、且主导值占比不低于 `xdrop_narrow_pct`（缺省 80）时，该字段才保留；两个端口都达标时只保留源端口。没有单个端口达标时，一个动作可以展开成多条规则：取某个端口字段排名靠前的端口，取 2 个到 `action_engine.xdrop_topk_max` 个（缺省 8，范围 1–8；设 1 即关闭展开），直到累计覆盖样本的 `xdrop_topk_pct`（缺省 80），每个端口建一条 xDrop 规则。这些规则各有自己的 `external_rule_id`，在 `GET /api/active-actions/xdrop` 和 `mitigation-summary` 的 `xdrop_rules` 里各占一行，都属于同一攻击、同一动作。`drop` 规则若什么都没收窄、也没有剩余的字面匹配字段，会退成按攻击 pps 阈值的 `rate_limit`（仅当该阈值规则单位为 `pps`）。每个决定都以 `shape:` 提示记入日志，例如 `shape: topk dst_port=3 85%`、`shape: item 1/3 dst_port=53`、`shape: dropped src_ip=12%`、`shape: fallback rate_limit=50000`。

### xDrop 目标

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/actions/:id/xdrop-targets` | 获取动作的 xDrop 连接器 ID 列表 |
| PUT | `/api/actions/:id/xdrop-targets` | 设置 xDrop 连接器 ID 列表 |

**PUT 请求体：** `{ "connector_ids": [1, 2, 3] }`

### 前置条件

动作的条件执行规则。

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/actions/:id/preconditions` | 列出前置条件 |
| PUT | `/api/actions/:id/preconditions` | 替换所有前置条件 |

**PUT 请求体：**

```json
{
  "preconditions": [
    { "attribute": "pps", "operator": "gt", "value": "100000" },
    { "attribute": "decoder", "operator": "eq", "value": "udp" }
  ]
}
```

支持的属性：`cidr`, `decoder`, `attack_type`, `severity`, `pps`, `bps`, `peak_pps`, `peak_bps`, `node`, `domain`, `carpet_bomb`, `dominant_src_port`, `dominant_src_port_pct`, `dominant_dst_port`, `dominant_dst_port_pct`, `unique_src_ips`。

`carpet_bomb eq true` 是 `domain eq subnet` 的可读性别名——匹配 DstIP 为子网的攻击（aggregate-at-destination 模式）。接受 `true` / `false` / `1` / `0` / `yes` / `no`（大小写不敏感）。操作符：`eq`、`neq`。

支持的操作符：`eq`, `neq`, `gt`, `gte`, `lt`, `lte`, `in`, `not_in`。

API 在替换任何已存条件前校验操作符与值：

| 属性类别 | 操作符 | 值格式 |
|---|---|---|
| 数值：`cidr`、`pps`、`bps`、`peak_pps`、`peak_bps`、所有 `dominant_*` 属性、`unique_src_ips` | 全部八种 | 去掉两侧空白后为十进制有符号 int64；`in` / `not_in` 要求逗号列表，每项非空且可解析为整数。 |
| `decoder`、`severity`、`domain` | `eq`、`neq`、`in`、`not_in` | `eq` / `neq` 原样匹配允许值，不去空白；列表各项去空白后须为非空允许值。decoder 使用含 `ip` 的阈值 decoder 注册表；severity 为 `low`、`medium`、`high`、`critical`；domain 为 `internal_ip`、`subnet`。 |
| `attack_type` | `eq`、`neq`、`in`、`not_in` | 非空文本，不校验枚举。 |
| `node` | `eq`、`in` | 两种操作符均接受逗号列表，每项去空白后须非空。 |
| `carpet_bomb` | `eq`、`neq` | `true`、`false`、`1`、`0`、`yes`、`no`，忽略两侧空白及大小写。 |

数值/枚举列表中的坏项和空项返回 HTTP 400。校验不改写入库存储的原始文本，不校验数值范围或 `attack_type` 枚举，因此不保证拒绝所有可能恒真的条件。

---

## Webhooks（旧版）

简单 Webhook 通知（Response System v2 之前的旧接口）。

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/webhooks` | 只读列出所有 Webhook |
| POST | `/api/webhooks` | 410 Gone |
| PUT | `/api/webhooks/:id` | 410 Gone |
| DELETE | `/api/webhooks/:id` | 410 Gone |

POST / PUT / DELETE 返回 410，零写入、零审计、零发布；全局 webhook 请使用 /api/settings/webhook-connectors。升级前经旧接口创建并已回 201、但尚未经历复制启动的源行，在连接器表已存在时升级后不会被复制：请核对 GET 结果并到连接器页手工重建。

非 admin JWT 用户先收到 403 `admin role required`，只有 admin/API key 请求才进入 410 响应。GET `/api/webhooks`、`/api/responses/:id`、`/api/responses/:id/actions` 以及 `webhook_connector`、`webhook`、`response_action` 的审计 diff 中，header 值遮为 `******`。

---

## 设置 -- 连接器

### Webhook 连接器

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/settings/webhook-connectors` | 列出全部（header 值遮成 `******`） |
| POST | `/api/settings/webhook-connectors` | 创建 |
| GET | `/api/settings/webhook-connectors/:id` | 获取（header 值遮成 `******`） |
| PUT | `/api/settings/webhook-connectors/:id` | 合并更新：省略字段或标量 `null` 沿用旧值；合并后的 name、URL 不能空。header 值原样回传 `******` 即沿用旧值；若 URL 已改，返回 400 `url changed: header values must be re-entered`。 |
| DELETE | `/api/settings/webhook-connectors/:id` | 删除（被动作引用时失败） |
| POST | `/api/settings/webhook-connectors/:id/test` | 发送测试请求。返回 HTTP 200 `{success, status_code}`（`success` = 上游 2xx），或 `{success:false, error}`（错误文案已脱敏）。 |

**创建/更新字段：**

| 字段 | 类型 | 说明 |
|------|------|------|
| `name` | string | **必填。** |
| `url` | string | **必填。** Webhook URL |
| `method` | string | `POST`、`PUT` 或 `PATCH`；去除首尾空白并转大写后存储。空串/纯空白为 `POST`；创建时省略默认 `POST`，更新时省略沿用旧方法（旧方法为空时变为 `POST`）。测试按钮使用执行侧同一规范化。 |
| `headers` | object/null | 值为字符串的 JSON 对象，如 `{"Key": "Value"}`。创建时可省略，也可为 `null`；PUT 显式 `null` 清空。PUT 省略沿用旧 headers 并校验形状；换 URL 时须重输 headers，除非旧 headers 缺省、为 `null` 或 `{}`。 |
| `timeout_ms` | int | >= 0，API 不设上限。创建时省略/0 存为 10000；PUT 省略沿用，显式 0 照存。执行侧对 0 或大于 10000 的值回落为 10 秒。 |
| `global` | bool | 创建/PUT 可设，默认 `false`；只有 `true` 才接收全局 Webhook 事件。 |
| `enabled` | bool | 创建时忽略并恒为 `true`；用 PUT 启停。 |

测试端点在连接器不存在时返回 404 `webhook connector not found`；请求构造失败返回 400，错误文案脱敏。

### xDrop 连接器

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/settings/xdrop-connectors` | 列出全部（API Key 脱敏） |
| POST | `/api/settings/xdrop-connectors` | 创建；不接收 `enabled`，新连接器恒为启用。通过 PUT 启用或停用。 |
| GET | `/api/settings/xdrop-connectors/:id` | 获取（API Key 脱敏） |
| PUT | `/api/settings/xdrop-connectors/:id` | 合并更新：省略字段或标量 `null` 沿用旧值，显式 0/false 照存；空/省略 `api_key` 沿用密钥。显式空 name 或 URL 被拒；URL 去除尾斜杠后若有变化，须重输 key。 |
| DELETE | `/api/settings/xdrop-connectors/:id` | 删除。被动作引用时返回 HTTP 409 `xDrop connector in use by N action(s)`；名下还有 active / delayed / withdrawing / failed 行（含创建失败记录）时返回 HTTP 409 `xDrop connector still has active rules`。规则使用情况检查出错时返回 HTTP 500 `failed to check xDrop connector usage`。 |
| POST | `/api/settings/xdrop-connectors/:id/test` | 使用连接器凭证调用 xDrop `GET /auth/me`。连接器不存在：404；请求构造失败：400；请求发送失败（含可构造但缺协议的地址）：HTTP 200 `{success:false, error}`。拿到上游响应后返回 HTTP 200 `{success, status_code, kind, name}`，失败时另带 `error`。`success` 要求上游 HTTP 200、响应体读取无错、JSON 可解析且 `kind=machine`。 |

**创建字段：**

| 字段 | 类型 | 说明 |
|------|------|------|
| `name` | string | **必填。** |
| `api_url` | string | **必填。** xDrop API 基础 URL（如 `https://xdrop.example.com:8000/api/v1`） |
| `api_key` | string | **必填。** xDrop v3 机器凭证的密钥，以 Bearer 认证发送。每台 xSight 使用独立凭证。 |
| `timeout_ms` | int | 每次 xDrop 请求的等待上限：创建、撤销、强制解除（首次等锁）、下发现查、连接器测试。创建时省略或 0 存 10000；0 按 10 s。API 不设上限；界面范围为 1–30000 毫秒。 |

xDrop `api_key` 读取值为 `***` 加末 4 位；长度不超过 4 时只显示 `***`。PUT 中任何非空 `api_key` 都作为新密钥存储，包括读取到的掩码值；不改密钥时应省略该字段，不要原样回传 GET 结果。

### Shell 连接器

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/settings/shell-connectors` | 列出全部 |
| POST | `/api/settings/shell-connectors` | 创建 |
| GET | `/api/settings/shell-connectors/:id` | 获取 |
| PUT | `/api/settings/shell-connectors/:id` | 合并更新：省略字段或标量 `null` 沿用旧值，显式 0/false 照存；合并后的 name、command 不能空。 |
| DELETE | `/api/settings/shell-connectors/:id` | 删除（被动作引用时失败） |

**创建字段：**

| 字段 | 类型 | 说明 |
|------|------|------|
| `name` | string | **必填。** |
| `command` | string | **必填。** 脚本/二进制的绝对路径（必须以 `/` 开头） |
| `default_args` | string | 默认参数。`{变量}` 必须是动作支持的模板变量（如 `{ip}`），未知名字会被拒；`${HOME}` 等 shell 表达式不受此校验改写。 |
| `timeout_ms` | int | 执行超时毫秒数（默认：30000） |
| `pass_stdin` | bool | 通过标准输入把攻击上下文以 JSON 传给命令（默认：`false`） |

创建时 `enabled` 强制为 `true`；用 PUT 启用或停用。

### BGP 连接器

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/settings/bgp-connectors` | 列出全部 |
| POST | `/api/settings/bgp-connectors` | 创建 |
| GET | `/api/settings/bgp-connectors/:id` | 获取 |
| PUT | `/api/settings/bgp-connectors/:id` | 更新 |
| DELETE | `/api/settings/bgp-connectors/:id` | 删除（被动作引用或有关联的 announcing/active/delayed/withdrawing/failed/orphan 公告时返回 409；预检查询失败返回 500） |
| POST | `/api/settings/bgp-connectors/:id/test` | 测试 FRR 连通性（`show bgp summary`）；vtysh 期限 25 秒，超时返回 502（`timed out`） |
| GET | `/api/settings/bgp-connectors/:id/routes` | 显示 BGP RIB；在同一个 25 秒 vtysh 期限内并发查询两个地址族，两者都失败才返回 502 |


BGP 测试成功返回 `{ok:true, output}`；任何 vtysh 失败均返回 502 `vtysh failed: …`。路由查询成功返回 `{output}`；两个地址族都失败时返回 502 `vtysh failed: ipv4=… ipv6=…`。

删除只做预检，不保证并发 Attach/Delete 的原子性。withdrawn、dismissed、dismissed_on_upgrade 公告不阻止删除；后两类已移交人工，路由仍可能存在于 FRR。

**创建字段：**

| 字段 | 类型 | 说明 |
|------|------|------|
| `name` | string | **必填。** |
| `bgp_asn` | int | **创建时必填。** 本地 BGP AS 号，范围 1-4294967295。PUT 省略/null 沿用旧 ASN；合并后的 ASN 必须在范围内。 |
| `vtysh_path` | string | vtysh 二进制路径（默认：`/usr/bin/vtysh`） |
| `address_family` | string | 为兼容保留，不起作用。缺省 `auto`，取值不校验。执行时按每个前缀自动判定地址族，`/routes` 固定查询两个地址族。 |
| `description` | string | PUT 时省略或 `null` 沿用原值，传 `""` 即清空。（`name`、`vtysh_path`、`address_family` 传 `""` 仍沿用原值。） |
| `enabled` | bool | 默认：`true` |

---

## 统计

### GET /api/stats/summary

<!-- fe-q0:B6 -->
响应新增可选 `action_mode`，为动作引擎配置的 `observe` 或 `auto` 模式；无动作引擎时省略。

仪表盘概览计数。

活跃攻击计数、节点列表、前缀计数、阈值计数任一查询失败，均返回 HTTP 500，响应体仅含 `{"error":"stats summary: <which>: database error"}`（原始错误只写进 controller 日志），不返回部分计数。

**响应：**

| 字段 | 类型 | 说明 |
|------|------|------|
| `active_attacks` | int | 当前活跃攻击数 |
| `total_nodes` | int | 已注册节点数 |
| `online_nodes` | int | 在线节点数 |
| `total_prefixes` | int | 监控前缀数 |
| `total_thresholds` | int | 阈值规则数 |
| `tracker_count` | int | 内存中跟踪的攻击数 |
| `attacks_created` | int | 启动以来创建的攻击总数 |
| `attacks_suppressed` | int | 因 `max_active_attacks` 上限而暂缓确认的次数：新攻击已满足确认条件、但没有严格胜过优先级最低的 Active / Expiring 攻击（优先级相同也算）时，每拍计一次；新攻击留在 Confirming，之后的拍上继续重试。去重抑制不计入 |
| `attacks_evicted` | int | 为腾出 `max_active_attacks` 名额而被驱逐的攻击数（被驱逐的 Expiring 攻击会提前执行 on_expired 动作） |

### GET /api/stats/timeseries

<!-- fe-q0:B1 -->
可选 `dst_ip` 按单个 IPv4/IPv6 目标取数；主机 CIDR `/32`、`/128` 规范化为裸地址。其他 CIDR 或非法地址返回 400 `invalid dst_ip`。与 `prefix` 互斥（400 `dst_ip and prefix are mutually exclusive`）。目标查询只读原始采样，只接受 `resolution=5s|5min`、`direction=receives|sends`（默认 receives），拒绝 `both`。`to - from` 最长 6 小时；省略 `to` 取当前时间，超限返回 400 `dst_ip queries are limited to 6h`。sends 方向的目标是本端源地址。

逐前缀或逐节点的时序流量数据。

| 参数 | 类型 | 说明 |
|------|------|------|
| `prefix` | string | CIDR；对该前缀及其包含的所有被监控子前缀求和。省略或为空 = 全部前缀。非法 CIDR 或主机位不为 0 返回 **400** `invalid input`。 |
| `node_id` | string | 按节点过滤 |
| `direction` | string | `receives`（默认）, `sends` 或 `both`；其他非空值返回 400 `direction must be 'receives', 'sends', or 'both'` |
| `resolution` | string | `5s`, `5min`（默认）或 `1h` |
| `from` | string | RFC3339 开始时间（默认：1 小时前） |
| `to` | string | RFC3339 结束时间 |
| `include_extras` | bool | 传 `true` 时附带 `extra_decoder_pps` / `extra_decoder_bps`（固定列以外 decoder 的逐 decoder 映射） |

### GET /api/stats/overview

<!-- fe-q0:B8 -->
响应新增 `nodes: [{id, pps, bps}]`，按 id 升序列出逐节点总量，与总览使用相同方向、`node_id` 过滤、虚拟全局前缀排除及 10 秒新鲜度。无新鲜数据的节点不出现；环未就绪时返回 `nodes: []`。`total_pps` 等于各节点 pps 之和。

从 Ring Buffer 获取的实时流量概览。返回总 PPS/BPS 和 Top 前缀。

| 参数 | 类型 | 说明 |
|------|------|------|
| `direction` | string | `receives`（默认）, `sends` 或 `both`；其他值（含显式空串）返回 400 `direction must be 'receives', 'sends', or 'both'` |
| `node_id` | string | 按节点过滤 |
| `limit` | int | 返回最大前缀数（默认：20，最大：200） |

**响应：**

| 字段 | 类型 | 说明 |
|------|------|------|
| `total_pps` | int | 聚合每秒包数 |
| `total_bps` | int | 聚合每秒比特数 |
| `node_count` | int | 贡献数据的节点数 |
| `active_prefixes` | int | 有近期流量的前缀数 |
| `top_prefixes` | array | 按 PPS 排序的 Top 前缀（含逐协议分解：tcp/udp/icmp 的 PPS 和 BPS，以及 `nodes: [{id, mode}]`）。不含全局前缀。实时流量数据不可用时所有计数为 0。 |

### GET /api/stats/total-timeseries

<!-- fe-q0:B1-total -->
接受与 `/api/stats/timeseries` 相同的 `dst_ip` 参数及全部目标查询限制，包括与 `prefix` 互斥、只读原始表、6 小时上限及方向语义。

聚合时序数据：全部前缀和节点，或只取 `node_id` / `prefix` 选中的部分。

| 参数 | 类型 | 说明 |
|------|------|------|
| `node_id` | string | 只取该节点的数据（与 `GET /api/nodes` 的 `id` 一致；已删节点的历史仍能筛出）。省略或为空 = 全部节点。 |
| `prefix` | string | CIDR；对该前缀及其包含的所有被监控子前缀求和。省略或为空 = 全部前缀。解析不了的 CIDR 或主机位不为 0 返回 **400** `invalid input`。 |
| `direction` | string | `receives`（默认）, `sends` 或 `both`；其他非空值返回 400 `direction must be 'receives', 'sends', or 'both'` |
| `resolution` | string | `5s`, `5min`（默认）或 `1h` |
| `from` | string | RFC3339 开始时间（默认：1 小时前） |
| `to` | string | RFC3339 结束时间 |
| `include_extras` | bool | 同 `/api/stats/timeseries` |

两个时序接口都返回点数组：`time`、`pps`、`bps`、`tcp_pps`、`tcp_syn_pps`、`udp_pps`、`icmp_pps`、`frag_pps`、`tcp_bps`、`udp_bps`、`icmp_bps`、`frag_bps`、`tcp_syn_bps`（`include_extras=true` 时另带 `extra_decoder_*` 映射）。解析不了的 `from` / `to` 被忽略。每种分辨率有行数上限，超出部分截断：`5s` 7200 点、`5min` 2000、`1h` 1000。窗口内没有匹配数据时，响应体是 `null`。`5min` / `1h` 分辨率且起点早于 90 分钟前时，两个时序接口都读 5 分钟聚合：正常运行下一个桶约在收尾后 1–6 分钟出现（不是严格上限），正在进行的桶不返回；`from` 不在 5 分钟整点时，起点所在的残桶不计入；传历史 `to` 时，终点所在的桶整桶计入。

每个时序点固定返回 `tcp_syn_bps`；升级前原始行的该字段为 0。`ts_stats_5min` 聚合升级到 v8（v1.4.0）时删除了 7 天以前的 5 分钟聚合，`5min` / `1h` 分辨率查询这些时段时无数据。总览与流量页缺省选择 `tcp`、`udp`，可在「解码器」中选择 SYN。

---

## 基线

### GET /api/baseline

所有已启用前缀的参考 P95 基线和建议手动阈值，每分钟按最近 1 小时的已存统计重算一次。只统计入向（`receives`）流量。每个前缀取数据点最多的那个节点。

此接口仅供参考。运行时的动态检测使用[动态检测](#动态检测)一节所述的周画像，不读取这里返回的任何值。

**响应：** JSON 数组，每个已启用前缀一个元素（没有已启用前缀时为 `null`）。计算器未运行时返回 503 `baseline calculator not available`。

| 字段 | 类型 | 说明 |
|------|------|------|
| `prefix` | string | 前缀 CIDR |
| `p95_pps` | int | 最近 1 小时的 P95 每秒包数 |
| `p95_bps` | int | 最近 1 小时的 P95 每秒比特数 |
| `recommend_pps` | int | 建议手动阈值（P95 × 2） |
| `recommend_bps` | int | 建议手动阈值（P95 × 2） |
| `detect_thresh_pps` | int | 仅供展示（P95 × 3）；动态检测不使用 |
| `detect_thresh_bps` | int | 仅供展示（P95 × 3）；动态检测不使用 |
| `data_points` | int | 窗口内的数据点数 |
| `active` | bool | 窗口内数据点不足 60 个（冷启动）时为 `false`，此时基于 P95 的字段为 0 |
| `source` | string | 恒为 `best_node` |

---

## 攻击

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/attacks` | 列出攻击（分页、可过滤） |
| GET | `/api/attacks/active` | 列出当前活跃攻击 |
| GET | `/api/attacks/mitigation-brief` | 批量缓解摘要（最多 50 个 ID） |
| GET | `/api/attacks/:id` | 获取攻击详情：`{attack, actions_log, timer?, current?}`（`timer` 仅在攻击仍被实时跟踪时出现）。`actions_log` 是执行日志行，不含 `/action-log` 的 `bgp_role` 等字段。ID 非数字返回 404。 |
| POST | `/api/attacks/:id/expire` | 强制过期一个活跃攻击 |
| GET | `/api/attacks/:id/action-log` | 获取攻击的动作执行日志（v1.2：包含 `bgp_role`） |
| GET | `/api/attacks/:id/sensor-logs` | 获取攻击的 Flow 级传感器日志 |
| GET | `/api/attacks/:id/mitigation-summary` | 单攻击的缓解聚合视图（v1.2） |

在 `/api/attacks/:id`、`/action-log` 及 mitigation-summary 的 `executions` 中，非空 Webhook `error_message` 缩减为 `HTTP <code>` 或 `webhook error (details redacted)`。`/action-log`、`/sensor-logs`、`/mitigation-summary`、`/expire` 的攻击 ID 非数字时返回 400 `invalid attack id`，不同于攻击详情端点的 404。

### 列出攻击 -- GET /api/attacks

默认按开始时间降序，同时间按 id 降序。

<!-- fe-q0:B11 -->
可选 `ended_after` 必须为 RFC3339（非法值返回 400 `invalid ended_after`），保留未结束或结束时间不早于该值的攻击。`ended_after=T0&to=T1` 筛选与 [T0, T1] 重叠的攻击；原 `from`/`to` 仍筛开始时间。
可选 `sort` 为 `started_at`（默认顺序）或 `peak_pps`（按峰值 PPS 降序，再按开始时间降序、id 降序）；其他值返回 400 `sort must be 'started_at' or 'peak_pps'`。
可选 `dst_ip` 接受 IP 或 CIDR（非法值返回 400 `invalid dst_ip`），命中落在所搜地址或网段内的攻击目标；搜单 IP 不命中包含该 IP 的网段攻击。列表和 `total` 使用同一过滤。

| 参数 | 类型 | 说明 |
|------|------|------|
| `status` | string | `active`（尚未结束）或 `expired`（已结束）。其他值被忽略。 |
| `direction` | string | `receives` 或 `sends`；其他非空值返回 400 `direction must be 'receives' or 'sends'` |
| `prefix_id` | int | 按前缀过滤 |
| `from` | string | RFC3339；开始时间不早于此刻的攻击。解析不了的值被忽略。 |
| `to` | string | RFC3339；开始时间不晚于此刻的攻击。解析不了的值被忽略。 |
| `limit` | int | 每页大小（省略时 50；非数字或 ≤0 时 100；最大 200） |
| `offset` | int | 分页偏移量 |

**响应：** `{ "attacks": [...], "total": N }`

### 活跃攻击 -- GET /api/attacks/active

<!-- fe-q0:B12 -->
实时 `timer` / `timers` 项新增可选 `threshold_value`、`threshold_unit`，表示触发规则快照。仅单位已知时同时出现，合法阈值 0 仍输出；恢复后单位未知的条目省略两键。
可选 `current: {<attack_id>: {pps, bps}}` 给出本页仍在跟踪的攻击的新鲜当前总量；`GET /api/attacks/:id` 同样新增 `current: {pps, bps}`。按攻击方向读取入向或出向环，对不超过 10 秒的节点读数求和；网段目标读取前缀总量。无点、单 IP 所属前缀未知、已结束或未在 tracker 中的攻击省略对应键，不用零表示未知。

| 参数 | 类型 | 说明 |
|------|------|------|
| `limit` | int | 最大返回数（默认、非数字或 ≤0 时 100，上限 1000）；按 `peak_pps DESC` 排序 |

**响应：** `{ "attacks": [...], "active_count": N, "returned": N, "tracker_count": N, "timers": {...} }`；`timers` 按攻击 ID 给出实时检测计时器，只含本次返回的攻击。

### 强制过期 -- POST /api/attacks/:id/expire

手动过期活跃攻击。触发 on_expired 动作（如 xDrop 解封、BGP 路由撤回）。

| 参数 | 类型 | 说明 |
|------|------|------|
| `hold_seconds` | int | 可选，0–86400。手动结束后，同一目标、同一 decoder、同一方向的新告警最多被压住这么多秒。`0` = 不压。省略 = 用 `detection.manual_expire_hold_seconds`（缺省等于 `expiry_interval_seconds`，夹在 0–86400 之间）。 |

其他值（包括空的 `hold_seconds=`）返回 **400** `hold_seconds must be an integer between 0 and 86400`。检测不再看到这股流量时压制提前解除，controller 重启也会清掉压制。`"method": "db"` 表示该攻击不在实时检测中（例如重启之后）：攻击照样结束，但不压制。已结束的攻击返回 **409** `attack already expired`。

**响应：** `{ "ok": true, "method": "tracker" }` 或 `{ "ok": true, "method": "db" }`

### 传感器日志 -- GET /api/attacks/:id/sensor-logs

返回攻击目标 IP 在攻击时间窗口内 `flow_logs` 表的逐 Flow 记录。对于活跃攻击，查询窗口限制为最近 1 小时。

| 参数 | 类型 | 说明 |
|------|------|------|
| `limit` | int | 最大 Flow 记录数（默认：1000，最大：10000） |

**响应：** `{ "flows": [...], "total": N, "expired": bool, "window": "full"|"last_1h" }`

全局攻击（`0.0.0.0/0`）返回 `{flows:[], total:0, expired:false}`，不含 `window`。

### 动作日志 -- GET /api/attacks/:id/action-log

返回该攻击的所有 `action_execution_log` 行。BGP `on_detected` 条目会带上 v1.2 公告级字段，前端借此区分"真正触发 vtysh 的攻击"与"加入已存在共享公告的攻击"。

**响应（数组元素形状）：**

| 字段 | 类型 | 说明 |
|------|------|------|
| `id`、`attack_id`、`action_id`、`response_name`、`action_type`、`connector_name`、`trigger_phase`、`status`、`status_code`、`error_message`、`request_body`、`response_body`、`external_rule_id`、`connector_id`、`duration_ms`、`executed_at`、`scheduled_for`、`detail`、`skip_reason` | — | `action_execution_log` 的基础字段；`scheduled_for`、`detail`、`skip_reason` 可省略。 |
| `bgp_role` | string | 仅 BGP `on_detected`。`"triggered"` = 本攻击是当前 cycle 中首个 attach 的（vtysh announce 为本攻击触发）。`"attached_shared"` = 本攻击加入已 active 的公告（无 vtysh 副作用）。其他情况为空。 |
| `announcement_id` | int | 仅 BGP `on_detected`。本条日志附带的 `bgp_announcements` 行 ID。 |
| `announcement_refcount` | int | 仅 BGP `on_detected`。查询时公告的当前 refcount。 |

### 批量缓解摘要 -- GET /api/attacks/mitigation-brief

<!-- fe-q0:B3 -->
必填 `ids=1,2,3`：1–50 个不重复的正整数，每个不超过 2147483647。空值、非正数、非法、重复或超量均返回 400；任一 store 调用失败使整个响应以数据库错误返回。不存在的 ID 返回两个空数组。

```json
{"1":{"xdrop_rules":[{"external_rule_id":"r1","status":"delayed","scheduled_for":"2026-10-27T12:05:00Z"}],"bgp":[{"prefix":"192.0.2.0/24","route_map":"RTBH","status":"active","attached_at":"2026-10-27T12:00:00Z","delay_minutes":5}]},"2":{"xdrop_rules":[],"bgp":[]}}
```

`scheduled_for` 仅在 XDrop 为 delayed、延迟起点存在且分钟数为正时输出，值为起点加延迟分钟数。BGP 的 `detached_at` 仅解绑后出现；`delay_minutes` 为该挂载的延迟。

### 缓解摘要 -- GET /api/attacks/:id/mitigation-summary (v1.2)

单个攻击的所有缓解结果聚合视图，由 v1.2 动作状态层驱动。供 攻击详情页渲染「BGP 角色」列、逐攻击「强制移除」按钮和逐攻击的缓解计数，前端无需从原始日志重新拼装状态。

**响应：**

| 字段 | 类型 | 说明 |
|------|------|------|
| `attack` | object | 攻击行本身 |
| `summary` | object | 计数：`total_evaluated`（该攻击的动作日志总数）、`success`、`failed`、`skipped`、`timeout`（对应 `status` 的日志数），以及 `skip_reasons`（skipped 日志按 `skip_reason` 计数的映射） |
| `executions` | array | 结构同 `/action-log` 响应（含 `bgp_role`、`announcement_id`、`announcement_refcount`） |
| `xdrop_rules` | array | 该攻击在 `xdrop_active_rules` 中的行：`id`、`attack_id`、`action_id`、`connector_id`、`external_rule_id`、`status`、`delay_started_at`、`delay_minutes`、`withdrawn_at`、`created_at`、`error_message`。`external_rule_id` 以 `failed-create-` 开头表示创建失败、结果未知，不是 xDrop 规则号。withdrawn 行的 `error_message` 为空。展开成前 K 名多规则的动作，每条规则各占一行。 |
| `bgp_announcements` | array | 逐公告的 attachment：`announcement`（完整 `bgp_announcements` 行）、`attached_at`、`detached_at`、`attack_delay_minutes`、`attack_action_id` |

---

## 活跃缓解 (v1.2)

<!-- fe-q0:B10 -->
XDrop 列表元素额外输出从历史请求体解析的非零整数 `src_port`、`dst_port`、`rate_limit`；接受 JSON 数字或纯数字字符串，其他形状忽略。`dst_ip` 缺少时回落到 `dst_cidr`。

当前 xSight 维护的 BGP 路由与 xDrop 规则的实时视图，含强制移除与 orphan 公告处理端点。

### 列表

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/active-actions/bgp` | 列出 xSight 仍在维护的 BGP 公告。返回的 `status` 为 `active`、`delayed`、`failed` 或 `orphan`（orphan 另带 `is_orphan: true`）。正在宣告、正在撤回的公告不显示，withdrawn、dismissed、dismissed_on_upgrade 的也不显示。 |
| GET | `/api/active-actions/xdrop` | 列出状态为 `active`、`delayed`、`failed` 的 xDrop 规则，含创建失败记录；withdrawing 和 withdrawn 行不显示。 |
| GET | `/api/active-actions/xdrop/delivery` | 按需现查规则在各节点的下发状态。 |
| GET | `/api/active-actions/timeline` | 获取单个制品的执行时间线（详情抽屉用） |

**列表元素：** 两个列表都返回数组（为空时为 `null`）。每个元素含 `attack_id`、`attack_dst_ip`、`action_id`、`action_type`、`connector_id`、`connector_name`、`external_rule_id`、`created_at`、`status`，delayed 行另带 `scheduled_for`。BGP 元素另有 `prefix`、`route_map`、`announcement_id` 和 `attached_attacks`（当前挂载的攻击，加最多 30 条已解绑记录）；其 `external_rule_id` 为 `<prefix>|<route_map>`。xDrop 元素另有从请求体解析的 `dst_ip`、`protocol`、`tcp_flags`、`action`。每个 xDrop 行代表一个攻击 + 动作对一条规则的持有：多个攻击持有同一条 XDrop 规则时，同一 `external_rule_id` 会出现在多行；展开成前 K 名多规则的动作，每条规则各占一行。行里看不出还有哪些攻击或系统也持有该规则。找不到原始执行日志时 `connector_name` 为空串。

**下发查询：** 必填参数为 `connector_id`（正整数）和 `rule_id`（非空）。参数错误返回 400；连接器不存在或停用返回 404 `xdrop connector not found`；上游错误返回 502。HTTP 200 在规则不存在时返回 `{found:false}`，否则返回 `{rule_id,target_gen,epoch,nodes:[{name,state,code?,error?}]}`。节点状态为 `confirmed`、`pending`、`disabled`、`offline`、`incompatible`、`overloaded`、`rejected`，反映已配置的规则代次，不是实测命中。遇到 `gen_epoch_mismatch` 重试一次。该接口用于按需现查。

**Timeline 查询参数：**

| 参数 | 类型 | 说明 |
|------|------|------|
| `attack_id` | int | **必填。** 攻击 ID。 |
| `external_rule_id` | string | **必填。** 外部规则 ID。 |
| `connector_id` | int | 可选的连接器过滤条件。 |

**Timeline 响应：** `{attack, logs}`。`logs` 是该攻击中 `external_rule_id` 相符的执行日志行，按时间正序（没有匹配时为 `null`）。带 `connector_id` 过滤时，没有连接器的日志行照样保留。此端点必须给攻击 ID，因此 orphan BGP 公告无法在这里查看时间线。

### 强制移除（逐攻击 / 逐制品）

```
POST /api/active-actions/force-remove
```

强制移除指定的缓解制品。BGP 会解绑共享公告上的全部攻击，并通过 vtysh 撤回整条路由，所有挂载攻击都会失去该路由的保护。对于普通 xDrop 规则，强制解除释放本攻击这个动作的持有；最后一个持有方释放后，xDrop 才删除规则。若有进行中的自动撤销，首次最多先等一个连接器超时。两种路径都会写入 `manual_override` 审计行，使自然的 on_expired 清理跳过该制品。

对于创建失败记录，能恢复创建依据时，先只读核对 xDrop 上有没有对应规则，再决定释放或只做本地收尾；无法恢复创建依据时，可能直接做本地收尾。整次操作可能超过一个连接器超时；成功关闭本地记录不代表一定向 xDrop 发了释放。普通规则与创建失败记录均拒绝在停用连接器上执行。

成功返回 HTTP 200 `{ok:true, message:"force removed <id> (attack #N)", warning?}`；已移除但执行日志写入失败时返回 HTTP 200 `{ok:true, warning}`，不带 `message`。执行失败返回 HTTP 500 `force remove failed`；明细在 `manual_override` 执行日志的 `error_message` 中。

**请求体：**

| 字段 | 类型 | 说明 |
|------|------|------|
| `artifact_type` | string | 可省略；传入时被忽略。 |
| `attack_id` | int | **必填。** |
| `action_id` | int | **必填。** |
| `connector_id` | int | **必填。** |
| `external_rule_id` | string | **必填。** |

### Orphan BGP 公告

Orphan 公告是 `BootstrapBGPOrphans` 在 Controller 启动时扫 FRR 发现、但 xSight 没有对应活跃攻击的路由。v1.2 首次升级时记录为 `dismissed_on_upgrade`；后续新出现的 orphan 为 `orphan`，需要运维处理。

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/active-actions/bgp/orphan-force-withdraw` | 通过 vtysh 撤回 orphan 公告。请求体：`{ "announcement_id": N }`。非 orphan 行返回 400——改用 `/force-remove`。 |
| POST | `/api/active-actions/bgp/orphan-dismiss` | 标记 orphan 为运维已知晓（不撤回）。请求体：`{ "announcement_id": N }` |
| GET | `/api/active-actions/bgp/dismissed-orphans` | 列出处于 `dismissed` / `dismissed_on_upgrade` 状态的公告 |
| POST | `/api/active-actions/bgp/orphan-undismiss` | 把已 dismiss 的 orphan 重新搬回可见列表。请求体：`{ "announcement_id": N }` |

孤立路由强制撤回在公告不存在时返回 404 `announcement not found`。成功返回 200 `{ok:true, announcement_id}`；vtysh 失败仍返回 200 `{ok:true, warning:"vtysh error: … (row marked failed)"}`。忽略非 orphan 行，或重新提示不处于 `dismissed` / `dismissed_on_upgrade` 的行，均返回 400。

---

## 审计日志

### GET /api/audit-log

用户和节点创建、更新、删除请求成功后新增 `user` / `node` 审计。它们尽力记录成功请求，没有下发版本，不触发配置发布。用户 diff 不含密码明文或哈希，更新包含 `password_changed`；节点 diff 不含 API key。API key 请求的用户 ID 为空，自删也记空用户 ID。

审计 diff 包含响应的 `enabled`、模板创建/复制的 `response_id`（复制还含 `description`）、动作快照中的 `paired_with` 与已知的 xDrop `target_node_ids` 新旧值、前置条件原列表（没有时为 `[]`），以及 Flow 创建时的真实 ID。

配置变更历史，含新旧值对比。

| 参数 | 类型 | 说明 |
|------|------|------|
| `entity_type` | string | 按实体类型过滤（如 `watch_prefix`, `threshold`, `response`, `user`, `node`） |
| `user_id` | int | 按用户过滤 |
| `from` | string | RFC3339 开始时间，含边界。解析不了的值被忽略。带时区偏移时 `+` 要写成 `%2B`，或直接用 `Z` 形式。 |
| `to` | string | RFC3339 结束时间，含边界。解析不了的值被忽略。 |
| `limit` | int | 每页大小（省略时 50；非数字或 ≤0 时 100；最大 200，超过按 200） |
| `offset` | int | 分页偏移量 |

**响应：** JSON 数组，最新的在前（没有匹配时为 `null`）。不返回总数；要判断有没有下一页，多取一行即可。

---

## 动态检测

动态检测把实时入向流量与按节点、按前缀学到的周画像比较。画像按 UTC 分 168 个小时槽（槽 0 = 周一 00:00 UTC，槽 167 = 周日 23:00 UTC）。每个小时结束时，该小时的 P95 pps / bps 用 EWMA（`ewma_alpha`；第一份样本原样采用）并入该槽的期望值，每周最多一次，该槽的 `sample_weeks` 加一。

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/dynamic-detection/config` | 获取配置（字段与 PUT 请求体相同） |
| PUT | `/api/dynamic-detection/config` | 整体替换配置 |
| GET | `/api/dynamic-detection/status` | 获取各前缀当前画像状态 |

### 判定规则

对每个节点 + 前缀，取当前槽：

1. 动态检测未启用、该槽没有画像，或其 `sample_weeks` 为 0（学习中）：不判定。采到一周样本即激活该槽。
2. 当前 pps 低于 `min_pps` **且**当前 bps 低于 `min_bps`：跳过。任一项达到下限即进入判定。
3. 偏差随该槽累积的周数从 `deviation_max` 线性收窄到 `deviation_min`：偏差 = `deviation_max` − min(`sample_weeks`, `stable_weeks`) / `stable_weeks` × (`deviation_max` − `deviation_min`)。
4. 阈值 = 期望 × (100 + 偏差) / 100，pps 与 bps 各算一个。任一超过阈值即判为超限。

超限之后与硬阈值一样走确认流程，确认时长用 `detection.dynamic_threshold_confirm_seconds`。由此产生的攻击方向为 `receives`、decoder 为 `ip`、domain 为 `subnet`。

示例：缺省 `deviation_max` 200、`deviation_min` 100、`stable_weeks` 4 时，只有一周样本的槽在超过期望 2.75 倍时告警，第 4 周起超过 2 倍即告警。

### 更新配置 -- PUT /api/dynamic-detection/config

**整体替换，不是合并：** 请求体覆盖全部字段，请发送完整对象（以 GET 结果为底稿）。省略 `stable_weeks` 或 `ewma_alpha` 返回 400；省略 `enabled` 即关闭检测；省略 `deviation_*` 或 `min_*` 会存为 0。响应回显入库后的配置。

| 字段 | 类型 | 缺省 | 说明 |
|------|------|------|------|
| `enabled` | bool | `false` | 启用/禁用动态检测 |
| `deviation_min` | int | 100 | 槽稳定后的偏差，单位**百分比**（100 = 超过期望 2 倍告警）。必须是 >= 0 的整数；传 1.5 这类小数返回 400。 |
| `deviation_max` | int | 200 | 只有一周样本的槽所用的偏差百分比（200 = 期望的 3 倍）。整数，必须 >= `deviation_min`。 |
| `stable_weeks` | int | 4 | 偏差从 `deviation_max` 收窄到 `deviation_min` 所用的样本周数（>= 1）。它不推迟激活。 |
| `ewma_alpha` | float | 0.3 | 最新一周在 EWMA 中的权重（0 < alpha < 1） |
| `min_pps` | int | 100000 | 流量下限，包/秒（>= 0）；见上文第 2 条 |
| `min_bps` | int | 1000000000 | 流量下限，比特/秒（>= 0）；见上文第 2 条 |

校验错误：`deviation values must be non-negative`、`deviation_min must be <= deviation_max`、`stable_weeks must be >= 1`、`ewma_alpha must be between 0 and 1 (exclusive)`、`min_pps must be >= 0`、`min_bps must be >= 0`。

### 检测状态 -- GET /api/dynamic-detection/status

画像引擎未运行时返回 503 `profile engine not available`。

**响应：**

| 字段 | 类型 | 说明 |
|------|------|------|
| `enabled` | bool | 动态检测是否启用 |
| `current_slot` | int | 当前小时槽位（0-167） |
| `current_slot_label` | string | 形如 `Monday 14:00 UTC` 的标签。当前槽没有画像数据时，显示此前最近一个有数据的槽，标签末尾带 ` (latest)`；`current_slot` 仍是当前槽号。 |
| `total_prefixes` | int | 所显示槽中有画像数据的前缀数 |
| `activated_count` | int | 已过学习阶段的前缀数 |
| `learning_count` | int | 仍在学习中的前缀数 |
| `prefixes` | array | 逐前缀详情（无数据时为 `null`）：`prefix`、`node_count`、`expected_pps`、`expected_bps`、`current_pps`、`current_bps`、`thresh_pps`、`thresh_bps`、`sample_weeks`、`status`（`learning`/`normal`/`exceeded`） |

多节点时，每个前缀取各节点中最大的期望值与阈值、当前流量求和、`sample_weeks` 取最小。`status` 只比较当前流量与阈值，不看 `min_pps` / `min_bps`，也不看确认窗口，因此可能与真正触发攻击的结果不一致。

---

## Flow 配置

管理 Flow 模式节点的 NetFlow/sFlow/IPFIX 监听器和数据源。

### Flow 监听器

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/flow-listeners?node_id=X` | 列出节点的监听器（**node_id 必填**） |
| POST | `/api/flow-listeners` | 创建 Flow 监听器 |
| GET | `/api/flow-listeners/:id` | 获取监听器（含数据源）：`{listener, sources}` |
| PUT | `/api/flow-listeners/:id` | 更新监听器（node_id 不可变） |
| DELETE | `/api/flow-listeners/:id` | 删除监听器（级联删除数据源） |

**创建字段：**

| 字段 | 类型 | 说明 |
|------|------|------|
| `node_id` | string | **必填。** 必须是 flow 模式节点 |
| `listen_address` | string | **必填。** `:port` 或 `host:port`（端口 1-65535） |
| `protocol_mode` | string | `auto`（默认）, `sflow`, `netflow` 或 `ipfix` |
| `description` | string | 自由文本描述 |

监听器与数据源创建时恒存 `enabled=true`；PUT 省略 `enabled` 沿用原值。

Listener 与数据源的 PUT 是整体替换，只有省略的 `enabled` 和不可变的归属 ID（`node_id` / `listener_id`）沿用原值。应发送全部字段：省略 `description` 会清空；数据源在 `auto` / `none` 模式省略 `sample_rate` 时存 0，`force` 模式则要求正值，否则返回 400。更新不补创建缺省值：Listener 必须发送 `listen_address` / `protocol_mode`，数据源必须发送 `name` / `device_ip` / `sample_mode`，否则返回 400。

### Flow 数据源

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/flow-sources?listener_id=N` | 列出监听器的数据源（**listener_id 必填**） |
| POST | `/api/flow-sources` | 创建 Flow 数据源 |
| GET | `/api/flow-sources/:id` | 获取数据源 |
| PUT | `/api/flow-sources/:id` | 更新数据源（listener_id 不可变） |
| DELETE | `/api/flow-sources/:id` | 删除数据源 |

**创建字段：**

| 字段 | 类型 | 说明 |
|------|------|------|
| `listener_id` | int | **必填。** 父监听器 |
| `name` | string | **必填。** 显示名称 |
| `device_ip` | string | **必填。** 导出器 IP 地址（必须是合法 IP） |
| `sample_mode` | string | `auto`（默认）, `force` 或 `none` |
| `sample_rate` | int | `sample_mode=force` 时必填（必须 > 0） |
| `description` | string | 自由文本描述 |

---

## 通用响应格式

### 成功

```json
{ "ok": true }
```

### 已创建

HTTP 201，返回：

```json
{ "id": 42 }
```

### 错误

```json
{ "error": "问题描述" }
```

以 HTTP 500 报出的数据库故障，多数正文是以 `database error` 结尾的固定文案（部分接口带简短前缀，如 `failed to check template responses: database error`）。少数操作用自己的固定文案：强制移除返回 `force remove failed`，动作更新回滚不完整时会在文案后追加没能回滚的步骤。这些情况下原始错误都只写进 controller 日志。按 URL 里的 ID 读取对象时遇到数据库故障，不少接口会报成 **404** `<对象> not found`，也不记日志，所以单凭 404 不能断定对象不存在。请求因输入问题被数据库拒绝时，多数接口改回固定文案：重复值返回 **409** `already exists`；引用的对象不存在返回 **400** `referenced object not found`（DELETE 时为 **409** `in use`）；违反约束或缺必填值返回 **400** `invalid value`；格式不对的输入（例如解析不了的 CIDR）或负数 `offset` 返回 **400** `invalid input`。把数据库错误转换成这些固定的输入错误响应时，不额外记录错误日志。`GET /api/stats/summary` 查询出错一律返回 500（见上文）。

除 `/api/login` 外，请求体 JSON 绑定失败返回 **400**，正文是校验器的原始文案。未知的 `/api/*` 路径，或已知路径用了不支持的方法，都返回 **404** `{"error":"not found"}`（没有 405）。

### 冲突（引用保护）

HTTP 409，尝试删除被其他实体引用的对象时返回：

```json
{ "error": "template in use by 3 prefixes: [198.51.100.0/24 203.0.113.0/24 192.0.2.0/24]" }
```
