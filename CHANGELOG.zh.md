# 更新日志

## v1.4.0 — 2026-10-31

### 升级注意（先读）

- `ts_stats_5min` 从 v7 升至 v8 时会删除原聚合（包括 7 天以前的全部 5 分钟历史），并在启动时同步从尚存原始数据回填固定的最近 7 天窗口，与 `ts_stats_days` 无关；旧原始行的 `tcp_syn_bps=0`，已从原始表删除的数据无法恢复。
- 构建需 Node.js 22.12+（控制台测试需 22.22.2+ 或 24.15+），先在 `controller/console` 运行 `npm ci && npm run build` 再构建 Go，无 Git 元数据的源码包须设置 `XSIGHT_VERSION`；旧前端 `controller/web` 已删除，缺省嵌入新控制台，`scripts/build-controller.sh` 会提供 Git 版本或 `unknown`。
- 正常启动或运行 `-migrate` 前须设置独有的 `auth.api_key`：空值、纯空白和默认占位值会被拒绝。
- 不再预置使用默认口令的管理员，用户表为空时首次正常启动须设置 `auth.initial_admin_password`（8–72 字节且不能使用旧默认口令），仅运行 `-migrate` 不需要此项。
- 存量 admin 角色账号若仍使用旧默认口令（包括已改名或停用的账号），必须设置 `auth.initial_admin_password` 以在启动时轮换这些口令；其他口令保留，初始化后应移除此配置项。
- `detection.hard_threshold_confirm_seconds` 和 `dynamic_threshold_confirm_seconds` 均不得超过 `ring.max_points_per_ip`，否则无法启动；确认攻击现在还要求连续越线数据点。
- `action_engine` 新增 `xdrop_narrow_pct=80`、`xdrop_topk_pct=80`（均为 1–100）、`xdrop_topk_max=8`（1–8，1 关闭 top-K）和 `xdrop_min_sample_packets=1000`（0 关闭最少样本数检查）；百分比或 top-K 上限越界会阻止启动。
- 新增 `detection.manual_expire_hold_seconds`，范围为 0–86400（0 关闭保持），未设置时取 `max(0, min(expiry_interval_seconds, 86400))`，越界会阻止启动。
- xDrop 集成要求 XDrop v3，并为每个 xSight 实例配置专用机器凭据，填入连接器的 `api_key`；请求使用 Bearer 认证，不兼容 v2。
- 已知迁移限制：升级前先让活跃 xDrop 规则全部撤销（等待攻击结束或使用**强制解除**），因为尚无依据确认新版能释放没有 `claim_ref` 的 v2 时代规则。
- XDP 节点所有网卡在启动和重载时必须使用相同的 `mode`、`sample_bytes` 与 `upstream_sample_rate`，不同设置须拆成多个节点；改变采集模式需要重启。
- 节点省略 `sample_bytes` 时现可正确使用缺省值 256，BPF 采样长度将 0 视为 256，并以上限 512 字节截断。
- controller↔node 协议未变，旧 node 已在流传输前握手，因此升级 controller 不要求同时替换 node；心跳、采样、GRE/ERSPAN、IPv6、per-IP 老化、重载、配置失败 ACK 和重连等节点侧修复仍需升级 node 才能生效。
- 升级后的 XDP 节点首次启动会因键编码和 ELF 变化冷重建 BPF pin，并清零其中的计数器；后续启动可复用匹配的 pin。
- 自动迁移修复空库安装，新增 `idx_action_exec_log_attack` 索引、`bgp_announcements.gen` 列（存量行初始为 0），并将 `bgp_connectors.bgp_asn` 从 INT 扩为 BIGINT。
- 升级前须确认旧版在此前任何迁移失败后已成功完成一次迁移：BGP 状态回填和旧 webhook 复制现在仅在目标表首次创建时于事务中执行，已有 BGP 表不再每次重启都从执行日志回填。
- 一次性旧 webhook 复制包含请求头，但连接器表创建后新增且从未复制的旧行须在**连接器**页手动重建；已认证的 admin/API key 写 `/api/webhooks` 返回 410，GET 保留，非 admin 写请求先返回 403。
- xDrop 与手动覆盖记录仍在每次启动时回填，创建阶段扩展至 confirmed/type_upgrade/updated，结束阶段扩展至 expired/evicted，已成功手动覆盖的对应规则不会被重建为活跃状态。
- 启动会清理已结束攻击残留的路由和规则（BGP 撤回最多等待 30 秒）、恢复全部活跃攻击、保留重复规范键中开始时间最新的攻击并按正常结束流程处理其他行，同方向同 decoder 的主机长度 CIDR 与 per-IP 身份也会合并。
- 首次保留清理可能删除更多行，因为符合条件的已结束攻击现在会连同日志和状态行整批删除（每批最多 10000 个攻击），保留/压缩设置为 0 会移除已有策略，cagg 新 chunk 的宽度随其保留期调整，同时仍受上述 v8 聚合重建影响。
- P95 推荐值和动态基线现在只统计入向流量，启动时按双方向重新估算的 ring 内存超过 8 GiB 会告警，原有内存拒绝启动阈值不变。
- 非 admin 角色（包括 viewer 和旧 operator）均为只读，写请求返回 403，REST API key 保留 admin 权限，JWT 校验仅接受 HS256。
- 升级后现有登录会话全部失效：旧版本签发的令牌会被拒绝，所有用户须重新登录。
- 请检查自动化脚本以适应更严格的写入校验：旧 `xdrop_api`、空 `trigger_phase`、非法动作/运行模式、阈值字段、webhook 方法/请求头、越界 ASN 或撤回延迟、IPv4-mapped 前缀，以及出向规则关联的 xDrop/BGP 动作会被拒绝，已存非法值在下次编辑时校验。
- 依赖 Shell 占位符展开为多个参数的脚本需要调整（现在每个占位符保留为一个参数，空结果也保留），同时须适应 webhook 的 10 秒超时上限，以及现已生效的 POST/PUT/PATCH 方法设置。
- xDrop 撤回仅以 HTTP 204 确认成功；包括 404 在内的其他响应会留下失败撤回状态，由对账循环退避重试。
- 修改 xDrop 连接器 URL 时必须重填密钥，修改 webhook URL 时必须重新提交请求头值。

### 重点变化

- 默认嵌入的新控制台提供分组导航、中英文界面、**自动** / **浅** / **深**外观、支持键盘读数和缩放的 SVG 流量图，以及可调整并保存的总览布局。
- xDrop v3 集成新增按持有者释放规则、按流量集中度收窄自定义规则和 top-K 端口规则。
- TCP SYN bps 现在会入库并出现在时序数据中，也可在控制台图表中选择。

### 新增

- 9 条旧控制台路由会重定向到对应新页面，已保存的 classic/amber 外观设置会迁移为「浅」/「深」。
- **添加节点**可生成 API 密钥和节点配置片段。
- 运行时对账会重试 xDrop 和 BGP 撤回，并检查 FRR 以修正 BGP announcing 状态。
- 手动结束攻击可通过 `hold_seconds` 设置保持时长，延后重新确认。

### 行为变化

- 控制台攻击列表每页 50 条，活跃攻击按峰值 pps 排序，流量筛选条件保存在 URL 中。
- 总览的已结束攻击表和总览 / 流量图上的攻击底纹最多加载最近 2000 条，超出时显示提示。
- 新增 12 个 `xsight_*` 指标，覆盖动作队列、状态写失败、启动清理、gRPC 身份拒绝、ring 内存估算、已结束攻击清扫、BGP 迟到写入、前置条件查询错误、BGP / xDrop 对账和配置发布失败；`max_active_attacks` 改为同时计入 active 与 expiring；响应 webhook 在 expired / evicted 事件上带 `end_reason`。
- 动作通过 tracker 锁外的单个 FIFO 调度器执行，队列容量为 4096，满时阻塞生产者。
- 停用的父前缀仍保留继承关系，per-IP 流量归属最具体的前缀，出向攻击的非结束事件跳过 xDrop/BGP 动作。
- 编辑 xDrop、Shell 和 webhook 连接器会保留省略字段，动作编辑会保留旧前置条件，并在部分步骤失败后尝试按逆序回滚。

### API

- 新增只读端点 `GET /api/attacks/mitigation-brief?ids=`（最多 50 个 ID）和 `GET /api/active-actions/xdrop/delivery`。
- 攻击查询新增 `dst_ip`、`ended_after` 和 `sort=started_at|peak_pps`，时序查询新增有限制的 `dst_ip` 筛选，总时序支持节点/前缀筛选，审计查询新增时间范围并将 limit 上限设为 200。
- 只读响应新增攻击当前速率与计时器阈值、摘要动作模式、总览各节点速率、最后统计时间、节点网卡/采集数据和 xDrop 端口/限速字段。
- 更新或删除最后一个启用的 admin 若会使启用管理员归零，现在返回 409 `at least one enabled admin is required`，不会修改用户。
- 配置审计 diff 现在包含响应启用状态、模板响应绑定、动作快照与 xDrop 目标、原前置条件列表，以及真实的 Flow 对象 ID。

### 安全

- 认证与授权修复涵盖默认凭据、登录滥用与用户枚举、令牌吊销、JWT 校验和 API key 比较。
- 安全修复涵盖命令注入、连接器响应/日志/审计中的凭据泄露，以及 API 响应中的数据库错误信息泄露。
- 其他修复涵盖节点身份检查、慢速 HTTP 请求头，以及可能遗漏必要限制的配置路径。

### 修复

- 即使响应或动作已停用/删除，或引擎处于观察模式，已结束攻击的清理仍会执行。
- 修复 xDrop 创建结果不确定、并发移除，以及迟到的 BGP 状态写入导致通告卡住的问题。
- 执行中的单次动作会去重，动作超时后仍可记录执行日志，攻击结束状态持久化失败后会保留待重试记录。
- 数据入库失败后按节点重试，被替换的旧流不再清除新流，配置失败 ACK 会被记录，配置发布失败也会写日志并计数。
- 节点修复涵盖实际采样率上报和随机采样、空闲 Flow 心跳、GRE 偏移与内层 IPv6、IPv4/IPv6 前缀键空间分离、空闲 per-IP 老化、上游采样率热加载和重连退避复位。
- 攻击开始时间相同时分页保持稳定，计数查询错误会返回；COALESCE 标记探测失败后仍会继续检查必需列。

更早版本：参见 git 历史（v1.3.10 = 提交 `10803e2`）。
