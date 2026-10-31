# xSight Controller

xSight 的管理平面 -- 基于 XDP/eBPF 的 DDoS 检测与响应系统。

Controller 提供 REST API、gRPC 数据接入、实时检测引擎、自动化响应系统以及内嵌的 Vue 3 Web UI。它从一个或多个 xSight Node（XDP 或 Flow 模式）接收逐 IP 和逐前缀的流量统计，执行阈值检测和动态基线检测，跟踪攻击生命周期，并通过 xDrop、BGP 黑洞、Webhook 或 Shell 脚本触发自动响应。

## 架构

```
                  +-----------+
  xSight Node --- | gRPC :50051 | --- StatsWriter ---> Ring Buffer（内存环形缓冲）
  (XDP/Flow)      +-----------+                              |
                                                  +----------+-----------+
                                                  |                      |
                                              DBWriter               Detector（1秒 tick）
                                                  |                      |
                                              ts_stats              ThresholdExceeded
                                          (PostgreSQL +                  |
                                           TimescaleDB)          AttackTracker（状态机）
                                                                         |
                                                                  ActionEngine
                                                              (xDrop / BGP / Webhook / Shell)
```

### 核心组件

| 包 | 说明 |
|---|------|
| `ingestion` | gRPC 服务端、StatsWriter（Ring Buffer 写入）、DBWriter（ts_stats 持久化）、NodeState（连接状态跟踪）、SampleWorkerPool、FlowWriter |
| `store/ring` | 逐 IP 和逐前缀流量环形缓冲由一把 RWMutex 保护，读者持锁复制最新数据点。以 1 秒粒度为实时阈值检测提供数据 |
| `store/postgres` | PostgreSQL + TimescaleDB 存储层。ts_stats 和 flow_logs 使用 hypertable，支持自动压缩和保留策略 |
| `engine/threshold` | 阈值继承树 + 检测器（每 tick 评估硬阈值）。支持 PPS、BPS 和百分比单位 |
| `engine/baseline` | EWMA 动态基线计算器。ProfileEngine 学习每小时流量画像（每周 168 个时间槽），使用渐进偏差检测异常 |
| `engine/classifier` | 攻击类型分类器，基于采样包数据（SYN Flood、UDP 放大等） |
| `engine/dedup` | 告警去重，防止对同一目标产生重复攻击记录 |
| `tracker` | 攻击生命周期状态机 -- 确认窗口、活跃跟踪、动态过期、从数据库崩溃恢复 |
| `action` | 响应执行引擎。支持四种动作类型（xDrop 过滤/限速、BGP 黑洞 via FRR/vtysh、Webhook HTTP 调用、Shell 脚本），带前置条件、触发阶段、运行模式和执行日志。v1.2 引入动作状态层（bgp_announcements + xdrop_active_rules + scheduled_actions）作为单一事实之源；v1.2.1 新增 xDrop decoder 兼容闸门 |
| `api` | 基于 Gin 的 REST API，支持 JWT + API Key 认证。所有配置实体的完整 CRUD，外加无需认证的 `/metrics` 端点 |
| `metrics` | Prometheus 埋点（v1.2.1）。vtysh 操作 / 动作分派 / skip / 恢复结果的内联计数器；BGP / xDrop / scheduled-action 状态 gauge 的 custom collector；攻击追踪封装。以 `store.Store` decorator 的方式一次性安装，指标即为 DB 写入的副作用 |
| `configpub` | 配置发布器 -- 除用户、节点外，配置变更及强制移除、孤立路由操作经发布路径递增启用节点的版本并重新推送，带漂移检测 |
| `retention` | 自动数据清理。TimescaleDB 策略删除 ts_stats / flow_logs 分区；普通表按行清理。过期的已结束攻击连同执行日志和状态行一起删除，状态未完结的攻击保留；另清理过期审计 |
| `watchdog` | systemd 就绪通知需 `Type=notify`，心跳另需 `WatchdogSec=`；随附 unit 为 `Type=simple` |

## Web UI

控制台使用 Vue 3 + TypeScript + Vite、全部自绘的控件、SVG 曲线和 vue-i18n，编译时嵌入 Go 二进制文件。

外观提供 **自动 / 浅 / 深** 三档；字体为 **IBM Plex Sans / Mono**。

UI 支持中英文切换。开发说明见[控制台 README（中文）](console/README.md)。

## 构建

### 前提条件

- Go 1.25+
- Node.js 22.12+（构建）；跑控制台测试需 22.22.2+ 或 24.15+；使用 npm

### 构建步骤

```bash
# 构建前端
cd console
npm ci
npm run build
cd ..

# 构建 Controller 二进制（嵌入 console/dist）
go build -o bin/xsight-controller .
```

非 git 检出环境须在 `npm run build` 前设置 `XSIGHT_VERSION`；`./scripts/build-controller.sh` 先构建控制台，再用 `-buildvcs=false -trimpath` 编译 Go，并在无法取得 Git 版本时使用 `unknown`。

或使用 Makefile：

```bash
make build    # 仅编译 Go 二进制（需要 console/dist 已构建）
make proto    # 重新生成 protobuf（需要 protoc + Go gRPC 插件）
make migrate  # 仅运行数据库迁移后退出
```

`make migrate` 要先有 `console/dist` 和 `controller/config.yaml`；`make proto` 使用 GNU `sed -i`，macOS/BSD 的 sed 不适用。

### 数据库准备

需要 PostgreSQL 15+，并且必须安装 TimescaleDB 2.x，用于自动分区压缩和保留策略。

```bash
sudo -u postgres psql -c "CREATE USER xsight WITH PASSWORD 'YOUR_DB_PASSWORD';"
sudo -u postgres createdb -O xsight xsight
sudo -u postgres psql -d xsight -c "CREATE EXTENSION IF NOT EXISTS timescaledb;"
```

BGP 公告及附着回填只在首次创建 bgp_announcements 时执行，与建表同事务；xDrop 和 override 回填仍每次启动执行，作为状态写失败兜底。旧 webhook 仅在首次创建 webhook_connectors 时复制，也与建表同事务。升级前，包含这些门表及回填的旧版本须已在相关失败后成功完成迁移；一条更早的 database migrations complete 日志不足以证明。

从 v7 升级时会重建 `ts_stats_5min`（v8，新增 `avg_tcp_syn_bps`）：7 天以前的 5 分钟聚合被删除，启动时同步从现存原始数据回填最近 7 天（固定 7 天，与 `ts_stats_days` 无关）；原始数据保留期更短时，可恢复的历史也更少。旧原始行的 `tcp_syn_bps` 为 0。完整升级注意见 [CHANGELOG](../CHANGELOG.zh.md)。

迁移在启动时自动执行。使用 `-migrate` 参数可仅运行迁移：

```bash
./bin/xsight-controller -config config.yaml -migrate
```

## 配置

首次正常启动前，将 `auth.initial_admin_password` 设为 8–72 字节的独立密码，不能为 `admin`。空用户表必须配置此项才能创建启用的 `admin` 账号；单独执行 `-migrate` 不需要它。使用该配置密码登录，初始化成功后可删除此字段。

升级已有数据库时，如果任何 admin 角色账号仍使用旧默认密码，应在升级前设置此项。启动时只轮换这些密码（包括改名及停用的管理员），保留其他字段；未配置时此类账号会阻止启动。已修改的密码不会被覆盖。本次升级后已有用户需重新登录。

复制 `config.example.yaml` 并编辑：

```yaml
listen:
  grpc: ":50051"           # Node gRPC 数据接入
  http: ":8080"            # Web UI + REST API

database:
  driver: "postgres"
  dsn: "postgres://xsight:PASSWORD@localhost:5432/xsight?sslmode=disable"

auth:
  api_key: "CHANGE_ME"    # REST API 密钥（X-API-Key 请求头）。生成方法：openssl rand -hex 32
                           # JWT 签名密钥也由它派生：修改后所有会话都会失效。
  initial_admin_password: ""   # 首个 admin 的密码，见上文

action_engine:
  mode: "observe"          # "observe"（默认，安全）下 xDrop 分派被跳过，
                           # 记录 skip_reason=mode_observe。设为 "auto"
                           # 才会真正下发 xDrop 封禁。BGP / Webhook / Shell
                           # 不受此开关影响。
  xdrop_narrow_pct: 80             # {dominant_*}/{src_ip} 字段在样本占比达到此值时保留
  xdrop_min_sample_packets: 1000   # 收窄所需的最少采样包数（0 = 不检查）
  xdrop_topk_pct: 80               # 前 K 名端口规则需累计覆盖的占比
  xdrop_topk_max: 8                # 每个动作最多展开的规则数（1-8；1 = 关闭前 K 名）

detection:
  hard_threshold_confirm_seconds: 3      # 连续超阈值秒数，达到后宣布攻击
  dynamic_threshold_confirm_seconds: 5
  expiry_interval_seconds: 300           # 未超阈值多少秒后攻击过期
  expiry_function: "static"              # "static" | "dynamic"（按攻击持续时间缩放）
  expiry_scale_base_seconds: 300         # 动态过期缩放基准
  expiry_max_scale: 4.0                  # 最大缩放倍数
  # manual_expire_hold_seconds: 300     # 手动结束后的压制秒数（0 = 不压，最大 86400）；省略 = expiry_interval_seconds，夹在 0–86400
  max_active_attacks: 10000
  dry_run: false                         # 仅检测，不创建攻击记录

ring:
  max_points_per_ip: 120      # 每 IP 历史深度（默认 120 = 2 分钟 @ 1秒/点）
  max_ips_per_prefix: 10000   # 每前缀最大跟踪 IP 数
  max_global_keys: 100000     # 全局最大跟踪 IP 总数

retention:
  ts_stats_days: 7             # 原始 5 秒统计
  ts_stats_compress_days: 1    # 超过 N 天的分区自动压缩（TimescaleDB）
  ts_stats_cagg_days: 90       # 5 分钟聚合（块宽自动：N/7 天向下取整、至少 1 天；0 = 不调整块宽）
  ts_stats_chunk_days: 0       # 0 = 自动块宽
  flow_logs_days: 7            # flow_logs（已压缩）
  flow_logs_compress_days: 1
  flow_logs_chunk_days: 0
  attacks_days: 90             # 已结束的攻击记录
  audit_log_days: 180          # 配置变更审计日志
  interval_hours: 24           # 清理频率
```

完整配置项参见 `config.example.yaml`，内含详细注释。未知或拼错的键会被静默忽略；`database.driver` 只支持 `postgres`。

ts_stats_days、flow_logs_days、ts_stats_cagg_days 为 0 时撤除对应表 retention 策略并永久保留；各 *_compress_days 为 0 时独立撤除 compression 策略。撤除失败记 WARNING 后继续启动；撤 retention 不恢复已删数据，撤 compression 不解压旧块。

## 运行

```bash
./bin/xsight-controller -config config.yaml
```

Controller 启动后将：
1. 连接 PostgreSQL 并执行迁移
2. 在 `:50051` 启动 gRPC 服务端，等待 Node 连接
3. 在 `:8080` 启动 HTTP 服务端，提供 Web UI 和 REST API
4. 开始 1 秒粒度的检测 tick 循环
5. 按配置周期启动数据保留清理器
6. 使用 `Type=notify` 时向 systemd 发送就绪信号；心跳另需 `WatchdogSec=`，随附 unit 为 `Type=simple`

pprof 调试端点运行在 `127.0.0.1:6060`（仅本地访问）。

**Prometheus 指标**在 HTTP listener 上通过 `GET /metrics` 暴露（无需认证——依赖网络层隔离）。指标目录见 [用户指南 § 5.1 指标](../docs/user-guide.zh.md#51-指标)。

## 目录结构

```
controller/
  main.go                  # 入口，组件装配
  embed_console.go         # go:embed 嵌入 console/dist
  config.example.yaml
  Makefile
  console/                 # Vue 3 + TypeScript 控制台源码
    src/
    dist/                  # 构建后的前端（嵌入二进制）
  internal/
    config/                # YAML 配置加载
    pb/                    # 生成的 protobuf（gRPC 服务定义）
    ingestion/             # gRPC 处理器、StatsWriter、DBWriter、NodeState、FlowWriter
    store/                 # Store 接口定义
      postgres/            # PostgreSQL 实现（迁移、查询）
      ring/                # 内存环形缓冲（逐 IP、逐前缀）
    engine/
      threshold/           # 阈值继承树 + 检测器
      baseline/            # EWMA 计算器 + ProfileEngine（168 时间槽/周）
      classifier/          # 攻击类型分类
      dedup/               # 告警去重
    tracker/               # 攻击生命周期状态机
    action/                # 响应执行（xDrop、BGP、Webhook、Shell）+ v1.2 动作状态层
    metrics/               # Prometheus 埋点（v1.2.1）
    api/                   # REST API 处理器 + 路由 + /metrics 端点
    configpub/             # 通过 gRPC 推送配置到节点
    retention/             # 数据保留清理
    netutil/               # IP/前缀格式化工具
    watchdog/              # systemd sd_notify 集成
```
