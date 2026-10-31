# xSight Console

Vue 3 / TypeScript / Vue Router / Vue I18n；无状态库。依赖版本由锁文件固定，统一使用 npm。控件全部自绘。

## 本地命令

Node.js 22.12+（构建）；跑控制台测试需 22.22.2+ 或 24.15+。使用锁文件匹配的 node_modules；`node scripts/gate.mjs` 会逐包确认版本，无需安装。使用完整本地缓存离线重装时可运行 `npm ci --ignore-scripts --offline`。

```sh
export XSIGHT_VERSION=$(git describe --always)
export XSIGHT_OUT="$(pwd)/_out"
export TMPDIR="$XSIGHT_OUT/tmp"
node scripts/gate.mjs
node scripts/artifact-scan.mjs
node scripts/native-scan.mjs
node scripts/css-scan.mjs
node scripts/third-party.mjs --check
node scripts/budget.mjs
npm run dev -- --host 127.0.0.1
```

`XSIGHT_VERSION` 未设时构建配置调用 `git describe --always`；也可显式设置该变量标识构建版本。

开发模式默认启用本地 mock。账号 demo / demo 成功；wrong / 任意非空密码返回 401；limited / 任意非空密码返回 429；unavailable / 任意非空密码返回 503。登录失败界面均显示统一文案。`XSIGHT_MOCK_ACTION=missing|observe|auto` 切换 summary 的 action_mode（默认 auto）。其余 summary 字段逐项对应 `statsSummary`。

需要真实 API 时由开发者设置 `XSIGHT_API`；默认开发模式不连接真实服务。mock 插件只在 serve + development 时加载；`/__dev/components` 只在 dev 注册，均由产物扫描守住。

## 结构与共用约定

- `src/state.ts`：单个 reactive 状态，沿用 token / user / theme / locale / xs-side；classic → light、amber → dark；自动主题依赖 prefers-color-scheme。
- `src/api/client.ts`：fetch、30 秒超时、ApiError、allow 状态码；401 清会话并 replace 到登录页，登录接口除外。safeNext 的输入必须是 Vue Router 已解码的 route.query.next，不得再次解码后跳转。
- `src/auth.ts`：isAdmin 与 AdminOnly；非 admin 隐藏写入口。
- `src/composables/usePoll.ts`：fn 返回数据，accept 在卸载/隐藏/序号检查后才应用；禁止在 fn 内直接写视图状态。暂停、恢复和同一时刻一个在途请求由公共实现负责。
- `src/notifications.ts` / App.vue：notify 与 notifyWrite，根容器跨路由保留，成功文字来自本地词典，失败文字按原文显示。
- `src/format.ts`：pps / bps / thousands / duration / relativeTime；dtRate 专供配置页（K 0 位、M/G/T 1 位）。
- `src/styles/`：共用样式 token、字体栈与三槽曲线颜色；base.css 按共用结构和 CSS 实现。标志使用本仓资产，不在运行时读取其他仓库。
- `src/router.ts`：history 路由及完整旧路径重定向。全部业务路由已接入；外壳、登录、关于、404 可用。
- `scripts/third-party.mjs`：实际渲染 JS 模块和字体来源生成许可证全文；独立的 source map 与字体 sha256 对照检查包集合。临时 witness 构建在 XSIGHT_OUT 内。

## 通用组件接口

业务页面复用以下接口；公共组件变更需明确兼容性影响。

| 组件 | props / 事件与插槽 |
|---|---|
| XListbox | v-model 字符串；options `{value,label,disabled?}`；label；mode `select/search/free`；disabled；固定浮层、键盘与置灰跳过 |
| XDrawer | v-model 布尔；title；width `default/460/600/680/780`；busy；default/footer 插槽；焦点陷阱及归还 |
| XConfirm | v-model 布尔；title、description、action 异步函数；default 插槽；原文失败保持打开，全局同时一条 |
| XTip | text；direction `down/up-right`；wide；按钮关联真实 tooltip 文本节点 |
| XSwitch / XCheck | v-model 布尔；label；disabled；Space 切换 |
| XSeg | v-model 字符串；options；label；左右箭头选择并聚焦 |
| XTabs | v-model 字符串；tabs `{value,label}`；label；query 开启 `?tab=`；各 tab.value 同名插槽 |
| XNumber | v-model 数字；label、min、max、digits、validateOnly、disabled；valid 事件；普通模式失焦钳制，空/非数回上一个有效值；只校验模式不提交无效值 |
| XTable | rows / columns `{key,label,sortable?,heat?}`；rowKey、sortKey、sortDirection、loading、error、clickable；sort / row 事件；列同名和 loading/error/empty 插槽 |
| XPager | v-model 页码（从 1 开始）；pageSize、total 或 hasNext、busy；总数分页/游标两种 |
| XPassword | v-model；label、id、disabled、autocomplete；两个静态 input 显隐 |
| XCopy | text；复制状态 1.5 秒 |
| XBadge / XPill / XDot | tone `ok/warn/crit/neutral`；label；default 插槽 |
| XKpi | label、value、secondary、tone；配对指标 |
| XEmpty | error 原文、loading；default 插槽 |

门中的阳性夹具使用同一入口：native → scanNative；CSS → scanCSS；词典 → checkDictionaries；artifact → scanArtifacts。jsdom 断言 DOM 行为，几何由 placePopup 纯函数测试；实际位置由桌面浏览器验收。

## 曲线、总览与流量

`/overview` 与 `/traffic` 使用只读接口；开发 mock 位于 `mock/data.ts`，默认不连接真实 API。
`XSIGHT_MOCK_CASE=normal|null|bulk|101|capped|empty|zero|loading|error` 提供验收夹具。
总览与流量的轮询都通过 `usePoll` 同步注册；数据函数返回结果，由 accept 应用。
曲线只注册一条 10 秒轮询，回调按当前时间档的 10/60 秒间隔判定是否发请求。

- `src/components/chart/XChart.vue`：props `points: {time:number, values:Record<string,number>}[]`、
  `selected: string[]`、`slots: Record<string,number>`、`bounds: [起点毫秒,终点毫秒]`；
  可选 `bands: {start:number,end:number|null,target:string,type:string}[]`、`metric: pps|bps`、
  `grain`（毫秒）、`sharedMax`、`zoomable`、`loading`、`error`、`outbound`；
  `v-model:window` 为绝对毫秒窗口或 null。双向共用该窗口与 sharedMax，各自保留自己的时间戳。
  Tab 聚焦后，←/→ 逐点读数，Home/End 到首末点，Esc 取消选区或清空读数；可放大时两次 Enter 选区放大，失焦清空键盘选区；props/emits、按钮与 circle 数量、指针操作均不变。
- `XSpark.vue`：`values: number[]`，单线无轴；空集合显示没有近期读数。
- `math.ts`：niceStep、mergeBands、assignSlots、downsample、zoomWindow、formatTick、segments、nearest。
  先分连续段再下采样；总计在线条最底层；颜色直接绑定主题 CSS 槽位变量。
- `DecoderPicker.vue`：使用共享 selection；同旧版键读取、过滤并限制三个 decoder；合计不占名额。
- `src/views/overview/data.ts`：接口类型、原子续页（200 × 10）、brief 分批（50）、CIDR 包含和数据轮询。
  续页任一页失败保留上轮数据并显示原文；List/Count 无数据库快照，页间变化可能暂时重复或遗漏。
- `src/api/contract.ts` 与 `scripts/contract-check.mjs`：离线默认检查 mock；只有显式 `--base` 才请求实例。
  验证者可传 `XSIGHT_TOKEN`；报告不会记录 token。`--contract` 接受独立契约副本，`--report` 指定报告文件。
  `node scripts/contract-positive.mjs` 使用错拼路径副本跑同一完整管道，断言退出码及指名错误。

总览布局存 `xs-ov-layout`；拖标题换位，分隔条 ←/→ 每次调整 2%，边界 30%–78%。
流量筛选写入 URL，decoder 查询键为 `decoders`。只进一侧 Top 的前缀，另一侧显示 —；真实零保留为 0。
阈值规则总数显示在阈值页；曲线 decoder 上限三条，无全选。


## 攻击列表与详情

`/attacks` 的筛选、页码写入 URL；`/attacks/:id` 使用 mitigation-summary 提供日志及缓解状态。
结束确认、强制移除结果使用全局通知；缓解区只读，强制入口按旧版放在动作日志行。
共用数据件位于 `src/api/data.ts`，XDrop 合成号与持有方计算位于 `src/api/xdropRules.ts`。
`XSIGHT_MOCK_CASE=attacks` 覆盖攻击页面；`sample-*`、`force-*` 提供错误和结果夹具。

契约离线命令：`node scripts/contract-check.mjs --attack 2`。
`{attack}` 必须由 `--attack <正整数>` 代入；白名单和报告使用模板路径。
`conditional` 仅用于 Go handler 的父级整键分支，缺键时其子路径为 hit-absent。
mock 严格模式拒绝 conditional-absent；`/api/attacks/active::timers` 始终为必需键。
阳性对照：`node scripts/contract-positive.mjs`，内部同样传入 `--attack`。
真实实例的 `--base` 仅由有联网授权的验证者运行。

## 缓解与节点

`/mitigations` 每 5 秒分别拉 BGP、已忽略孤儿、XDrop 与连接器表；下发和时间线只在打开抽屉或手动刷新时现查。
`/nodes` 每 5 秒拉节点和入向总览；节点抽屉查询状态、Flow 监听数及最近 15 分钟入向曲线。
添加与删除节点、孤儿三操作、BGP / XDrop 强撤的结果通过跨路由通知显示。

离线契约：`node scripts/contract-check.mjs --attack 2 --node edge-a`。
`{node}` 必须传 `--node <id>`，路径和查询参数均以 `encodeURIComponent` 代入。
`optional` 数组父级只放行缺父级的元素；有父级元素的子字段仍严格核对。
`node scripts/contract-positive.mjs` 同时传入两种模板参数。
真实实例仍由验证者执行，timeline / delivery 由本地行为格覆盖。

## 前缀、阈值与基线

`/prefixes` 读前缀、模板与基线三表，不轮询。`/thresholds` 是模板列表，`/thresholds/rules` 是全部规则，`/thresholds/:id` 是模板详情；`/baseline` 只有画像状态每 30 秒刷新。
两类 PUT 按后端「键出现才改」：前缀编辑发五键（不含 `prefix`），父级 / 模板清空发 `null`；默认响应与规则响应只发 `response_id` 一个键。
15 种写操作（前缀、模板、模板规则、全部规则、基线保存）的结果都经跨路由通知显示。
`dtRate` 与旧 `formatRate` 逐值相同：K 取整，M / G / T 一位小数，舍入到 1000 时升一级；非数值显示 `—`。目前只用于检测三页。

离线契约照旧 `node scripts/contract-check.mjs --attack 2 --node edge-a`。
模板详情 `/api/threshold-templates/:id` 不进 `contract.ts`，由 `tests/qe-shared.test.ts` 单独调用 `checkContract` 核对。

## 响应

`/responses` 读响应列表，不轮询；`/responses/:id` 读响应详情与 XDrop / Webhook / Shell / BGP 四张连接器表。
动作编辑器打开前先读 `GET /api/actions/:id/preconditions`；读取失败时条件只读，保存不发条件请求。
保存沿用旧版三步：条件有变化时先以停用写动作，再整份替换条件，最后重新启用；第二步失败提示动作已以停用保存，第三步失败提示重新启用未确认。三步编排在 `src/views/responses/data.ts` 的 `saveAction`，离开页面后仍会走完。

离线契约：`node scripts/contract-check.mjs --attack 2 --node edge-a --response 1`。
`{response}` 必须传 `--response <正整数>`，缺省或非法时该模板条目全部判 `missing`。
`actions[].paired_with` 与 `actions[].auto_generated` 是 `optional`（Go `omitempty`）；条件接口只由 mock 夹具与行为格覆盖。

## 连接器

`/connectors` 与 `/connectors/:kind` 一页显示 BGP / XDrop / Webhook / Shell 四类连接器和旧版 Webhook 只读区，分段由路由参数驱动。
进页并发读四类列表与 `/api/webhooks`，不轮询；每类独立加载与报错，写成功后只重拉该类。BGP / Webhook / Shell / 旧版空表为 `null`，XDrop 为 `[]`。
请求体只由 `src/views/connectors/data.ts` 的 `connectorBody` 构造：XDrop 编辑时密钥框为空就不发 `api_key`（后端会把任何非空值当新密钥）；
Webhook 编辑原样回传 `******` 由后端回填原值，清空整个框发 `{}`；XDrop / Webhook / Shell 新建不发 `enabled`（后端强制启用）；
Shell 不发 `pass_stdin`、BGP 不发 `address_family`（PUT 缺键保留原值）。XDrop 地址按「去空白、去全部尾斜杠」比较是否改动。

测试与路由表端点会真发 HTTP 或在主机执行 vtysh，只由 `src/views/connectors/probe.ts` 发出（超时 45 s），
不进契约门，也不进差分清单——`tests/parity.test.ts` 的 G-sites 把该文件列为排除。mock 只返回夹具回包。
mock 模式：`qg-fail`（某一类列表 500）· `qg-legacy-fail` · `qg-test-fail`（三类测试失败形状与路由 502）· `qg-empty`（四类与旧版全空）。
mock 的 Webhook 行存合成真值、读取时掩码，掩码 PUT 按 Go 回填存储值。

`scripts/artifact-scan.mjs` 只对 hostname 为 `example.com` / `.net` / `.org` 或其子域的 URL 例外放行（RFC 2606），用于表单示例。
`controller/console_connectors_test.go` 锁定 `connectors.decoderScopeBody` 中英各一条、含全部 XDrop 可用 decoder。

## Flow 配置

`/flow` 跳到第一个 mode = flow 的节点；`/flow/:node` 对不存在或非 Flow 的节点显示空页。节点 id 一律 `encodeURIComponent`。
进页读一次 `/api/nodes`；选定节点后并发读状态、listener 列表和每个 listener 的详情（取数据源，N+1）。
只有节点状态每 10 秒轮询，listener 与数据源只在进页、换节点和写成功后重拉。换节点或离页时中止在途请求，
节点序号守卫丢弃旧节点的迟到回包；状态请求另有逐次序号，同节点乱序回包只认最新一次。状态失败保留上次读数、不弹全局提示。
「连接时长」只看 `uptime_seconds` 是否存在，与在线 / 离线独立（`online` 只看最近 10 秒有无统计）。

请求体只由 `src/views/flow/data.ts` 的 `listenerBody` / `sourceBody` 构造。后端 PUT 整体替换，编辑与启停恒带全部四键 / 六键；
新建不发 `enabled`，编辑不发 `node_id` / `listener_id`。只有新建 / 编辑表单做 trim；启停用行上原值，仅把 `device_ip` 去掉末尾 `/数字`。
编辑表单回填 `sample_rate || 1000`，启停保留原值（含 0）。前端只校验三项必填，其余显示后端原文。
数据源运行状态按节点上报的 `netip…Unmap().String()` 匹配：去前缀后，`::ffff:a.b.c.d` 还原成 IPv4，`::a.b.c.d` 换成十六进制写法。

mock 模式：`qh`（多 listener 夹具与第二个 Flow 节点 `flow-d`）· `qh-stale`（离线但仍连着）· `qh-offline` · `qh-status-fail` ·
`qh-empty` · `qh-no-flow` · `qh-detail-fail`；既有模式的 Flow 回包不变。契约门模板参数 `{listener}` 由 `--listener <正整数>` 代入，
缺参或非正整数时该模板条目全部 missing。

## 用户与审计

用户页进页读一次 `/api/users`，写成功后重拉。最后一个启用的 admin 不能被删除、降级或禁用：
`src/views/users/data.ts` 的 `adminGuard` 既用于禁用控件，也在新建 / 编辑 / 删除的处理函数入口再判一次。
同一浏览器标签页内的用户写共用一道写闸（模块作用域 `userGate`：在途写数 `inFlight` 与写代次 `writeGen`）。
页面只有在没有在途写、最近一次读取成功、这次读取发出时的代次等于当前代次、且是本页最新读序号时才可写；
写开始与结束各加一次代次，所有已挂载的用户页随之重拉，离页再回来的新实例同样适用。
抽屉的 `busy` 只在写请求在途时为真；写结束后即使暂不可写，也能关闭抽屉、取消确认和重试读取。
另一个标签页、另一个会话或直接调接口由后端兜底（见「后端最后 admin 保护」一节）；前端这层只防误操作。

改自己或删自己成功后先 `clearSession()`，再去 `/login?notice=account-updated&next=/users`（删自己为 `notice=account-deleted`）；
是否是自己在发请求前就确定，写请求不随离页取消。后端任何成功的 PUT 都会刷新 `updated_at`，该用户的旧令牌随即 401。
请求体只由 `userBody` 构造：新建 `{username, password, role}`（用户名 trim、密码原样）；
编辑 `{role, enabled}`，新密码非空才带 `password`，不发 `username` / `id`。编辑时全空格的新密码在前端拦下。

审计页的请求路径只由 `src/views/audit/data.ts` 的 `auditQuery` 构造：键顺序固定，时间经 `auditTime` 按本地时间解析
（精度到秒、各分量须回读一致）后以 `toISOString()` 发送，`limit=51`、`offset=(页码-1)*50`，多出的第 51 行只用来判断有无下一页。
换筛选、翻页或离页会中止在途请求，读序号丢弃迟到回包；开始晚于结束时不发请求。翻页失败保留当前页，回包 `null` 视为空。

所有 mock 模式都带四个用户与 59 行审计夹具。新模式：`qi`（基础）· `qi-last-admin`（`ops-2` 停用，demo 是唯一启用的 admin）· `qi-users-fail` ·
`qi-audit-fail` · `qi-audit-empty` · `qi-audit-page-fail`（只有 `offset > 0` 失败）。`qi*` 模式另可用 `audit-ro/demo` 以 viewer 登录（id 3）。

## 后端最后 admin 保护

「计入」= `role` 精确等于 `"admin"` 且 `enabled` 为真（与鉴权中间件同口径）。`PUT` / `DELETE /api/users/:id` 会让计入行归零时，
后端回 `409 {"error":"at least one enabled admin is required"}`，不改库、不写审计、不刷新 `updated_at`（旧令牌仍有效）。
判定在 store 层（`store.ErrLastAdmin`）：PG 的 `Update` / `Delete` 在 READ COMMITTED 事务里先取全局事务级咨询锁
（`userAdminLockKey`），再读当前行和其余计入行，所以并发的降级 / 删除不会两边都通过；`Create` 不取锁。
PUT 的次序：400 → 404 `user not found` → 500 `hash failed` → 409 最后 admin → 库错误。页面原样显示该原文，写闸结束后重拉。
内存仓储（`fe_parity_mem_test.go`）与 mock（`mock/users.ts`）同语义，判定先于用户名重复检查；差分末尾 `qj-*` 十步覆盖。
真库格 `TestQJLastAdmin*`（顺序语义、零计入起点、`pg_locks` 同键锁等待见证、20 轮并发）只在设置 `XSIGHT_TEST_ADMIN_DSN` 时运行。
mock 的用户写不追加审计行；既有模式的回包不变。

## 差分测试：mock ↔ Go handler

请求、种子、金标准与 CIDR 语料位于 `../internal/store/postgres/testdata/mock-parity/`：

- `requests.json` 是串行请求清单及 `sites` 表。每个页面写调用必须有覆盖步；`site` 指实际发出请求的文件。
  `builder` 用页面真构造器重算 body，`payload` 的表单附带 `phase`，前缀编辑由请求方法判断。
- `seed.json` 只由 `scripts/parity-seed.mjs` 从 attacks 模式的新 mock 会话导出，
  固定时钟为 `2026-10-28T00:00:00.000Z`；不可手改。G-seed 会重算并逐字段比较。
- `golden.json` 只由 `TestFEParityMem` 经真实 `api.NewRouter` 生成；不可手改。
  Go 使用 `httptest.NewRecorder` 与 `ServeHTTP`，vitest 使用中间件探针，全程无需端口或开发服务器。

`cidr-corpus.json` 只由验证者从真库 `SELECT $1::cidr::text` 取得，不手改、不自行增删。
G-cidr 在 TypeScript 与 Go 中分别检查全部 75 条语料（53 条规范文本、22 条 `22P02`），
`TestFEParityPG` 还会对 live PG 逐条重查；语料未覆盖的写法不声称与 PG 一致。
`inet-corpus.json` 同样只由验证者从真库 `SELECT $1::inet::text` 取得（43 条，Go `net.ParseIP` 接受 28 条），
G-inet 在 TypeScript 与 Go 中分别检查，`TestFEParityPG` 逐条 live 重查。
清单里只有五步的写请求预期 500，均不落行、不耗号：`qh-source-int32-overflow` 与 `qh-source-int32-update-overflow`
回 `{"error":"database error"}`（`sample_rate` 超出 INT 范围，pgx 编码失败）；`qi-user-pw-73`、`qi-user-pw-multibyte`
与 `qi-user-pw-update-73` 回 `{"error":"hash failed"}`（bcrypt 拒绝超过 72 个 UTF-8 字节的密码，编辑按 trim 后的值算）。
两处执行器按步 id + 方法 + 路径放行，并逐字比对该步登记的原文；其余步仍要求 < 500。
差分执行器不接配置发布，运行期只会写出 `node` / `user` 审计行，时间为运行时刻（晚于固定时钟）。
因此清单里的审计读步一律带 `to`，且不晚于 `2026-10-28T00:00:00.000Z`，只看种子行（`tests/parity.test.ts` 的 G-audit-window 强制）；
种子审计行时间互不相同，`ORDER BY created_at DESC` 没有并列。

改 mock 夹具后，在 console 下运行 `node scripts/parity-seed.mjs`，然后到 controller 下运行
`XSIGHT_PARITY_UPDATE=1 go test -count=1 -run '^TestFEParityMem$' ./internal/store/postgres/`，
最后回到 console 运行 `npm test`。仅有意改变 Go 行为时，执行后两步。
离线运行应设置 `GOFLAGS=-mod=readonly GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local`，
并将 `GOCACHE`、`TMPDIR`、`XSIGHT_OUT` 指向可写的缓存、临时和输出目录；
构建时将 `XSIGHT_VERSION` 设为待验收版本。

每次运行的 G-go 是 `go test -count=1 -v -run '^TestFEParity(Mem|Guard|Compare)$' ./internal/store/postgres/`。
G-parity、G-cidr、G-address、G-seed、G-sites、G-shape、G-mask、G-cmp 均在 `tests/parity.test.ts`，
由全量 `node scripts/gate.mjs` 一并执行。添加页面写操作时更新清单与 `sites` 计数，并重生成金标准。
G-address 检查四份 JSON、mock 源码及公告模板生成的地址，只允许文档段、私网与 IETF 保留／特殊用途段。
其阳性地址仅在测试内存中构造，不以完整字面量写入文件。
请求状态码与 JSON 深相等；仅遮非 null 的 `*_at`，以及在指定 ORDER BY 同键连续段内按 id 排序。
当前逐步 mask 清单为空；复制见证覆盖空模板和单规则模板，不遮复制规则的新 id。

内存仓储只实现页面路径所需的 PG 语义，包括七条引用约束及模板／前缀规则组合键的两个唯一索引。
失败 INSERT 仍消耗号；失败 UPDATE 不改原行。所有 mode 共用响应、动作、条件和连接器状态，
列表计数与引用错误从当前状态计算。节点／孤儿只比较写回包，GET 仍保留原无状态夹具。
force-remove、expire、login 及 orphan force-withdraw 成功路径不在本门范围。
执行器在每次 force-withdraw 前读取当前公告，当前 orphan 必须由安全栏拒绝。

离线验证不设置 `XSIGHT_TEST_ADMIN_DSN`，`TestFEParityPG` 应 SKIP。验证者在测试库所在主机的一次性测试库做真库校准，
变更验收及割接前各做一次；种子／清单文本取值变更也须重跑。
文本排序使用字节序，选值必须与测试库所在主机的 `en_HK.UTF-8` libc collation 结论一致：
避免大小写首字母混排及 `10.1.…`／`10.10.…` 这类去标点后产生歧义的前缀对。
最终一致性由 G-pg 证明，mock 不复刻 locale。

测试库所在主机上的验证方式：将 controller（排除 console/node_modules、console/dist、_out）和 shared
整树复制到专用校准目录，以 `PARITY_DIR` 表示其绝对路径，不使用 `--delete`。
在 controller 下先编译
`go test -c -o "$PARITY_DIR/postgres.test" ./internal/store/postgres`，
编译后 `chmod -R o+rX "$PARITY_DIR"`，核验 postgres 用户可执行二进制、可读 JSON。
切到 `controller/internal/store/postgres`，以 OS 用户 postgres 执行：

```sh
XSIGHT_TEST_ADMIN_DSN='postgres:///postgres?host=/var/run/postgresql' \
  "$PARITY_DIR/postgres.test" -test.count=1 -test.v -test.run '^TestFEParityPG$'
```

要求 PASS（不可 SKIP），测试后 `xsight_ct_*` 残留库数为 0，生产库 `xsight` 仍为 1。
不操作生产库、不启动 xsight 或端口、不停启服务。
阳性对照：复制金标准并改一个值，设置 `XSIGHT_PARITY_GOLDEN=<副本绝对路径>` 后重跑 PG 测试，必须红。
Mem 同样支持此只读覆盖；该变量不能与更新模式合用。PG 差异须区分内存语义、collation 或 PG 不确定性，
记录后按生成顺序修正；不可直接编辑金标准。

## 构建与嵌入

在仓库根运行 `./scripts/build-controller.sh all`，完成前端和 Go 二进制构建。
也可先在 `controller/console` 运行 `npm ci && npm run build`，再到 `controller` 运行 `go build`。
缺省 Go 构建嵌入 `console/dist`，因此必须先构建前端；`-tags console` 不再改变嵌入目标。
脚本会在未设置 `XSIGHT_VERSION` 时从仓库取版本，无法取到则使用 `unknown`。
直接运行 `npm run build` 仍需要 Git 仓库，或显式设置 `XSIGHT_VERSION`。
