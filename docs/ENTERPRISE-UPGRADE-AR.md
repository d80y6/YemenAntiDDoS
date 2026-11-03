# خطة الترقية المؤسسية لمنصة xSight

> رؤية هندسية موحّدة لرفع xSight من منصة رصد إلى منصة تخفيف هجومية ذاتية (Autonomous Mitigation)
> قادرة على العمل بثبات في بيئة إنتاجية نظيفة بسعة **10Gbps** وأحمال **64-byte** عالية الحزم (PPS).
> مرجع الكود: `github.com/d80y6/YemenAntiDDoS` (Controller + Node + shared + console؛ مسار وحدات Go الداخلي `github.com/d80y6/YemenDDoS/...`).

---

## 1. الملخّص التنفيذي

تتكوّن xSight من:

- **Controller** (Go 1.25): واجهة REST/Gin، محرّك كشف (threshold + EWMA baseline)، محرّك إجراءات
  (xDrop / BGP RTBH / webhook / shell)، تخزين TimescaleDB، وواجهة Vue 3.
- **Node** (Go 1.24): وكيل XDP/eBPF (وضع `xdp`) أو مستقبل sFlow/NetFlow/IPFIX (وضع `flow`)،
  يرسل الإحصاءات عبر gRPC والاتصال ثنائي الاتجاه `ControlStream`.

الفجوات المؤسسية الخمس التي تعالجها هذه الخطة:

| # | العمود | الفجوة الحالية | الهدف |
|---|--------|----------------|-------|
| 1 | أمن النقل | gRPC نصّي، والهوية من `node_id` داخل الرسالة | mTLS كامل + هوية من الشهادة (URI SAN) |
| 2 | التخفيف الذاتي | نافذة تأكيد 3–5 ثوانٍ، عتبة عينات صلبة 1000 | مسار سريع (fast-path) + عتبة عينات تكيفية |
| 3 | رؤية L7 | مفكّكات L3/L4 فقط | HTTP flood، Slowloris، شذوذ TLS handshake |
| 4 | توجيه الشبكة | BGP RTBH فقط (حجب البادئة كاملة) | BGP Flowspec + أتمتة Cisco/Juniper/Arista |
| 5 | الموثوقية والأداء | لا اختبار حمل، لا خط أساس 10Gbps | harness لاختبار الضغط + استرجاع الحالة |

### حالة التنفيذ في هذا المستودع

| المكوّن | الحالة | الملفات |
|---------|--------|---------|
| mTLS (حزمة + ربط + أداة شهادات) | ✅ منفّذ ومُختبَر | `shared/tlsconf/`، `controller/cmd/xsight-cert/`، `docs/MTLS.md` |
| Fast-path للتأكيد | ✅ منفّذ ومُختبَر | `controller/internal/tracker/tracker.go`، `fastpath_test.go` |
| عتبة عينات تكيفية | ✅ منفّذة (اختيارية) | `controller/internal/action/xdrop_shape.go`، `xdrop_adaptive_test.go` |
| تحليل L7 (HTTP/Slowloris/TLS) | ✅ منفّذ ومُختبَر (Node + Controller + Console) | `shared/l7/`، `node/internal/l7collector/`، `controller/internal/l7store/`، `docs/L7.md` |
| مُولّد أوامر BGP Flowspec | ✅ مُختبَر (FRR + قوالب موردين) | `controller/internal/action/flowspec/` |
| اختبار الضغط وسيناريوهات الفوضى | ✅ أدوات ووثائق | `scripts/stress-10g.sh`، `docs/CHAOS-TESTS.md` |

---

## 2. المعمارية العامة (بعد الترقية)

```
                    ┌──────────────────────────────────────────────┐
                    │              Controller                      │
   mTLS 1.3         │  ┌────────────┐   ┌──────────────┐           │
 Node ──────► gRPC ─┼─►│ Ingestion  │──►│ Detection     │          │
 (XDP/flow)         │  │ (+identity │   │ threshold+EWMA│          │
                    │  │  from cert)│   └──────┬───────┘           │
                    │  └────────────┘          │                    │
                    │                    ┌─────▼──────┐             │
                    │                    │  Tracker    │            │
                    │                    │ (fast-path) │            │
                    │                    └─────┬───────┘            │
                    │                    ┌─────▼───────┐            │
                    │                    │ Action      │            │
                    │                    │ Engine      │            │
                    │                    └──┬───┬───┬──┘            │
                    │         xDrop v3 ◄────┘   │   └────► BGP/Flowspec
                    │        (rate_limit)       │          (FRR vtysh)
                    │                       webhook/shell          │
                    └──────────────────────────────────────────────┘
```

مبدأ التصميم: **لا يُنشأ أي إجراء تخفيف بناءً على بيانات غير موثّقة الهوية**. كل مسار
من Node إلى Controller يجب أن يمر عبر هوية شهادة، وكل قرار تخفيف يُسجَّل مع سببه.

---

## 3. العمود الأول: أمن النقل (mTLS) — ✅ منفّذ ومُتحقَّق منه

### 3.1 نموذج الهوية

- كل شهادة Node تحمل URI SAN بالصيغة `spiffe://xsight/node/<node_id>`.
- الـ Controller يستخرج الهوية من الشهادة المتحقَّق منها فقط، **لا** من `NodeHandshake.node_id`.
- عند التعارض بين SAN و`node_id` تُرفض المصافحة والتدفقات اللاحقة.

### 3.2 الحزمة المشتركة `shared/tlsconf`

| الرمز | الوظيفة |
|-------|---------|
| `NodeURI(id)`, `NodeURIPrefix` | بناء/قراءة هوية SPIFFE من/إلى الشهادة |
| `NodeIDFromCert(cert)` | استخراج `node_id` من URI SAN |
| `FileConfig{CAFile,CertFile,KeyFile,ServerName,AllowLegacyTLS12}` | وصف ملفات الشهادة |
| `ServerConfig(fc)` | `tls.Config` للخادم: TLS 1.3، `RequireAndVerifyClientCert` |
| `ClientConfig(fc)` | `tls.Config` للعميل: `RootCAs` + شهادة عميل + `ServerName` |
| `FileConfig.LeafNotAfter()` | تحذير قبل انتهاء الشهادة |
| `reloader` (داخلي) | إعادة تحميل الشهادة عند تغيّر mtime/size، بحدّ 30 ثانية |

قرارات التصميم:

- **CA ثابت + أوراق قابلة للتحميل** بدل «Controller كـ CA» لتجنّب الاعتماد الدائري.
- **TLS 1.3 كحدّ أدنى**؛ `allow_legacy_tls12` للطوارئ فقط ويُسجَّل تحذير.
- `SessionTicketsDisabled` لمنع استئناف الجلسة عبر هويات مختلفة.
- إعادة التحميل تحافظ على آخر شهادة صالحة عند فشل القراءة (لا انقطاع مفاجئ).

### 3.3 الربط في المكوّنات

| الملف | التعديل |
|-------|---------|
| `controller/internal/config/config.go` | كتلة `tls:` + تحقّق fail-fast عند الإقلاع |
| `controller/internal/ingestion/server.go` | `grpc.NewServer(grpc.Creds(...))` عند التفعيل |
| `controller/main.go` | بناء `ServerConfig` وتمريره |
| `controller/internal/ingestion/grpc_handler.go` | `peerCertNodeID(ctx)` + ربط الهوية في `Handshake`، `StatsStream`، `SampleStream`، `CriticalEventStream`، `ControlStream` |
| `node/internal/config/config.go` | كتلة `tls:` + تحقّق |
| `node/internal/reporter/reporter.go` | `transportCredentials(tls)` بدل `insecure` |
| `node/main.go` / `node/flow_main.go` | بناء `ClientConfig` لوضعي xdp وflow |
| `controller/cmd/xsight-cert/main.go` | أداة `init-ca` / `issue` / `verify` |
| `docs/MTLS.md` | دليل النشر والتدوير والإلغاء (النسخة الإنجليزية) |
| `docs/MTLS.ar.md` | دليل النشر والتدوير والإلغاء (هذه النسخة العربية) |

### 3.4 التحقّق

- اختبار `TestMutualTLSInterop`: مصافحة TLS 1.3 حقيقية + استخراج الهوية من URI SAN.
- اختبار `TestServerRejectsUnknownCA`: رفض شهادة عميل من CA غير موثوق (فشل الخادم).
- اختبار وظيفي لأداة `xsight-cert`: إنشاء CA، إصدار، تحقّق، رفض عدم تطابق الهوية، صلاحيات `0600`.

---

## 4. العمود الثاني: محرّك التخفيف الذاتي (Zero-Touch) — ✅ جوهره منفّذ

### 4.1 المشكلة الدقيقة

1. كشف العتبة يعمل كل ثانية، ولا يُؤكَّد الهجوم إلا بعد `hard_threshold_confirm_seconds` (افتراضي 3)
   أو `dynamic_threshold_confirm_seconds` (افتراضي 5).
2. هجمات **hit-and-run** التي تدوم 1–2 ثانية تنتهي قبل التأكيد ⇒ لا يُنشأ أي إجراء إطلاقًا.
3. تضييق القاعدة يعتمد على `xdrop_min_sample_packets` (1000). الهجمات القصيرة لا تجمع 1000 عينة،
   فتبقى القاعدة عريضة (أو `rate_limit` احتياطيًا).

### 4.2 الحلول المنفّذة

**(أ) Fast-Path في الطبقة `tracker`**

```go
// controller/internal/tracker/tracker.go — داخل Feed
if t.cfg.FastPathMultiplier > 0 && evt.Value > 0 &&
    float64(evt.Actual) >= t.cfg.FastPathMultiplier*float64(evt.Value) {
    if a.ConsecutiveExceeded < a.ConfirmThreshold { a.ConsecutiveExceeded = a.ConfirmThreshold }
    if a.tickSustained < a.ConfirmThreshold { a.tickSustained = a.ConfirmThreshold }
}
```

- التفعيل من `action_engine.fast_path_multiplier` (افتراضي 5.0، و`0` يعطّل).
- يُرفع الهجوم إلى `active` في أول tick عندما يكون المعدل ≥ 5× العتبة.
- لا يزال xDrop محكومًا بـ `mode: auto`، فلا تنفيذ غير مرغوب في وضع المراقبة.

**(ب) عتبة عينات تكيفية في الطبقة `action`**

```go
// controller/internal/action/xdrop_shape.go
func effectiveMinSamples(dominantPct int) uint64 {
    base := xdropShapeSettings.MinSamplePackets
    if base == 0 || !xdropShapeSettings.AdaptiveSamples { return base } // 0 = بلا حدّ
    var lowered uint64
    switch {
    case dominantPct >= 95: lowered = maxU64(32, base/20)
    case dominantPct >= 90: lowered = maxU64(64, base/10)
    default: return base
    }
    if lowered >= base { return base }
    return lowered
}
```

- اختيارية عبر `action_engine.xdrop_adaptive_samples` (افتراضي `false` للحفاظ على العقد الحالي).
- لا ترفع الحدّ أبدًا، وتُعطَّل تلقائيًا عندما يكون `xdrop_min_sample_packets: 0`.
- النتيجة: هجوم قصير لكن إشارته حاسمة (≥90% على منفذ واحد) يمكن تضييقه فورًا.

### 4.3 المتبقّي (المرحلة التالية)

- **Narrow-then-rebreadth**: إنشاء قاعدة `rate_limit` فورًا عند الكشف، ثم `EnqueueRebreach`
  لتضييقها عندما تتراكم عينات كافية (البنية موجودة أصلًا في `EnqueueRebreach`).
- **حظر الإجراءات اليدوية في وضع auto**: التحقق من أن `Execution == manual` لا يعطّل التخفيف الذاتي.
- مراقبة معدل التضخّم (cardinality) لقواعد xDrop الناتجة عن التكيف.

---

## 5. العمود الثالث: رؤية وتصفية الطبقة السابعة

### 5.1 التصميم

المفكّكات الحالية (14) تعمل على L3/L4 داخل XDP. فحص L7 يتطلّب إمّا:

- **مسار XDP خفيف**: تفتيش أول 64–128 بايت من الحمولة (بعد رؤوس TCP) لاكتشاف:
  - HTTP methods/paths متكرّرة (GET/POST flood)،
  - بطء الرؤوس (Slowloris): TCP نافذة صغيرة + رؤوس غير مكتملة،
  - شذوذ TLS ClientHello (حجم/عدد cipher suites غير معتاد).
- **مرحلة user-space اختيارية** على Node للترافيك المرآة (لسـ ERPAN) مع تجميع معدلات
  لكل (src_ip, dst_port, path).

### 5.2 هيكل القواعد المقترح

فكّكا L7 مخصّصان في فتحات 14–15 المحجوزة:

```go
// shared/decoder/decoder.go
const (
    HTTPFlood   = 14 // payload-rate: requests/sec لكل (src_ip,dst_ip,path)
    TLSAnomaly  = 15 // handshake-rate: ClientHello/sec + شذوذ الحجم
)
```

قاعدة عتبة جديدة: `Unit: "rps"` (requests per second) مع `Decoder: http_flood`،
و`Unit: "hsps"` (handshakes per second) مع `Decoder: tls_anomaly`.

استخدام placeholders الموجودة `{dominant_dst_port}`, `{src_ip}` لأتمتة xDrop،
وإضافة `{http_path}` و`{tls_sni}` اختياريًا.

### 5.3 خطة التنفيذ

1. توسيع `shared/decoder` وأسماء الفتحات.
2. إضافة أعمدة/جداول في `ts_stats` عبر `AutoMigrate` (لا ملفات `.sql`).
3. إضافة `payload sampler` على Node (قراءة دنيا، بلا نسخ على المسار الساخن).
4. اختبارات وحدات لفكّ الترميز + اختبار معدل خاطئ (L7 flood محاكى).

---

## 6. العمود الرابع: تنسيق الشبكة وBGP Flowspec

### 6.1 Flowspec

إضافة نوع موصّل `bgp_flowspec` يستخدم FRR عبر `vtysh`:

```
configure terminal
flowspec
  flow spec ipv4 1 permit
    match destination 198.51.100.7/32
    match protocol tcp
    match destination-port 443
    then actions rate-limit 1000000
```

- يدعم `drop` و`rate-limit` بدقة أعلى من RTBH (لا يحجب البادئة كاملة).
- يُخزَّن في جدول `bgp_announcements` بحقل `kind` (`rtbh|flowspec`).
- استرجاع آمن: نفس منطق `startup_cleanup` مع `splitExternalRuleID` وتوسيعه لـ Flowspec.

### 6.2 أتمتة الموردين

قوالب لكل مورّد (Cisco IOS-XR، Juniper JunOS، Arista EOS) تُولّد الأوامر من قالب واحد
مع متغيّرات `{prefix}`, `{port}`, `{proto}`, `{rate}`. اختيار القالب عبر حقل
`vendor` في موصّل BGP، مع `testBGPConnector` يتحقّق من القدرة.

### 6.3 خطة التنفيذ

1. `controller/internal/api/bgp_connector.go`: إضافة `Vendor` و`FlowspecEnabled`.
2. `controller/internal/action/bgp.go`: دالة `announceFlowspec` / `withdrawFlowspec`.
3. توسيع `scheduled_actions` ليشمل `flowspec_withdraw`.
4. اختبارات محاكاة `vtysh` عبر stub.

---

## 7. العمود الخامس: الموثوقية واختبار الضغط والمراقبة

### 7.1 خط أساس 10Gbps / 64-byte

- 10Gbps بحزم 64-byte ⇒ ≈ **14.88 Mpps** (بما فيها FCS/preamble/IFG).
- يجب أن يظل Node يخدم معدل العينات دون إشباع CPU:
  - قياس `samples/sec` و`dropped` من `bpftool`/counter.
  - ضبط `bpf.max_entries` و`parse_workers` وفق النتائج.
- سيناريوهات الفوضى (chaos):
  1. تدفق 64-byte ثابت 10Gbps لمدة 10 دقائق ⇒ لا فقدان XDP، CPU < 80%.
  2. هجوم hit-and-run 2 ثانية × 50 ⇒ قياس زمن «الكشف→قاعدة xDrop».
  3. انقطاع FRR ثم عودته ⇒ تحقّق استرجاع الحالة دون تعليق.
  4. إعادة تشغيل Controller أثناء وجود قواعد xDrop نشطة ⇒ استرجاع `xdrop_active_rules`.

### 7.2 استبقاء البيانات

- مراجعة سياسات `retention` وضغط TimescaleDB و`continuous aggregates`.
- إضافة قياس لمعدل نمو الجداول وتنبيه قبل بلوغ الحدّ.

### 7.3 الاسترجاع الرشيق

- اختبار `scheduled_actions` العالقة في `executing` بعد crash (الوظائف موجودة؛ نضيف
  اختبارات تكامل تغطيها).
- مهلة موحّدة للإجراءات المتأخرة وتوثيق حالات الفشل.

---

## 8. خارطة الطريق التنفيذية

| المرحلة | المحتوى | معيار القبول |
|---------|---------|--------------|
| م0 | تدقيق الكود الحالي (منجز) | خرائط نقاط الحقن في الأعمدة الخمسة |
| م1 | mTLS كامل + أداة الشهادات (منجز) | اختبارات mTLS + وظيفية الشهادات تمرّ |
| م2 | Fast-path + عتبة عينات تكيفية (منجز جزئيًا) | اختبارات tracker/action تمرّ |
| م2ب | Narrow-then-rebreadth + مراجعة manual | سيناريو hit-and-run يُخفَّف < 2s |
| م3 | فكّكا L7 + أعمدة الإحصاء | كشف HTTP flood وSlowloris في اختبار |
| م4 | BGP Flowspec + قوالب الموردين | htb/stub vtysh + تحقق من الأوامر |
| م5 | harness اختبار 10Gbps + سيناريوهات فوضى | تقرير أداء مُوثّق |
| م6 | توثيق تشغيلي نهائي + دليل ترقية | `docs/` محدّثة |

### أوامر التحقّق القياسية

```bash
# بناء الحزم المتأثرة
cd shared   && go build ./... && go test ./...
cd controller && GOTOOLCHAIN=auto go build ./... && GOTOOLCHAIN=auto go test ./internal/...
cd node     && go build ./...   # يحتاج bpf2go مُولَّدًا (make node)

# اختبار mTLS
cd shared && go test ./tlsconf/ -v

# توليد شهادات
go run ./controller/cmd/xsight-cert init-ca --out /tmp/pki
go run ./controller/cmd/xsight-cert issue --ca /tmp/pki --node-id node-01
go run ./controller/cmd/xsight-cert verify --ca /tmp/pki/ca.crt --cert /tmp/pki/node-01.crt --node-id node-01
```

---

## 9. مصفوفة التحقّق من الأمان

| التهديد | قبل | بعد |
|---------|-----|-----|
| تنصّت سلبي على الإحصاءات | ممكن | ممنوع (TLS 1.3) |
| MITM / تعديل على المسار | ممكن | ممنوع (تثبيت CA) |
| انتحال هوية Node | ممكن بعد مصافحة واحدة | ممنوع (هوية من الشهادة) |
| إدخال إحصاءات مزوّرة | مفتاح API مسروق | شهادة موقّعة من CA |
| هجوم hit-and-run لا يُكتشف | وارد | يُكتشف ويُخفَّف عبر fast-path |

---

## 10. ملاحظات تشغيلية مهمّة

- `mode: observe` افتراضي ⇒ لا تُنشأ قواعد xDrop؛ للتفعيل الكامل اضبط `mode: auto`
  مع `fast_path_multiplier` و`xdrop_adaptive_samples` حسب بيئتك.
- تفعيل `tls.enabled` على الـ Controller يعني **رفض أي اتصال نصّي**؛ انتقل على مراحل
  وفق `docs/MTLS.md`.
- الواجهة `console/dist` يجب بناؤها (`npm run build`) قبل `go build ./controller/...`
  الكامل بسبب `embed`.
