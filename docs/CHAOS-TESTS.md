# سيناريوهات الفوضى واختبار الضغط (Chaos & Load)

هذا المستند يحدّد كيف نُثبت أن xSight يبقى مستقرًا في بيئة 10Gbps نظيفة، وأن
مسار التخفيف الذاتي يتفاعل أسرع من عمر الهجمات القصيرة.

## 0. خط الأساس الرياضي

| المعدل | حزم 64-byte في الثانية | ملاحظة |
|--------|------------------------|--------|
| 1 Gbps | 1,488,095 pps | 84 بايت على السلك |
| 10 Gbps | 14,880,952 pps | 14.88 Mpps |
| 40 Gbps | 59,523,809 pps | للاختبار المستقبلي |

المعادلة: `pps = gbps * 1e9 / (84 * 8)`.

## 1. سيناريوهات الاختبار

### S1 — إشباع ثابت 10Gbps / 64-byte (10 دقائق)

- الهدف: ثبات XDP تحت 14.88 Mpps.
- الأمر: `IFACE=eth1 GBPS=10 RUN=1 DURATION=600 ./scripts/stress-10g.sh`
- معايير النجاح:
  - `xdp_exception` لا يزيد.
  - CPU للـ Node < 80% (mpstat).
  - `samples/sec` المُرسل للـ Controller ضمن 10% من pps المحقون.
  - لا `OOM` ولا إعادة تشغيل للعملية.

### S2 — هجوم hit-and-run (2 ثانية × 50 مرة)

- الهدف: إثبات مسار `fast_path_multiplier`.
- التوليد: نبضات 2s بمعدل 10× العتبة، فاصل 5s.
- معايير النجاح:
  - كل نبضة تصل إلى `state=active`.
  - زمن «أول ثانية متجاوزة → قاعدة xDrop» < 2s.
  - لا قواعد معلّقة بعد انتهاء النبضة + `expiry_interval`.

### S3 — انقطاع FRR ثم عودته

- الهدف: استرجاع حالة BGP دون تعليق.
- الخطوات: أوقف `frr`، أنشئ هجومًا، ثم أعد تشغيله.
- معايير النجاح:
  - الإجراءات تفشل بسرعة وتُسجَّل `status=failed` مع السبب.
  - بعد العودة، `startup_cleanup`/`scheduled_actions` تُعيد الاتساق.
  - لا إجراءات عالقة في `executing`.

### S4 — إعادة تشغيل Controller مع قواعد xDrop نشطة

- الهدف: استرجاع `xdrop_active_rules`.
- معايير النجاح:
  - بعد الإقلاع، القواعد النشطة تُعاد مزامنتها أو تُسحب بأمان.
  - لا تكرار في `xdrop_active_rules`.

### S5 — تلف/تأخّر شهادة Node (mTLS)

- الهدف: ألا يُسقط تدوير الشهادة الاتصال.
- معايير النجاح:
  - إعادة التحميل خلال ≤ 30s دون إعادة تشغيل.
  - شهادة منتهية ⇒ رفض واضح في السجلات، لا panic.

### S6 — ضغط cardinality (هجوم carpet-bombing)

- الهدف: حماية `max_global_keys` و`max_active_attacks`.
- معايير النجاح:
  - لا تضخّم غير محدود في الذاكرة.
  - سياسة الإخلاء تعمل كما هو موثّق في `config.example.yaml`.

## 2. أدوات القياس

```bash
# XDP counters
bpftool prog show | grep -i xdp
ethtool -S eth1 | grep -Ei 'xdp|drop'
# CPU
mpstat -P ALL 1 10
# Controller metrics
curl -s localhost:9090/metrics | grep -E 'xsight_(samples|packets|drops|action)_'
# state machine
psql "$DSN" -c "select state,count(*) from attacks group by 1;"
psql "$DSN" -c "select state,count(*) from xdrop_active_rules group by 1;"
```

## 3. قالب تقرير النتائج

```
التاريخ:
البيئة: kernel / NIC / driver / CPU
السيناريو: S1..
المعدل المحقون: pps
المعدل المستلم: pps
CPU (Node): avg / peak
xdp_exception:
samples dropped:
زمن الكشف→xDrop:
الملاحظات:
```
