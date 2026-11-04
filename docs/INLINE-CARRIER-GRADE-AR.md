# دليل المعمارية والتنفيذ لمنظومة التخفيف المباشر (Carrier-Grade Inline Mitigation)

> مواصفة معمارية وهندسية تفصيلية لتحويل YemenAntiDDoS (xSight) إلى منظومة حماية وتنظيف مباشر (Inline Scrubbing & Mitigation) تعمل بسرعة السلك (Line-rate) ومكافئة لمنظومات Corero SmartWall و Netscout TMS في بيئات مزودي خدمات الإنترنت (ISPs).

---

## 1. نظرة عامة والمعمارية المستهدفة

المنظومة الحالية تعتمد على الكشف خارج المسار (Out-of-Band via SPAN/Flow) وتوجيه إجراءات خارجية (BGP RTBH / Flowspec / xDrop). لترقيتها إلى منظومة تنظيف وتخفيف مباشر على سرعة السلك، تتوزع المعمارية على 5 محاور رئيسية:

```
                              ┌───────────────────────────────────────────┐
                              │     YemenAntiDDoS Central Controller      │
                              │ ┌──────────────┐   ┌────────────────────┐ │
                              │ │  Fast-Track  │   │ Inline Rule Engine │ │
                              │ │  Ingestion   │   │  & Clean-Pipe Sync │ │
                              │ └──────▲───────┘   └─────────┬──────────┘ │
                              └────────┼─────────────────────┼────────────┘
        CriticalEventStream (<500ms)   │                     │ gRPC ControlStream
                                       │                     ▼ (Active Filters)
             ┌─────────────────────────┴─────────────────────┴────────────┐
             │            XDP Inline Scrubbing Node (Line-Rate)           │
             │                                                            │
WAN / Peering│  ┌──────────────┐   ┌───────────────┐   ┌───────────────┐  │ LAN / Core
Ingress ────►│  │  XDP Parser  ├──►│ Stateless SYN ├──►│ Filter & Rate ├──┼────► Clean Pipe
             │  │  & Decoders  │   │  Cookie (L4)  │   │ Limiter (Maps)│  │      Egress
             │  └──────┬───────┘   └───────────────┘   └───────┬───────┘  │
             │         │ (Burst > Threshold)                   │ (Drop)   │
             │         ▼                                       ▼          │
             │  ┌──────────────┐                         XDP_DROP         │
             │  │Micro-Mitigate│                                          │
             │  │ local 2s lock│                                          │
             │  └──────────────┘                                          │
             └────────────────────────────────────────────────────────────┘
```

---

## 2. المحور الأول: مسار البيانات والتنظيف المباشر (Inline & Clean-Pipe Scrubbing Engine)

### 2.1 وضع التشغيل المباشر `xdp_filter` (Inline Bridge / Router Mode)
1. **الازدواجية والربط بين المنافذ (Dual-Port Interface Pair):**
   * يتم ربط العقدة بمنفذي شبكة: منفذ الدخول الخارجي `ingress_if` (المتصل بالـ Upstream/Transit)، ومنفذ الخروج النظيف `egress_if` (المتصل بالـ Core Router).
   * الحزم المشروعة تمر عبر توجيه XDP فائق السرعة `bpf_redirect(egress_ifindex, 0)` بزمن انتقال لا يتجاوز ميكروثوانٍ معدودة.
2. **إعادة حقن الترافيك عبر أنفاق التنظيف (Clean-Pipe Return Tunnels):**
   * عند استخدام العقدة كمركز تنظيف لامركزي (Scrubbing Center)، يتم سحب ترافيك الهجوم عبر BGP، وبعد التصفية يتم تغليف الحزم النظيفة داخل أنفاق **GRE** أو **Geneve** لإعادتها إلى موجه المزود دون حدوث دوران في التوجيه (Routing Loop).
3. **تجاوز الأعطال العتادي والمنطقي (Zero-Loss Fail-Open):**
   * دعم بطاقات الشبكة ذات التجاوز البصري (Optical Bypass NICs)؛ في حال انقطاع الطاقة عن السيرفر، تتحول الدائرة إلى مسار مباشر لتجنب انقطاع خط الترانزيت.

---

## 3. المحور الثاني: التصفية الجراحية وخوارزمية SYN Cookie في النواة (Stateless Mitigation)

### 3.1 محرك TCP SYN Cookie الخالي من الحالة (Stateless at XDP)
عند تعرض خادم ويب لهجوم SYN Flood:
1. **الاعتراض والتوليد (Challenge Generation):**
   * يعترض كود XDP حزم `SYN` المتجهة للعنوان المحمي.
   * يتم حساب Cookie تسلسلي 32-bit:
     $$\text{Cookie} = \text{TruncatedHMAC}(\text{SIP}, \text{DIP}, \text{SPort}, \text{DPort}, \text{ISN}, \text{TimeSlot}, \text{Secret})$$
   * يبدل برنامج XDP عناوين MAC و IP في ترويسة الحزمة ذاتها في الذاكرة (In-place packet swap)، ويحول نوع الحزمة إلى `SYN-ACK` مع رقم الـ Sequence المحسوب، ويعيد إرسالها فوراً عبر نفس المنفذ `XDP_TX` دون استهلاك أي مقبس أو ذاكرة في الكيرنل.
2. **التحقق وتمرير العميل (Validation & Whitelisting):**
   * عند وصول حزمة `ACK` من العميل، يتم فحص المعادلة.
   * إذا تطابق الـ Cookie، يُضاف عنوان العميل إلى جدول موثوقين مؤقت (`bpf_map_type_lru_hash`)، ويُعاد تفعيل تمرير الحزم للعميل الشرعي بشفافية تامة.

---

## 4. المحور الثالث: الكشف الذاتي والاستجابة في أجزاء من الثانية (< 500ms Autonomous Detection)

### 4.1 الكشف السريع في النواة (Kernel Burst Triggering)
* يتم الحفاظ على نافذة عدادات دقيقة (100ms Burst Counters) داخل eBPF Maps.
* إذا تجاوز معدل حزم بروتوكول معين عتبة الانفجار (Burst Threshold):
  1. يدخل الـ Node فوراً في وضع **Micro-Mitigation** محلي يطبق إسقاطاً مؤقتاً أو تحديد معدل (Rate-limit) لمدة 2 ثانية في الكيرنل.
  2. يُطلق الـ Node رسالة طارئة غير متزامنة عبر `CriticalEventStream` إلى الـ Controller.
  3. يتجاوز الـ Controller مؤقتات الدقائق ويدخل في الـ **Fast-Track** لتأكيد الهجوم وتوزيع قواعد التصفية الشاملة في أقل من 500 ميلي ثانية.

### 4.2 استراتيجية التضييق التدريجي (Narrow-then-Rebreadth)
1. **المرحلة الأولى (< 200ms):** فرض قيود معدل عامة على البادئة أو المنفذ المستهدف لحماية الروابط من الاختناق.
2. **المرحلة الثانية (500ms – 1s):** مع وصول أول دفعات Flow Samples وتحليل البصمات، يتم تضييق الفلتر إلى المنافذ المحددة أو الشبكات الفرعية للمهاجمين، وإلغاء القيود عن باقي الترافيك.

---

## 5. المحور الرابع: حماية الطبقة السابعة ومكافحة البوتات (L7 Anti-Bot Mitigation)

1. **بصمات TLS (JA3 / JA4 Fingerprinting):**
   * فحص أول حزمة `ClientHello`، واستخراج تسلسل الـ Ciphers والـ Extensions لحساب تجزئة MD5/SHA256.
   * حظر أو تقييد أدوات الهجوم الآلية (مثل Golang/Python attack scripts و Mirai variants) التي تشترك في نفس البصمة.
2. **تحديات المتصفح الخفيفة (Stateless HTTP Challenges):**
   * استخدام ردود `HTTP 307 Redirect` مع كوكي مشفر وموقع أو كود JavaScript خفيف (Proof-of-Work Challenge) للتحقق من أن المتصل متصفح بشري، مع عزل وإسقاط برمجيات البوت غير القادرة على تنفيذ الكود.

---

## 6. المحور الخامس: التسريع العتادي الفائق (Carrier-Grade Hardware Acceleration)

1. **التفريغ العتادي على بطاقات الشبكة (SmartNIC Hardware Offload):**
   * دعم وضع `XDP_OFFLOAD` على بطاقات مثل Nvidia/Mellanox ConnectX-6 Dx/Lx و BlueField DPUs أو Intel E810.
   * إسقاط حزم الهجمات الحجمية (DDoS Volumetric Drops) داخل شريحة بطاقة الشبكة قبل وصولها للمعالج المركزي إطلاقاً.
2. **طبقة AF_XDP Zero-Copy:**
   * استخدام مقابس `AF_XDP (XSK)` مع تفعيل `UMEM Zero-Copy` لنقل الحزم الشرعية إلى طبقة المستخدم بسرعات تتجاوز 10Gbps بدون أي عمليات نسخ إضافية في الذاكرة.
3. **تثبيت الأنوية والعزل (CPU Pinning & RSS Isolation):**
   * عزل أنوية محددة من المعالج لمعالجة مقاطعات كروت الشبكة (Receive Side Scaling - RSS)، وتجنب تبديل السياق (Context Switching) لضمان ثبات الأداء عند 14.88 Mpps وما فوق.
