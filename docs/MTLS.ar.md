# mTLS لقناة gRPC بين المتحكم والعقدة

يغطي هذا المستند طبقة الأمان المتبادل (Mutual TLS) المضافة في المحور الأول من خطة
التصلّب المؤسسي. تُغني هذه الطبقة قناة gRPC غير المشفرة ونموذج الهوية القائم على
حقل `node_id` داخل الرسائل الموصوف في قسم «القيود المعروفة» من ملف README.

> النسخة الإنجليزية: [docs/MTLS.md](MTLS.md)

## نموذج التهديد المعالَج

قبل هذا التغيير كان المتحكم (Controller) يقبل الإحصاءات بحسب قيمة `node_id`
المكتوبة داخل كل رسالة بعد نجاح مصافحة واحدة. النتائج:

| الهجوم | قبل | بعد |
|---|---|---|
| التنصّت السلبي على قناة القياس | ممكن | مستحيل (TLS 1.3) |
| التعديل في المسار / هجوم الوسيط (MITM) | ممكن | مستحيل (تثبيت الشهادة بالـ CA) |
| انتحال عقدة أخرى بعد الفوز بمصافحة واحدة | ممكن | مستحيل (الهوية تُستخرج من URI SAN في الشهادة) |
| عقدة مزوّرة تحقن إحصاءات بمفتاح API مسروق | ممكن | يتطلب شهادة هوية موقّعة من الـ CA |

## نموذج الهوية

تحمل شهادة كل عقدة نطاق URI SAN بالشكل:

```
spiffe://xsight/node/<node_id>
```

يستمد المتحكم هوية العقدة **من الشهادة المتحقق منها**، وليس أبداً من حقل
`NodeHandshake.node_id`. يجب أن تتطابق القيمتان؛ وأي تعارض يُرفض قبل معالجة أي
إحصاءات.

## الملفات على القرص

| الدور | الملفات |
|---|---|
| جهة الإصدار CA (بلا اتصال / مؤمَّنة) | `ca.crt`، `ca.key` |
| المتحكم | `controller.crt`، `controller.key`، `ca.crt` |
| العقدة `<id>` | `<id>.crt`، `<id>.key`، `ca.crt` |

يجب أن تكون المفاتيح الخاصة بوضع `0600` ومملوكة لمستخدم الخدمة. يُفضَّل إبقاء
مفتاح الـ CA دون اتصال أو داخل HSM؛ إذ يلزم فقط لإصدار الأوراق الطرفية أو
تدويرها.

## توليد الشهادات

تتوفر أداة مساعدة (`cmd/xsight-cert`) وهي **مضمّنة** في صورة المتحكم على المسار
`/usr/local/bin/xsight-cert`، فلا حاجة إلى تثبيت Go على المضيف. وللبناء محليًا (اختياري):

```bash
(cd controller && go build -o /usr/local/bin/xsight-cert ./cmd/xsight-cert)
```

يُثبَّت المجلد `./pki` داخل حاوية المتحكم **للقراءة فقط**
(فالمتحكم لا يحتاج إلا قراءة `ca.crt` والشهادات والمفاتيح)، لذا تُولَّد المواد عبر حاوية مؤقتة
بمجلد قابل للكتابة:

```bash
mkdir -p pki   # من جذر المستودع

# 1. إنشاء CA الخاصة بالنشر (مرة واحدة، ثم يُحفظ ca.key دون اتصال)
docker compose run --rm -v "$PWD/pki:/etc/xsight/pki" --entrypoint xsight-cert \
  controller init-ca --out /etc/xsight/pki --cn "xSight Deployment CA"

# 2. إصدار شهادة المتحكم
docker compose run --rm -v "$PWD/pki:/etc/xsight/pki" --entrypoint xsight-cert \
  controller issue --ca /etc/xsight/pki --cn controller \
  --dns controller --dns localhost --ip 10.0.0.10 --out /etc/xsight/pki/controller

# 3. إصدار شهادة لكل عقدة
docker compose run --rm -v "$PWD/pki:/etc/xsight/pki" --entrypoint xsight-cert \
  controller issue --ca /etc/xsight/pki --node-id node-01 --out /etc/xsight/pki/node-01

# 4. التحقق من السلسلة قبل النشر
docker compose run --rm -v "$PWD/pki:/etc/xsight/pki" --entrypoint xsight-cert \
  controller verify --ca /etc/xsight/pki/ca.crt \
  --cert /etc/xsight/pki/node-01.crt --node-id node-01
```

تعمل الصورة بالمستخدم `10001`، لذا يجب أن يملك هذا المستخدم قراءة المجلد قبل تشغيل الخدمة:
`sudo chown -R 10001:10001 pki && chmod 700 pki && chmod 600 pki/*.key`، ثم يُحفظ `ca.key` دون اتصال.

## إعدادات المتحكم

```yaml
tls:
  enabled: true
  ca_file: /etc/xsight/pki/ca.crt      # يتحقق من شهادات العقد (العميل)
  cert_file: /etc/xsight/pki/controller.crt
  key_file: /etc/xsight/pki/controller.key
  server_name: controller              # الاسم المتوقع في شهادتنا الطرفية
  allow_legacy_tls12: false            # أبقه false ما لم يفرض وسيط TLS 1.2
```

## إعدادات العقدة

```yaml
tls:
  enabled: true
  ca_file: /etc/xsight/pki/ca.crt      # يتحقق من شهادة المتحكم
  cert_file: /etc/xsight/pki/node-01.crt
  key_file: /etc/xsight/pki/node-01.key
  server_name: controller              # يجب أن يطابق SAN في شهادة المتحكم
```

## تسلسل التفعيل (ترحيل بدون توقف)

1. نشر الـ CA وإصدار شهادة المتحكم؛ تفعيل `tls.enabled: true` على المتحكم
   مع إبقاء `tls.enabled: false` على العقد مؤقتاً.
   *المتحكم بعد التفعيل يطلب شهادات عميل، ما يقطع العقد غير المشفرة.* لذلك
   استخدم الترتيب التالي بدلاً من ذلك:
2. **المرحلة أ** — إبقاء المتحكم غير مشفر. إصدار شهادات كل العقد ونشرها مع
   `tls.enabled: false` (الشهادات على القرص وغير مستخدمة).
3. **المرحلة ب** — تحويل المتحكم إلى `tls.enabled: true` خلال نافذة صيانة.
   يجب أن تحمل كل العقد شهاداتها وتُحوَّل في نفس الوقت (المستمع لم يعد يقبل
   الاتصالات غير المشفرة).
4. **المرحلة ج** — التحقق من ظهور `handshake accepted` مع `tls: ... (mTLS)`
   في سجل المتحكم لكل عقدة.

> إذا تعذّر الترحيل المتدرج، فعِّل TLS على كل العقد وعلى المتحكم في نفس نافذة
> التغيير. يرفض المتحكم الاتصالات غير المشفرة فور تفعيل `tls.enabled`.

## التدوير

تعيد العقدة والمتحكم تحميل شهادتهما الطرفية من القرص عند تغيّر mtime أو حجم
الملف، بفحص لا يتجاوز 30 ثانية لكل مصافحة. للتدوير:

1. إصدار ورقة طرفية جديدة بنفس `node_id` / اسم الخادم.
2. استبدال `cert_file` و`key_file` ذرياً (الكتابة في ملف مؤقت داخل نفس
   المجلد ثم `mv`).
3. تستخدم إعادة الاتصال التالية المادة الجديدة؛ دون الحاجة لإعادة التشغيل.

تدوير **الـ CA** يتطلب حزمة ثقة تضم شهادتي الـ CA القديمة والجديدة خلال فترة
التداخل، ثم جولة ثانية لإسقاط القديمة.

## الإبطال

إبطال الشهادات غير مطبَّق (لا CRL ولا OCSP). لإزالة عقدة:

1. تعطيل العقدة من واجهة الويب (`enabled: false`) — تُرفض المصافحة بغضّ النظر
   عن صلاحية الشهادة.
2. حذف ملفات شهادتها وإعادة الإصدار فقط إذا عادت.

التعطيل من الواجهة هو الضابط المرجعي؛ الشهادات ليست بديلاً عنه.

## حالات الفشل

| العرَض | السبب |
|---|---|
| `tls: load keypair` عند الإقلاع | ملف الشهادة أو المفتاح مفقود أو غير مقروء |
| `tls: CA ... contains no PEM certificate` | صيغة `ca_file` خاطئة |
| العقدة: `certificate has no spiffe://xsight/node/<id> URI SAN` | الورقة أُصدرت دون `--node-id` |
| العقدة: `x509: certificate signed by unknown authority` | `ca_file` للعقدة ليس الـ CA الذي وقّع شهادة المتحكم |
| العقدة: `x509: certificate is valid for X, not Y` | `server_name` لا يطابق أي SAN في شهادة المتحكم |
| رفض المصافحة `identity mismatch` | معرّف العقدة في SAN يخالف `node_id` المضبوط |
