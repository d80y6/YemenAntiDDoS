# إدارة BGP Flowspec

> النسخة الإنجليزية: [docs/FLOWSPEC.md](FLOWSPEC.md)

## نظرة عامة

يستطيع YemenAntiDDoS إعلان قواعد BGP Flowspec (متعددة البائعين) بدلاً من
الرجوع إلى الإعلان الشامل RTBH (الترحيل إلى القائمة السوداء). تُخزَّن القواعد في جدول
`bgp_announcements` بالقيمة `kind='flowspec'` مع `rule_spec` بصيغة JSON، وتُنفَّذ
عبر FRR (`vtysh`) للموصّل المحلي؛ أما موصّلات Cisco وJuniper وArista فهي للتصدير
فقط (تُولَّد الأوامر لتطبيقها يدوياً).

## المسار

1. هجوم يُفعِّل إجراءً موصولاً بموصّل BGP عليه `flowspec_enabled=true`.
2. يبني `executeBGPFlowspec` قاعدة `flowspec.Rule` عبر
   `flowspecRuleFor(dstIP, attack)` ويُرفق `BGPAnnouncement` بالقيمة
   `RouteMap = xsight-<prefix>` و`Kind="flowspec"`.
3. لموصّلات FRR تُصيَّر القاعدة عبر `flowspec.Render` وتُطبَّق عبر `vtysh`.
4. لموصّلات غير FRR يُعلَّم الإعلان كمُعلَن مع الأوامر المصيَّرة للتصدير.

## الوحدة (Console)

تعرض تبويب **Mitigations → Flowspec** الإعلانات، ويفتح درجاً يعرض القاعدة
وأوامر التثبيت والسحب (قابلة للنسخ)، ويظهر الهجمات المرفقة، ويدعم السحب
القسري. تعرض لوحة **Preview** قاعدة لأي بائع/بادئة/بروتوكول/منفذ/إجراء
دون إنشاء إعلان.

## السحب القسري

`POST /api/flowspec/announcements/:id/withdraw` تصيّر أمر `no …` الخاص بالبائع،
وتنفّذه عبر FRR إن انطبق، وتُعلّم الإعلان مسحوباً.

## توحيد أسماء البائعين

يقبل `normalizeVendor` القيم `frr` و`cisco` و`juniper` و`arista` (لا حساسية
لحالة الأحرف) ويعود إلى `frr` عند الفراغ. القيم غير المعروفة تُرجع خطأ.

## ضبط الموصّلات

تُضبط موصّلات BGP من وحدة الويب (Console → Settings → BGP Connectors) وليس من
ملف YAML. الحقول لكل موصّل:

| الحقل | القيم |
|---|---|
| `vendor` | `frr` (الافتراضي) \| `cisco_xr` \| `juniper` \| `arista` |
| `flowspec_enabled` | `true` = إعلان قواعد Flowspec، `false` = RTBH فقط |
| `bgp_asn` | رقم النظام المستقل المحلي (مطلوب) |
| `vtysh_path` | مسار أداة vtysh لـ FRR (لبائع frr فقط) |
| `address_family` | `ipv4` \| `ipv6` |

تُطبَّق القواعد محلياً لموصّلات FRR عبر vtysh؛ بينما تبقى Cisco XR وJuniper و
Arista للتصدير فقط — تصيّر الوحدة الأوامر الخاصة بكل بائع في درج Mitigations →
Flowspec لتطبيقها يدوياً.
