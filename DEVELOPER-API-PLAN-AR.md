# SmartRisk Developer API — v0.9 Plan

## الهدف

تحويل SmartRisk من واجهة فحص للمستخدم إلى محرك يمكن للمطورين بناء منتجات فوقه، مع إبقاء الفحص العام متاحًا بدون تسجيل الدخول.

## المعمارية

```text
Developer
   ↓
API Key (X-API-Key)
   ↓
Batch API
   ↓
Batch Coordinator
   ↓
ScanService / Redis Workers
   ↓
UnifiedRiskEngine
   ↓
Programmatic JSON
```

## قواعد المنتج

- API Key لا يظهر إلا داخل الحساب بعد تسجيل الدخول.
- الفحص العام `/v1/scans` لا يتطلب حسابًا.
- الـDeveloper API منفصل منطقيًا عن Scanner العام.
- كل Batch غير متزامن Async؛ لا ينتظر HTTP تنفيذ جميع الفحوص.
- الحد التصميمي الأول: Developer = 500 عقدة/دفعة، Pro = 2,000 عقدة/دفعة.
- الحدود النهائية تعتمد على اختبارات الحمل الفعلية.
- خطتا اشتراك فقط: Developer وPro.
- الدفع عبر USDT مرحلة لاحقة، لذلك توجد طبقة Subscription مستقلة عن Payment Provider.

## ما تم تنفيذه في v0.9 الآن

1. API key generation/revoke/hash/last-used.
2. Developer portal بعد تسجيل الدخول.
3. خطتا Developer وPro في قاعدة البيانات.
4. Subscription abstraction مع development access مؤقت عندما لا يكون billing مطلوبًا.
5. Batch API غير متزامن.
6. Batch items كـchild scans.
7. Deduplication داخل الدفعة.
8. Idempotency-Key.
9. Network اختياري لكل عنصر لتجاوز discovery.
10. Auto network discovery عند غياب chain_id.
11. Quota شهري مبدئي.
12. Plan-based RPS وbatch limit وconcurrency.
13. JSON summary/full results.
14. Pagination.
15. JSON/JSONL/CSV export.
16. OpenAPI 3.1 specification.
17. حماية ملكية النتائج بحيث لا يمكن API key الوصول إلى Batch/Scan يخص مستخدمًا آخر.
18. الحفاظ على anonymous scanning دون تغيير.

## المرحلة التالية

- Redis-backed Batch Execution وربطها بالكامل مع worker pool متعدد العمليات/العقد.
- Global distributed rate limits.
- Webhooks لـ `batch.completed` و`batch.partial`.
- Load tests: 10 / 50 / 100 / 250 / 500 / 1000 / 2000.
- قياس RPC calls وCPU/RAM والـp95/p99 وزمن الفحص.
- تثبيت حدود Developer/Pro النهائية.
- بناء نظام الدفع والاشتراك USDT لاحقًا.
