# حالة تنفيذ بقية خطة SmartRisk

## الحالة الحالية

تم تنفيذ الدفعة الأولى من العمل المتبقي على الفرع `main` حتى commit `e82fa28`. أصبحت المنصة تحتوي على عقد بيانات موحد أولي، سجل أدلة Alchemy، state diff، event ledger، policy registry، وطبقة job/API محلية.

نجحت جميع الاختبارات الحالية:

```text
29 passed
```

## ما تم تنفيذه فعلياً

### الأساس المشترك

أضيفت `AnalysisJob` و`UnifiedAnchor` و`SourceBundle` و`RawAlchemyEvidence`. التقرير الموحد يحتوي الآن على job manifest وanchor عندما يقدمه أحد المحركات.

أضيف `AlchemyGateway` مع cache TTL، request ID، params hash، raw response evidence، error capture، وcapability matrix أولية.

### State-Fork

أصبح كل scenario يلتقط الحالة قبل وبعد التنفيذ. تشمل النتيجة native balance delta وtoken balance delta عند تمرير `observed_tokens`، إضافة إلى receipt وlogs وtrace.

مثال:

```json
{
  "scenario_id": "sell",
  "observed_tokens": ["0xToken"],
  "from": "0xTrader",
  "to": "0xRouter",
  "data": "0x..."
}
```

### Ingestion وToken Ledger

أضيف `TransferLedger` الذي يفك أحداث ERC-20 Transfer، يمنع التكرار، يعالج `removed=true`، ويعيد بناء holder snapshots من الأحداث canonical. أضيف `AlchemyEventIndexer` مع block chunking واستدعاء gateway.

### Scoring Policy

أضيف `PolicyRegistry` وملف:

```text
policies/score-v0.2.json
```

يمكن تغيير الأوزان والإصدار خارج كود Python مع الحفاظ على policy version في `RiskScore`.

### التشغيل المحلي

أضيف SQLite `JobStore` و`ScanService` وHTTP API محلي:

```text
POST /v1/scans
GET  /v1/scans/{id}
POST /v1/scans/{id}/rerun
```

تشغيل الخدمة:

```bash
smartrisk serve --host 127.0.0.1 --port 8787
```

هذه طبقة تطوير محلية. لا تعتبر نشر إنتاجياً قبل إضافة authentication وsandboxing وresource limits وdeployment مستقل.

## ما تبقى من الخطة ولم يُنفذ بعد

ما زالت هناك أعمال كبيرة حتى تطابق المنصة تعريف الإنتاج في الخطة:

1. توسيع capability matrix لتشمل archive وstate override وWebSocket وtrace coverage و429 limits.
2. إضافة `eth_call` وstorage slots وtransaction metadata وtoken metadata إلى gateway/indexer.
3. إكمال state diff الحقيقي وstorage writes وreturn data وrevert selector وgas normalization.
4. بناء scenario generator من ABI/source وإضافة transferFrom وmint/burn وpause وupgrade وroles.
5. توسيع ledger إلى holder concentration وchurn وvelocity وcounterparty/deployer flows.
6. إضافة reorg canonical-chain replay الكامل، لا مجرد معالجة log removed في الذاكرة.
7. إضافة policy family caps وhard blocks وexpiry وreferences وcalibration.
8. ربط ledger وstate diff وstatic findings في evidence correlation حقيقي.
9. إضافة API authentication، durable queue، worker isolation، timeouts، وdead-letter handling.
10. إضافة SARIF/HTML، replay offline، result/evidence store منفصل، وAPI timeline.
11. إضافة integration tests مع Alchemy وAnvil وreorg/pagination/429/archive scenarios.
12. إضافة sandboxing وnon-root execution وresource limits وSBOM وNOTICE ومراجعة التراخيص.
13. إضافة performance benchmarks وcanary metrics وCU/job وunknown rate وfalse-positive tracking.

## الحكم

التنفيذ الحالي تقدم فعلي من MVP إلى **MVP قابل لإعادة التشغيل ومزود بأساس indexing وjobs**، لكنه ليس بعد production-grade. لا ينبغي إعلان اكتمال الخطة قبل إغلاق state diff الاقتصادي، holder ledger، evidence correlation، security isolation، والاختبارات الحية.
