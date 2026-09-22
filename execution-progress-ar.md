# SmartRisk Engine — تقدم التنفيذ

## v0.3.0 — Phase 3/4 foundation

تم تنفيذ طبقة التداول الديناميكي فوق State-Fork مع إبقاء Static/Fork/Intelligence منفصلة.

### المنفذ
- DexScreener pair discovery وتطبيع بيانات الزوج.
- Local `DexRouteRegistry` دون استدعاء أي security provider.
- Uniswap V2-compatible calldata builder.
- Automatic native buy -> approve -> dynamic sell.
- Independent snapshots لكل سيناريو.
- Sell amount مبني على `observed_buy_token_delta`.
- Baseline / partial_sell / sell_all matrix.
- Transfer-event + reserve + token0/token1 + native-output correlation.
- V2 expected output + dynamic tax metrics عندما تكون الأدلة مكتملة.
- Hard signal محلي للـsell block داخل السيناريو الموثق.
- CLI `--auto-trade` و`--plan-only` مع الحفاظ على المسار القديم.

### حدود متعمدة
- لا GoPlus/TokenSniffer/De.Fi أو أي security API.
- لا تخمين للـrouter؛ unknown عند غياب route محلية.
- التنفيذ التلقائي الأساسي حاليًا native-v2 routes المعروفة.
- V3/V4/Universal Router وERC20-quote ما زالت ضمن مراحل لاحقة.
- `sell_blocked` ليس verdict عامًا خارج السيناريو والـanchor الموثق.

### التحقق
- `PYTHONPATH=. python -m pytest -q`
- **52 passed**
- `python -m compileall -q smartrisk` ناجح.

## v0.4.0 — Intelligence + Correlation

تم تنفيذ المرحلة التالية من الخطة فوق v0.3 دون حذف Static/State-Fork/Heuristics:

- Holder intelligence من Transfer ledger.
- Top 10/20/50/100 concentration.
- Top-holder contract/EOA probing محدود ومكلفته مقيدة.
- LP/pair analysis: token0/token1/reserves/LP total supply وحاملي LP من الأحداث.
- Deployer/distribution candidate analysis مع فصل creator_verified عن candidate.
- Historical behavior: buyers/sellers/round trips/volume/early-late overlap.
- Wallet cluster graph + largest supply cluster + fan-out bursts.
- Intelligence risk rules اختيارية عند غياب المدخلات.
- Unified correlation بين Static/Intelligence/State-Fork/market context.
- Risk dimensions الجديدة للحائزين والمطور والعناقيد والسلوك التاريخي.
- تصحيح ERC-20 Transfer topic في TransferLedger.

### التحقق
- `pytest -q`
- **54 passed**
- `compileall` ناجح.

## v0.5.0 — التنفيذ الحالي

تم إغلاق دفعة إضافية من فجوات الخطة دون إزالة المحركات الحالية:

- Proxy implementation recursion محدود حتى عمق 2 مع cycle/loader unknown handling.
- `transfer_only` أصبح تنفيذًا فعليًا في Trade Matrix بعد observed buy delta، ولا يحتاج approval.
- إضافة `state_diff.storage_diff` وتطبيع استجابة `prestateTracer diffMode` إلى account/storage deltas.
- إضافة `ScamFingerprintAnalyzer` وربط fingerprint findings بـHeuristics/Unified evidence.
- Unified يضيف `job.anchor_consistency` ويعامل اختلاف anchors كـuncertainty.
- تحديث نسخ المحركات إلى static 0.3.0 / fork 0.4.0 / heuristics 0.3.0 / intelligence 0.5.0 / unified 0.3.0.

### التحقق
- `python -m pytest -q`
- **59 passed**
- `python -m compileall -q smartrisk`
- لا توجد تغييرات على الشبكة الحقيقية أو المفاتيح الخاصة؛ سيناريوهات التداول تبقى local Anvil فقط.

### الحدود المتبقية
- Phase 6 ما زالت indicator/fingerprint layer وليست control-flow symbolic analysis.
- Phase 7 fuzzing/symbolic deep scan غير منفذة.
- State diff يعتمد على توفر tracer لتفاصيل storage/account؛ عند عدم توفره يبقى unknown.
- Unified anchor consistency يثبت الاتساق أو يسجل عدمه، لكنه لا يعيد تشغيل المحركات تلقائيًا على anchor موحد.
- Production sandboxing/distributed workers/observability/adaptive provider failover ما زالت ضمن Phase 10.

## v0.6.0 — Evidence graph + RPC capability depth + runtime accounting

تمت مواصلة التنفيذ فوق v0.5 مع تركيز على فجوات Phase 4/8/9/10:

- إضافة decoder محلي لـ`Error(string)` و`Panic(uint256)` مع إبقاء صيغ revert غير المعروفة `unknown`.
- إضافة `revert_reason` و`revert_info` إلى `SimulationResult` عند توفر evidence.
- إضافة accounting summary موحد لـnative/token/allowance/pair/storage/gas deltas.
- إضافة `ScenarioGenerator.standard_scenarios()` بحد ثابت 12 probe قياسيًا للـtransfer/approval/transferFrom/mint/burn/pause/upgrade/roles/owner.
- توسيع `AlchemyGateway.capability_matrix()` لفحص storage/call/transaction/receipt/asset transfers/token balances/metadata بالإضافة إلى trace/archive/cache.
- إضافة asset-transfer pagination وbounded in-memory cache metrics في الـgateway.
- إضافة `evidence_graph` في Unified Report مع nodes/edges للأ engines/findings/evidence/decisions/correlations.
- عند anchor mismatch يتم تعليم correlations كـ`untrusted` وخفض coverage/confidence بدل دمجها كما لو كانت على block واحد.
- إصلاح latent ordering bug في fingerprint finding attachment داخل HeuristicsEngine.
- تحديث إصدارات State-Fork/Heuristics وإصدار الحزمة إلى خط v0.6.

### التحقق
- `python -m pytest -q`
- `python -m compileall -q smartrisk`
- اختبارات إضافية للـrevert decoder، standard scenarios، gateway pagination/cache، fingerprint regression، وevidence graph.

## v0.7.0 — تشغيلية + reorg + durable evidence/jobs

تمت مواصلة التنفيذ فوق v0.6 مع التركيز على Phase 0/8/9/10:

- ربط `AlchemySource` بـ`AlchemyGateway` المشترك بدل تمرير RPC مباشرة لكل قراءة chain fact.
- إضافة `fresh=True` للـblock/log polling لمنع cache stale من إخفاء reorg.
- إضافة `SQLiteEvidenceStore` اختياري لحفظ raw evidence بشكل durable مع bounded retention.
- إضافة latency/error metrics للـgateway.
- إضافة `get_block_by_number` و`get_block_receipts` و`get_transaction_count` و`get_trace` إلى gateway.
- إضافة `PollingChainIndexer` للـbackfill/sync مع `CanonicalChain` وTransferLedger.
- تحسين canonical reorg handling للـreplacement blocks في heights أقدم من head.
- إضافة atomic `JobStore.claim()`، attempts، started_at، stale recovery، واستئناف pending jobs عند بدء الخدمة.
- إضافة `/v1/metrics` وقياس job durations/completed/failed/recovered.
- Unified يحاول تثبيت block number مشترك قبل Fork عندما يستطيع الوصول إلى chain anchor؛ لا يتم تحويل فشل probe إلى safe.
- إضافة `PolicyRegistry.validate()` للـpolicy schema.
- إصدار الحزمة: `0.7.0`.

### التحقق
- **75 passed**.
- `compileall` ناجح.

### ما بقي
- WebSocket subscriptions/backfill orchestration.
- distributed workers + sandbox/process/resource isolation.
- multi-provider adaptive routing/failover.
- persistent evidence graph/database وربطه بالـreplay.
- fuzzing/symbolic execution.
- large regression/adversarial corpus + statistical FP/FN calibration.

## v0.8.0 — Deep verification + production execution controls

أغلقت هذه الدفعة فجوات WebSocket / distributed workers / sandbox / multi-provider / fuzzing / symbolic / calibration:

- WebSocket `newHeads` subscriber + reconnect + multi-provider URL fallback + canonical backfill bridge.
- Redis Streams consumer group + `XREADGROUP` + `XAUTOCLAIM` + durable job state + at-least-once worker semantics.
- Command sandbox بحدود موارد وnetwork isolation عبر bubblewrap عندما يكون متاحًا، مع sandboxed custom detector worker.
- MultiProviderRpc health/circuit/capability-aware failover، مربوط تلقائيًا بـAlchemyRpcClient عند توفر عدة مزودات.
- Deterministic calldata fuzzing على Anvil مع trace coverage.
- Bounded symbolic branch guidance + optional Z3 solving.
- Statistical FP/FN calibration framework مع holdout/Wilson/Brier/ECE.
- CLI: `smartrisk-deep` و`smartrisk-worker`.

التحقق: **95 passed** + `compileall` PASS.


## v0.8.1 — Hardening

- Redis reclaim window: 15m default + CLI override.
- WebSocket provider failover regression test.
- bubblewrap `/work` project mount + explicit host-network switch.
- Optional Foundry/Halmos runner تحت نفس sandbox.
- Group-aware calibration holdout + duplicate corpus validation.
- Verification: **100 tests passed** + compileall PASS.

## v0.9.0 — Accuracy Foundation

دفعة تحسين دقة فوق v0.8.1 دون إضافة مكونات جديدة:
- Static semantic authorization/internal-call tracing وتحسين reflection/trading-control detection.
- Honeypot matrix: micro/small/transfer-only، failure-cause classification، threshold/dynamic-tax detection.
- Holder/history normalization وتقليل market-only scoring.
- Selector-aware deterministic fuzzing وbounded symbolic guard hints.
- Unified/State-Fork decisive verdicts وprimary detection.

### التحقق
- **115 passed**.
- `compileall` **PASS**.
- لا real-chain transactions.
