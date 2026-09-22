# SmartRisk Engine — مرجع التطوير الرئيسي

هذا الملف هو المرجع التنفيذي لتطوير محرك SmartRisk، مع الحفاظ على المحركات الثلاثة المقصودة وعدم الاعتماد على مزود أمني خارجي.

## مصدر البيانات المسموح
- Alchemy / EVM RPC: حالة السلسلة، البلوكات، logs، receipts، storage، calls، transfers، التنفيذ والبنية التحتية.
- DexScreener: ملاحظات السوق والأزواج والسيولة/الحجم والسعر.
- أدوات ومكتبات open-source تعمل محلياً داخل SmartRisk عند الحاجة، وليس كخدمات أمنية خارجية.

## المحركات
1. Static Engine: AST/IR + Slither + custom data-flow + bytecode intelligence.
2. State-Fork Engine: Anvil fork + automatic scenarios + dynamic trading/tax/state diff.
3. Heuristics/Intelligence Engine: on-chain + market + holders + liquidity + deployer + behavioral analysis.
4. Unified Engine: evidence graph + correlation + hard verdicts + multi-dimensional risk.

## مراحل التنفيذ
- Phase 1: Contract Profile, bytecode profiling, EIP-1967 state, adaptive logs. [Implemented]
- Phase 2: Static capability/dependency analysis, deeper privileges, proxy implementation analysis. [Foundation started]
- Phase 3: Automatic DEX discovery + buy/sell simulation + honeypot matrix. [Scenario classification foundation started]
- Phase 4: Dynamic tax + state diff + balance/allowance/reserve accounting. [Runtime accounting foundation implemented]
- Phase 5: Holder/LP/deployer intelligence + address clusters.
- Phase 6: Scam fingerprinting + time-bomb/deferred behavior.
- Phase 7: Optional fuzzing/symbolic deep scan.
- Phase 8: Unified evidence correlation + hard verdict engine + risk dimensions.
- Phase 9: Regression corpus + adversarial testing + false-positive/false-negative calibration.
- Phase 10: production performance, caching, reorg safety, adaptive RPC, observability.

## قواعد معمارية غير قابلة للكسر
- لا GoPlus API ولا TokenSniffer API ولا De.Fi API كمصادر حكم أو fallback.
- Missing data = Unknown، وليس Safe.
- Trace API ليس dependency أساسيًا.
- Static/Fork/Intelligence لا يتم حذفها لصالح محرك واحد.
- كل finding مهم يجب أن يرتبط بأدلة قابلة للمراجعة.
- Proxy/delegatecall/selfdestruct/time logic هي signals، وليست بمفردها دليلاً على maliciousness.
- لا تغييرات على واجهات العميل أو نظام الفحص الإنتاجي إلا عند الحاجة المباشرة لتوسعة engine.

## Phase 3/4 — التنفيذ الحالي 0.3
- DexScreener pair discovery أصبح طبقة تطبيع مستقلة مع اختيار موضوعي لأعلى سيولة/نشاط، دون تحويل الاختيار إلى حكم أمني.
- أضيفت `DexRouteRegistry` محلية؛ لا يتم اكتشاف router من مزود أمني ولا يتم تخمينه. المسارات غير المعروفة تبقى `unknown`.
- أضيفت حزم calldata أصلية لـUniswap-v2-compatible supporting-fee-on-transfer.
- أضيف `Automatic native buy -> approve -> dynamic sell` plan.
- أضيفت مصفوفة `baseline / partial_sell / sell_all / transfer_only` للتخطيط.
- كل محاولة تداول تحصل على snapshot مستقل؛ لا يوجد تلوث بين اختبارات البيع الجزئي والكامل.
- كمية البيع تبنى من `observed buy token delta`، لا من توقع مسبق.
- أضيف ربط buy/sell مع reserves + token0/token1 + ERC-20 Transfer events + native gas-adjusted output.
- أضيف حساب V2 expected output وحساب `input_tax_bps` و`output_tax_bps` و`effective_output_tax_bps` عندما تكون الأدلة كافية.
- تم تحسين state capture لقراءة `token0/token1` وreserves لكل pair.
- تم تصحيح baseline native balance ليتم أخذ snapshot بعد إعداد حساب الـfork.
- CLI القديم بقي متوافقًا، مع إضافة `--auto-trade` و`--plan-only`.
- الاختبارات بعد هذه المرحلة: 52 اختبارًا ناجحًا، بما فيها اختبار تكامل مصغّر للتأكد من بناء كميات البيع ديناميكيًا لكل سيناريو من الكمية المشتراة فعليًا.

### حدود 0.3 الحالية
- التنفيذ التلقائي الحالي يستهدف native-v2 routes المعروفة محليًا فقط.
- V3/V4 وUniversal Router وطرق ERC20-quote لم تدخل مسار التنفيذ الأساسي بعد؛ تظهر كـunsupported/unknown بدل التخمين.
- لا يتم اعتبار `sell_blocked` حكمًا عامًا إلا داخل السيناريو الموثق وعلى fork محدد.
- Dynamic tax يعتمد على كفاية reserves وtoken orientation وTransfer events؛ نقص أي منها يؤدي إلى `unknown` جزئي.

## Phase 5/8 — التنفيذ الحالي 0.4
- أضيف `IntelligenceAnalyzer` محلي يعتمد على RPC/Alchemy + market observation من DexScreener فقط.
- أضيفت إعادة بناء holders من ERC-20 Transfer logs مع Top 10/20/50/100 concentration.
- أضيف تصنيف محدود للحائزين الأعلى نشاطًا عبر `eth_getCode` لمعرفة contract/EOA-or-unknown دون خدمة خارجية.
- أضيف تحليل LP لكل pair مكتشف: `token0/token1/getReserves/totalSupply` + إعادة بناء حاملي LP من Transfer logs.
- أضيفت مؤشرات LP concentration وLP candidate/deployer-linked control وburn share مع اعتبار burn سياقًا لا عقوبة تلقائية.
- أضيف `historical_behavior`: unique buyers/sellers، round trips، transfer volume، early/late wallet overlap.
- أضيف `wallet cluster` graph محليًا مع largest supply share وfan-out burst detection.
- أضيف `deployer intelligence` مع فصل صريح بين `creator_verified` عند إدخال عنوان deployer وبين `distribution candidate` المستنتج من أول mint observed؛ لا يتم تسمية المرشح Deploy­er موثّقًا دون دليل.
- أضيفت قواعد scoring جديدة للحائزين والسيولة والمطور/المرشح والعناقيد والسلوك التاريخي، مع جعلها اختيارية عندما لا تتوفر مدخلاتها.
- أضيف `intelligence.coverage` إلى نموذج التغطية.
- أضيف `Unified correlations` تربط Static مع Intelligence، وState-Fork مع السوق والسلوك التاريخي، وتحوّل الأدلة المستقلة المتوافقة إلى correlation strength.
- أضيفت `risk_dimensions`: holder distribution، deployer risk، cluster behavior، historical behavior، بالإضافة إلى الأبعاد السابقة.
- تم تصحيح ثابت ERC-20 `Transfer(address,address,uint256)` في `TransferLedger` إلى Keccak الصحيح، وهو تصحيح مهم لسلامة الـledger التاريخي.
- تم الحفاظ على عدم الاعتماد على أي security provider خارجي.
- الاختبارات الحالية: **54 اختبارًا ناجحًا**.

### حدود 0.4 الحالية
- لا يزال اكتشاف creator/deployer الحقيقي تلقائيًا محدودًا عندما لا يقدم عنوانًا صريحًا؛ first-mint recipient هو `candidate` فقط.
- LP lock/unlock ليس حكمًا مستقلًا ما لم توجد أدلة on-chain محلية كافية؛ عقد locker غير المعروف لا يُفترض أنه lock.
- cluster analysis مبني على transfer graph المرصود في النافذة الحالية، وليس قاعدة بيانات تاريخية عالمية.
- Unified correlation يعمل على تقارير المحركات الحالية؛ automatic trade-matrix orchestration داخل Unified سيأتي مع مرحلة لاحقة.

## التنفيذ التالي — v0.5

- Phase 2: أضيف تحليل recursive محدود لسلسلة EIP-1967 implementation عند توفر loader محلي، مع منع الدورات وتسجيل unknown عند فشل القراءة.
- Phase 3: أصبح `transfer_only` سيناريو تنفيذ فعليًا بعد شراء ناجح، بدون approval، مع تصنيف مستقل `transfer_succeeded/transfer_blocked`.
- Phase 4: أضيف تطبيع `prestateTracer diffMode` إلى `storage_diff.accounts` مع فروق balance/nonce/code/storage، مع إبقاء الشكل الخام وعدم تحويل tracer غير المفهوم إلى zero-diff.
- Phase 6: أضيف `ScamFingerprintAnalyzer` محلي لدمج إشارات timestamp/block + state mutation/external execution، upgrade surface، destructive capability، tx.origin+state، وCREATE2+time/block. هذه fingerprints مؤشرات للمراجعة فقط وليست حكمًا على maliciousness.
- Phase 8: أضيف فحص `anchor_consistency` في التقرير الموحد؛ عدم تطابق anchors يحول الحالة إلى partial ويضيف uncertainty صريحة بدل افتراض أن النتائج قابلة للدمج.
- Phase 9: ارتفع regression suite المحلي إلى 59 اختبارًا ناجحًا، مع تغطية مباشرة للفingerprints وstate-diff normalization وtransfer-only.

## التنفيذ الحالي — v0.6
- Phase 4: أضيف decoder محلي لـrevert payloads الشائعة، runtime accounting summary موحد، وربط أوضح بين token/native/allowance/reserve/storage/gas evidence.
- Phase 8: أضيف `evidence_graph` مستقل داخل التقرير الموحد، مع nodes/edges قابلة للمراجعة، وربط engine → finding → evidence → decision → correlation.
- Phase 9: أضيف regression tests للـrevert decoding، standard scenarios، gateway pagination/cache، fingerprint attachment، وevidence graph.
- Phase 10: وسع `AlchemyGateway.capability_matrix` إلى state/call/tx/receipt/asset transfers/token balances/metadata/trace/archive، وأضاف pagination للـasset transfers ومؤشرات cache bounded.

### حدود v0.6 الحالية
- WebSocket/backfill orchestration والـdurable job workers لم تدخل بعد.
- Fuzzing/symbolic execution ما زالت خارج التنفيذ.
- Evidence graph حاليًا deterministic projection من تقارير المحركات وليس persistent graph database.
- Standard scenarios هي candidate probes؛ لا تتحول حالات revert فيها تلقائيًا إلى maliciousness verdict.

## التنفيذ الحالي — v0.7

تم تنفيذ دفعة تشغيلية فوق v0.6 لإغلاق أجزاء ملموسة من Phase 0/8/9/10:
- ربط `AlchemySource` بحد `AlchemyGateway` المشترك لقراءات chain facts، مع `fresh` للقراءات الحساسة لإعادة التنظيم.
- إضافة `SQLiteEvidenceStore` اختياري لحفظ raw Alchemy evidence بشكل durable ومحدود الحجم.
- إضافة latency/error metrics للـgateway.
- إضافة `PollingChainIndexer` للـbackfill/sync على JSON-RPC مع canonical ledger وreorg reconciliation.
- تحسين `CanonicalChain` حتى يعالج replacement blocks في ارتفاعات سابقة بدل تجاهلها، مع الحفاظ على branch canonical.
- إضافة atomic job claim، attempts، started_at، stale-running recovery، واستئناف pending jobs في `JobStore/ScanService`.
- إضافة `/v1/metrics` للمراقبة المحلية وقياس مدد الوظائف.
- إضافة wrappers صريحة لـblock/tx count/trace في الـgateway.
- إضافة shared-anchor block resolution في Unified قبل تشغيل الـFork عند توفر chain source؛ عند الفشل تبقى حالة عدم اليقين صريحة.
- إضافة `PolicyRegistry.validate()` للتحقق البنيوي من caps/weights/confidence factors/expiry/family references.
- تحديث package release إلى `0.7.0` وUnified schema version إلى `unified-v0.5`.

### التحقق v0.7
- `PYTHONPATH=. python -m pytest -q` → **75 passed**.
- `python -m compileall -q smartrisk` → **PASS**.
- لم يتم تشغيل شبكة حقيقية أو broadcast لأي transaction.

### حدود v0.7
- النقل الفعلي عبر WebSocket ما زال غير منفذ؛ الموجود polling/backfill reorg-aware.
- لا يوجد distributed queue أو process/container sandbox أو resource limits.
- لا يوجد provider failover متعدد فعلي داخل الـgateway؛ يمكن حقنه على مستوى RPC ولكن routing متعدد المزودين ليس طبقة مكتملة.
- Phase 6 لا تزال deterministic fingerprinting وليست symbolic/control-flow execution.
- Phase 7 fuzzing/symbolic deep scan غير منفذة.
- Phase 9 لم تصل بعد إلى corpus كبير ومعايرة FP/FN إحصائية؛ الاختبارات الحالية regression/adversarial unit coverage.

## التنفيذ الحالي — v0.8.0 — إغلاق فجوات التشغيل والتحقق العميق

تم تنفيذ الفجوات التي كانت متبقية كطبقات فعلية قابلة للتشغيل، مع إبقاء الاعتماديات الخارجية اختيارية ومعلنة:

- **WebSocket:** إضافة `ChainWebSocketSubscriber` لـ`eth_subscribe/newHeads` مع reconnect/backoff، دعم عدة مزودين، وتحويل كل head إلى `PollingChainIndexer.sync_once()` عبر `ReorgAwareRealtimeIndexer` حتى يبقى الـWebSocket trigger ولا يصبح مصدر الحقيقة canonical.
- **Distributed workers:** إضافة `RedisStreamJobStore` و`DistributedScanWorker` باستخدام Redis Streams consumer groups، مع `XREADGROUP` للعمل الموزع و`XAUTOCLAIM` لاسترداد الرسائل المتروكة بعد فشل worker. النتيجة at-least-once، وrun_id ثابت لكل job لحماية إعادة التنفيذ.
- **Sandboxing:** إضافة `CommandSandbox` بحدود CPU/RAM/file-size/open-files/processes/wall-time/output، و`bubblewrap --unshare-net` عندما يكون متاحًا. تم ربطه بـSlither وبـcustom Slither detector worker بدل إبقاء التحليل الدلالي الحساس في نفس العملية.
- **Multi-provider failover:** إضافة `MultiProviderRpc` بصحة لكل مزود، circuit breaker، exponential retry، method-capability suppression، failover counter، وprovider-aware raw evidence. `AlchemyRpcClient` يستخدم الـrouter تلقائيًا عندما تكون عدة مزودات مهيأة في البيئة. ترتيب افتراضي: Ethereum → Alchemy ثم QuickNode ثم Chainstack؛ BNB → Alchemy ثم Chainstack ثم QuickNode.
- **Fuzzing:** إضافة `DeterministicCalldataFuzzer` و`StateForkFuzzer` مع mutations reproducible، execution على Anvil، وtrace coverage keys مبنية من `structLogs/call traces`.
- **Symbolic deep scan:** إضافة `EvmBoundedSymbolicAnalyzer` لالتقاط branch/dispatcher patterns وتوليد selector guidance، مع optional Z3 لإيجاد calldata words الموافقة لقيود selector البسيطة. النتائج توصف صراحة بأنها bounded symbolic guidance وليست complete path proof.
- **FP/FN calibration:** إضافة `StatisticalCalibrator` بتقسيم train/holdout، threshold selection من البيانات التدريبية فقط، confusion metrics، Wilson confidence intervals، Platt-style probability calibration، Brier score وECE. لا يغير سياسة الإنتاج تلقائيًا.
- **CLI:** إضافة `smartrisk-deep` للـsymbolic والفuzz و`smartrisk-worker` للـdistributed worker.
- **الإصدار:** `0.8.0`، Unified=`unified-v0.8`.

### تحقق v0.8
- `PYTHONPATH=. python -m pytest -q` → **95 passed**.
- `python -m compileall -q smartrisk` → **PASS**.
- WebSocket integration test محلي → **PASS**.
- Sandbox command tests للوقت/output → **PASS**.
- لم يتم استخدام شبكة حقيقية أو broadcast لأي transaction أثناء التحقق.

### البند الوحيد الذي يعتمد على بيانات خارج الكود
المعايرة الإحصائية أصبحت **مكتملة كآلية**، لكن calibration النهائي للإنتاج لا يمكن ادعاؤه دون corpus حقيقي موسوم ground-truth. المشروع لا يفترض labels صناعية أو يحول نتائج الاختبارات الاصطناعية إلى دقة إنتاجية.


## v0.8.1 — Hardening after integration validation

تم تنفيذ تحسينات إضافية فوق v0.8 دون تغيير ادعاءات التغطية: 
- **Distributed workers:** رفع default `XAUTOCLAIM` idle window إلى 15 دقيقة، مع تمريره configurable عبر `--claim-idle-ms` لتقليل duplicate execution في scans التي تستغرق عدة دقائق.
- **WebSocket:** إضافة اختبار failover حقيقي على مستوى transport: provider أول يفشل، والـsubscriber ينتقل للمزود التالي ويستمر في استقبال `newHeads`.
- **Sandbox:** أصبح `/work` داخل bubblewrap يمثل المشروع الفعلي، ويمكن تركيب مجلدات writable بداخله، مع خيار network صريح؛ الوضع الافتراضي للـstatic analysis يبقى `--unshare-net`.
- **Deep tooling:** إضافة `FoundryDeepRunner` كـadapter اختياري لتشغيل Foundry fuzz أو Halmos symbolic suites الموجودة أصلًا داخل مشروع Foundry تحت الـsandbox، دون توليد اختبارات مصطنعة أو تعديل كود المستخدم.
- **Calibration:** أصبح holdout group-aware عند توفير `group_id` لتقليل data leakage بين عينات العقد/المجموعة نفسها، مع رفض duplicate `sample_id`.
- **الإصدار:** `0.8.1`.

### تحقق v0.8.1
- `pytest` → **100 passed**.
- `compileall` → **PASS**.
- CLIs → **PASS** (`deep`, `calibrate`, `realtime`, `worker`).

### حدود صريحة
- Halmos/Foundry يتطلبان executable + test harness محليًا؛ غياب الأدوات يرجع `unavailable` ولا يتحول إلى success.
- symbolic bytecode path المدمج يظل bounded guidance؛ الإثبات الشامل لكل مسارات EVM غير مدعى.
- calibration الإنتاجي ما زال يحتاج corpus حقيقي مستقل وموسوم ground-truth.

## التنفيذ الحالي — v0.9.0 — Accuracy Foundation

تمت مواصلة التنفيذ فوق v0.8/v0.8.1 بدون إضافة محرك أو مزود جديد، مع التركيز على رفع دقة الكشف خصوصًا لعملات Meme:

- **Data/Feature correctness:** إزالة تكرار `selfdestruct`، إضافة market activity fields، وربط provider من observation الحقيقي بدل افتراض Alchemy.
- **Static semantic analysis:** تحسين تتبع internal calls/modifiers والـauthorization، recursive storage writes، وإضافة كشف semantic لـtrading controls وreflection-style supply/balance names بدل الاعتماد على اسم الدالة فقط.
- **Honeypot/Fork accuracy:** إضافة micro/small sell probes و`transfer_only`، وتمييز فشل router/AMM/allowance عن token-level restriction. الـsell لا يصنف Honeypot إلا عند evidence منطق التوكن/التقييد.
- **Dynamic tax:** حساب tax فقط عند وجود token delta قابل للقياس، مع كشف high/effectively-blocked tax وamount thresholds وdynamic sell behavior.
- **Holder/history normalization:** استبعاد pair/burn balances من EOA-like concentration، وتشديد عينة no-sellers حتى لا تتحول الإطلاقات الجديدة تلقائيًا إلى risk.
- **Risk scoring:** خفض وزن market-only signals ومنع double counting بين top10/top20 وبعض إشارات التاريخ/السوق، مع إبقاء verdict حاسمًا عندما توجد درجة فعلية، و`UNKNOWN` فقط عند غياب قابلية التقييم أو نقص جوهري.
- **Fuzzing:** الحفاظ على selector في mutations الأساسية بحيث تصبح calldata mutations ABI-aware أكثر للوظائف المحددة.
- **Bounded symbolic guidance:** إضافة guard signals وrisk hints لفروع تعتمد على caller/calldata/time/block/storage مع توضيح أنها guidance وليست path proof كاملًا.
- **Decisive verdicts:** State-Fork وUnified أصبحا يعيدان verdicts صريحة مثل `LOW_RISK` و`HIGH_RISK` و`CRITICAL_RISK` و`HONEYPOT_DETECTED` و`UNVERIFIED`، مع `primary_detection`.

### تحقق v0.9.0
- `PYTHONPATH=. python -m pytest -q` → **115 passed**.
- `python -m compileall -q smartrisk` → **PASS**.
- لا توجد معاملات حقيقية أو broadcast أثناء الاختبار؛ التنفيذ الديناميكي محلي على fork.

### الخطوة التالية
الانتقال إلى دقة أعلى داخل نفس المكونات: wallet-differential/anti-bot scenarios، تطبيع LP/deployer supply denominator، evidence-driven correlation، إزالة double counting المتبقي، adversarial corpus، ثم calibration مستقل واختبار Ethereum/BNB regression.
