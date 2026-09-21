# مقارنة الخطة الأصلية بالتنفيذ الفعلي في GitHub

## الملخص التنفيذي

الخطة المرفقة تصف **منصة إنتاجية كاملة** لفحص مخاطر EVM، تتكون من ثلاثة محركات ومنظومة ingestion وevidence store وorchestration وworkers وواجهات API وإعادة تشغيل ومراقبة تشغيلية. أما مستودع `smartrisk` الحالي فقد نفذ **MVP معماري للطبقات الأساسية الثلاث** مع CLI موحد ومخرج JSON، لكنه لم ينفذ بعد البنية الإنتاجية الكاملة أو معظم قدرات الفهرسة العميقة.

التقييم العام:

| المحور | الحالة الحالية |
|---|---|
| وجود المحركات الثلاثة | منفذ جزئياً بشكل واضح |
| Unified Risk Engine وCLI | منفذ MVP |
| Static AST/IR | MVP جيد نسبياً، لكنه ليس coverage الخطة الكامل |
| State-Fork | هيكل تنفيذي جيد، لكن القياسات والسيناريوهات ما زالت محدودة |
| Heuristics | طبقة أولية تعتمد على features سوقية قليلة، وليست indexer/ledger كاملاً |
| عقد البيانات الموحد | موزع بين نماذج مستقلة، وليس AnalysisJob/evidence contract كاملاً |
| Alchemy integration | RPC أساسي محدود، وليس gateway/indexing platform |
| Dexscreener | مدمج كطبقة market observation، كما طلب التحديث اللاحق للخطة |
| API/workers/storage/monitoring | غير منفذة |
| الاختبارات | 20 اختباراً unit/mock ناجحة؛ لا توجد اختبارات live/integration شاملة |
| الجاهزية للإنتاج | غير جاهز؛ جاهز كنقطة انطلاق MVP قابلة للتوسعة |

## نطاق المقارنة

المقارنة تستخدم كامل الملف المرفق، بما في ذلك ملحق تحديث الخطة الذي غيّر القيد من «Alchemy كمزود خارجي وحيد» إلى «Alchemy لحقائق السلسلة والتنفيذ، وDexscreener كمزود سوقي إضافي». لذلك لا أعد دمج Dexscreener مخالفة للخطة الحالية؛ بل هو مطابق لملحق التحديث في القسم 12.

الحالة المرجعية للمستودع هي الفرع `main` عند commit:

```text
92f0ef9 chore: ignore build metadata and fix test packages
```

## 1. القرار المعماري العام

| مطلب الخطة | التنفيذ الفعلي | التقييم |
|---|---|---|
| ثلاثة محركات مستقلة: Static، Fork، Heuristics | توجد حزم `static_engine` و`state_fork` و`heuristics` | منفذ |
| محرك عام ينسقها | توجد حزمة `unified` و`UnifiedRiskEngine` | منفذ MVP |
| عدم إنتاج حكم ثنائي آمن/احتيالي | المخرجات تحتوي `score` و`band` و`confidence` و`coverage` و`unknowns` | منفذ جزئياً |
| فصل الأدلة عن النتائج | لكل محرك نماذج evidence/features/observations، لكن لا يوجد evidence store immutable مستقل | جزئي |
| إعادة حساب الدرجة من الأدلة دون إعادة تشغيل المحركات | لا توجد خدمة replay أو policy registry مستقلة؛ التقرير يحتفظ ببعض البيانات فقط | غير منفذ |
| تثبيت anchor مشترك قبل تشغيل المحركات | Fork وHeuristics يثبتان anchor داخلياً، لكن Unified لا ينشئ anchor مشتركاً ويمرره إلى المحركات | جزئي مهم |

**الملاحظة الأساسية:** الدمج الحالي هو orchestration استدعاءات، وليس بعد correlation حقيقياً. التقرير الموحد يجمع النتائج، لكنه لا يطابق مثلاً finding ثابتاً مع storage slot أو transaction أو fork trace.

## 2. الأكواد الجاهزة والمكونات الخارجية

| المكوّن المحدد في الخطة | حالته في المستودع |
|---|---|
| Slither | مستخدم كـworker خارجي عبر adapter |
| Solidity compiler/solc | مستخدم عبر compiler manager و`solc-select` أو binaries محلية |
| Aderyn | غير مدمج |
| OpenZeppelin solidity-ast | غير مدمج |
| Anvil | يوجد runner وتشغيل fork محلي، لكن binary غير موجود في بيئة التنفيذ الحالية |
| REVM | غير مدمج، كما تسمح الخطة بتأجيله |
| EDR | غير مدمج، كما تسمح الخطة بتأجيله |
| web3.py | غير مستخدم؛ تم بناء JSON-RPC client dependency-free |
| Ethereum ETL | غير مستخدم |
| SBOM وNOTICE وlock/commit manifest | غير منفذة كحزمة تسليم واضحة |
| license review رسمي | README يذكر مخاطر AGPL/GPL، لكن لا يوجد تقرير قانوني أو NOTICE مكتمل |

تأجيل REVM وEDR صحيح بالنسبة للخطة، لأن الخطة نفسها تنص على عدم إضافة بدائل متعددة إلى المسار الأساسي قبل الحاجة. أما عدم وجود Aderyn وSBOM وNOTICE فهو فجوة مباشرة في Phase 0 وPhase 1.

## 3. عقد البيانات المشترك

الخطة تقترح `AnalysisJob` يحتوي على `jobId` و`chainId` و`contractAddress` و`anchor` و`sourceBundle` و`policyVersion`، ثم كيانات موحدة مثل `StaticFinding` و`StateSnapshot` و`SimulationResult` و`DerivedFeature` و`RuleDecision` و`RiskResult`.

### الموجود فعلياً

- `StaticRun`, `Finding`, `Evidence` في المحرك الساكن.
- `BlockAnchor`, `SimulationScenario`, `SimulationResult`, `HoneypotResult`, `ForkRun` في State-Fork.
- `RawObservation`, `Feature`, `RuleDecision`, `RiskScore`, `HeuristicsRun` في Heuristics.
- `UnifiedRequest`, `EngineSummary`, `UnifiedRiskReport` في المحرك الموحد.

### الفجوة

لا يوجد كيان موحد واحد للـjob والـanchor والمصدر والسياسة. كما أن أسماء الحقول والمعاني ليست موحدة بالكامل:

- `BlockAnchor` في State-Fork يختلف عن `ChainAnchor` في Heuristics.
- `RawObservation` لا يطبق schema الخطة الكامل مثل request ID وparams hash وpage key وremoved.
- لا يوجد `StateSnapshot` فعلي للـbalance/nonce/code hash/storage slots.
- `SimulationResult.state_diff` موجود كحقل قابل للتوسعة، لكنه لا يُملأ.
- `RiskResult` موجود عملياً باسم `UnifiedRiskReport`، لكنه لا يحتوي anchor أعلى التقرير.

**النتيجة:** العقد المشترك منفذ على مستوى نماذج محلية، وليس contract إنتاجي ثابت قابل للتخزين وإعادة الحساب.

## 4. تغطية Alchemy

### المنفذ حالياً

| واجهة | الاستخدام الحالي |
|---|---|
| `eth_chainId` | capability/anchor |
| `eth_getBlockByNumber` | safe/finalized/latest وblock anchor |
| `eth_getCode` | code feature وstatic/runtime support أساسي |
| `eth_getBalance` | client موجود، وليس جزءاً من feature pipeline الرئيسي |
| `eth_getLogs` | log window في Heuristics |
| `eth_getTransactionReceipt` | receipt داخل Anvil المحلي |
| `debug_traceTransaction` | محاولة اختيارية من Anvil المحلي |

### غير المنفذ مقارنة بالخطة

- `eth_getStorageAt` وstorage slot cache.
- `eth_getTransactionCount`.
- `eth_call` وreference probes مثل owner/roles/paused/decimals/balanceOf.
- `eth_getTransactionByHash`.
- `alchemy_getAssetTransfers`.
- `alchemy_getTokenBalances`.
- `alchemy_getTokenMetadata`.
- `trace_transaction` و`debug_traceCall` كمسار capability-aware.
- WebSocket `newHeads` و`logs`.
- Webhooks وbackfill بعد الانقطاع.
- pagination و`pageKey`.
- chunking للـlogs.
- reorg reconciliation و`removed=true` وrollback/replay.
- cache مركزي وCU budget وRetry-After وbounded concurrency.
- capability matrix كاملة للـarchive/trace/debug/state override/WebSocket.

الـ`capability_probe` الحالي يفحص chain ID وlatest/finalized/safe فقط. هذا أقل بكثير من capability probe المحدد في الخطة.

## 5. المحرك الأول: Static AST/IR

### ما تم تنفيذه

- source/project intake.
- hash للمدخلات.
- compiler manager يقرأ pragma ويختار نسخة compiler.
- Slither adapter.
- detectors مخصصة تعتمد على storage writes وIR وauthorization flow، لا على أسماء الدوال فقط.
- detectors للصلاحيات والترقية وmint/burn وblacklist وpause وfees.
- اختبار عقد ضعيف وعقد محمي.
- حالات `unknown` عند غياب compiler أو Slither أو المصدر.
- source locations وevidence وremediation ضمن نماذج finding.

README يسجل نتيجة اختبار محلي سابقة: 10 findings إجمالية للعقد الضعيف، منها 7 custom data-flow findings، و4 findings عامة فقط للعقد المحمي، مع 0 custom findings.

### ما لم يصل إلى مستوى الخطة

- لا يوجد Standard JSON compilation pipeline كامل موثق لتوليد AST وIR وYul وsource maps ككيانات مستقلة.
- لا يوجد Aderyn cross-check.
- لا توجد 15–20 detectors مستقرة مع سياسة severity/confidence موحدة؛ الموجود مجموعة أولية أصغر.
- لا توجد كواشف كاملة لكل البنود المذكورة: reentrancy، tx.origin، delegatecall، selfdestruct، proxy admin/implementation، role admin، compiler patterns، visibility وreturn checks.
- لا يوجد runtime correlation فعلي مع Alchemy `eth_call` وownership/role/upgrade events وstorage slots.
- لا توجد mutation tests وcompiler matrix واسعة وقياس false positives/false negatives.
- لا يوجد SARIF output في المسار الموحد.
- لا يوجد معيار أداء P95 موثق على corpus حتى 200 ملف.

**التقييم:** Static هو أقرب محرك إلى MVP عملي، لكنه ما زال detector baseline لا المنتج الكامل في الخطة.

## 6. المحرك الثاني: State-Fork Simulation

### ما تم تنفيذه

- fork من Alchemy HTTP RPC عبر Anvil.
- fork block number.
- التحقق من block hash بين Alchemy وAnvil.
- impersonation محلي وset balance محلي.
- snapshot/revert.
- تنفيذ scenarios وsequence.
- buy → optional approve → sell.
- تصنيف `sell_succeeded` و`sell_blocked` و`buy_failed` و`unknown`.
- receipt وlogs وtrace اختياري.
- عدم إرسال transaction إلى الشبكة.
- unknown عند غياب credentials أو Anvil.

### الفجوات الرئيسية

| مطلب الخطة | الحالة |
|---|---|
| gas used كحقل موحد | receipt موجود، لكن لا يوجد استخراج/normalization مخصص في النتيجة |
| revert selector وrevert data | error نصي جزئي؛ لا يوجد decoder موحد |
| return data | غير مطبق |
| state diff | الحقل موجود لكنه لا يُملأ |
| storage writes | غير مطبق |
| token deltas/native deltas/fees | غير مطبق |
| lazy canonical state cache | غير مطبق؛ Anvil يدير fork دون طبقة SmartRisk cache |
| scenario generator من ABI/source | غير مطبق؛ السيناريوهات JSON يدوية |
| 8–12 سيناريو قياسي | الموجود basic scenario وhoneypot sequence فقط |
| transferFrom/mint/burn/pause/upgrade/roles | لا توجد مولدات أو runners متخصصة |
| not_tested | التصنيف الحالي يستخدم unknown/buy_failed، ولا يوجد state واضح لـ`not_tested` |
| timeouts/isolation بين jobs | isolation داخل scenario موجود، لكن لا توجد job sandbox/worker isolation |
| REVM differential tests | غير مطبق |
| historical receipt/trace comparison | غير مطبق |

**الأهم:** محاكاة البيع الحالية تثبت فقط نتيجة calldata التي أدخلها المستخدم. لا يوجد بعد قياس آلي يثبت أن token delta المتوقع وصل للمشتري أو أن native delta/fee مطابقان.

## 7. المحرك الثالث: Heuristics + Rule Scoring

### ما تم تنفيذه

- Alchemy source للـanchor/code/logs.
- Dexscreener token-pairs adapter، وهو متوافق مع ملحق الخطة اللاحق.
- cache وretries وraw observations.
- features للسوق: pair count، liquidity، volume، buys/sells، price range، pair age.
- feature للـruntime code.
- feature لعدد logs.
- rules versioned داخل Python باسم `score-v0.1`.
- evidence refs وcoverage وconfidence وunknown reasons.
- حماية من اعتبار timeout في Dexscreener دليلاً على غياب pair.

### ما لم يُنفذ

هذا المحرك ليس بعد indexer/ledger كما تصفه الخطة. المفقود يشمل:

- block-window ingestion مع pagination وbounded concurrency.
- raw response store قبل تأكيد المهمة.
- idempotent event keys.
- reorg rollback/replay.
- فك topics/data وبناء ABI-aware event ledger.
- token ledger وholder snapshots.
- holder concentration وchurn وvelocity وcounterparty graph.
- owner/admin/roles/proxy/upgrade history.
- fee/tax asymmetry من on-chain evidence.
- failed-call rate وtransfer accounting mismatch.
- deployer/admin flows وapproval exposure.
- `alchemy_getAssetTransfers` وtoken balances/metadata كمسارات مساعدة.
- قواعد YAML/JSON خارج الكود.
- family caps وhard_block وconfidence_factor وexpiry وreferences.
- calibration منفصلة عن correctness.
- replay تاريخي property tests.

كما أن Dexscreener في التنفيذ الحالي ليس مجرد adapter إضافي محايد تماماً؛ فهو مصدر أساسي لبعض market features. الخطة المعدلة تسمح به كمصدر سوقي، لكن يلزم في المرحلة التالية cross-check أقوى مع Alchemy قبل تحويل feature السوق إلى evidence عالية الثقة.

## 8. Unified Risk Engine

### المنفذ

- `UnifiedRiskEngine` يستدعي Static وState-Fork وHeuristics.
- يدعم scenarios أو honeypot.
- يجمع findings وdecisions وevidence وunknowns.
- يحسب score موحداً بأوزان أولية: Static 30%، Fork 40%، Heuristics 30%.
- ينتج `status` و`risk.score` و`band` و`confidence` و`coverage`.
- CLI مشترك:

```bash
smartrisk scan ...
```

- config JSON اختياري.
- مخرج JSON نهائي.
- لا يحول غياب محرك إلى safe.

### الفجوة مع Orchestrator الخطة

| عنصر الخطة | الحالة |
|---|---|
| `POST /v1/scans` | غير منفذ |
| GET status/report/rerun | غير منفذ |
| capability probe موحد قبل التشغيل | كل مصدر يفحص قدراته داخلياً، لكن لا يوجد probe موحد شامل |
| تثبيت anchor واحد مشترك | غير منفذ على مستوى Unified |
| تشغيل بالتوازي | الاستدعاءات متسلسلة داخل Python |
| بناء scenarios تلقائياً من ABI/source | غير منفذ |
| correlation bus بين الأدلة | غير منفذ؛ aggregation موجود |
| versioned policy registry | أوزان وقواعد داخل Python |
| async jobs/workers | غير منفذ |
| result/evidence store | غير منفذ |
| replay/rerun | غير منفذ |
| SARIF/HTML reports | غير منفذ؛ JSON فقط |
| reorg/source update rerun | غير منفذ |

يوجد أيضاً اختلاف مهم في schema: الخطة تعرض `engines` ككائن مفاتيحه static/fork/heuristics وanchor أعلى التقرير، بينما التنفيذ يعرض `engines` كمصفوفة summaries ولا يضع anchor أعلى `risk report`.

## 9. مراحل التسليم مقارنة بما تم

| المرحلة في الخطة | المطلوب | حالة التنفيذ |
|---|---|---|
| Phase 0: الأساس المشترك | schema، gateway، capability matrix، raw evidence store، fixtures، SBOM | schema أولي وfixtures موجودة؛ gateway/store/matrix/SBOM غير منفذة |
| Phase 1: Static MVP | source intake، solc matrix، Slither، Aderyn، 15–20 detectors، JSON/SARIF، golden/mutation | source/solc/Slither/custom JSON موجودة؛ Aderyn/SARIF/golden/mutation غير موجودة |
| Phase 2: Fork MVP | Anvil، lazy state، trace/state diff، 8–12 scenarios، isolation، differential | Anvil/anchor/snapshot/trace أولي موجود؛ lazy state/diff/scenarios/differential غير موجود |
| Phase 3: Heuristics MVP | ingestion، ledger، roles/proxy، holders، feature store، scoring، reorg | features وscore أولية فقط؛ ingestion/ledger/holders/reorg غير موجودة |
| Phase 4: الدمج | orchestrator، correlation، evidence، API/CLI، async، rerun | orchestrator وCLI وJSON موجودة؛ correlation/API/async/rerun غير موجودة |
| Phase 5: Canary/production | metrics، CU، unknown rate، drift، FP، security review | غير منفذة |

## 10. الأمن والعزل

### الموجود

- لا توجد private keys داخل State-Fork.
- impersonation محلي فقط.
- لا ترسل المعاملات إلى الشبكة.
- unknown بدلاً من safe عند غياب المزود أو الأداة.
- README يذكر مخاطر تراخيص Slither/compiler.

### غير الموجود

- containers أو sandbox process isolation.
- non-root execution policy.
- read-only filesystem.
- CPU/RAM/PIDs/time limits.
- seccomp/AppArmor.
- network egress deny-by-default.
- RPC gateway داخلي وحيد.
- archive/zip bomb/path traversal/symlink protections.
- compiler plugin isolation.
- job/tenant/cache separation.
- signed images/lockfiles/SBOM.
- dead-letter queue.

لا ينبغي تشغيل StaticEngine على source غير موثوق في بيئة إنتاجية قبل إضافة هذه الضوابط، لأن compiler وSlither عمليات خارجية وليست مجرد دوال آمنة داخل العملية.

## 11. ما تم بشكل صحيح

1. **اختيار بنية طبقية واضحة:** المحركات مستقلة ويمكن اختبارها بحقن dependencies.
2. **تطبيق unknown semantics:** فشل Alchemy/Anvil/Dexscreener لا يتحول تلقائياً إلى safe.
3. **تثبيت fork anchor والتحقق من hash:** هذه نقطة مهمة ومطابقة لجزء أساسي من الخطة.
4. **عدم استخدام private keys أو بث mutations:** State-Fork محلي.
5. **تحسين detectors من regex إلى storage writes وIR وauthorization flow:** تقدم فعلي نحو الهدف الصحيح.
6. **إضافة Dexscreener في المكان الصحيح نسبياً:** داخل market observation لا داخل chain facts أو execution.
7. **وجود CLI وJSON وfixtures واختبارات آلية:** يوفر نقطة انطلاق عملية للمرحلة التالية.
8. **الاحتفاظ بتقارير المحركات داخل التقرير الموحد:** يسهل debugging وreview، حتى لو لم يصل بعد إلى evidence store مستقل.

## 12. أهم الفجوات التي يجب عدم إخفائها

- المحرك الموحد حالياً يجمع نتائج ولا ينفذ evidence correlation.
- State-Fork لا يقيس state diff أو token/native deltas؛ لذلك لا يكفي وحده لإثبات قابلية البيع بدقة اقتصادية.
- Heuristics لا يبني holder ledger أو event index، ولذلك لا ينافس بعد أدوات تعتمد على clustering/concentration.
- Alchemy integration ليست gateway/indexer ولا تغطي كل endpoints المحددة.
- قواعد scoring داخل Python وليست policy files قابلة للإصدار والمراجعة وإعادة الحساب.
- لا توجد live integration tests مثبتة مع Alchemy وAnvil في البيئة الحالية.
- لا توجد اختبارات reorg/pagination/429/archive/trace capabilities.
- Unified report لا يحمل anchor موحداً أعلى التقرير.

## 13. الأولويات المقترحة للمرحلة التالية

### أولوية P0: تصحيح العقد الموحد

1. إضافة `AnalysisJob` و`UnifiedAnchor` واحد.
2. توحيد `ChainAnchor` و`BlockAnchor`.
3. إضافة `evidence_id` immutable و`raw_alchemy` schema.
4. نقل scoring policies إلى YAML/JSON مع `policyVersion`.
5. إضافة `anchor` أعلى التقرير النهائي.

### أولوية P1: جعل State-Fork دليلاً اقتصادياً

1. إضافة `eth_call` وABI encoder/decoder.
2. قياس token balances قبل/بعد كل خطوة.
3. قياس native balances، gas، fees، return data، revert selector.
4. استخراج storage writes وstate diff عبر prestate/trace عند توفره.
5. إضافة سيناريوهات transfer/approve/transferFrom وbuy/sell وfee-on-transfer.
6. إدخال `not_tested` كحالة مستقلة عن `unknown`.

### أولوية P1: بناء ingestion حقيقي

1. `eth_getLogs` chunking وpagination.
2. raw response store وrequest metadata.
3. idempotency وdeduplication.
4. reorg handling مع removed logs وreplay.
5. token ledger وholder snapshots.

### أولوية P2: توسيع Heuristics

1. owner/roles/proxy/upgrade features.
2. holder concentration/churn/velocity.
3. fee/tax asymmetry وfailed-call rate.
4. cross-check Dexscreener مع Alchemy.
5. rules family caps وhard blocks وexpiry وreferences.

### أولوية P2: الإنتاج والتشغيل

1. Alchemy gateway موحد مع cache/CU budget/backoff.
2. worker model وjob queue.
3. API `/v1/scans` وreport/rerun/replay.
4. sandboxing وresource limits.
5. SBOM وNOTICE وlicense review.
6. live integration/canary metrics.

## الخلاصة

التنفيذ الحالي يحقق **الهيكل الأساسي للمرحلة الأولى من بناء المنصة**: توجد المحركات الثلاثة، وطبقة Unified، وCLI، وJSON، وunknown handling، وfixtures واختبارات unit. لكنه لا يحقق بعد تعريف الخطة لمنصة منافسة لـGoPlus وTokenSniffer على مستوى البيانات أو التشغيل أو الدليل القابل لإعادة الحساب.

التوصيف الأدق هو:

> **SmartRisk حالياً Unified MVP تقني، وليس production-grade EVM risk platform.**

أكبر قرار هندسي صحيح في النسخة الحالية هو الحفاظ على الفصل بين Alchemy كحقيقة سلسلة، Dexscreener كملاحظة سوق، وAnvil كتنفيذ محلي. وأكبر فجوة يجب معالجتها قبل توسيع scoring هي إنشاء عقد evidence/anchor موحد ثم بناء state diff وtoken ledger وreorg-safe ingestion؛ وإلا ستبقى الدرجة الموحدة تجميعاً لنتائج ناقصة بدلاً من risk engine قابل للتدقيق وإعادة التشغيل.
