# تقرير بنية SmartRisk وقدراتها وتصنيف الجاهزية

## الخلاصة التنفيذية

SmartRisk في حالتها الحالية ليست مجرد كاشف واحد، وليست منصة إنتاجية مكتملة مثل GoPlus أو TokenSniffer. التوصيف الأدق هو:

> **محرك فحص مخاطر EVM موحد ومتقدم، تحيط به طبقة منصة محلية أولية لإدارة jobs وواجهة HTTP.**

المحرك الموحد يجمع ثلاثة محركات تحليل مختلفة، ويحافظ على نتائجها وأدلتها وحالات `unknown`. توجد أيضاً مكونات أولية للفهرسة وAlchemy gateway وSQLite job store وworker threads وrerun. لكن المنصة لم تصل بعد إلى مستوى الإنتاج الكامل، لأن authentication والعزل الأمني الكامل والـdurable queue والتخزين الدائم للأدلة والمراقبة والاختبارات الحية والتوزيع متعدد العمال ليست مكتملة.

حالة المستودع التي بني عليها هذا التقرير:

```text
ebbf53c feat: expand capabilities state evidence scenarios ledger analytics and policies
```

والتحقق الحالي:

```text
34 passed
main == origin/main
```

## 1. الفرق بين محرك الفحص والمنصة

### محرك الفحص

محرك الفحص هو النظام الذي يأخذ عقداً أو عنوان token ومدخلات الشبكة، ثم يحلل المخاطر ويصدر findings وscore وevidence. في SmartRisk يتكون هذا الجزء من:

- Static AST/IR Engine.
- State-Fork Simulation Engine.
- On-chain Heuristics + Rule Scoring Engine.
- Unified Risk Engine الذي ينسق المحركات الثلاثة.
- Alchemy gateway وDexscreener adapter كمصادر بيانات.
- Scenario generator وtoken ledger وpolicy registry كقدرات مساعدة.

هذا الجزء موجود ويعمل كـMVP قابل للاختبار.

### المنصة

المنصة الكاملة تحتاج، إضافة إلى المحرك، إلى دورة تشغيل مستمرة تشمل استقبال jobs، المصادقة، queue دائمة، عمالاً معزولين، تخزيناً دائماً للنتائج والأدلة، APIs مستقرة، replay، مراقبة، حدود موارد، إدارة أسرار، deployment، وتجارب integration حية.

SmartRisk تحتوي حالياً على بداية لهذه الطبقة:

- SQLite Job Store.
- Scan Service.
- ThreadPool worker محلي.
- `POST /v1/scans`.
- `GET /v1/scans/{id}`.
- `POST /v1/scans/{id}/rerun`.

لكنها لا تمثل بعد منصة إنتاجية مكتملة.

## 2. الصورة المعمارية العامة

```text
                             ┌─────────────────────────┐
                             │     Unified Risk API     │
                             │  CLI / local HTTP API   │
                             └────────────┬────────────┘
                                          │
                             ┌────────────▼────────────┐
                             │     Scan Service / Job   │
                             │  SQLite + local workers │
                             └────────────┬────────────┘
                                          │
                             ┌────────────▼────────────┐
                             │    Unified Risk Engine   │
                             │ anchor / orchestration   │
                             │ score / unknown / report│
                             └──────┬────────┬──────────┘
                                    │        │
                  ┌─────────────────┘        └──────────────────┐
                  │                                             │
        ┌─────────▼─────────┐                         ┌─────────▼──────────┐
        │ Static AST/IR     │                         │ State-Fork          │
        │ solc + Slither    │                         │ Alchemy + Anvil     │
        │ detectors         │                         │ scenarios + diffs  │
        └─────────┬─────────┘                         └─────────┬──────────┘
                  │                                             │
                  └─────────────────┬───────────────────────────┘
                                    │
                         ┌──────────▼───────────┐
                         │ On-chain Heuristics  │
                         │ Alchemy + Dexscreener│
                         │ features + scoring   │
                         └──────────┬───────────┘
                                    │
                   ┌────────────────▼────────────────┐
                   │ Evidence / Ledger / Policy     │
                   │ raw evidence, TransferLedger,  │
                   │ canonical replay, score policy │
                   └─────────────────────────────────┘
```

## 3. طبقة البيانات والمصادر

### Alchemy

Alchemy هو المصدر المرجعي لحقائق السلسلة والتنفيذ. توجد طبقة `AlchemyGateway` موحدة توفر:

- JSON-RPC calls.
- cache TTL.
- request IDs.
- deterministic params hash.
- raw response evidence.
- block number وblock hash داخل evidence عند وجود anchor.
- تسجيل errors.
- عداد rate-limit events عند ظهور 429 أو أخطاء rate limit.
- قياس trace attempts وtrace successes.

وتدعم الطبقة واجهات:

- `eth_chainId`.
- `eth_getBlockByNumber`.
- `eth_getCode`.
- `eth_getBalance` عبر عميل RPC.
- `eth_call`.
- `eth_getStorageAt`.
- `eth_getTransactionByHash`.
- `eth_getTransactionReceipt`.
- `eth_getLogs`.
- `alchemy_getTokenMetadata`.
- `alchemy_getAssetTransfers`.
- `debug_traceTransaction`.
- state override probing عبر صيغة `eth_call` ذات المعامل الثالث.

### capability matrix

تسجل capability matrix حالياً:

| Capability | السلوك الحالي |
|---|---|
| Latest block | probe فعلي |
| Safe block | probe فعلي عند دعم الشبكة |
| Finalized block | probe فعلي عند دعم الشبكة |
| Logs | probe فعلي |
| Trace | probe ومحاولة قياس التغطية |
| State override | probe عبر `eth_call`؛ قد يحتاج تفسيراً حسب RPC |
| Archive | `not_probed` دون historical block، أو probe عند تمرير block قديم |
| WebSocket | `not_probed`؛ لم يتم فتح اتصال WebSocket فعلي |
| 429 limits | عداد أخطاء rate limit؛ لا تزال إدارة quota مركزية كاملة غير منفذة |

القرار المتعمد هو عدم تحويل capability غير المثبتة إلى `available`. النتيجة تكون `unknown` أو `not_probed` عندما لا توجد أدلة كافية.

### Dexscreener

Dexscreener مصدر لملاحظات السوق فقط، وليس مصدراً لحقائق السلسلة. يستخدم لاستخراج:

- عدد الأزواج.
- أفضل سيولة مرصودة.
- حجم التداول.
- عدد عمليات الشراء والبيع.
- أقل وأعلى سعر.
- عمر الزوج.

لا يجوز اعتبار هذه البيانات وحدها إثباتاً للشرعية أو لقابلية البيع. فشل Dexscreener لا يساوي عدم وجود pair، بل ينتج نقصاً في feature و`unknown`.

## 4. المحرك الأول: Static AST/IR

### الهدف

يحلل Solidity source والمشروع باستخدام compiler وSlither، ثم يطبق detectors دلالية على AST/IR وstorage writes ومسارات الصلاحيات.

### خط التنفيذ

```text
Source/project
    │
    ▼
Pragma detection + compiler manager
    │
    ▼
solc / Slither / SlithIR
    │
    ▼
Storage writes + IR operations + modifiers + internal calls
    │
    ▼
Custom detectors
    │
    ▼
Static Findings + source locations + evidence + remediation
```

### القدرات الحالية

- قراءة pragma واختيار compiler مناسب.
- compiler version صريح من CLI.
- اكتشاف solc-select وbinaries المحلية.
- رفض compiler غير المثبت بدلاً من تنزيله بصمت.
- تشغيل Slither كـworker خارجي.
- findings موحدة مع rule ID وseverity وconfidence وsource location.
- evidence وremediation وstorage variables وIR operations.
- تحليل دلالي بدلاً من الاعتماد على أسماء الدوال فقط.
- التحقق من state variables المكتوبة.
- فحص modifiers وinternal calls ومؤشرات authorization.
- حالات `unknown` عند غياب source أو compiler أو Slither.

### الكواشف الحالية

- `access.unprotected-sensitive-function`.
- `upgrade.unprotected`.
- `token.unprotected-mint-burn`.
- `token.unprotected-blacklist`.
- `token.unprotected-pause`.
- `token.unprotected-fee`.
- `token.unbounded-fee`.

### ما يثبته وما لا يثبته

يثبت المحرك وجود نمط دلالي مريب ومسار كتابة وصلاحيات غير كافية بدرجة confidence محددة. لكنه لا يثبت exploitability الكاملة وحده، ولا يضمن أن المسار قابل للاستغلال على حالة السلسلة الحالية.

## 5. المحرك الثاني: State-Fork Simulation

### الهدف

ينفذ معاملات وسلاسل معاملات على fork محلي لحالة السلسلة عند block محدد، دون بث أي transaction إلى الشبكة الحقيقية.

### خط التنفيذ

```text
Alchemy RPC
    │
    ▼
Capability probe + chain/block anchor
    │
    ▼
Anvil fork عند block محدد
    │
    ▼
Impersonation + local balance setup
    │
    ▼
Snapshot
    │
    ▼
Pre-state capture + eth_call preview
    │
    ▼
Transaction / sequence execution
    │
    ▼
Receipt + logs + traces + post-state
    │
    ▼
State diff + token/native deltas + result classification
    │
    ▼
Revert إلى snapshot
```

### القدرات الحالية

- fork من Alchemy.
- block anchor.
- chain ID وblock hash verification.
- safe/finalized/latest policy.
- local impersonation.
- local balance setup.
- snapshot/revert لكل scenario.
- `buy → approve → sell` honeypot sequence.
- `success` و`reverted` و`unknown` و`failed`.
- receipt وlogs وtrace عند توفره.
- pre-state وpost-state.
- native balance delta.
- ERC-20 balance delta عند تمرير `observed_tokens`.
- `eth_call` return data preview.
- revert selector extraction عند وجود selector في الخطأ.
- gas used وeffective gas price normalization.
- prestate trace لمحاولة استخراج storage/state diff.
- عدم استخدام private keys.
- عدم إرسال mutations إلى الشبكة الحقيقية.

### Scenario Generator

يمكن توليد scenarios من ABI أو Solidity source. تشمل القوالب الحالية:

- `transfer`.
- `approve`.
- `transferFrom`.
- `mint`.
- `burn`.
- `pause` و`unpause`.
- `upgradeTo`.
- `grantRole`.
- `revokeRole`.
- `renounceRole`.
- `owner`.

المولد ينتج calldata للأنواع الأساسية مثل address وuint وbool وbytes32. إنشاء السيناريو لا يعني نجاحه؛ التنفيذ الفعلي يظل مشروطاً بالصلاحيات والسيولة وحالة العقد والـrouter الصحيح.

### تصنيفات Honeypot

- `sell_succeeded`: نجح الشراء والموافقة والبيع.
- `sell_blocked`: نجح الشراء والموافقة وفشل البيع.
- `buy_failed`: فشل الشراء، ولا يسمى تلقائياً honeypot.
- `unknown`: لم تتوفر أدلة كافية للحكم.

## 6. المحرك الثالث: On-chain Heuristics + Rule Scoring

### الهدف

يستخرج features من حالة السلسلة وملاحظات السوق، ثم يطبق قواعد versioned لإنتاج risk score مشروح.

### خط التنفيذ

```text
Alchemy facts + Dexscreener observations
                 │
                 ▼
          Feature extraction
                 │
                 ▼
       Evidence + coverage + confidence
                 │
                 ▼
       Versioned RuleEngine
                 │
                 ▼
 RiskScore + band + decisions + unknown reasons
```

### Features الحالية

- `market.pair_count`.
- `market.best_liquidity_usd`.
- `market.volume_h24_usd`.
- `market.buys_h24`.
- `market.sells_h24`.
- `market.price_min_usd`.
- `market.price_max_usd`.
- `market.pair_age_hours`.
- `chain.token_has_code`.
- `chain.log_count_window`.

كل feature تحتوي على source وconfidence وcoverage وevidence references وunknown reasons.

### القواعد الحالية

- `market.no_pair`.
- `market.low_liquidity`.
- `market.sell_activity_absent`.
- `market.price_divergence`.
- `market.stale_pair`.
- `chain.no_contract_code`.

### Policy Registry

يمكن تحميل policy من JSON خارجي، ويتضمن:

- version.
- family caps.
- rule weights.
- hard blocks.
- confidence factors.
- references.
- expiry dates.
- calibration.

الملف الحالي هو `policies/score-v0.2.json`. القاعدة `chain.no_contract_code` يمكن أن تعمل كـhard block، بينما قواعد السوق تقع تحت family cap منفصل.

## 7. Event Ledger وAnalytics

### Transfer Ledger

يتم فك أحداث ERC-20 Transfer مع:

- token address.
- from/to.
- amount.
- block number/hash.
- transaction hash.
- log index.
- removed flag.

ويطبق النظام:

- idempotent event key.
- deduplication.
- معالجة `removed=true`.
- إعادة بناء holder snapshot.
- replay من raw logs.

### Analytics الحالية

- holder concentration.
- holder churn حول block split.
- transfer count.
- token volume.
- volume per block.
- counterparty graph.
- deployer inflow.
- deployer outflow.
- deployer net flow.

### Canonical Chain Replay

توجد بنية `CanonicalChain` تحفظ block ancestry وcanonical head، وتنفذ:

- اكتشاف fork.
- إيجاد common ancestor.
- اختيار الفرع canonical.
- إعادة بناء ledger من canonical block path.
- التخلص من أحداث الفرع القديم عند reorg.

هذه capability موجودة كمنطق محلي قابل للاختبار. تحويلها إلى indexer دائم واسع النطاق يحتاج database durable وbackfill وWebSocket أو polling مستمر وjob recovery.

## 8. Unified Risk Engine

### المسؤوليات

- استقبال `UnifiedRequest`.
- تشغيل المحركات المتاحة.
- جمع findings والقرارات والأدلة.
- دمج score وband وconfidence وcoverage.
- تجميع unknowns والافتراضات.
- حفظ إصدارات المحركات والقواعد.
- إخراج JSON موحد.
- إنشاء job manifest وanchor عندما يتوفر anchor من أحد المحركات.

### شكل النتيجة

```json
{
  "run_id": "...",
  "status": "complete|partial|unknown|failed",
  "risk": {
    "score": 72,
    "band": "high",
    "confidence": 0.68,
    "coverage": 0.84
  },
  "engines": [],
  "findings": [],
  "decisions": [],
  "evidence": [],
  "unknowns": [],
  "assumptions": [],
  "versions": {},
  "job": {}
}
```

المحرك لا يحول نقص البيانات إلى `safe`. إذا كانت التغطية غير كافية أو لم تتوفر مدخلات جوهرية، تظهر `unknown` أو `partial`.

## 9. طبقة jobs وAPI الحالية

تحتوي الشفرة على:

- `JobStore` باستخدام SQLite.
- `ScanService`.
- ThreadPool workers محلية.
- `POST /v1/scans`.
- `GET /v1/scans/{id}`.
- `POST /v1/scans/{id}/rerun`.
- أمر CLI لتشغيل API المحلي:

```bash
smartrisk serve --host 127.0.0.1 --port 8787
```

هذه الطبقة مناسبة للتطوير والاختبارات المحلية. لا ينبغي اعتبارها deployment إنتاجياً لأنها لا تحتوي بعد على authentication، queue موزعة، worker isolation، durable evidence store، quotas، metrics، أو إدارة secrets.

## 10. ما الذي يمكن للمنصة الحالية فعله؟

يمكنها حالياً:

1. تحليل Solidity source عبر compiler وSlither.
2. اكتشاف مجموعة من أخطار الصلاحيات والترقية وخصائص token.
3. تنفيذ transaction scenarios على Anvil fork.
4. اختبار مسار buy/approve/sell.
5. التقاط بعض فروق الأرصدة والـgas والـreturn/revert evidence.
6. فحص market features من Dexscreener.
7. قراءة حقائق سلسلة من Alchemy عبر gateway موحد.
8. بناء Transfer ledger وholder snapshot.
9. حساب concentration وchurn وvelocity وcounterparty/deployer flows.
10. التعامل مع canonical reorg محلياً.
11. تطبيق score policy قابلة للإصدار مع caps وhard blocks وreferences.
12. دمج النتائج في تقرير JSON موحد.
13. تخزين job status محلياً وإعادة تشغيل job.

## 11. ما الذي لا تستطيع ضمانه بعد؟

لا تضمن النسخة الحالية:

- أن token آمن لمجرد غياب static finding.
- أن token قابل للبيع في كل routers أو كل الأزواج.
- أن market liquidity حقيقية وقابلة للسحب.
- أن archive capability متاحة دون historical probe.
- أن WebSocket متاح؛ فهو غير منفذ كاتصال فعلي بعد.
- أن trace متوفر لكل شبكة أو خطة Alchemy.
- state override ناجح لكل RPC؛ probe يحتاج تفسيراً حسب النتيجة.
- exploitability كاملة من static analysis وحده.
- تغطية كل holder history دون backfill دائم كامل.
- مقاومة reorg على مستوى خدمة موزعة طويلة التشغيل.
- idempotent recovery بعد انهيار worker مع durable queue.
- تشغيل production آمن دون sandboxing وresource limits.

## 12. الحكم النهائي على الجاهزية

| المستوى | الحالة |
|---|---|
| مكتبة محركات فحص | نعم، منفذة ومختبرة |
| Unified Risk Engine | نعم، MVP متقدم |
| Scanner CLI | نعم |
| Local job/API layer | نعم، أولية |
| منصة تحليل داخلية قابلة للتجربة | نعم |
| منصة SaaS إنتاجية | لا بعد |
| بديل إنتاجي كامل لـGoPlus/TokenSniffer | لا بعد |

التصنيف النهائي:

> **SmartRisk حالياً محرك فحص مخاطر EVM موحد، مع طبقة منصة محلية أولية.**

ولكي تصبح منصة كاملة، يجب إغلاق العناصر التشغيلية التالية:

- durable evidence/result store.
- queue وworkers قابلون للاسترداد.
- authentication وauthorization.
- sandboxing وnon-root وCPU/RAM/PID limits.
- Alchemy gateway مركزي مع CU budgets و429 backoff.
- WebSocket/backfill دائم.
- live integration tests مع Alchemy وAnvil.
- SARIF/HTML وtimeline API.
- metrics وtracing وalerting.
- SBOM ومراجعة التراخيص.
- performance benchmarks وcanary وfalse-positive tracking.

## المراجع

[1]: https://github.com/brahim-artygg/smartrisk "SmartRisk GitHub repository"
[2]: https://github.com/crytic/slither "Slither repository"
[3]: https://github.com/foundry-rs/foundry "Foundry and Anvil repository"
[4]: https://docs.dexscreener.com/api/reference "Dexscreener API reference"
