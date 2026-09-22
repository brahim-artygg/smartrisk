from __future__ import annotations

import hashlib
import json
import math
import random
import statistics
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Sequence


@dataclass(frozen=True)
class FuzzCase:
    case_id: str
    data: str
    value_wei: int
    mutation: str
    seed: int


@dataclass(frozen=True)
class FuzzResult:
    case_id: str
    status: str
    coverage_key: str
    new_coverage: bool
    data: str
    mutation: str
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class FuzzCampaign:
    seed: int
    iterations: int
    results: list[FuzzResult] = field(default_factory=list)
    unique_coverage: set[str] = field(default_factory=set)

    @property
    def new_paths(self) -> int:
        return sum(1 for item in self.results if item.new_coverage)

    def to_dict(self) -> dict[str, Any]:
        return {
            "seed": self.seed,
            "iterations": self.iterations,
            "results": [item.to_dict() for item in self.results],
            "unique_coverage": sorted(self.unique_coverage),
            "new_paths": self.new_paths,
        }


class DeterministicCalldataFuzzer:
    """Mutation-based EVM calldata fuzzer with reproducible seeds."""

    def __init__(self, seed: int = 20260921):
        self.seed = seed
        self.rng = random.Random(seed)

    def generate(self, base_data: str, iterations: int = 32, selectors: Sequence[str] = ()) -> list[FuzzCase]:
        base = self._normalize_data(base_data)
        generated: list[FuzzCase] = []
        seen: set[str] = set()
        mutation_names = ("zero", "ff", "bitflip", "byteflip", "truncate", "extend", "edge32", "selector")
        for index in range(max(0, iterations)):
            mutation = mutation_names[index % len(mutation_names)]
            if mutation == "selector" and selectors:
                selector = selectors[self.rng.randrange(len(selectors))]
                data = selector[2:] + base[8:]
                data = "0x" + data
            else:
                data = self._mutate(base, mutation)
            if data in seen:
                continue
            seen.add(data)
            generated.append(FuzzCase(f"fuzz-{self.seed}-{index:04d}", data, self._edge_value(index), mutation, self.seed))
        return generated

    def _mutate(self, data: str, mutation: str) -> str:
        raw = bytearray.fromhex(data[2:]) if data.startswith("0x") else bytearray.fromhex(data)
        if not raw:
            raw = bytearray(b"\x00" * 4)
        # Preserve the 4-byte function selector for argument mutations. This turns
        # the existing mutator into an ABI-aware fuzzer for the common case instead
        # of destroying the dispatch path on every zero/ff mutation.
        selector_len = 4 if len(raw) >= 4 else 0
        payload_len = max(0, len(raw) - selector_len)
        if mutation == "zero":
            if payload_len:
                raw[selector_len:] = b"\x00" * payload_len
        elif mutation == "ff":
            if payload_len:
                raw[selector_len:] = b"\xff" * payload_len
        elif mutation == "bitflip":
            if payload_len:
                index = selector_len + self.rng.randrange(payload_len)
                raw[index] ^= 1 << self.rng.randrange(8)
        elif mutation == "byteflip":
            if payload_len:
                raw[selector_len + self.rng.randrange(payload_len)] ^= 0xFF
        elif mutation == "truncate":
            new_payload_len = self.rng.randrange(max(1, payload_len + 1))
            raw = raw[:selector_len + new_payload_len]
        elif mutation == "extend":
            raw.extend(b"\x00" * self.rng.randrange(1, 33))
        elif mutation == "edge32":
            if len(raw) < selector_len + 32:
                raw.extend(b"\x00" * (selector_len + 32 - len(raw)))
            value = self.rng.choice((0, 1, 2**32 - 1, 2**256 - 1))
            raw[-32:] = value.to_bytes(32, "big")
        return "0x" + raw.hex()

    @staticmethod
    def _normalize_data(data: str) -> str:
        text = data[2:] if data.startswith("0x") else data
        if len(text) % 2 or any(ch not in "0123456789abcdefABCDEF" for ch in text):
            raise ValueError("calldata must be even-length hexadecimal")
        return "0x" + text.lower()

    @staticmethod
    def _edge_value(index: int) -> int:
        values = (0, 1, 2, 10**9, 10**18, 2**256 - 1)
        return values[index % len(values)]


def trace_coverage_key(trace: Any) -> str:
    pcs: set[int] = set()
    calls: set[tuple[str, str]] = set()

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            if isinstance(value.get("pc"), int):
                pcs.add(value["pc"])
            elif isinstance(value.get("pc"), str) and value["pc"].isdigit():
                pcs.add(int(value["pc"]))
            if value.get("type") and value.get("to"):
                calls.add((str(value.get("type")), str(value.get("to")).lower()))
            for child_key in ("structLogs", "calls"):
                child = value.get(child_key)
                if isinstance(child, list):
                    for item in child:
                        walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)

    walk(trace)
    material = {"pcs": sorted(pcs), "calls": sorted(calls)}
    return hashlib.sha256(json.dumps(material, sort_keys=True).encode()).hexdigest()


class StateForkFuzzer:
    """Execute deterministic calldata mutations against an existing local fork."""

    def __init__(self, fuzzer: DeterministicCalldataFuzzer | None = None):
        self.fuzzer = fuzzer or DeterministicCalldataFuzzer()

    def run(self, fork: Any, base_scenario: Any, anchor: Any, iterations: int = 32, selectors: Sequence[str] = ()) -> FuzzCampaign:
        campaign = FuzzCampaign(self.fuzzer.seed, iterations)
        for case in self.fuzzer.generate(base_scenario.data, iterations, selectors):
            scenario = base_scenario.__class__(
                case.case_id,
                base_scenario.from_address,
                base_scenario.to_address,
                case.data,
                case.value_wei,
                base_scenario.gas_limit,
                f"fuzz mutation {case.mutation}",
                base_scenario.observed_tokens,
                base_scenario.observed_allowances,
                base_scenario.observed_pairs,
                "fuzz",
                base_scenario.risk_tags,
            )
            try:
                result = fork.run_scenario(scenario, anchor, trace_mode="structLogs")
                key = trace_coverage_key(result.trace)
                is_new = key not in campaign.unique_coverage
                campaign.unique_coverage.add(key)
                campaign.results.append(FuzzResult(case.case_id, result.status, key, is_new, case.data, case.mutation, result.error))
            except Exception as exc:
                campaign.results.append(FuzzResult(case.case_id, "unknown", hashlib.sha256(str(exc).encode()).hexdigest(), False, case.data, case.mutation, str(exc)))
        return campaign


@dataclass(frozen=True)
class BranchFact:
    pc: int
    destination: int | None
    opcode: str
    selector: str | None
    constant: int | None
    condition_pattern: str
    guard_signals: tuple[str, ...] = ()


class EvmBoundedSymbolicAnalyzer:
    """Bounded symbolic branch guidance for common EVM dispatcher patterns.

    This intentionally reports symbolic *hints* rather than claiming complete
    path feasibility for arbitrary EVM bytecode. It is useful for steering the
    fork fuzzer toward selector/constant guards while remaining deterministic.
    """

    PUSH_BASE = 0x60

    def analyze(self, bytecode: str, max_instructions: int = 20_000) -> dict[str, Any]:
        code = bytearray.fromhex(bytecode[2:] if bytecode.startswith("0x") else bytecode)
        instructions: list[tuple[int, int, bytes]] = []
        pc = 0
        while pc < len(code) and len(instructions) < max_instructions:
            opcode = code[pc]
            width = opcode - self.PUSH_BASE + 1 if self.PUSH_BASE <= opcode <= 0x7F else 0
            data = bytes(code[pc + 1: pc + 1 + width]) if width else b""
            instructions.append((pc, opcode, data))
            pc += 1 + width
        facts: list[BranchFact] = []
        selectors: set[str] = set()
        for index, (pc_value, opcode, data) in enumerate(instructions):
            if opcode != 0x57 or index < 2:  # JUMPI
                continue
            previous = instructions[max(0, index - 8):index]
            following = instructions[index + 1:index + 25]
            constant = None
            destination = None
            selector = None
            pattern_parts: list[str] = []
            guard_signals: set[str] = set()
            for _, op, raw in previous:
                if 0x63 <= op <= 0x66:
                    selector = "0x" + raw.hex()
                    selectors.add(selector)
                if 0x60 <= op <= 0x7F:
                    value = int.from_bytes(raw, "big")
                    if value < 2**24:
                        constant = value
                    if len(raw) <= 3:
                        destination = value
                if op == 0x14:
                    pattern_parts.append("EQ")
                elif op == 0x10:
                    pattern_parts.append("LT")
                elif op == 0x11:
                    pattern_parts.append("GT")
                elif op == 0x35:
                    pattern_parts.append("CALLDATALOAD")
                    guard_signals.add("calldata")
                elif op == 0x36:
                    pattern_parts.append("CALLDATASIZE")
                    guard_signals.add("calldata_size")
                elif op == 0x33:
                    guard_signals.add("caller")
                elif op == 0x34:
                    guard_signals.add("callvalue")
                elif op == 0x42:
                    guard_signals.add("timestamp")
                elif op == 0x43:
                    guard_signals.add("block_number")
                elif op == 0x54:
                    guard_signals.add("storage_read")
            for _, op, _ in following:
                if op == 0x55:
                    guard_signals.add("nearby_sstore")
                elif op == 0xF4:
                    guard_signals.add("nearby_delegatecall")
                elif op == 0xFF:
                    guard_signals.add("nearby_selfdestruct")
            facts.append(BranchFact(pc_value, destination, "JUMPI", selector, constant, ">".join(pattern_parts) or "unknown", tuple(sorted(guard_signals))))
        solver_models = {}
        if self._z3_available():
            for selector in sorted(selectors):
                model = self._solve_selector(selector)
                if model is not None:
                    solver_models[selector] = model
        deferred = sum(1 for fact in facts if any(signal in fact.guard_signals for signal in ("timestamp", "block_number")) and "nearby_sstore" in fact.guard_signals)
        privileged = sum(1 for fact in facts if "caller" in fact.guard_signals and "nearby_sstore" in fact.guard_signals)
        return {
            "status": "complete",
            "instruction_count": len(instructions),
            "branches": [asdict(item) for item in facts],
            "function_selectors": sorted(selectors),
            "z3_available": self._z3_available(),
            "z3_selector_models": solver_models,
            "risk_hints": {
                "deferred_state_branches": deferred,
                "privileged_state_branches": privileged,
            },
            "limitations": ["bounded/static branch guidance; not a complete EVM path proof", "proximity of SSTORE/DELEGATECALL is a heuristic and does not prove path reachability"],
        }

    @staticmethod
    def _solve_selector(selector: str) -> dict[str, Any] | None:
        try:
            import z3  # type: ignore
        except ImportError:
            return None
        value = int(selector[2:], 16)
        word = z3.BitVec("calldata_word0", 256)
        solver = z3.Solver()
        solver.add(z3.LShR(word, 224) == z3.BitVecVal(value, 256))
        if solver.check() != z3.sat:
            return None
        model = solver.model()
        resolved = model.eval(word, model_completion=True).as_long()
        return {"calldata_word0": hex(resolved), "selector": selector}

    @staticmethod
    def _z3_available() -> bool:
        try:
            import z3  # type: ignore
            return bool(z3)
        except ImportError:
            return False


@dataclass(frozen=True)
class LabeledScore:
    sample_id: str
    score: float
    label: int
    group_id: str | None = None


@dataclass(frozen=True)
class ConfusionMetrics:
    threshold: float
    tp: int
    tn: int
    fp: int
    fn: int
    precision: float
    recall: float
    specificity: float
    fpr: float
    fnr: float


def _wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n <= 0:
        return (0.0, 1.0)
    p = k / n
    denom = 1 + z * z / n
    center = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt((p * (1 - p) + z * z / (4 * n)) / n) / denom
    return max(0.0, center - half), min(1.0, center + half)


@dataclass
class CalibrationReport:
    status: str
    train_size: int
    test_size: int
    selected_threshold: float | None
    train_metrics: ConfusionMetrics | None
    test_metrics: ConfusionMetrics | None
    train_metric_intervals: dict[str, tuple[float, float]]
    test_metric_intervals: dict[str, tuple[float, float]]
    brier_score: float | None
    expected_calibration_error: float | None
    diagnostics: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        return payload


class StatisticalCalibrator:
    """Deterministic threshold + Platt-style calibration on labeled historical scores."""

    def __init__(self, min_samples_per_class: int = 25, holdout_fraction: float = 0.2, seed: int = 1337):
        self.min_samples_per_class = max(2, min_samples_per_class)
        self.holdout_fraction = min(0.4, max(0.1, holdout_fraction))
        self.seed = seed
        self.intercept = 0.0
        self.slope = 1.0

    def fit(self, records: Iterable[LabeledScore]) -> CalibrationReport:
        data = list(records)
        positives = [item for item in data if item.label == 1]
        negatives = [item for item in data if item.label == 0]
        if len(positives) < self.min_samples_per_class or len(negatives) < self.min_samples_per_class:
            return CalibrationReport("insufficient_data", len(data), 0, None, None, None, {}, {}, None, None, [f"need at least {self.min_samples_per_class} positive and negative samples"])
        if len({item.sample_id for item in data}) != len(data):
            return CalibrationReport("invalid_corpus", len(data), 0, None, None, None, {}, {}, None, None, ["sample_id values must be unique"])
        rng = random.Random(self.seed)
        groups: dict[str, list[LabeledScore]] = {}
        for item in data:
            groups.setdefault(item.group_id or item.sample_id, []).append(item)
        group_keys = list(groups)
        rng.shuffle(group_keys)
        target_pos = max(1, round(len(positives) * self.holdout_fraction))
        target_neg = max(1, round(len(negatives) * self.holdout_fraction))
        test: list[LabeledScore] = []
        train_groups: list[str] = []
        pos_test = neg_test = 0
        for key in group_keys:
            members = groups[key]
            member_pos = sum(item.label == 1 for item in members)
            member_neg = len(members) - member_pos
            needs_pos = pos_test < target_pos
            needs_neg = neg_test < target_neg
            if needs_pos or needs_neg:
                test.extend(members)
                pos_test += member_pos
                neg_test += member_neg
            else:
                train_groups.append(key)
        train = [item for key in train_groups for item in groups[key]]
        if not train or not test or not any(item.label == 1 for item in train) or not any(item.label == 0 for item in train) or not any(item.label == 1 for item in test) or not any(item.label == 0 for item in test):
            return CalibrationReport("insufficient_stratification", len(train), len(test), None, None, None, {}, {}, None, None, ["group-aware holdout could not preserve both labels in train and holdout"])
        threshold = self._select_threshold(train)
        self._fit_platt(train)
        train_metrics = self._confusion(train, threshold)
        test_metrics = self._confusion(test, threshold)
        train_intervals = self._intervals(train_metrics)
        test_intervals = self._intervals(test_metrics)
        probs = [self.predict_probability(item.score) for item in test]
        brier = statistics.fmean((prob - item.label) ** 2 for prob, item in zip(probs, test)) if test else None
        ece = self._ece(test, probs, bins=10)
        return CalibrationReport("ready", len(train), len(test), threshold, train_metrics, test_metrics, train_intervals, test_intervals, brier, ece)

    def predict_probability(self, score: float) -> float:
        x = max(0.0, min(1.0, score / 100.0))
        value = max(-30.0, min(30.0, self.intercept + self.slope * x))
        return 1.0 / (1.0 + math.exp(-value))

    @staticmethod
    def load_json(path: str | Path) -> list[LabeledScore]:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(payload, list):
            raise ValueError("calibration corpus must be a JSON array")
        records = []
        for item in payload:
            if not isinstance(item, dict) or "sample_id" not in item or "score" not in item or "label" not in item:
                raise ValueError("each calibration sample needs sample_id, score and label")
            label = int(item["label"])
            if label not in (0, 1):
                raise ValueError("label must be 0 or 1")
            group_id = str(item["group_id"]) if item.get("group_id") is not None else None
            records.append(LabeledScore(str(item["sample_id"]), float(item["score"]), label, group_id))
        return records

    @staticmethod
    def _confusion(records: list[LabeledScore], threshold: float) -> ConfusionMetrics:
        tp = tn = fp = fn = 0
        for item in records:
            pred = item.score >= threshold
            if pred and item.label == 1:
                tp += 1
            elif pred and item.label == 0:
                fp += 1
            elif not pred and item.label == 0:
                tn += 1
            else:
                fn += 1
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        specificity = tn / (tn + fp) if tn + fp else 0.0
        fpr = fp / (fp + tn) if fp + tn else 0.0
        fnr = fn / (fn + tp) if fn + tp else 0.0
        return ConfusionMetrics(float(threshold), tp, tn, fp, fn, precision, recall, specificity, fpr, fnr)

    def _select_threshold(self, records: list[LabeledScore]) -> float:
        candidates = sorted({0.0, 100.0, *(max(0.0, min(100.0, item.score)) for item in records)})
        best = None
        for threshold in candidates:
            metrics = self._confusion(records, threshold)
            objective = (metrics.recall + metrics.specificity) / 2
            distance = abs(metrics.fpr - metrics.fnr)
            key = (objective, -distance, -threshold)
            if best is None or key > best[0]:
                best = (key, threshold)
        assert best is not None
        return best[1]

    def _fit_platt(self, records: list[LabeledScore]) -> None:
        # Small deterministic gradient descent; adequate for calibration, not for model training.
        intercept = 0.0
        slope = 1.0
        for _ in range(2_000):
            gi = gs = 0.0
            for item in records:
                x = max(0.0, min(1.0, item.score / 100.0))
                z = max(-30.0, min(30.0, intercept + slope * x))
                p = 1 / (1 + math.exp(-z))
                error = p - item.label
                gi += error
                gs += error * x
            lr = 0.02 / max(1.0, len(records))
            intercept = max(-10.0, min(10.0, intercept - lr * gi))
            slope = max(-20.0, min(20.0, slope - lr * gs))
        self.intercept = intercept
        self.slope = slope

    @staticmethod
    def _intervals(metrics: ConfusionMetrics) -> dict[str, tuple[float, float]]:
        return {
            "precision": _wilson(metrics.tp, metrics.tp + metrics.fp),
            "recall": _wilson(metrics.tp, metrics.tp + metrics.fn),
            "specificity": _wilson(metrics.tn, metrics.tn + metrics.fp),
        }

    @staticmethod
    def _ece(records: list[LabeledScore], probs: list[float], bins: int = 10) -> float | None:
        if not records:
            return None
        bucket_error = 0.0
        for index in range(bins):
            low = index / bins
            high = (index + 1) / bins
            members = [i for i, prob in enumerate(probs) if (prob >= low and (prob < high or index == bins - 1))]
            if not members:
                continue
            confidence = statistics.fmean(probs[i] for i in members)
            accuracy = statistics.fmean(records[i].label for i in members)
            bucket_error += len(members) / len(records) * abs(confidence - accuracy)
        return bucket_error
