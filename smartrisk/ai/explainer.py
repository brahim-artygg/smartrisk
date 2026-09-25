from __future__ import annotations

import hashlib
import json
import os
import urllib.request
from typing import Any


class AIExplainer:
    """Optional narrative layer; it cannot produce or modify risk decisions."""

    MODEL = "gpt-5-mini"

    def __init__(self, enabled: bool | None = None, model: str | None = None, timeout: float = 8.0):
        raw_enabled = os.getenv("SMARTRISK_AI_EXPLANATION_ENABLED", "false").lower() in {"1", "true", "yes", "on"}
        self.enabled = raw_enabled if enabled is None else bool(enabled)
        self.model = model or os.getenv("SMARTRISK_AI_MODEL", self.MODEL)
        self.timeout = timeout

    def explain(self, report: dict[str, Any]) -> dict[str, Any] | None:
        """Return a bounded explanation, or None when the feature is disabled/unavailable."""
        if not self.enabled:
            return None
        api_key = os.getenv("OPENAI_API_KEY")
        base = os.getenv("OPENAI_API_BASE")
        if not api_key or not base:
            return {"status": "unavailable", "reason_code": "AI_NOT_CONFIGURED", "model": self.model}

        payload = self._input_payload(report)
        prompt = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        prompt_hash = hashlib.sha256(prompt.encode("utf-8")).hexdigest()
        body = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": "You explain a deterministic EVM risk report. Never change, infer, or restate a score or verdict as your own conclusion. Use only supplied findings, checks, evidence references, assumptions, and unknowns. Output JSON only."},
                {"role": "user", "content": "Explain this report for a non-expert user. Mark uncertainty explicitly and cite check_id or evidence_refs in every key finding.\n" + prompt},
            ],
            "max_completion_tokens": 700,
            "response_format": {
                "type": "json_schema",
                "json_schema": {
                    "name": "smartrisk_report_explanation",
                    "strict": True,
                    "schema": {
                        "type": "object",
                        "properties": {
                            "summary": {"type": "string"},
                            "key_findings": {"type": "array", "items": {"type": "object", "properties": {"title": {"type": "string"}, "explanation": {"type": "string"}, "check_id": {"type": "string"}, "evidence_refs": {"type": "array", "items": {"type": "string"}}}, "required": ["title", "explanation", "check_id", "evidence_refs"], "additionalProperties": False}},
                            "evidence_gaps": {"type": "array", "items": {"type": "string"}},
                            "limitations": {"type": "array", "items": {"type": "string"}},
                        },
                        "required": ["summary", "key_findings", "evidence_gaps", "limitations"],
                        "additionalProperties": False,
                    },
                },
            },
        }
        request = urllib.request.Request(
            base.rstrip("/") + "/chat/completions",
            data=json.dumps(body).encode("utf-8"),
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                result = json.loads(response.read().decode("utf-8"))
            content = result["choices"][0]["message"]["content"]
            explanation = json.loads(content)
            return {"status": "complete", "model": self.model, "prompt_hash": prompt_hash, **self._bounded_output(explanation)}
        except Exception as exc:
            return {"status": "unavailable", "reason_code": "AI_PROVIDER_ERROR", "model": self.model, "prompt_hash": prompt_hash, "error": str(exc)[:240]}

    @staticmethod
    def _input_payload(report: dict[str, Any]) -> dict[str, Any]:
        return {
            "risk": report.get("risk"),
            "verdict": report.get("verdict"),
            "findings": (report.get("findings") or [])[:12],
            "checks": (report.get("checks") or [])[:12],
            "unknowns": (report.get("unknowns") or [])[:12],
            "assumptions": (report.get("assumptions") or [])[:8],
        }

    @staticmethod
    def _bounded_output(value: dict[str, Any]) -> dict[str, Any]:
        return {
            "summary": str(value.get("summary", ""))[:1200],
            "key_findings": [
                {"title": str(item.get("title", ""))[:180], "explanation": str(item.get("explanation", ""))[:500], "check_id": str(item.get("check_id", ""))[:100], "evidence_refs": [str(ref)[:180] for ref in (item.get("evidence_refs") or [])[:8]]}
                for item in (value.get("key_findings") or [])[:5] if isinstance(item, dict)
            ],
            "evidence_gaps": [str(item)[:300] for item in (value.get("evidence_gaps") or [])[:8]],
            "limitations": [str(item)[:300] for item in (value.get("limitations") or [])[:8]],
        }
