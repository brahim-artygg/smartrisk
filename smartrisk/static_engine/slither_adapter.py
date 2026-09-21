from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from .models import Evidence, Finding, SourceLocation


class SlitherUnavailable(RuntimeError):
    pass


class SlitherAdapter:
    """Runs the installed Slither CLI and normalizes its JSON output.

    Slither remains an external worker process. This keeps the engine boundary
    explicit and avoids coupling the core package to AGPL code at import time.
    """

    def __init__(self, executable: str = "slither", timeout_seconds: int = 120):
        self.executable = executable
        self.timeout_seconds = timeout_seconds

    def available(self) -> bool:
        return shutil.which(self.executable) is not None

    def run(self, project: Path) -> tuple[list[Finding], list[Evidence], list[str]]:
        if not self.available():
            raise SlitherUnavailable(f"{self.executable} was not found on PATH")
        with tempfile.TemporaryDirectory(prefix="smartrisk-slither-") as tmp:
            output = Path(tmp) / "slither.json"
            command = [self.executable, str(project), "--json", str(output)]
            try:
                completed = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    timeout=self.timeout_seconds,
                    check=False,
                )
            except subprocess.TimeoutExpired as exc:
                raise SlitherUnavailable("Slither timed out") from exc
            diagnostics = [line for line in (completed.stderr or "").splitlines() if line.strip()]
            if not output.exists():
                raise SlitherUnavailable(
                    f"Slither produced no JSON output (exit={completed.returncode})"
                )
            payload = json.loads(output.read_text(encoding="utf-8"))
            return self._normalize(payload, project, diagnostics)

    def _normalize(
        self, payload: dict[str, Any], project: Path, diagnostics: list[str]
    ) -> tuple[list[Finding], list[Evidence], list[str]]:
        findings: list[Finding] = []
        evidence: list[Evidence] = []
        detectors = payload.get("results", {}).get("detectors", [])
        for index, detector in enumerate(detectors):
            elements = detector.get("elements") or []
            location = self._location(elements[0] if elements else {}, project)
            evidence_id = f"slither:{index}"
            evidence.append(
                Evidence(
                    evidence_id=evidence_id,
                    kind="static-finding",
                    source="slither",
                    locator={"file": location.file if location else None},
                    details={"raw": detector},
                )
            )
            findings.append(
                Finding(
                    finding_id=f"slither:{detector.get('check', 'unknown')}:{index}",
                    engine="static",
                    rule_id=detector.get("check", "slither.unknown"),
                    title=detector.get("description", detector.get("check", "Slither finding")),
                    description=detector.get("description", ""),
                    severity=self._severity(detector.get("impact")),
                    confidence=self._confidence(detector.get("confidence")),
                    status="likely",
                    source_location=location,
                    evidence_refs=[evidence_id],
                    metadata={"slither": detector},
                )
            )
        return findings, evidence, diagnostics

    @staticmethod
    def _severity(value: str | None) -> str:
        return {
            "High": "high",
            "Medium": "medium",
            "Low": "low",
            "Informational": "informational",
        }.get(value or "", "informational")

    @staticmethod
    def _confidence(value: str | None) -> float:
        return {"High": 0.9, "Medium": 0.65, "Low": 0.4}.get(value or "", 0.3)

    @staticmethod
    def _location(element: dict[str, Any], project: Path) -> SourceLocation | None:
        source = element.get("source_mapping") or {}
        filename = source.get("filename_relative") or source.get("filename_absolute")
        if not filename:
            return None
        try:
            filename = os.path.relpath(filename, project)
        except ValueError:
            pass
        lines = source.get("lines") or []
        line = lines[0] if lines else None
        return SourceLocation(file=filename, line=line)
