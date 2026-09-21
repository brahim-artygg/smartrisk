from __future__ import annotations

import hashlib
import json
import subprocess
import uuid
from pathlib import Path
from typing import Any

from .compiler_manager import CompilerManager
from .custom_detectors import CustomDetectorRunner
from .models import StaticRun
from .slither_adapter import SlitherAdapter, SlitherUnavailable


ENGINE_VERSION = "0.2.0"


class StaticEngine:
    def __init__(
        self,
        slither: SlitherAdapter | None = None,
        compiler_manager: CompilerManager | None = None,
        custom_detectors: CustomDetectorRunner | None = None,
    ):
        self.slither = slither or SlitherAdapter()
        self.compiler_manager = compiler_manager or CompilerManager()
        self.custom_detectors = custom_detectors or CustomDetectorRunner()

    def analyze(
        self,
        project: str | Path,
        run_id: str | None = None,
        compiler_version: str | None = None,
    ) -> StaticRun:
        root = Path(project).resolve()
        run_id = run_id or str(uuid.uuid4())
        input_hash = self._hash_inputs(root)
        if not root.exists():
            return StaticRun(
                run_id, "failed", "static", ENGINE_VERSION, input_hash, {},
                unknown_reasons=[f"project does not exist: {root}"],
            )
        selection = self.compiler_manager.inspect(root, requested=compiler_version)
        compiler = selection.to_dict()
        if selection.status != "ready":
            return StaticRun(
                run_id, "unknown", "static", ENGINE_VERSION, input_hash, compiler,
                unknown_reasons=[selection.reason or "compiler unavailable"],
            )
        env = self.compiler_manager.environment(selection)
        try:
            findings, evidence, diagnostics = self.slither.run(root, env=env)
            custom_findings, custom_evidence, custom_diagnostics = self.custom_detectors.run(root, env=env)
        except SlitherUnavailable as exc:
            return StaticRun(
                run_id, "unknown", "static", ENGINE_VERSION, input_hash, compiler,
                unknown_reasons=[str(exc), "install/configure Slither and solc"],
            )
        except (OSError, RuntimeError, json.JSONDecodeError, subprocess.SubprocessError) as exc:
            return StaticRun(
                run_id, "failed", "static", ENGINE_VERSION, input_hash, compiler,
                unknown_reasons=[f"static analysis failed: {exc}"],
            )
        return StaticRun(
            run_id,
            "complete",
            "static",
            ENGINE_VERSION,
            input_hash,
            compiler,
            findings=findings + custom_findings,
            evidence=evidence + custom_evidence,
            diagnostics=diagnostics + custom_diagnostics,
        )

    @staticmethod
    def _hash_inputs(root: Path) -> str:
        digest = hashlib.sha256()
        if not root.exists():
            return digest.hexdigest()
        files = sorted(p for p in root.rglob("*") if p.is_file() and ".git" not in p.parts)
        for path in files:
            digest.update(str(path.relative_to(root)).encode())
            digest.update(path.read_bytes())
        return digest.hexdigest()
