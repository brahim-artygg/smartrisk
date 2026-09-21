from __future__ import annotations

import hashlib
import json
import subprocess
import uuid
from pathlib import Path
from typing import Any

from .models import StaticRun
from .slither_adapter import SlitherAdapter, SlitherUnavailable


ENGINE_VERSION = "0.1.0"


class StaticEngine:
    def __init__(self, slither: SlitherAdapter | None = None):
        self.slither = slither or SlitherAdapter()

    def analyze(self, project: str | Path, run_id: str | None = None) -> StaticRun:
        root = Path(project).resolve()
        run_id = run_id or str(uuid.uuid4())
        input_hash = self._hash_inputs(root)
        compiler = self._compiler_manifest(root)
        if not root.exists():
            return StaticRun(
                run_id, "failed", "static", ENGINE_VERSION, input_hash, compiler,
                unknown_reasons=[f"project does not exist: {root}"],
            )
        try:
            findings, evidence, diagnostics = self.slither.run(root)
        except SlitherUnavailable as exc:
            return StaticRun(
                run_id,
                "unknown",
                "static",
                ENGINE_VERSION,
                input_hash,
                compiler,
                unknown_reasons=[str(exc), "install solc and Slither or provide a configured worker"],
            )
        except (OSError, json.JSONDecodeError, subprocess.SubprocessError) as exc:
            return StaticRun(
                run_id, "failed", "static", ENGINE_VERSION, input_hash, compiler,
                unknown_reasons=[f"Slither execution failed: {exc}"],
            )
        return StaticRun(
            run_id,
            "complete",
            "static",
            ENGINE_VERSION,
            input_hash,
            compiler,
            findings=findings,
            evidence=evidence,
            diagnostics=diagnostics,
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

    @staticmethod
    def _compiler_manifest(root: Path) -> dict[str, Any]:
        manifest: dict[str, Any] = {}
        for name in ("foundry.toml", "hardhat.config.js", "hardhat.config.ts", "package.json"):
            path = root / name
            if path.exists():
                manifest["project_config"] = name
                break
        try:
            completed = subprocess.run(["solc", "--version"], capture_output=True, text=True, timeout=5)
            if completed.returncode == 0:
                manifest["solc"] = completed.stdout.strip()
            else:
                manifest["solc_error"] = completed.stderr.strip()
        except (FileNotFoundError, subprocess.SubprocessError):
            manifest["solc"] = None
        return manifest
