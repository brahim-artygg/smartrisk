from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any

PRAGMA_RE = re.compile(r"pragma\s+solidity\s+([^;]+);", re.IGNORECASE)
VERSION_RE = re.compile(r"(\d+)\.(\d+)\.(\d+)")


@dataclass(frozen=True)
class CompilerSelection:
    requested: str | None
    pragma_constraints: list[str]
    selected_version: str | None
    executable: str | None
    status: str
    reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class CompilerManager:
    """Selects an installed solc version without silently downloading one."""

    def __init__(self, solc_executable: str | None = None, solc_select: str | None = None):
        self.solc_executable = solc_executable
        self.solc_select = solc_select or shutil.which("solc-select")

    def inspect(self, project: str | Path, requested: str | None = None) -> CompilerSelection:
        root = Path(project).resolve()
        constraints = self._pragma_constraints(root)
        installed = self._installed_versions()
        selected = self._choose(requested, constraints, installed)
        executable = self._resolve_executable(selected)
        if selected and executable:
            return CompilerSelection(requested, constraints, selected, executable, "ready")
        reason = "no installed solc satisfies the project pragma"
        if requested and requested not in installed:
            reason = f"requested solc {requested} is not installed"
        return CompilerSelection(requested, constraints, selected, executable, "unavailable", reason)

    def environment(self, selection: CompilerSelection) -> dict[str, str]:
        env = dict(os.environ)
        if selection.selected_version:
            env["SOLC_VERSION"] = selection.selected_version
        if selection.executable:
            # Slither invokes the command named `solc`. Put a stable shim first
            # so a versioned binary is not shadowed by solc-select's wrapper.
            runtime_dir = Path.home() / ".cache" / "smartrisk" / "solc" / (selection.selected_version or "active")
            runtime_dir.mkdir(parents=True, exist_ok=True)
            shim = runtime_dir / "solc"
            if shim.exists() or shim.is_symlink():
                shim.unlink()
            shim.symlink_to(selection.executable)
            env["PATH"] = str(runtime_dir) + os.pathsep + str(Path(selection.executable).parent) + os.pathsep + env.get("PATH", "")
        return env

    def _pragma_constraints(self, root: Path) -> list[str]:
        constraints: list[str] = []
        if not root.exists():
            return constraints
        paths = [root] if root.is_file() else sorted(root.rglob("*.sol"))
        for path in paths:
            if path.suffix.lower() != ".sol":
                continue
            if ".git" in path.parts or ".venv" in path.parts:
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            constraints.extend(match.group(1).strip() for match in PRAGMA_RE.finditer(text))
        return sorted(set(constraints))

    def _installed_versions(self) -> list[str]:
        versions: set[str] = set()
        if self.solc_select:
            try:
                result = subprocess.run([self.solc_select, "versions"], capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    versions.update(match.group(0) for match in VERSION_RE.finditer(result.stdout))
            except (OSError, subprocess.SubprocessError):
                pass
        executable = self.solc_executable or shutil.which("solc")
        if executable:
            try:
                result = subprocess.run([executable, "--version"], capture_output=True, text=True, timeout=5)
                versions.update(match.group(0) for match in VERSION_RE.finditer(result.stdout))
            except (OSError, subprocess.SubprocessError):
                pass
        local_dir = Path(__file__).resolve().parents[2] / ".venv" / "bin"
        for candidate in local_dir.glob("solc-*"):
            if not candidate.is_file() or not candidate.name.startswith("solc-"):
                continue
            version = candidate.name.removeprefix("solc-")
            if VERSION_RE.fullmatch(version):
                versions.add(version)
        return sorted(set(versions), key=self._version_tuple)

    def _resolve_executable(self, selected: str | None) -> str | None:
        configured = self.solc_executable or shutil.which("solc")
        if configured and (not selected or self._version_of(configured) == selected):
            return configured
        local = Path(__file__).resolve().parents[2] / ".venv" / "bin" / "solc"
        versioned = Path(__file__).resolve().parents[2] / ".venv" / "bin" / f"solc-{selected}" if selected else None
        if versioned and versioned.exists():
            return str(versioned)
        if local.exists():
            return str(local)
        return configured

    @staticmethod
    def _choose(requested: str | None, constraints: list[str], installed: list[str]) -> str | None:
        if requested:
            return requested if requested in installed else None
        exact = []
        for constraint in constraints:
            exact.extend(VERSION_RE.findall(constraint))
        for version in sorted(set(exact), key=CompilerManager._version_tuple, reverse=True):
            if version in installed:
                return version
        return installed[-1] if installed else None

    @staticmethod
    def _version_of(executable: str) -> str | None:
        try:
            result = subprocess.run([executable, "--version"], capture_output=True, text=True, timeout=5)
            match = VERSION_RE.search(result.stdout)
            return match.group(0) if match else None
        except (OSError, subprocess.SubprocessError):
            return None

    @staticmethod
    def _version_tuple(value: str) -> tuple[int, int, int]:
        match = VERSION_RE.search(value)
        return tuple(int(part) for part in match.groups()) if match else (0, 0, 0)
