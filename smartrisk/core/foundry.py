from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from .sandbox import CommandSandbox, SandboxLimits, SandboxResult


@dataclass(frozen=True)
class FoundryToolResult:
    tool: str
    status: str
    command: tuple[str, ...]
    sandbox: SandboxResult | None = None
    diagnostics: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "tool": self.tool,
            "status": self.status,
            "command": list(self.command),
            "sandbox": self.sandbox.to_dict() if self.sandbox else None,
            "diagnostics": list(self.diagnostics),
        }


class FoundryDeepRunner:
    """Optional adapter for real Foundry fuzzing / Halmos symbolic testing.

    SmartRisk's deployed-bytecode path remains self-contained. When a Foundry
    project and a test harness are available, this adapter runs the project's
    native fuzz or Halmos symbolic suite behind the same OS sandbox used by
    static analysis. No user tests are silently modified or generated.
    """

    def __init__(self, sandbox: CommandSandbox | None = None):
        self.sandbox = sandbox or CommandSandbox(SandboxLimits(wall_timeout_seconds=180.0, cpu_seconds=150))

    @staticmethod
    def capabilities() -> dict[str, object]:
        return {
            "forge": shutil.which("forge"),
            "halmos": shutil.which("halmos"),
            "sandbox": CommandSandbox().capabilities(),
        }

    def run(
        self,
        project_dir: str | Path,
        *,
        mode: str = "fuzz",
        match_test: str | None = None,
        fuzz_runs: int = 256,
        network: bool = False,
    ) -> FoundryToolResult:
        project = Path(project_dir).resolve()
        if not project.is_dir():
            raise ValueError(f"Foundry project directory does not exist: {project}")
        if mode not in {"fuzz", "symbolic"}:
            raise ValueError("mode must be 'fuzz' or 'symbolic'")
        tool = "halmos" if mode == "symbolic" else "forge"
        executable = shutil.which(tool)
        if not executable:
            return FoundryToolResult(tool, "unavailable", (tool,), diagnostics=(f"{tool} executable not found",))

        if mode == "symbolic":
            command = [executable]
            if match_test:
                command += ["--match-test", match_test]
        else:
            command = [executable, "test", "--fuzz-runs", str(max(1, fuzz_runs)), "--json"]
            if match_test:
                command += ["--match-test", match_test]

        for directory in (project / "cache", project / "out"):
            directory.mkdir(parents=True, exist_ok=True)
        result = self.sandbox.run(
            command,
            cwd=project,
            readonly_paths=(project,),
            writable_paths=(project / "cache", project / "out"),
            allow_network=network,
        )
        status = "complete" if result.status == "complete" and result.returncode == 0 else result.status
        return FoundryToolResult(tool, status, tuple(command), result)
