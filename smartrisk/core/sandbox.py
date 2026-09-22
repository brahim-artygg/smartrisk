from __future__ import annotations

import os
import platform
import shutil
import signal
import subprocess
import tempfile
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Sequence


@dataclass(frozen=True)
class SandboxLimits:
    wall_timeout_seconds: float = 120.0
    cpu_seconds: int = 90
    memory_bytes: int = 1_500_000_000
    file_size_bytes: int = 256_000_000
    max_open_files: int = 256
    max_processes: int = 32
    max_output_bytes: int = 2_000_000

    def to_dict(self) -> dict[str, int | float]:
        return asdict(self)


@dataclass(frozen=True)
class SandboxResult:
    status: str
    returncode: int | None
    stdout: str
    stderr: str
    timed_out: bool
    output_truncated: bool
    network_isolation: str
    limits: dict[str, int | float]
    duration_ms: float
    diagnostics: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "status": self.status,
            "returncode": self.returncode,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "timed_out": self.timed_out,
            "output_truncated": self.output_truncated,
            "network_isolation": self.network_isolation,
            "limits": self.limits,
            "duration_ms": self.duration_ms,
            "diagnostics": list(self.diagnostics),
        }


class SandboxUnavailable(RuntimeError):
    pass


class CommandSandbox:
    """Run compiler/static-analysis tools with OS resource limits.

    On Linux hosts with bubblewrap, --unshare-net is used to isolate the worker
    from the network. Without bubblewrap, POSIX rlimits are still enforced and
    the result explicitly records that network isolation wasn't available.
    """

    def __init__(self, limits: SandboxLimits | None = None, require_network_isolation: bool = False):
        self.limits = limits or SandboxLimits()
        self.require_network_isolation = require_network_isolation
        self.bwrap = shutil.which("bwrap") if platform.system().lower() == "linux" else None

    def capabilities(self) -> dict[str, object]:
        posix_limits = os.name == "posix"
        return {
            "platform": platform.system(),
            "resource_limits": posix_limits,
            "network_isolation": bool(self.bwrap),
            "bubblewrap": self.bwrap,
            "status": "ready" if posix_limits or self.bwrap else "limited",
        }

    def run(
        self,
        command: Sequence[str],
        *,
        cwd: str | Path | None = None,
        env: dict[str, str] | None = None,
        readonly_paths: Sequence[str | Path] = (),
        writable_paths: Sequence[str | Path] = (),
        timeout_seconds: float | None = None,
        allow_network: bool = False,
    ) -> SandboxResult:
        if not command:
            raise ValueError("sandbox command must not be empty")
        if self.require_network_isolation and allow_network:
            raise SandboxUnavailable("network access cannot be enabled for a network-isolated sandbox")
        if self.require_network_isolation and not self.bwrap:
            raise SandboxUnavailable("bubblewrap is required for network-isolated sandbox execution")

        limits = self.limits
        timeout = timeout_seconds or limits.wall_timeout_seconds
        diagnostics: list[str] = []
        run_dir = Path(tempfile.mkdtemp(prefix="smartrisk-sandbox-"))
        stdout_path = run_dir / "stdout"
        stderr_path = run_dir / "stderr"
        actual_cwd = Path(cwd).resolve() if cwd else run_dir
        actual_cwd.mkdir(parents=True, exist_ok=True)
        child_env = self._safe_env(env or {}, actual_cwd)

        rewritten = [str(item) for item in command]
        network_isolation = "none"
        if self.bwrap:
            network_isolation = "bubblewrap-host-network" if allow_network else "bubblewrap-unshare-net"
            rewritten = self._wrap_bwrap(rewritten, actual_cwd, readonly_paths, writable_paths, allow_network=allow_network)
            child_cwd = "/work"
        else:
            child_cwd = str(actual_cwd)
            diagnostics.append("bubblewrap unavailable; network isolation is not enforced")

        started = time.perf_counter()
        timed_out = False
        returncode: int | None = None
        try:
            with stdout_path.open("wb") as stdout_file, stderr_path.open("wb") as stderr_file:
                process = subprocess.Popen(
                    rewritten,
                    cwd=child_cwd,
                    env=child_env,
                    stdout=stdout_file,
                    stderr=stderr_file,
                    stdin=subprocess.DEVNULL,
                    shell=False,
                    start_new_session=True,
                    preexec_fn=self._limit_process if os.name == "posix" else None,
                    close_fds=os.name == "posix",
                )
                try:
                    returncode = process.wait(timeout=max(0.1, timeout))
                except subprocess.TimeoutExpired:
                    timed_out = True
                    self._terminate_group(process)
                    returncode = process.returncode
        finally:
            elapsed_ms = (time.perf_counter() - started) * 1000

        stdout, stdout_cut = self._read_capped(stdout_path, limits.max_output_bytes)
        stderr, stderr_cut = self._read_capped(stderr_path, limits.max_output_bytes)
        output_truncated = stdout_cut or stderr_cut
        if output_truncated:
            diagnostics.append(f"worker output exceeded {limits.max_output_bytes} bytes per stream")
        try:
            shutil.rmtree(run_dir, ignore_errors=True)
        except OSError:
            pass

        if timed_out:
            status = "timeout"
        elif returncode == 0:
            status = "complete"
        else:
            status = "failed"
            if returncode is not None and returncode < 0 and -returncode in {signal.SIGXCPU, signal.SIGKILL}:
                diagnostics.append("worker may have exceeded CPU/resource limits")
                status = "resource_exceeded"
        return SandboxResult(
            status=status,
            returncode=returncode,
            stdout=stdout,
            stderr=stderr,
            timed_out=timed_out,
            output_truncated=output_truncated,
            network_isolation=network_isolation,
            limits=limits.to_dict(),
            duration_ms=round(elapsed_ms, 3),
            diagnostics=tuple(diagnostics),
        )

    @staticmethod
    def _safe_env(env: dict[str, str], cwd: Path) -> dict[str, str]:
        safe: dict[str, str] = {}
        for key in ("PATH", "LANG", "LC_ALL", "SystemRoot"):
            if os.environ.get(key):
                safe[key] = os.environ[key]
        safe["HOME"] = str(cwd)
        safe["TMPDIR"] = str(cwd / "tmp")
        (cwd / "tmp").mkdir(parents=True, exist_ok=True)
        for key, value in env.items():
            if key in {"PATH", "LANG", "LC_ALL", "SOLC_VERSION", "PYTHONPATH"}:
                safe[key] = value
        return safe

    def _wrap_bwrap(self, command: list[str], cwd: Path, readonly_paths: Sequence[str | Path], writable_paths: Sequence[str | Path], *, allow_network: bool = False) -> list[str]:
        assert self.bwrap is not None
        args = [
            self.bwrap,
            "--die-with-parent",
            "--new-session",
            "--ro-bind", "/", "/",
            "--tmpfs", "/tmp",
            "--proc", "/proc",
            "--dev", "/dev",
            "--dir", "/input",
            "--dir", "/output",
            "--dir", "/work",
        ]
        if not allow_network:
            args.append("--unshare-net")

        cwd = cwd.resolve()
        writable = [Path(path).resolve() for path in writable_paths]
        readonly = [Path(path).resolve() for path in readonly_paths]
        cwd_is_writable = cwd in writable
        args.extend(["--bind" if cwd_is_writable else "--ro-bind", str(cwd), "/work"])
        args.extend(["--chdir", "/work"])

        readonly_map: list[tuple[Path, str]] = [(cwd, "/work")]
        writable_map: list[tuple[Path, str]] = [(cwd, "/work")] if cwd_is_writable else []
        for index, path in enumerate(writable):
            if path == cwd:
                continue
            try:
                rel = path.relative_to(cwd)
                target = "/work/" + rel.as_posix()
            except ValueError:
                target = f"/output/{index}"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.mkdir(parents=True, exist_ok=True) if not path.exists() else None
            args.extend(["--bind", str(path), target])
            writable_map.append((path, target))
        input_index = 0
        for path in readonly:
            if path == cwd:
                continue
            try:
                rel = path.relative_to(cwd)
                target = "/work/" + rel.as_posix()
                # It is already covered by the read-only cwd mount.
                continue
            except ValueError:
                target = f"/input/{input_index}"
                input_index += 1
            args.extend(["--ro-bind", str(path), target])
            readonly_map.append((path, target))

        rewritten: list[str] = []
        for item in command:
            mapped = None
            try:
                source = Path(item).resolve()
                for root, target in writable_map + readonly_map:
                    if source == root:
                        mapped = target
                        break
                    if root.is_dir():
                        try:
                            rel = source.relative_to(root)
                            mapped = target + "/" + rel.as_posix()
                            break
                        except ValueError:
                            pass
            except (OSError, RuntimeError, ValueError):
                mapped = None
            rewritten.append(mapped or item)
        return args + ["--"] + rewritten

    def _limit_process(self) -> None:
        try:
            import resource
            resource.setrlimit(resource.RLIMIT_CPU, (self.limits.cpu_seconds, self.limits.cpu_seconds))
            resource.setrlimit(resource.RLIMIT_AS, (self.limits.memory_bytes, self.limits.memory_bytes))
            resource.setrlimit(resource.RLIMIT_FSIZE, (self.limits.file_size_bytes, self.limits.file_size_bytes))
            resource.setrlimit(resource.RLIMIT_NOFILE, (self.limits.max_open_files, self.limits.max_open_files))
            if hasattr(resource, "RLIMIT_NPROC"):
                resource.setrlimit(resource.RLIMIT_NPROC, (self.limits.max_processes, self.limits.max_processes))
        except (ImportError, OSError, ValueError):
            return

    @staticmethod
    def _terminate_group(process: subprocess.Popen[str]) -> None:
        try:
            if os.name == "posix":
                os.killpg(process.pid, signal.SIGKILL)
            else:
                process.kill()
        except (OSError, ProcessLookupError):
            pass

    @staticmethod
    def _read_capped(path: Path, limit: int) -> tuple[str, bool]:
        data = path.read_bytes() if path.exists() else b""
        truncated = len(data) > limit
        if truncated:
            data = data[:limit]
        return data.decode("utf-8", errors="replace"), truncated
