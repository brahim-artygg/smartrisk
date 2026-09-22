import os
import sys

from smartrisk.core.sandbox import CommandSandbox, SandboxLimits


def test_sandbox_runs_command_with_bounded_output(tmp_path):
    sandbox = CommandSandbox(SandboxLimits(wall_timeout_seconds=5, max_output_bytes=32))
    result = sandbox.run([sys.executable, "-c", "print('hello')"], cwd=tmp_path)
    assert result.status == "complete"
    assert result.returncode == 0
    assert "hello" in result.stdout
    assert result.limits["max_output_bytes"] == 32


def test_sandbox_reports_output_truncation(tmp_path):
    sandbox = CommandSandbox(SandboxLimits(wall_timeout_seconds=5, max_output_bytes=8))
    result = sandbox.run([sys.executable, "-c", "print('x'*100)"], cwd=tmp_path)
    assert result.status == "complete"
    assert result.output_truncated is True


def test_sandbox_times_out(tmp_path):
    sandbox = CommandSandbox(SandboxLimits(wall_timeout_seconds=0.2, cpu_seconds=1))
    result = sandbox.run([sys.executable, "-c", "import time; time.sleep(2)"], cwd=tmp_path)
    assert result.status == "timeout"
    assert result.timed_out is True
