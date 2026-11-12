"""The install script, exercised in dry-run mode only. Nothing here writes outside tmp."""

from __future__ import annotations

import subprocess
import sys

import pytest
from conftest import ROOT

SCRIPT = ROOT / "scripts" / "install.sh"
REAL = ["--otel-endpoint", "https://otel.corp.internal:4317", "--mcp-url", "https://mcp.corp.internal/*"]


def run(*args):
    return subprocess.run(["bash", str(SCRIPT), *args], capture_output=True, text=True, check=False)


@pytest.mark.parametrize("os_name", ["macos", "linux"])
def test_dry_run_with_real_values_succeeds_and_installs_nothing(os_name):
    r = run("--dry-run", "--os", os_name, "--python", sys.executable, *REAL)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "dry run" in r.stdout and "0755" in r.stdout


@pytest.mark.parametrize("os_name", ["macos", "linux"])
def test_placeholder_values_are_refused(os_name):
    r = run("--dry-run", "--os", os_name, "--python", sys.executable)
    assert r.returncode == 1
    assert "refusing" in r.stderr


def test_unknown_options_and_systems_are_rejected():
    assert run("--bogus").returncode == 2
    assert run("--os", "windows", *REAL).returncode == 2


def test_a_real_install_requires_root():
    import os

    if os.geteuid() == 0:
        pytest.skip("running as root; a real install would write to the system directory")
    r = run("--os", "linux", "--python", sys.executable, *REAL)
    assert r.returncode == 1 and "root" in r.stderr


def test_doctor_check_refuses_to_write_system_files_without_opt_in():
    script = ROOT / "scripts" / "doctor_check.sh"
    r = subprocess.run(
        ["bash", str(script)], capture_output=True, text=True, check=False, env={"PATH": "/usr/bin:/bin"}
    )
    assert r.returncode == 2 and "refusing" in r.stderr
