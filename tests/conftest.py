"""Load the hook and the linter by path. They are single-file scripts, not an installed package."""

from __future__ import annotations

import importlib.util
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
HOOK = ROOT / "policy" / "hooks" / "ccg_guard.py"
LINT = ROOT / "tools" / "ccg_lint.py"
RENDER = ROOT / "scripts" / "render.py"
HOME = "/home/alice"
CWD = "/home/alice/proj"


def _load(name: str, path: pathlib.Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="session")
def guard():
    return _load("ccg_guard", HOOK)


@pytest.fixture(scope="session")
def lint():
    return _load("ccg_lint", LINT)


@pytest.fixture(scope="session")
def render():
    return _load("ccg_render", RENDER)


LEVELS = {"allow": 0, "ask": 1, "deny": 2}


@pytest.fixture()
def bash(guard):
    def run(command: str):
        payload = {"tool_name": "Bash", "tool_input": {"command": command}, "cwd": CWD}
        return guard.decide(payload, HOME)

    return run


@pytest.fixture()
def tool(guard):
    def run(name: str, **tool_input):
        return guard.decide({"tool_name": name, "tool_input": tool_input, "cwd": CWD}, HOME)

    return run
