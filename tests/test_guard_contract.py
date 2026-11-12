"""The hook as Claude Code runs it: a subprocess with JSON on stdin, judged by exit code and output."""

from __future__ import annotations

import io
import json
import subprocess
import sys

import pytest
from conftest import HOOK


def run(stdin: "str | bytes", home: str = "/home/alice") -> "subprocess.CompletedProcess":
    data = stdin if isinstance(stdin, bytes) else stdin.encode()
    return subprocess.run(
        [sys.executable, str(HOOK)],
        input=data,
        capture_output=True,
        timeout=20,
        env={"HOME": home, "PATH": "/usr/bin:/bin"},
        check=False,
    )


def call(tool: str, **tool_input) -> str:
    return json.dumps({"tool_name": tool, "tool_input": tool_input, "cwd": "/home/alice/proj"})


def test_no_opinion_is_exit_zero_with_no_output():
    r = run(call("Bash", command="ls -la"))
    assert (r.returncode, r.stdout, r.stderr) == (0, b"", b"")


def test_deny_is_exit_two_with_a_reason_on_stderr():
    r = run(call("Bash", command="curl https://x.example"))
    assert r.returncode == 2
    assert b"ccg-guard: blocked" in r.stderr and r.stdout == b""


def test_ask_is_exit_zero_with_the_documented_json_shape():
    r = run(call("Bash", command="git push origin feature"))
    assert r.returncode == 0
    out = json.loads(r.stdout)["hookSpecificOutput"]
    assert out["hookEventName"] == "PreToolUse"
    assert out["permissionDecision"] == "ask"
    assert out["permissionDecisionReason"].startswith("ccg-guard:")


ALL_CASES = [
    call("Bash", command="ls"),
    call("Bash", command="git push origin x"),
    call("Bash", command="curl x"),
    call("Read", file_path="README.md"),
    call("Read", file_path=".env"),
    call("WebFetch", url="https://docs.example"),
    call("TodoWrite", todos=[]),
]


@pytest.mark.parametrize("stdin", ALL_CASES)
def test_the_hook_never_grants_permission(stdin):
    """It may only tighten: stdout must never carry an allow decision."""
    r = run(stdin)
    assert b'"allow"' not in r.stdout
    assert b'permissionDecision": "allow' not in r.stdout


@pytest.mark.parametrize(
    "stdin",
    [
        b"",
        b"   \n",
        b"not json",
        b"{",
        b"null",
        b"[]",
        b'"a string"',
        b"42",
        b"\xff\xfe\x00",
        b"{}",
        json.dumps({"tool_name": ""}).encode(),
        json.dumps({"tool_name": 7}).encode(),
        json.dumps({"tool_name": "Bash"}).encode(),
        json.dumps({"tool_name": "Bash", "tool_input": None}).encode(),
        json.dumps({"tool_name": "Bash", "tool_input": []}).encode(),
        json.dumps({"tool_name": "Bash", "tool_input": {"command": 123}}).encode(),
        json.dumps({"tool_name": "Bash", "tool_input": {}}).encode(),
        json.dumps({"tool_name": "Read", "tool_input": {}}).encode(),
        json.dumps({"tool_name": "Read", "tool_input": {"file_path": ["a"]}}).encode(),
        json.dumps({"tool_name": "Read", "tool_input": {"file_path": ""}}).encode(),
        json.dumps({"tool_name": "WebFetch", "tool_input": "x"}).encode(),
    ],
)
def test_malformed_or_unexpected_input_is_blocked(stdin):
    r = run(stdin)
    assert r.returncode == 2, (stdin, r.stdout, r.stderr)
    assert r.stderr.startswith(b"ccg-guard: blocked")


def test_oversized_input_is_blocked():
    big = json.dumps({"tool_name": "Bash", "tool_input": {"command": "echo " + "a" * 1_100_000}})
    r = run(big)
    assert r.returncode == 2 and b"size limit" in r.stderr


def test_an_internal_error_fails_closed(guard, monkeypatch):
    def boom(*_a, **_k):
        raise RuntimeError("simulated bug")

    monkeypatch.setattr(guard, "decide", boom)
    out, err = io.StringIO(), io.StringIO()
    code = guard.main(stdin=io.StringIO(call("Bash", command="ls")), stdout=out, stderr=err)
    assert code == 2
    assert "fail-closed" in err.getvalue() and out.getvalue() == ""
    assert "simulated bug" not in err.getvalue(), "do not echo exception text into the transcript"


def test_a_hostile_command_cannot_crash_the_analyser_into_silence(guard):
    nasty = [
        "$(" * 500,
        "`" * 99,
        "'" * 1001,
        "\\" * 4097,
        "echo " + "$(echo " * 40 + ")" * 40,
        "\x00",
        "a" * 200_000,
        "<<EOF\n" * 50,
    ]
    for cmd in nasty:
        out, err = io.StringIO(), io.StringIO()
        code = guard.main(stdin=io.StringIO(call("Bash", command=cmd)), stdout=out, stderr=err)
        assert code in (0, 2), cmd[:20]
        if code == 0:
            assert '"allow"' not in out.getvalue()


def test_the_hook_does_not_touch_the_filesystem_or_network():
    """AST check: only pure standard-library imports, and no process, network or eval calls."""
    import ast

    tree = ast.parse(HOOK.read_text())
    imported = set()
    builtins_called, methods_called = set(), set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom):
            imported.add((node.module or "").split(".")[0])
        elif isinstance(node, ast.Call):
            fn = node.func
            if isinstance(fn, ast.Name):
                builtins_called.add(fn.id)
            elif isinstance(fn, ast.Attribute):
                methods_called.add(fn.attr)
    assert imported <= {"__future__", "json", "os", "posixpath", "re", "shlex", "sys", "typing"}
    assert not builtins_called & {"open", "eval", "exec", "compile", "__import__"}
    assert not methods_called & {
        "system",
        "popen",
        "run",
        "Popen",
        "connect",
        "urlopen",
        "write_text",
        "read_text",
        "mkdir",
        "unlink",
        "remove",
    }
