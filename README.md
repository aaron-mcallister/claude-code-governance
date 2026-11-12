# claude-code-governance

[![CI](https://github.com/aaron-mcallister/claude-code-governance/actions/workflows/ci.yml/badge.svg)](https://github.com/aaron-mcallister/claude-code-governance/actions/workflows/ci.yml)

A **tested reference policy** for running Claude Code on developer machines: managed settings, a
PreToolUse guard hook, a policy linter, and a test suite that proves the policy blocks what it says it
blocks and **fails closed** when it breaks.

> A personal project. Not official guidance from Anthropic or any employer. Claude Code changes quickly:
> verify every key against the [current documentation](https://docs.claude.com) before deploying, and read
> [`docs/VALIDATION.md`](docs/VALIDATION.md) for what was and was not tested.

## The idea

Most agent-governance writing is a checklist. Checklists cannot be run. This repository treats the policy
as code:

- **A policy template** (`policy/managed-settings.template.json`) with deny and ask rules, managed-only
  hooks and MCP servers, a required sandbox with a network allowlist, and telemetry.
- **A guard hook** (`policy/hooks/ccg_guard.py`): one standard-library file, written to Python 3.9 syntax so it runs on stock macOS. It reads
  the tool call, and can only ever **ask or deny**. Malformed, oversized or unparseable input, and any
  internal error, end in a block.
- **A linter** (`tools/ccg_lint.py`) with two modes. `managed` checks that a rendered policy still carries
  every control (so it cannot drift). `repo` checks a repository's own `.claude/` and `.mcp.json` for
  constructs that run code or redirect traffic on whoever clones it.
- **Tests that attack the controls.** Every lint rule has a mutation test (break the policy in exactly that
  way, assert the linter notices). The hook is tested against tables of benign and hostile commands, a
  fuzz, and an AST check that it does no file or network I/O.
- **An honest gap list.** Seven things a text check cannot catch are written down, pinned by tests, and each
  names the control that covers it.

## What it does and does not do

| Stops (hook and rules) | Covered by the sandbox, not the hook |
|---|---|
| `curl`, `wget`, `nc` and friends, including `command curl`, wrappers and nested shells | A script or Makefile that makes the request for itself |
| Reads of `.env`, `~/.ssh`, `~/.aws`, `/proc/*/environ` | Glob-obfuscated paths (`cat ~/.s*/id_rs?`) |
| `git push` (asks), force/mirror/delete pushes (denies), `git -C . push` forms | `git clone`, `npm install` and other tools that happen to use the network |
| `rm -rf` of root or home, `dd` to a device, `mkfs` | A copied or renamed binary |
| Edits to the policy, hooks, `.mcp.json`, shell rc files | |
| Strong secret patterns in WebFetch, WebSearch and MCP arguments | |

It does **not** stop attacks whose only effect is the text the model writes back (a rendered link, a
misleading summary). No tool-call gate can. See
[agent-security-evals](https://github.com/aaron-mcallister/agent-security-evals), the companion project that
measures this.

The most useful finding from building it: **a malformed `hooks` block in managed settings is silently
ignored at runtime.** A typo switches the guard off with no error. `claude doctor` reports it; a running
session does not. That is why CI runs both the linter and, optionally, the real `claude doctor`.

## Quick start

```sh
pip install -r requirements-dev.txt
pytest

# Render for your OS and lint it. Warnings are errors, so placeholder values fail.
python scripts/render.py --os linux \
  --otel-endpoint https://otel.example.internal:4317 \
  --mcp-url 'https://mcp.example.internal/*' --out /tmp/managed-settings.json
python tools/ccg_lint.py managed /tmp/managed-settings.json --fail-on-warning

# Check a repository you do not trust before opening it in Claude Code
python tools/ccg_lint.py repo path/to/repo

# Install (root; use --dry-run first)
sudo scripts/install.sh --os linux --dry-run --otel-endpoint ... --mcp-url ...
```

## Layout

```
policy/                  managed-settings template and the guard hook
tools/ccg_lint.py        managed and repo policy linter
scripts/                 render.py, install.sh, doctor_check.sh (real `claude doctor` gate)
tests/                   guard, contract, mutation, install and known-gap tests
docs/THREAT-MODEL.md     assets, adversaries, threats, controls, residual risk
docs/CONTROL-MAP.md      every control, its strength, and the known gaps
docs/ROLLOUT.md         pilot, install, verify, change control, drift, rollback
docs/VALIDATION.md      what was tested (and what was not), with dates and versions
```

## Design choices worth arguing with

- **The hook is soft on purpose.** Claude Code's own documentation says deny rules on Bash text are not a
  security boundary. The hook catches the cheap and the accidental, and the sandbox is what holds when text
  lies. The control map grades each control hard, soft or detective.
- **Tighten only.** The hook never prints "allow". A bug costs convenience, not safety.
- **`allowManagedHooksOnly` has a price.** It stops hostile repositories adding hooks, and it stops your own
  teams too. The rollout guide says how to plan for that.
- **Vendor-neutral.** Nothing here depends on a particular MDM, SIEM or proxy product. Delivery and
  collection are left to what you already run.

## Status and contributing

Version 0.1. Issues that include the exact command or file that was wrongly blocked or wrongly allowed are
the most useful; each accepted fix comes with a test. See [`SECURITY.md`](SECURITY.md) to report a
vulnerability privately.

## License

MIT. See [`LICENSE`](LICENSE).
