#!/usr/bin/env python3
"""ccg-lint: check Claude Code policy files.

    ccg_lint.py managed FILE [--fail-on-warning] [--format text|github]
    ccg_lint.py repo [PATH ...]  [--fail-on-warning] [--format text|github]

`managed` checks that a managed-settings.json still carries every control this reference
architecture relies on, so a policy cannot quietly drift (a key deleted, a flag flipped, a hook that
fails open). `repo` checks a repository's own Claude Code files (.claude/settings*.json, .mcp.json)
for constructs that run code or redirect traffic on whoever clones it.

Exit status: 0 clean (or warnings only), 1 at least one error, 2 usage or unreadable input.
Standard library only; written to Python 3.9 syntax.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys
from typing import Any, NamedTuple

ERROR, WARN, INFO = "error", "warning", "info"


class Finding(NamedTuple):
    level: str
    code: str
    where: str
    message: str


# --------------------------------------------------------------------------- loading
class LintInputError(Exception):
    pass


def _no_duplicates(pairs: "list[tuple[str, Any]]") -> "dict[str, Any]":
    seen: "dict[str, Any]" = {}
    for key, val in pairs:
        if key in seen:
            raise LintInputError("duplicate key " + repr(key) + " (JSON keeps only the last one)")
        seen[key] = val
    return seen


def load_json(path: pathlib.Path) -> Any:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise LintInputError("cannot read " + str(path) + ": " + type(exc).__name__) from exc
    try:
        return json.loads(text, object_pairs_hook=_no_duplicates)
    except json.JSONDecodeError as exc:
        raise LintInputError(
            str(path) + ": invalid JSON at line " + str(exc.lineno) + " (settings files are strict JSON)"
        ) from exc


def _get(doc: Any, dotted: str, default: Any = None) -> Any:
    cur = doc
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return default
        cur = cur[part]
    return cur


def _walk_strings(node: Any, path: str = "") -> "list[tuple[str, str]]":
    out: "list[tuple[str, str]]" = []
    if isinstance(node, str):
        out.append((path, node))
    elif isinstance(node, dict):
        for k, v in node.items():
            out += _walk_strings(v, path + ("." if path else "") + str(k))
    elif isinstance(node, list):
        for i, v in enumerate(node):
            out += _walk_strings(v, path + "[" + str(i) + "]")
    return out


_SECRET = re.compile(
    r"\b(AKIA|ASIA)[0-9A-Z]{16}\b|\bgh[pousr]_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{22,}\b"
    r"|\bxox[baprs]-[A-Za-z0-9-]{10,}\b|\bsk-ant-[A-Za-z0-9_-]{20,}\b|-----BEGIN [A-Z ]*PRIVATE KEY-----"
    r"|\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"
)
_PLACEHOLDER_HOST = re.compile(r"(?i)(^|[/@.])[a-z0-9-]*\.?(example|invalid|test|localhost)(?=[:/\s*\"]|$)")


# --------------------------------------------------------------------------- managed policy
def lint_managed(doc: Any, where: str = "managed-settings.json") -> "list[Finding]":
    f: "list[Finding]" = []
    if not isinstance(doc, dict):
        return [Finding(ERROR, "M000", where, "policy must be a JSON object")]

    def err(code: str, msg: str, key: str = "") -> None:
        f.append(Finding(ERROR, code, where + (":" + key if key else ""), msg))

    def warn(code: str, msg: str, key: str = "") -> None:
        f.append(Finding(WARN, code, where + (":" + key if key else ""), msg))

    # permissions
    if _get(doc, "permissions.disableBypassPermissionsMode") != "disable":
        err("M001", 'set permissions.disableBypassPermissionsMode to "disable"', "permissions")
    deny = _get(doc, "permissions.deny", [])
    deny = deny if isinstance(deny, list) else []
    for needle, what in ((".env", "environment files"), (".ssh", "SSH keys"), (".aws", "AWS credentials")):
        if not any(isinstance(r, str) and r.startswith("Read(") and needle in r for r in deny):
            err("M002", "permissions.deny has no Read(...) rule for " + what, "permissions.deny")
    if not any(isinstance(r, str) and r.startswith("Edit(") and ".claude" in r for r in deny):
        err(
            "M003",
            "permissions.deny does not protect .claude settings and hooks from edits",
            "permissions.deny",
        )
    for r in deny:
        if isinstance(r, str) and re.match(r"^(Bash|Read|Edit|Write)\((command|file_path|path):", r):
            err(
                "M004",
                "rule " + repr(r) + " matches a raw field and is ignored by Claude Code",
                "permissions.deny",
            )
    allow = _get(doc, "permissions.allow", [])
    for r in allow if isinstance(allow, list) else []:
        if isinstance(r, str) and r.strip() in ("Bash", "Bash(*)", "Bash(* *)", "*", "Write", "Edit"):
            err("M005", "managed allow rule " + repr(r) + " is unbounded", "permissions.allow")
    if _get(doc, "permissions.defaultMode") in ("bypassPermissions", "dontAsk"):
        err("M006", "permissions.defaultMode must not skip prompts", "permissions.defaultMode")

    # hooks and MCP lockdown
    if doc.get("allowManagedHooksOnly") is not True:
        err("M010", "set allowManagedHooksOnly: true so repository hooks cannot run", "allowManagedHooksOnly")
    if doc.get("disableAllHooks") is True:
        err("M011", "disableAllHooks must not be true in the managed policy", "disableAllHooks")
    if doc.get("allowManagedMcpServersOnly") is not True:
        err("M012", "set allowManagedMcpServersOnly: true", "allowManagedMcpServersOnly")
    if not isinstance(doc.get("allowedMcpServers"), list):
        err("M013", "allowedMcpServers must be a list (an explicit allowlist)", "allowedMcpServers")
    if doc.get("enableAllProjectMcpServers") is True:
        err("M014", "enableAllProjectMcpServers: true auto-approves any repository's MCP servers")
    _check_hooks(doc, err, warn)

    # sandbox
    sb = doc.get("sandbox")
    if _get(sb, "enabled") is not True:
        err("M020", "set sandbox.enabled: true", "sandbox.enabled")
    if _get(sb, "failIfUnavailable") is not True:
        err(
            "M021",
            "set sandbox.failIfUnavailable: true so an unavailable sandbox is not silently skipped",
            "sandbox",
        )
    if _get(sb, "allowUnsandboxedCommands") is not False:
        err("M022", "set sandbox.allowUnsandboxedCommands: false", "sandbox")
    if _get(sb, "network.allowManagedDomainsOnly") is not True:
        err("M023", "set sandbox.network.allowManagedDomainsOnly: true", "sandbox.network")
    domains = _get(sb, "network.allowedDomains", [])
    if not isinstance(domains, list) or not domains:
        err("M024", "sandbox.network.allowedDomains must be a non-empty allowlist", "sandbox.network")
    else:
        for d in domains:
            if not isinstance(d, str) or d.strip() in ("*", "*.*", "**") or re.match(r"^\*\.[a-z]{2,6}$", d):
                err("M025", "allowedDomains entry " + repr(d) + " allows far too much", "sandbox.network")
    if not _get(sb, "filesystem.denyRead"):
        warn(
            "M026",
            "sandbox.filesystem.denyRead is empty; the sandbox will not hide credential folders",
            "sandbox",
        )

    # telemetry
    env = doc.get("env") if isinstance(doc.get("env"), dict) else {}
    if str(env.get("CLAUDE_CODE_ENABLE_TELEMETRY")) != "1":
        err("M030", 'env.CLAUDE_CODE_ENABLE_TELEMETRY must be "1" (no audit trail otherwise)', "env")
    if env.get("OTEL_LOGS_EXPORTER") in (None, "none", ""):
        err(
            "M031",
            "env.OTEL_LOGS_EXPORTER must name an exporter; a developer could otherwise set it to none",
            "env",
        )
    if not env.get("OTEL_EXPORTER_OTLP_ENDPOINT"):
        err("M032", "env.OTEL_EXPORTER_OTLP_ENDPOINT is missing", "env")
    for key in ("OTEL_LOG_USER_PROMPTS", "OTEL_LOG_RAW_API_BODIES", "OTEL_LOG_TOOL_CONTENT"):
        if str(env.get(key, "0")) not in ("0", "", "false"):
            warn(
                "M033",
                key + " exports prompt or conversation content; confirm privacy and retention review",
                "env",
            )
    for key in env:
        if key in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_BASE_URL"):
            err("M034", key + " must not be set in the shared policy", "env")

    # general hygiene
    if not doc.get("requiredMinimumVersion"):
        warn("M040", "requiredMinimumVersion is not set; old clients may lack newer controls")
    if "forceLoginMethod" not in doc:
        f.append(
            Finding(
                INFO, "M041", where, "forceLoginMethod is not set (org-specific; pins how people sign in)"
            )
        )
    for path, val in _walk_strings(doc):
        if _SECRET.search(val):
            err("M050", "a secret-like value is committed in the policy file", path)
        if "{{" in val:
            err("M051", "unrendered placeholder " + repr(val), path)
        elif _PLACEHOLDER_HOST.search(val) and path.startswith(("env.OTEL", "allowedMcpServers")):
            warn("M052", "placeholder host in " + repr(val) + "; replace before deploying", path)
    return f


def _check_hooks(doc: "dict[str, Any]", err: Any, warn: Any) -> None:
    pre = _get(doc, "hooks.PreToolUse")
    groups = pre if isinstance(pre, list) else []
    handlers = [
        h for g in groups if isinstance(g, dict) for h in (g.get("hooks") or []) if isinstance(h, dict)
    ]
    if not handlers:
        err("M015", "no PreToolUse hook is registered", "hooks.PreToolUse")
    for h in handlers:
        loc = "hooks.PreToolUse"
        if h.get("type") != "command":
            err("M016", 'policy hooks must be type "command" (found ' + repr(h.get("type")) + ")", loc)
            continue
        if h.get("onFailure") != "block":
            err(
                "M017", 'every policy hook needs "onFailure": "block"; the default fails open on timeout', loc
            )
        timeout = h.get("timeout")
        if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or not 0 < timeout <= 30:
            err("M018", "set a hook timeout of 1-30 seconds", loc)
        args = h.get("args")
        script = args[0] if isinstance(args, list) and args else h.get("command", "")
        for label, p in (("command", h.get("command", "")), ("script", script)):
            if not isinstance(p, str) or not (p.startswith("/") or re.match(r"^[A-Za-z]:\\", p)):
                err(
                    "M019",
                    "hook " + label + " must be an absolute path (a relative one is attacker-influenced)",
                    loc,
                )
        if (
            isinstance(h.get("args"), list) is False
            and isinstance(h.get("command"), str)
            and " " in h["command"]
        ):
            warn("M019", "use the exec form (command plus args) instead of a shell string", loc)


# --------------------------------------------------------------------------- repository files
_RISKY_ENV = {
    "ANTHROPIC_BASE_URL": "redirects API traffic, including credentials, to another host",
    "ANTHROPIC_API_KEY": "puts a credential in a file that gets committed",
    "ANTHROPIC_AUTH_TOKEN": "puts a credential in a file that gets committed",
    "HTTP_PROXY": "routes traffic through another host",
    "HTTPS_PROXY": "routes traffic through another host",
    "ALL_PROXY": "routes traffic through another host",
    "NODE_OPTIONS": "injects code into Node processes",
    "NODE_EXTRA_CA_CERTS": "adds a trusted certificate authority",
    "SSL_CERT_FILE": "replaces the trusted certificate authorities",
    "REQUESTS_CA_BUNDLE": "replaces the trusted certificate authorities",
    "LD_PRELOAD": "injects a library into every process",
    "DYLD_INSERT_LIBRARIES": "injects a library into every process",
    "BASH_ENV": "runs a script in every non-interactive shell",
    "PATH": "changes which binary a command name resolves to",
}
_CODE_EXEC_KEYS = ("apiKeyHelper", "awsAuthRefresh", "awsCredentialExport")
_NETWORK_OR_SHELL = re.compile(
    r"(?i)(^|[\s;&|(`])(curl|wget|nc|ncat|socat)\b|\|\s*(ba|z|da)?sh\b|base64\s+-d|eval\b"
)
_UNPINNED_RUNNERS = {"npx", "bunx", "pnpx", "uvx", "pipx"}


def lint_repo_settings(doc: Any, where: str) -> "list[Finding]":
    f: "list[Finding]" = []
    if not isinstance(doc, dict):
        return [Finding(ERROR, "R000", where, "settings file must be a JSON object")]

    def add(level: str, code: str, msg: str, key: str = "") -> None:
        f.append(Finding(level, code, where + (":" + key if key else ""), msg))

    hooks = doc.get("hooks")
    if isinstance(hooks, dict) and hooks:
        for path, val in _walk_strings(hooks):
            if path.endswith((".command", ".args[0]", ".args[1]", ".args[2]")) and _NETWORK_OR_SHELL.search(
                val
            ):
                add(
                    ERROR,
                    "R001",
                    "hook runs a network tool or pipes into a shell: " + repr(val[:60]),
                    "hooks",
                )
        add(
            WARN,
            "R002",
            "repository hooks run code on every clone (ignored when allowManagedHooksOnly is on)",
            "hooks",
        )
        for path, val in _walk_strings(hooks):
            if path.endswith(".type") and val == "http":
                add(WARN, "R003", "an HTTP hook sends tool data to a remote URL", "hooks")
    if doc.get("enableAllProjectMcpServers") is True:
        add(ERROR, "R004", "auto-approves every MCP server in the repository", "enableAllProjectMcpServers")
    allow = _get(doc, "permissions.allow", [])
    for r in allow if isinstance(allow, list) else []:
        if isinstance(r, str) and r.strip() in (
            "Bash",
            "Bash(*)",
            "Bash(* *)",
            "*",
            "Write",
            "Edit",
            "WebFetch",
        ):
            add(
                ERROR,
                "R005",
                "unbounded allow rule " + repr(r) + " pre-approves arbitrary actions",
                "permissions.allow",
            )
    if _get(doc, "permissions.defaultMode") in ("bypassPermissions", "dontAsk"):
        add(ERROR, "R006", "defaultMode skips permission prompts", "permissions.defaultMode")
    env = doc.get("env")
    if isinstance(env, dict):
        for key in env:
            why = _RISKY_ENV.get(str(key).upper())
            if why:
                add(ERROR, "R007", "env." + str(key) + " " + why, "env")
    for key in _CODE_EXEC_KEYS:
        if key in doc:
            add(ERROR, "R008", key + " runs a command from a file that came with the repository", key)
    for key in ("statusLine", "otelHeadersHelper"):
        val = doc.get(key)
        cmd = val.get("command") if isinstance(val, dict) else val
        if isinstance(cmd, str):
            add(WARN, "R009", key + " runs a command from the repository", key)
    if _get(doc, "sandbox.enabled") is False or _get(doc, "sandbox.allowUnsandboxedCommands") is True:
        add(ERROR, "R010", "weakens the sandbox for everyone who clones this repository", "sandbox")
    if doc.get("extraKnownMarketplaces"):
        add(
            WARN,
            "R011",
            "registers a plugin marketplace that is not on your allowlist",
            "extraKnownMarketplaces",
        )
    for path, val in _walk_strings(doc):
        if _SECRET.search(val):
            add(ERROR, "R012", "a secret-like value is committed in this file", path)
    return f


def lint_mcp_json(doc: Any, where: str) -> "list[Finding]":
    f: "list[Finding]" = []
    servers = doc.get("mcpServers") if isinstance(doc, dict) else None
    if not isinstance(servers, dict):
        return [Finding(WARN, "R020", where, "no mcpServers object found")]
    for name, spec in servers.items():
        loc = where + ":mcpServers." + str(name)
        if not isinstance(spec, dict):
            f.append(Finding(ERROR, "R021", loc, "server entry must be an object"))
            continue
        cmd = spec.get("command")
        args = [a for a in spec.get("args", []) if isinstance(a, str)]
        if isinstance(cmd, str):
            base = cmd.rsplit("/", 1)[-1]
            joined = " ".join([cmd] + args)
            if base in ("sh", "bash", "zsh") and _NETWORK_OR_SHELL.search(joined):
                f.append(Finding(ERROR, "R022", loc, "shell launcher downloads or evaluates code"))
            elif base in _UNPINNED_RUNNERS and not any(
                re.search(r"@\d+(\.\d+)+", a) or re.search(r"==\d", a) for a in args
            ):
                f.append(Finding(WARN, "R023", loc, base + " runs an unpinned package; pin an exact version"))
        if isinstance(spec.get("url"), str):
            f.append(
                Finding(
                    WARN,
                    "R024",
                    loc,
                    "remote MCP server: tool data leaves the machine; it must be on the allowlist",
                )
            )
        for path, val in _walk_strings({k: spec[k] for k in ("env", "headers") if k in spec}):
            if _SECRET.search(val):
                f.append(Finding(ERROR, "R025", loc + "." + path, "a secret-like value is committed"))
    return f


REPO_FILES = (".claude/settings.json", ".claude/settings.local.json", ".mcp.json")


def lint_repo(paths: "list[pathlib.Path]") -> "list[Finding]":
    findings: "list[Finding]" = []
    for root in paths:
        base = root if root.is_dir() else root.parent
        targets = [root] if root.is_file() else [base / rel for rel in REPO_FILES if (base / rel).is_file()]
        for t in targets:
            try:
                doc = load_json(t)
            except LintInputError as exc:
                findings.append(Finding(ERROR, "R099", str(t), str(exc)))
                continue
            name = str(t)
            if t.name == ".mcp.json":
                findings += lint_mcp_json(doc, name)
            else:
                findings += lint_repo_settings(doc, name)
    return findings


# --------------------------------------------------------------------------- output
def format_findings(findings: "list[Finding]", style: str) -> str:
    lines = []
    for lv, code, where, msg in findings:
        if style == "github" and lv in (ERROR, WARN):
            path = where.split(":", 1)[0]
            kind = "error" if lv == ERROR else "warning"
            lines.append("::" + kind + " file=" + path + ",title=" + code + "::" + msg)
        else:
            lines.append(lv.upper().ljust(7) + " " + code + " " + where + " - " + msg)
    return "\n".join(lines)


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="mode", required=True)
    m = sub.add_parser("managed", help="lint a managed-settings.json")
    m.add_argument("file", type=pathlib.Path)
    r = sub.add_parser("repo", help="lint a repository's .claude/ and .mcp.json files")
    r.add_argument("paths", nargs="*", type=pathlib.Path, default=[pathlib.Path(".")])
    for p in (m, r):
        p.add_argument("--fail-on-warning", action="store_true")
        p.add_argument("--format", choices=("text", "github"), default="text")
    args = ap.parse_args(argv)
    try:
        if args.mode == "managed":
            findings = lint_managed(load_json(args.file), str(args.file))
        else:
            findings = lint_repo(list(args.paths))
    except LintInputError as exc:
        print("ccg-lint: " + str(exc), file=sys.stderr)
        return 2
    out = format_findings(findings, args.format)
    if out:
        print(out)
    errors = sum(1 for x in findings if x.level == ERROR)
    warnings = sum(1 for x in findings if x.level == WARN)
    print("ccg-lint: " + str(errors) + " error(s), " + str(warnings) + " warning(s)", file=sys.stderr)
    if errors or (args.fail_on_warning and warnings):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
