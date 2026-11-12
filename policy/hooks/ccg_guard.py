#!/usr/bin/env python3
"""ccg_guard: a fail-closed PreToolUse hook for Claude Code.

Contract (Claude Code hooks): the tool call arrives as JSON on stdin. Exit 0 with no output means
"no opinion" and Claude Code carries on with its normal permission flow. Exit 2 blocks the call and
stderr is shown as the reason. Exit 0 with a JSON `permissionDecision` of "ask" forces a prompt.

Design rules, each enforced by tests:

* The hook only ever TIGHTENS. It never prints "allow", so it cannot grant anything that the
  permission rules would not. (Claude Code also evaluates deny and ask rules regardless of what a
  hook returns, so a hook cannot loosen those either.)
* Anything the hook cannot parse or trust is blocked: empty or malformed input, oversized input,
  unexpected shapes, and any internal exception. Pair this with `"onFailure": "block"` in the hook
  registration so a missing script or a timeout blocks too.
* It is best effort for shell commands. Shell is too expressive to police by pattern. The hard
  controls are the sandbox (network and filesystem) and managed permission deny rules. This hook
  normalises the forms those rules miss (`git -C . push`, `/usr/bin/curl`, `env curl`, `sh -c "..."`)
  and adds checks that need context, such as secret-looking values in outbound tool arguments.

Standard library only, written to Python 3.9 syntax so it runs on the interpreter that ships with
macOS developer tools.
"""

from __future__ import annotations

import json
import os
import posixpath
import re
import shlex
import sys
from typing import Any

MAX_INPUT_BYTES = 1_000_000
MAX_DEPTH = 6

ALLOW, ASK, DENY = 0, 1, 2

OK: "tuple[int, str]" = (ALLOW, "")


def _worst(decisions: "list[tuple[int, str]]") -> "tuple[int, str]":
    best = OK
    for d in decisions:
        if d[0] > best[0]:
            best = d
    return best


# --------------------------------------------------------------------------- path rules
_ENV_FILE = re.compile(r"(^|/)\.env($|\.(?!(example|sample|template|dist|defaults)$)[^/]*$)")
_SENSITIVE_SUFFIX = re.compile(r"\.(pem|key|p12|pfx)$|/id_(rsa|dsa|ecdsa|ed25519)$")
_SENSITIVE_SYSTEM = re.compile(r"^/proc/[^/]+/environ$|^/etc/(shadow|sudoers)(\.d)?(/|$)")
_HOME_SENSITIVE = (
    r"\.(ssh|aws|gnupg|kube|netrc|npmrc|pypirc|git-credentials)(/|$)",
    r"\.config/(gh|gcloud)(/|$)",
    r"\.docker/config\.json$",
    r"\.claude/\.credentials\.json$",
    r"\.claude\.json$",
    r"library/keychains(/|$)",
)

_PROTECTED_ANYWHERE = re.compile(
    r"(^|/)\.claude/settings(\.local)?\.json$"
    r"|(^|/)\.claude/hooks(/|$)"
    r"|(^|/)\.mcp\.json$"
    r"|(^|/)\.git/(hooks(/|$)|config$)"
    r"|^/etc/claude-code(/|$)"
    r"|^/library/application support/claudecode(/|$)"
)
_PROTECTED_HOME = re.compile(r"\.(zshrc|zshenv|zprofile|bashrc|bash_profile|profile)$")
_ASK_WRITE = re.compile(r"(^|/)\.github/workflows/|(^|/)\.husky/")


def _home(home: str) -> str:
    return home.rstrip("/").lower() or "/"


def expand_candidates(raw: str, cwd: str, home: str) -> "list[str]":
    """Normalised, lowercased absolute candidates for a path as written.

    Lowercased because the default macOS filesystem is case-insensitive (`.ENV` is `.env`).
    Both the lexical path and the symlink-resolved path are returned so a symlink named like an
    innocent file cannot hide a sensitive target, and vice versa.
    """
    p = raw.strip()
    if not p or "\x00" in p:
        return []
    if p.startswith("~"):
        p = home + p[1:]
    elif p.startswith("$HOME"):
        p = home + p[len("$HOME") :]
    elif p.startswith("${HOME}"):
        p = home + p[len("${HOME}") :]
    if not posixpath.isabs(p):
        p = posixpath.join(cwd or os.getcwd(), p)
    lexical = posixpath.normpath(p)
    out = [lexical.lower()]
    try:
        real = os.path.realpath(lexical)
    except (OSError, ValueError):
        real = lexical
    if real.lower() not in out:
        out.append(real.lower())
    return out


def sensitive_read(path: str, home: str) -> bool:
    h = _home(home)
    if _ENV_FILE.search(path) or _SENSITIVE_SUFFIX.search(path) or _SENSITIVE_SYSTEM.search(path):
        return True
    return any(re.search("^" + re.escape(h) + "/" + pat, path) for pat in _HOME_SENSITIVE)


def is_home_or_ancestor(path: str, home: str) -> bool:
    h = _home(home)
    return path == "/" or h == path or h.startswith(path.rstrip("/") + "/")


def protected_write(path: str, home: str) -> "tuple[int, str]":
    h = _home(home)
    if _PROTECTED_ANYWHERE.search(path):
        return (DENY, "this file controls Claude Code, git hooks or its policy")
    if re.search("^" + re.escape(h) + "/", path) and _PROTECTED_HOME.search(path):
        return (DENY, "shell startup files are a persistence mechanism")
    if _ASK_WRITE.search(path):
        return (ASK, "CI and git-hook files change what runs on other machines")
    return OK


def check_path(raw: str, cwd: str, home: str, write: bool, what: str = "path") -> "tuple[int, str]":
    cands = expand_candidates(raw, cwd, home)
    if not cands:
        return (DENY, "empty or invalid " + what)
    decisions: "list[tuple[int, str]]" = []
    for c in cands:
        if sensitive_read(c, home):
            decisions.append((DENY, "reading or listing credentials and secrets is not permitted"))
        if write:
            pw = protected_write(c, home)
            if pw[0] != ALLOW:
                decisions.append(pw)
    return _worst(decisions)


# --------------------------------------------------------------------------- secret patterns
_STRONG_SECRETS = [
    re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
]
_GENERIC_SECRET = re.compile(
    r"(?i)\b(password|passwd|secret|token|api[_-]?key|private[_-]?key)\b\s*[=:]\s*[\"']?[^\s\"']{12,}"
)


def secret_decision(text: str, strong_level: int) -> "tuple[int, str]":
    for pat in _STRONG_SECRETS:
        if pat.search(text):
            return (strong_level, "a secret-like credential appears in this call")
    if _GENERIC_SECRET.search(text):
        return (ASK, "something that looks like a password, token or key appears in this call")
    return OK


# --------------------------------------------------------------------------- shell scanning
_SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "ash", "fish"}
_INTERPRETERS = {"python", "python3", "node", "ruby", "perl", "php", "deno", "bun"}
_NET_DENY = {"curl", "wget", "nc", "ncat", "netcat", "socat", "telnet", "ftp", "tftp"}
_NET_ASK = {"ssh", "scp", "sftp", "rsync"}
_FS_DESTROY = {"mkfs", "wipefs", "shred", "fdisk", "parted"}
_READ_ONLY_MENTION = {"echo", "printf", "ls", "stat", "test", "[", "[[", "true", "false", "which", "type"}
_WRITERS = {"tee", "cp", "mv", "rm", "ln", "install", "chmod", "chown", "truncate", "dd", "touch"}
_NET_WORDS = re.compile(
    r"\b(urllib|requests|httpx|aiohttp|http\.client|socket|urlopen|fetch|XMLHttpRequest|"
    r"net/http|Net::HTTP|file_get_contents|curl_exec)\b"
)
_KEYWORDS = {"if", "then", "elif", "else", "do", "while", "until", "!", "time", "{", "}", "fi", "done"}
_ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_REDIR = re.compile(r"^(\d*)(>>?|<)(.*)$")
_HEREDOC = re.compile(r"<<-?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1")


def _strip_heredocs(text: str) -> "tuple[str, bool]":
    """Remove heredoc bodies (data, not commands). Return (text, shell_reads_heredoc)."""
    lines = text.split("\n")
    out: "list[str]" = []
    shell_heredoc = False
    i = 0
    while i < len(lines):
        line = lines[i]
        out.append(line)
        m = _HEREDOC.search(line)
        if m:
            first = line.strip().split(None, 1)[0] if line.strip() else ""
            if posixpath.basename(first) in _SHELLS | _INTERPRETERS:
                shell_heredoc = True
            term = m.group(2)
            i += 1
            while i < len(lines) and lines[i].strip() != term:
                i += 1
        i += 1
    return "\n".join(out), shell_heredoc


def _find_close(text: str, start: int) -> int:
    """Index of the ')' that closes a '(' just before `start`, honouring nesting and quotes."""
    depth, i, quote = 1, start, None
    while i < len(text):
        ch = text[i]
        if quote:
            if ch == "\\" and quote == '"':
                i += 1
            elif ch == quote:
                quote = None
        elif ch in "'\"":
            quote = ch
        elif ch == "\\":
            i += 1
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


def scan(text: str) -> "tuple[list[tuple[str, str]], list[str]]":
    """Split a shell string into (operator_before, segment) pairs plus nested command strings."""
    segs: "list[tuple[str, str]]" = []
    nested: "list[str]" = []
    buf: "list[str]" = []
    op = ""
    quote = None
    i, n = 0, len(text)

    def flush(next_op: str) -> None:
        nonlocal op
        segs.append((op, "".join(buf).strip()))
        buf.clear()
        op = next_op

    while i < n:
        ch = text[i]
        if quote == "'":
            buf.append(ch)
            if ch == "'":
                quote = None
            i += 1
            continue
        if ch == "\\" and i + 1 < n:
            buf.append(text[i : i + 2])
            i += 2
            continue
        if ch == "`":
            j = text.find("`", i + 1)
            if j == -1:
                nested.append(text[i + 1 :])
                i = n
            else:
                nested.append(text[i + 1 : j])
                i = j + 1
            buf.append("$SUB")
            continue
        if text.startswith("$((", i) and quote is None:
            buf.append(ch)
            i += 1
            continue
        if (text.startswith("$(", i) or (quote is None and text[i : i + 2] in ("<(", ">("))) and (
            quote != "'"
        ):
            j = _find_close(text, i + 2)
            inner = text[i + 2 : j] if j != -1 else text[i + 2 :]
            nested.append(inner)
            buf.append("$SUB")
            i = (j + 1) if j != -1 else n
            continue
        if quote == '"':
            buf.append(ch)
            if ch == '"':
                quote = None
            i += 1
            continue
        if ch in "'\"":
            quote = ch
            buf.append(ch)
            i += 1
            continue
        if ch == "#" and (not buf or buf[-1].isspace()):
            while i < n and text[i] != "\n":
                i += 1
            continue
        if ch in ";\n(){}" and not (ch in "{}" and not _word_boundary(text, i)):
            flush(";")
            i += 1
            continue
        if ch == "|":
            if text.startswith("||", i):
                flush("||")
                i += 2
            else:
                flush("|")
                i += 1
            continue
        if ch == "&":
            prev = text[i - 1] if i else ""
            nxt = text[i + 1] if i + 1 < n else ""
            if prev in "<>" or nxt == ">":
                buf.append(ch)
                i += 1
                continue
            if nxt == "&":
                flush("&&")
                i += 2
            else:
                flush("&")
                i += 1
            continue
        buf.append(ch)
        i += 1
    flush("")
    return [(o, s) for o, s in segs if s], nested


def _word_boundary(text: str, i: int) -> bool:
    prev = text[i - 1] if i else " "
    nxt = text[i + 1] if i + 1 < len(text) else " "
    return prev.isspace() and nxt.isspace() or (text[i] == "}" and prev in ";\n ")


def _tokens(segment: str) -> "list[str] | None":
    try:
        return shlex.split(segment, posix=True)
    except ValueError:
        return None


# --------------------------------------------------------------------------- wrappers
_OPT_ARG = {
    "sudo": {"-u", "-g", "-h", "-p", "-r", "-t", "-U", "-D", "-C", "-T", "-R"},
    "doas": {"-u", "-C"},
    "env": {"-u", "-C", "-S"},
    "timeout": {"-k", "-s", "--kill-after", "--signal"},
    "nice": {"-n"},
    "stdbuf": {"-i", "-o", "-e"},
    "xargs": {"-I", "-n", "-P", "-d", "-L", "-s", "-E", "-a"},
    "ionice": {"-c", "-n", "-p"},
    "watch": {"-n", "-d"},
    "flock": {"-w", "-E"},
}
_SIMPLE_WRAPPERS = {"command", "builtin", "exec", "nohup", "time", "setsid", "unbuffer"}


def unwrap(argv: "list[str]") -> "list[str]":
    """Strip env assignments and process wrappers so the real command is argv[0]."""
    argv = list(argv)
    for _ in range(MAX_DEPTH + 4):
        while argv and (argv[0] in _KEYWORDS or _ASSIGN.match(argv[0])):
            argv = argv[1:]
        if not argv:
            return argv
        argv[0] = posixpath.basename(argv[0].lstrip("\\")) or argv[0]
        cmd = argv[0]
        if cmd in _SIMPLE_WRAPPERS:
            if cmd == "command" and len(argv) > 1 and argv[1] in ("-v", "-V"):
                return ["true"]
            argv = argv[1:]
            continue
        if cmd in _OPT_ARG:
            takes = _OPT_ARG[cmd]
            j = 1
            while j < len(argv):
                a = argv[j]
                if a == "--":
                    j += 1
                    break
                if a in takes:
                    j += 2
                elif a.startswith("-") or (cmd == "env" and _ASSIGN.match(a)):
                    j += 1
                elif cmd == "timeout" and re.match(r"^\d", a):
                    j += 1
                    break
                else:
                    break
            if cmd == "timeout" and j < len(argv) and re.match(r"^\d+(\.\d+)?[smhd]?$", argv[j]):
                j += 1
            argv = argv[j:]
            if cmd == "env" and not argv:
                return ["printenv"]  # a bare `env` prints the whole environment
            continue
        return argv
    return argv


# --------------------------------------------------------------------------- command analysis
class Ctx:
    def __init__(self, cwd: str, home: str) -> None:
        self.cwd = cwd
        self.home = home


def _path_args(argv: "list[str]") -> "list[str]":
    out = []
    for a in argv[1:]:
        if a.startswith("-") and "=" in a:
            a = a.split("=", 1)[1]
        elif a.startswith("-"):
            continue
        elif "=" in a and not a.startswith(("/", "~", ".")):
            key, _, val = a.partition("=")
            if key.isidentifier():
                a = val
        if a:
            out.append(a)
    return out


def _dangerous_rm_target(raw: str, ctx: Ctx) -> "tuple[int, str]":
    cands = expand_candidates(raw.rstrip("/") or "/", ctx.cwd, ctx.home)
    for c in cands:
        if is_home_or_ancestor(c, ctx.home):
            return (DENY, "recursive delete of the filesystem root or a home directory")
        parent, base = posixpath.split(c)
        if base in ("*", ".*") and is_home_or_ancestor(parent or "/", ctx.home):
            return (DENY, "recursive delete of everything in a home directory or root")
    if raw in ("*", ".", "..", "./*", "../*", ".*"):
        return (ASK, "recursive delete of the whole working directory or its parent")
    return OK


def _git(argv: "list[str]") -> "tuple[int, str]":
    i = 1
    glob_arg = {"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--exec-path", "--super-prefix"}
    while i < len(argv):
        a = argv[i]
        if a in glob_arg:
            i += 2
        elif a.startswith("-"):
            i += 1
        else:
            break
    if i >= len(argv):
        return OK
    sub, rest = argv[i], argv[i + 1 :]
    if sub == "push":
        refspecs = [a for a in rest if not a.startswith("-")]
        forced = any(
            a in ("-f", "--mirror", "--delete", "-d", "--prune")
            or a.startswith(("--force", "--mirror", "--delete"))
            for a in rest
        ) or any(r.startswith("+") or r.startswith(":") for r in refspecs[1:])
        if forced:
            return (DENY, "force, mirror or delete pushes rewrite shared history")
        return (ASK, "pushing publishes code to a remote")
    if sub == "config":
        joined = " ".join(rest).lower()
        if re.search(r"core\.(sshcommand|hookspath|fsmonitor|pager|editor)|credential\.|alias\.", joined):
            return (ASK, "this git setting can run arbitrary commands later")
    if sub in ("filter-branch", "filter-repo"):
        return (ASK, "history rewrite")
    return OK


_RECURSIVE_READERS = {"grep", "rg", "find", "ag", "ack", "du", "tree"}


def _nested_claude_bypass(args: "list[str]") -> bool:
    for a in args:
        if a in ("--dangerously-skip-permissions", "--settings", "--setting-sources", "--mcp-config"):
            return True
        if a.startswith(("--settings=", "--mcp-config=", "--permission-mode=bypass")):
            return True
    return "bypassPermissions" in args


def _inline_code(argv: "list[str]") -> "tuple[int, str]":
    flags = {
        "python": "-c",
        "node": "-e",
        "deno": "eval",
        "bun": "-e",
        "ruby": "-e",
        "perl": "-e",
        "php": "-r",
    }
    flag = flags.get("python" if argv[0].startswith("python") else argv[0])
    if flag and flag in argv:
        code = " ".join(argv[argv.index(flag) + 1 :])
        if _NET_WORDS.search(code):
            return (ASK, "inline script with network access; the sandbox allowlist applies")
    return OK


def analyse_argv(argv: "list[str]", ctx: Ctx, depth: int) -> "list[tuple[int, str]]":
    out: "list[tuple[int, str]]" = []
    argv = unwrap(argv)
    if not argv:
        return out
    cmd = argv[0]
    args = argv[1:]

    if cmd in _NET_DENY:
        out.append((DENY, "direct network tools are not permitted; use an approved tool or MCP server"))
    elif cmd in _NET_ASK:
        out.append((ASK, "this connects to a remote machine"))
    if cmd in _FS_DESTROY or cmd.startswith("mkfs"):
        out.append((DENY, "disk-level destructive command"))
    if cmd == "dd" and any(a.startswith("of=/dev/") for a in args):
        out.append((DENY, "writing raw data to a device"))
    dumps_env = (cmd == "printenv" and not args) or (
        cmd in ("export", "declare", "set") and (not args or args in (["-p"], ["-x"]))
    )
    if dumps_env:
        out.append((DENY, "dumping the environment exposes secrets to the transcript"))
    elif cmd == "printenv":
        out.append((ASK, "printing an environment variable can expose a secret"))
    if cmd == "claude" and _nested_claude_bypass(args):
        out.append((DENY, "a nested Claude Code session must not bypass the policy"))
    if cmd in ("docker", "podman") and any(
        a in ("--privileged", "--pid=host", "--net=host", "--network=host")
        or a.startswith("-v/")
        or re.match(r"^(-v|--volume)=?/:", a)
        for a in args
    ):
        out.append((DENY, "container flags that give the container the host"))
    if cmd == "git":
        out.append(_git(argv))
    if cmd in ("rm",):
        recursive = any(
            a in ("-r", "-R", "--recursive") or (re.match(r"^-[a-zA-Z]+$", a) and ("r" in a or "R" in a))
            for a in args
        )
        if "--no-preserve-root" in args:
            out.append((DENY, "rm --no-preserve-root"))
        if recursive:
            for t in (a for a in args if not a.startswith("-")):
                out.append(_dangerous_rm_target(t, ctx))
    if cmd in ("chmod", "chown") and any(a in ("-R", "--recursive") for a in args):
        for t in (a for a in args if a.startswith(("/", "~"))):
            if _dangerous_rm_target(t, ctx)[0] == DENY:
                out.append((DENY, "recursive permission change on root or a home directory"))

    # shells and eval: analyse the string they run
    if cmd in _SHELLS:
        for idx, a in enumerate(args):
            if re.match(r"^-[a-zA-Z]*c[a-zA-Z]*$", a) and idx + 1 < len(args):
                out.extend(analyse_string(args[idx + 1], ctx, depth + 1))
                break
    elif cmd == "eval":
        out.extend(analyse_string(" ".join(args), ctx, depth + 1))
    elif cmd in _INTERPRETERS:
        out.append(_inline_code(argv))

    # paths in arguments and redirections
    write_cmd = (
        cmd in _WRITERS
        or (cmd == "sed" and any(a.startswith("-i") or a == "--in-place" for a in args))
        or (cmd == "perl" and any(a.startswith("-i") for a in args))
    )
    read_exempt = cmd in _READ_ONLY_MENTION
    redirects: "list[tuple[str, str]]" = []
    plain: "list[str]" = [argv[0]]
    k = 0
    while k < len(args):
        m = _REDIR.match(args[k])
        if m and m.group(2):
            target = m.group(3)
            if not target and k + 1 < len(args):
                k += 1
                target = args[k]
            redirects.append((m.group(2), target.lstrip("&")))
        else:
            plain.append(args[k])
        k += 1
    for target_op, target in redirects:
        if target and not target.isdigit() and target != "/dev/null":
            d = check_path(target, ctx.cwd, ctx.home, write=target_op.startswith(">"), what="redirect")
            if d[0] != ALLOW:
                out.append(d)
    for raw in _path_args(plain):
        for d in (check_path(raw, ctx.cwd, ctx.home, write=write_cmd, what="argument"),):
            if d[0] == ALLOW:
                continue
            if d[0] == DENY and "credentials" in d[1] and read_exempt:
                continue
            out.append(d)
    if cmd in _RECURSIVE_READERS and any(
        is_home_or_ancestor(c, ctx.home)
        for raw in _path_args(plain)
        for c in expand_candidates(raw, ctx.cwd, ctx.home)
    ):
        out.append((ASK, "searching a home directory or root reaches credential folders"))
    return out


def analyse_string(text: str, ctx: Ctx, depth: int = 0) -> "list[tuple[int, str]]":
    if depth > MAX_DEPTH:
        return [(ASK, "command nesting is too deep to analyse")]
    text, shell_heredoc = _strip_heredocs(text)
    out: "list[tuple[int, str]]" = []
    if shell_heredoc:
        out.append((ASK, "a script passed on stdin to an interpreter is not analysed"))
    segs, nested = scan(text)
    for inner in nested:
        out.extend(analyse_string(inner, ctx, depth + 1))
    for op, seg in segs:
        argv = _tokens(seg)
        if argv is None:
            out.append((ASK, "unbalanced quoting; command cannot be analysed"))
            continue
        if not argv:
            continue
        norm = unwrap(argv)
        if (
            norm
            and norm[0] in _SHELLS
            and op == "|"
            and not any(re.match(r"^-[a-zA-Z]*c", a) for a in norm[1:])
            and not [a for a in norm[1:] if not a.startswith("-")]
        ):
            out.append((ASK, "piping data into a shell runs it unreviewed"))
        out.extend(analyse_argv(argv, ctx, depth))
    return out


def decide_bash(command: str, ctx: Ctx) -> "tuple[int, str]":
    result = _worst(analyse_string(command, ctx))
    if result[0] == ALLOW:
        result = secret_decision(command, ASK)
    return result


# --------------------------------------------------------------------------- dispatch
_READ_TOOLS = {"Read", "NotebookRead"}
_WRITE_TOOLS = {"Edit", "Write", "MultiEdit", "NotebookEdit"}
_SEARCH_TOOLS = {"Glob", "Grep"}
_PATH_KEYS = ("file_path", "notebook_path", "path")


def decide(payload: Any, home: str) -> "tuple[int, str]":
    if not isinstance(payload, dict):
        return (DENY, "hook input was not a JSON object")
    tool = payload.get("tool_name")
    if not isinstance(tool, str) or not tool:
        return (DENY, "hook input had no tool_name")
    tool_input = payload.get("tool_input", {})
    if not isinstance(tool_input, dict):
        return (DENY, "tool_input was not an object")
    cwd = payload.get("cwd")
    cwd = cwd if isinstance(cwd, str) and cwd else os.getcwd()
    ctx = Ctx(cwd, home)

    if tool == "Bash":
        command = tool_input.get("command")
        if not isinstance(command, str):
            return (DENY, "Bash call had no command string")
        return decide_bash(command, ctx)

    if tool in _READ_TOOLS | _WRITE_TOOLS | _SEARCH_TOOLS:
        found = False
        decisions = []
        for key in _PATH_KEYS:
            val = tool_input.get(key)
            if val is None:
                continue
            if not isinstance(val, str):
                return (DENY, "path argument was not a string")
            found = True
            decisions.append(check_path(val, cwd, home, write=tool in _WRITE_TOOLS))
            if tool in _SEARCH_TOOLS and any(
                is_home_or_ancestor(c, home) for c in expand_candidates(val, cwd, home)
            ):
                decisions.append((ASK, "searching a home directory or root reaches credential folders"))
        if not found and tool in _READ_TOOLS | _WRITE_TOOLS:
            return (DENY, tool + " call had no path")
        return _worst(decisions)

    if tool in ("WebFetch", "WebSearch") or tool.startswith("mcp__"):
        try:
            blob = json.dumps(tool_input, ensure_ascii=False)
        except (TypeError, ValueError):
            return (DENY, "tool arguments could not be inspected")
        return secret_decision(blob, DENY)

    return OK


def _emit(decision: "tuple[int, str]", stdout: Any, stderr: Any) -> int:
    level, reason = decision
    if level == DENY:
        stderr.write("ccg-guard: blocked. " + reason + "\n")
        return 2
    if level == ASK:
        stdout.write(
            json.dumps(
                {
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "permissionDecision": "ask",
                        "permissionDecisionReason": "ccg-guard: " + reason,
                    }
                }
            )
            + "\n"
        )
    return 0


def main(stdin: Any = None, stdout: Any = None, stderr: Any = None, home: "str | None" = None) -> int:
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    stderr = stderr or sys.stderr
    try:
        raw = stdin.buffer.read(MAX_INPUT_BYTES + 1) if hasattr(stdin, "buffer") else stdin.read()
        if isinstance(raw, str):
            raw = raw.encode("utf-8", "replace")
        if len(raw) > MAX_INPUT_BYTES:
            return _emit((DENY, "hook input exceeded the size limit"), stdout, stderr)
        if not raw.strip():
            return _emit((DENY, "hook input was empty"), stdout, stderr)
        payload = json.loads(raw.decode("utf-8"))
        return _emit(decide(payload, home or os.path.expanduser("~")), stdout, stderr)
    except Exception as exc:  # noqa: BLE001 - fail closed on anything unexpected
        stderr.write("ccg-guard: blocked (fail-closed). internal error: " + type(exc).__name__ + "\n")
        return 2


if __name__ == "__main__":
    sys.exit(main())
