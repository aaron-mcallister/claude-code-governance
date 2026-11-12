#!/usr/bin/env python3
"""Render policy/managed-settings.template.json for one operating system.

Usage: render.py --os macos|linux [--python PATH] [--otel-endpoint URL] [--mcp-url URL] [--out FILE]

The template has four placeholders. Rendering refuses to emit a file with any left unresolved.
Defaults point at `.example` hosts (RFC 2606), which the linter reports as placeholders, so a policy
rendered without real values cannot be mistaken for a deployable one.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
TEMPLATE = ROOT / "policy" / "managed-settings.template.json"

HOOK_DIRS = {
    "macos": "/Library/Application Support/ClaudeCode/hooks",
    "linux": "/etc/claude-code/hooks",
}


def render(os_name: str, python: str, otel_endpoint: str, mcp_url: str) -> str:
    if os_name not in HOOK_DIRS:
        raise ValueError("os must be one of: " + ", ".join(sorted(HOOK_DIRS)))
    text = TEMPLATE.read_text(encoding="utf-8")
    values = {
        "{{HOOK_DIR}}": HOOK_DIRS[os_name],
        "{{PYTHON}}": python,
        "{{OTEL_ENDPOINT}}": otel_endpoint,
        "{{MCP_ALLOWED_URL}}": mcp_url,
    }
    for key, val in values.items():
        text = text.replace(key, val)
    if "{{" in text:
        raise ValueError("unresolved placeholder left in template")
    json.loads(text)  # must still be valid JSON after substitution
    return text


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--os", required=True, choices=sorted(HOOK_DIRS))
    ap.add_argument("--python", default="/usr/bin/python3")
    ap.add_argument("--otel-endpoint", default="https://otel-collector.example:4317")
    ap.add_argument("--mcp-url", default="https://mcp.internal.example/*")
    ap.add_argument("--out")
    args = ap.parse_args(argv)
    try:
        out = render(args.os, args.python, args.otel_endpoint, args.mcp_url)
    except ValueError as exc:
        print("render: " + str(exc), file=sys.stderr)
        return 2
    if args.out:
        pathlib.Path(args.out).write_text(out, encoding="utf-8")
    else:
        sys.stdout.write(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
