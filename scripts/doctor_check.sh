#!/usr/bin/env bash
# Validate the rendered policy with the real `claude doctor`.
#
# Why this exists: Claude Code silently ignores a malformed `hooks` block in managed settings, so a
# typo would switch the guard off with no error at runtime. `claude doctor` reports it. This script
# makes that check repeatable (CI or a throwaway machine).
#
# It WRITES TO THE SYSTEM MANAGED-SETTINGS DIRECTORY, so it refuses to run unless you opt in with
# CCG_ALLOW_SYSTEM_WRITE=1, and it refuses if a managed policy already exists. Use a CI runner,
# container or VM, never a developer machine that has a real policy.
#
#   CCG_ALLOW_SYSTEM_WRITE=1 CCG_CLAUDE=/path/to/claude scripts/doctor_check.sh
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
claude="${CCG_CLAUDE:-claude}"
python="${CCG_PYTHON:-$(command -v python3)}"

if [ "${CCG_ALLOW_SYSTEM_WRITE:-}" != "1" ]; then
  echo "doctor_check: refusing. This writes to the system managed-settings directory." >&2
  echo "Set CCG_ALLOW_SYSTEM_WRITE=1 on a throwaway runner or container to proceed." >&2
  exit 2
fi
case "$(uname -s)" in
  Linux) dest="/etc/claude-code"; os=linux ;;
  Darwin) dest="/Library/Application Support/ClaudeCode"; os=macos ;;
  *) echo "doctor_check: unsupported OS" >&2; exit 2 ;;
esac
if [ -e "$dest/managed-settings.json" ]; then
  echo "doctor_check: $dest/managed-settings.json already exists; not overwriting" >&2
  exit 2
fi
if ! command -v "$claude" >/dev/null 2>&1 && [ ! -x "$claude" ]; then
  echo "doctor_check: claude not found (set CCG_CLAUDE)" >&2
  exit 2
fi

tmp="$(mktemp -d)"
cleanup() { rm -rf "$tmp" "$dest/managed-settings.json" "$dest/hooks/ccg_guard.py"; rmdir "$dest/hooks" "$dest" 2>/dev/null || true; }
trap cleanup EXIT

mkdir -p "$dest/hooks"
"$python" "$here/scripts/render.py" --os "$os" --python "$python" \
  --otel-endpoint https://otel.corp.internal:4317 --mcp-url 'https://mcp.corp.internal/*' \
  --out "$dest/managed-settings.json"
cp "$here/policy/hooks/ccg_guard.py" "$dest/hooks/ccg_guard.py"

# A clean environment: no credentials, no inherited Claude Code settings.
out="$(env -i HOME="$tmp" PATH="$PATH" DISABLE_AUTOUPDATER=1 "$claude" doctor 2>&1 || true)"
echo "$out"
if echo "$out" | grep -qE "Invalid settings|may not work as written"; then
  echo "doctor_check: FAILED - claude doctor reported problems with the policy" >&2
  exit 1
fi
if ! echo "$out" | grep -q "Claude Code doctor"; then
  echo "doctor_check: FAILED - unexpected doctor output" >&2
  exit 1
fi
echo "doctor_check: ok - claude doctor reported no invalid settings"
