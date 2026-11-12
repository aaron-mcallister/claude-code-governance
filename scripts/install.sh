#!/usr/bin/env bash
# Install the policy pack on this machine (macOS or Linux). Run with --dry-run first.
#
#   sudo scripts/install.sh --otel-endpoint https://otel.corp.example:4317 \
#                           --mcp-url 'https://mcp.corp.example/*'
#
# The script renders the policy, refuses to install anything the linter objects to (including
# placeholder hosts), installs root-owned files that a developer account cannot edit, and prints
# the checks to run next. A hook that the developer can rewrite is not a control.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
dry=0
os=""
python="/usr/bin/python3"
otel="https://otel-collector.example:4317"
mcp="https://mcp.internal.example/*"

while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) dry=1 ;;
    --os) os="${2:?--os needs a value}"; shift ;;
    --python) python="${2:?--python needs a value}"; shift ;;
    --otel-endpoint) otel="${2:?--otel-endpoint needs a value}"; shift ;;
    --mcp-url) mcp="${2:?--mcp-url needs a value}"; shift ;;
    -h|--help) sed -n '2,10p' "$0"; exit 0 ;;
    *) echo "install: unknown option $1" >&2; exit 2 ;;
  esac
  shift
done

if [ -z "$os" ]; then
  case "$(uname -s)" in
    Darwin) os=macos ;;
    Linux) os=linux ;;
    *) echo "install: unsupported OS $(uname -s)" >&2; exit 2 ;;
  esac
fi
case "$os" in
  macos) dest="/Library/Application Support/ClaudeCode"; group=wheel ;;
  linux) dest="/etc/claude-code"; group=root ;;
  *) echo "install: --os must be macos or linux" >&2; exit 2 ;;
esac

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

"$python" "$here/scripts/render.py" --os "$os" --python "$python" \
  --otel-endpoint "$otel" --mcp-url "$mcp" --out "$tmp/managed-settings.json"
if ! "$python" "$here/tools/ccg_lint.py" managed "$tmp/managed-settings.json" --fail-on-warning; then
  echo "install: refusing to install a policy with findings (replace placeholder values?)" >&2
  exit 1
fi

if [ "$dry" -eq 1 ]; then
  echo "dry run: would install to $dest (owner root:$group)"
  echo "  $dest/managed-settings.json  mode 0644"
  echo "  $dest/hooks/ccg_guard.py      mode 0755"
  exit 0
fi
if [ "$(id -u)" -ne 0 ]; then
  echo "install: run as root (sudo) so the files are not editable by developers" >&2
  exit 1
fi

if [ -f "$dest/managed-settings.json" ] && ! cmp -s "$tmp/managed-settings.json" "$dest/managed-settings.json"; then
  backup="$dest/managed-settings.json.bak.$(date +%Y%m%d%H%M%S)"
  cp -p "$dest/managed-settings.json" "$backup"
  echo "existing policy saved to $backup"
fi

install -d -m 0755 -o root -g "$group" "$dest" "$dest/hooks"
install -m 0755 -o root -g "$group" "$here/policy/hooks/ccg_guard.py" "$dest/hooks/ccg_guard.py"
install -m 0644 -o root -g "$group" "$tmp/managed-settings.json" "$dest/managed-settings.json"

if [ -n "$(find "$dest" -perm -0002 -print -quit)" ] || [ -n "$(find "$dest" -perm -0020 ! -user root -print -quit)" ]; then
  echo "install: $dest is writable by someone other than root; fix before relying on it" >&2
  exit 1
fi

echo "installed. sha256:"
shasum -a 256 "$dest/managed-settings.json" "$dest/hooks/ccg_guard.py" 2>/dev/null \
  || sha256sum "$dest/managed-settings.json" "$dest/hooks/ccg_guard.py"
echo
echo "next: run 'claude doctor' (no invalid settings expected) and '/status' inside Claude Code"
echo "      ('Setting sources' should list Enterprise managed settings). See docs/ROLLOUT.md."
