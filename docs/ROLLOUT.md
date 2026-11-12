# Rollout

How to take the baseline from this repository to a fleet without breaking everyone's day.

## 1. Decide the three values

The template has four placeholders. Three of them are yours to decide:

| Placeholder | Decide |
|---|---|
| `{{OTEL_ENDPOINT}}` | Where telemetry goes. Needs a collector you operate. |
| `{{MCP_ALLOWED_URL}}` | The MCP server URL pattern you approve, or the list you will extend. |
| `network.allowedDomains` | Edit in the template. The default (npm, PyPI, GitHub) is a starting point, not a recommendation. |

`{{PYTHON}}` is an absolute path to a Python 3.9+ interpreter on the target machines. `/usr/bin/python3`
works on stock macOS and most Linux images; use your managed interpreter if you have one.

## 2. Pilot

Roll out to a small group who will tell you what broke. Expect these:

- Shell commands that need a domain you did not allow. Add it, with a review.
- `sandbox.failIfUnavailable` stopping work on a machine where the sandbox cannot start.
- Teams that relied on project hooks, now blocked by `allowManagedHooksOnly`.
- The hook asking about something ordinary. Open an issue with the exact command; most are one-line fixes
  and each fix gets a test.

Keep the pilot to two weeks and read the telemetry before widening it.

## 3. Install

```sh
sudo scripts/install.sh --os macos \
  --python /usr/bin/python3 \
  --otel-endpoint https://otel.example.internal:4317 \
  --mcp-url 'https://mcp.example.internal/*'
```

Use `--dry-run` first. The script renders the policy, **refuses to install it if the linter reports any
error or warning**, backs up an existing policy, installs root-owned files, verifies nothing is writable by
a non-root user, and prints the SHA-256 of what it wrote.

For a fleet, do not run the script by hand. Render once in CI, then deliver the same two artefacts (the
rendered `managed-settings.json` and `hooks/ccg_guard.py`) with your MDM. Claude Code also supports
server-managed settings; at the time of writing they do not support per-group policy, so check whether that
fits before choosing it.

## 4. Verify on a machine

1. In Claude Code, run `/status` and confirm the managed settings are listed as a source.
2. Run `claude doctor`. It should report no invalid settings. This is not optional: a malformed `hooks`
   block is ignored at runtime without any visible error.
3. Ask the agent to read `.env` and to run `curl https://example.com`. Both should be refused.
4. Confirm telemetry arrives, including a `managed_settings_resolved` event (needs 2.1.274 or later).

## 5. Change control

The policy is code. Changes go through a pull request, and `.github/CODEOWNERS` requires a security owner
for `policy/`, `tools/`, `scripts/` and `.github/`. Protect `main` with a ruleset that requires the `check`
jobs and code-owner review. CI re-renders the policy for both operating systems and lints it with warnings
as errors, so a change that weakens a required control fails before it merges.

## 6. Drift detection

A policy you installed is not a policy that is in force.

- Alert on machines that stop emitting `managed_settings_resolved`, and on events whose resolved settings
  differ from the hash of the policy you released.
- Re-run `scripts/install.sh --dry-run` output through your MDM compliance check, comparing the SHA-256.
- Treat a machine with no telemetry at all as unmanaged.

## 7. Rollback

Keep the previous rendered policy. The install script writes a timestamped backup next to the managed file;
restoring it is a file copy. If the hook itself is the problem, a policy without the `hooks` block is a
smaller blast radius than no policy: the deny rules and sandbox keep working. Do not roll back by deleting
the managed file, which removes every control at once.

## 8. What to tell developers

- The agent will sometimes ask or refuse. That is the policy working; the message says why.
- Network access from shell commands is limited to a short list. To add a domain, open a pull request.
- Bypass-permissions mode is disabled on purpose.
- If something legitimate is blocked, send the exact command. Do not work around the hook; ask for the fix.

## Telemetry and privacy

The template exports tool-call metadata and the resolved policy. It does **not** turn on the flags that
export prompt text, raw API bodies or tool content, because those capture source code and anything pasted
into a session. The linter warns (M033) if you enable them. Decide that with your privacy and legal teams,
not in a config file.
