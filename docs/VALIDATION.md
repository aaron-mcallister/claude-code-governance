# Validation record

What was checked, when, on what, and what was **not** checked. Dated so it can go stale honestly.

**Date:** 2026-11-11
**Claude Code:** 2.1.322 (installed from npm into a scratch directory)
**Platform:** Linux x64, in a cloud container
**Python:** 3.13 (primary), 3.9.25 (the oldest supported, for stock macOS)

## 1. Unit and contract tests

- `pytest` passes on 3.13, and on 3.9.25 in a separate virtualenv.
- CI runs the suite on 3.11 and 3.13.
- Coverage includes: the hook on tables of benign and hostile commands, tool-specific cases, a symlink
  case, case-insensitivity, malformed and oversized input, an internal exception, a fuzz over hostile
  command shapes, an AST check that the hook does no I/O, a mutation test per linter rule, and a property
  test that every linter rule has a mutation test.

## 2. The real CLI against the rendered policy

`scripts/doctor_check.sh` renders the policy into the managed location, runs `claude doctor` in a clean
environment (`env -i`), and fails on any invalid-settings message.

| Case | Result |
|---|---|
| The shipped policy | "No installation issues found"; no invalid settings. |
| Negative control: `onFailure` set to an invalid value | Reported: "Invalid command hook (onFailure: ... expected one of "continue"\|"block")", and "hooks: Failed schema validation. This field was ignored." Script exits non-zero. |
| Negative control: wrong type for `sandbox.enabled` | Reported as an invalid type. |
| Negative control: `Bash(command:rm *)` in `deny` | Reported: the rule "targets command as a raw string and will not match". |

The second row is why the gate exists. A schema error in `hooks` does not stop Claude Code; it removes the
guard.

Two observations from the same run:

- On Linux, `**/`-prefixed Read and Edit rules produce a sandbox glob warning. The template avoids them.
- Running inside a cloud session adds notices that the managed file "may only restrict". These come from the
  session's own environment variables and do not apply to a normal developer machine.

## 3. Not validated

Read this list before you rely on the policy.

- **End-to-end hook execution inside a live Claude Code session.** That needs an authenticated session, and
  none was used. The hook is tested against the documented stdin and exit-code contract, not against the
  product. The first thing to do on your own machine is step 4 of `docs/ROLLOUT.md`.
- **macOS and Windows.** The macOS paths come from the documentation. They were not exercised on a Mac.
  Windows is not supported by the install script.
- **The sandbox itself.** The settings are validated. What the sandbox then does at runtime was not tested
  here, and the known gaps lean on it. Test it on your platform, including with `failIfUnavailable` on.
- **MDM and server-managed delivery.** Only the file-based path was exercised.
- **Newer Claude Code versions.** Re-run `scripts/doctor_check.sh` when you upgrade. The CI `doctor` job pins
  the version that was validated.
- **Performance at scale.** The hook runs for every tool call with a 10 second timeout; typical runs are
  milliseconds, but this was not measured on a loaded laptop.
