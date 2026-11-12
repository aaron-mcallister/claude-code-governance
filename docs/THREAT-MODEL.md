# Threat model

Scope: a coding agent (Claude Code) running on a developer's machine, with shell, file and network access,
working on repositories the developer may not fully trust. The goal is a **baseline an organisation can
deploy to every developer** without making the tool unusable.

This is a model of the agent on a workstation. It is not a model of the model provider, the network, or the
developer's operating system.

## Assets

| Asset | Why it matters |
|---|---|
| Credentials on the machine | SSH keys, cloud credentials, tokens in `.env` files and CLI config. The highest-value target. |
| Source code and unpublished work | Confidentiality and integrity. |
| The policy itself | If the agent or a repository can rewrite it, nothing else holds. |
| The remote repositories | A push is hard to undo and visible to others. |
| The audit trail | You cannot investigate what you did not record. |

## Adversaries

| Class | Description | Typical vector |
|---|---|---|
| **A. Hostile content** | Text the agent reads that was written by someone else: a README, an issue, a web page, a tool result. | Prompt injection telling the agent to run a command or send data out. |
| **B. Hostile repository configuration** | A cloned repo that ships its own `.claude/settings.json`, hooks or `.mcp.json`. | Opening the folder runs the repository's configuration with the developer's privileges. |
| **C. The over-eager agent** | No attacker at all. The agent decides, wrongly, that a destructive or irreversible action is the quickest route. | `git push --force`, `rm -rf`, reading `.env` "to check the config". |
| **D. Extension supply chain** | A malicious or compromised MCP server, or one whose tool descriptions carry instructions. | Tool poisoning, data sent to a server nobody reviewed. |
| **E. Convenience bypass** | A developer, under time pressure, turns the controls off. | Bypass-permissions mode, a local settings override, "just this once". |

Not in scope: an attacker with root on the machine, a compromised Claude Code binary, and the developer
acting maliciously. A baseline cannot stop the last one; it can only make it visible.

## Threats and controls

Strength is as defined in `docs/CONTROL-MAP.md`: **hard**, **soft**, **detective**.

| # | Threat | Adversary | Controls | Strength | Residual risk |
|---|---|---|---|---|---|
| T1 | Agent reads a credential file and sends it out | A, C | Deny rules on secret paths; hook blocks secret reads in shell commands; sandbox `denyRead`; sandbox network allowlist | Hard + soft | Glob and indirection tricks (G3, G1) are caught only by the sandbox, and only for shell commands. |
| T2 | Agent puts a secret in a URL, query or tool argument | A | Hook blocks strong secret patterns in WebFetch, WebSearch and MCP arguments; asks in shell | Soft | Encoded or split secrets are not recognised. |
| T3 | Agent makes arbitrary network requests | A, C | Hook denies `curl`, `wget`, `nc` and similar; sandbox domain allowlist | Soft + hard | Programs that happen to speak HTTP (G4, G5). The allowlist covers them for shell commands. |
| T4 | Repository config runs code or widens permissions on open | B | `allowManagedHooksOnly`; managed MCP allowlist; repo-mode linter in CI and pre-commit | Hard + detective | A repository you do not control cannot be made to run the linter. |
| T5 | Agent edits the policy, hooks or MCP config to remove a control | A, B, C | Deny rules on those files; hook denies writes to them; files are root-owned at the managed path | Hard + soft | None while the files stay root-owned and managed-only is on. |
| T6 | Irreversible or shared-state action (force push, `rm -rf`, device writes) | C | Hook denies the destructive forms and asks on ordinary `git push`; ask rule | Soft | Destructive commands the hook does not enumerate. Prefer a protected branch on the server as the real control. |
| T7 | Malicious or poisoned MCP server | D | Managed allowlist of server URLs, managed-only | Hard (which server) | What an approved server says or does. Out of scope here. |
| T8 | Controls silently disabled | E | Bypass mode disabled; managed precedence; `claude doctor` and linter gates; `managed_settings_resolved` telemetry | Hard + detective | A machine that never received the policy. Detect by absence of telemetry. |
| T9 | The guard itself breaks and nobody notices | (operational) | `onFailure: "block"`; fail-closed hook; doctor check in CI | Hard + detective | The guard blocks legitimate work when it fails. This is deliberate. |
| T10 | Output-only attacks (rendered links, misleading summaries) | A | None in this repository | None | Open. Measured in the companion evals project. |

## Design principles

1. **A policy that cannot be tested is a wish.** Every control has a test that breaks it and checks the
   linter or the hook notices. The known gaps are tested too, so the documentation cannot drift from the code.
2. **Tighten only.** The hook can ask or deny and never approves. A bug can cost convenience, never safety.
3. **Fail closed.** Malformed input, oversized input, an exception, an unparseable command and a hook
   timeout all end in a block or a prompt.
4. **Layer by what each layer can see.** A hook sees text. A sandbox sees system calls. Put each control
   where it can actually decide. The text check is a fast, readable first line; the sandbox is the one that
   holds when the text lies.
5. **Say what is not covered.** A short, honest gap list is more useful to a security reviewer than a long
   claim of coverage.
6. **No secrets, no network, no filesystem in the guard.** The hook is standard library only and an AST test
   proves it imports nothing that does I/O, so reviewing it is reading one file.
7. **Make the secure path the easy one.** One install script, one template, one linter. Controls that need a
   wiki page to deploy do not get deployed.
