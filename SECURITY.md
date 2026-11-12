# Security policy

This is a personal open-source project, not an official product of any employer or of Anthropic. It is a
reference policy and set of tools for governing a coding agent. It is **not** a substitute for your own
review, and it documents its own gaps in `docs/CONTROL-MAP.md`.

## Reporting a vulnerability

Please **do not open a public issue**. Use GitHub's private reporting:
**Security tab -> "Report a vulnerability"** on this repository.

In scope:

- A command or tool call the guard hook **allows silently that it documents as blocked** (a bypass of a
  stated control, as opposed to a listed known gap).
- A way to make the hook **allow** something. It is designed never to.
- A policy change the linter accepts although it removes a required control.
- Code execution, file access or network access by the hook, linter or scripts beyond what they document.
- Dependency issues in the development tooling.

A gap that is already listed in `docs/CONTROL-MAP.md` is known and not a vulnerability. A *new* class of
gap is welcome as a normal issue, with the command that demonstrates it.

Responses are best-effort. Reports will be taken seriously and credited if you like.

## Handling secrets

The hook, linter and install scripts do not read, store or transmit credentials, and tests use only
obviously fake values. Do not put real secrets in an issue, a test or a policy file. The linter flags
secret-shaped strings in policy files (M050, R012).
