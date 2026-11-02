"""The composite Action: inputs never pasted into a script, and an empty
database URL is a loud skip, or a failure when the live checks are required."""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

import pytest

ACTION = Path(__file__).parents[1] / "action.yml"


def run_blocks(text: str) -> dict[str, str]:
    """Each step's ``run:`` script, by step name, from the action's YAML."""
    blocks: dict[str, str] = {}
    lines = text.splitlines()
    name = ""
    i = 0
    while i < len(lines):
        line = lines[i]
        if m := re.match(r"\s*- name: (.+)", line):
            name = m.group(1).strip()
        if m := re.match(r"(\s*)run: (.*)", line):
            indent, value = len(m.group(1)), m.group(2)
            if value.strip() == "|":
                body = []
                i += 1
                while i < len(lines) and (
                    not lines[i].strip() or len(lines[i]) - len(lines[i].lstrip()) > indent
                ):
                    body.append(lines[i][indent + 2 :])
                    i += 1
                blocks[name] = "\n".join(body) + "\n"
                continue
            blocks[name] = value + "\n"
        i += 1
    return blocks


def test_no_input_is_pasted_into_a_script() -> None:
    blocks = run_blocks(ACTION.read_text())
    assert set(blocks) == {"Install rls-guard", "Static checks", "Live checks"}
    for name, script in blocks.items():
        assert "${{" not in script, name


@pytest.mark.parametrize(
    ("require", "code", "says"), [("true", 2, "::error::"), ("false", 0, "::notice::")]
)
def test_an_empty_database_url(require: str, code: int, says: str) -> None:
    script = run_blocks(ACTION.read_text())["Live checks"]
    env = {**os.environ, "RLS_GUARD_DSN": "", "RLS_GUARD_CONFIG": "x.toml", "REQUIRE_LIVE": require}
    done = subprocess.run(["bash", "-c", script], env=env, capture_output=True, text=True)
    assert done.returncode == code
    assert says in done.stdout
