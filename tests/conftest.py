"""Every test gets its own workspace home.

``secrets_app.pending`` keeps real state under
``$AW_WORKSPACE_HOME/data/secrets`` — outstanding approval ids — on storage
shared with every container in the workspace. Without this fixture the suite
reads and writes *that*: the same pattern in aw-app-ssh truncated the live
``pending.json`` on a developer's machine, and two tests then failed because
they were reading state left behind by a third.

Autouse, so it cannot be forgotten by the next module. A test that genuinely
wants the real paths has to say so by overriding the env var itself, which is
the right way round.
"""
from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def isolated_workspace_home(tmp_path, monkeypatch):
    monkeypatch.setenv("AW_WORKSPACE_HOME", str(tmp_path / "aw-workspace-home"))
    return tmp_path / "aw-workspace-home"
