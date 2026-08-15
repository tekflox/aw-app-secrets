"""The three tools, with the approval loop faked out.

What these pin, and why each one:

* a read is gated and a write is not — the asymmetry is the whole design, and
  it is the kind of thing a later "consistency" refactor quietly breaks;
* every unhappy ending is distinguishable (denied / expired / timed out /
  already delivered), because "it didn't work" is the failure mode that has
  cost the most time in this system;
* list never returns a value, no matter what the backend hands back.
"""
from __future__ import annotations

import pytest

from secrets_app.backend_client import ApprovalDenied, BackendUnavailable
from secrets_app.tools import SecretTools


class _FakeBackend:
    """Scripted approval: `sequence` is polled in order, then repeats the last."""

    def __init__(self, sequence=None, secrets=None):
        self.sequence = list(sequence or [("approved", "s3cr3t")])
        self.secrets = secrets if secrets is not None else [
            {"name": "resend_api_key", "description": "Resend", "value": "LEAKED"},
        ]
        self.requests = []
        self.writes = []
        self.policies = []
        self.polls = 0

    def list_secrets(self):
        return self.secrets

    def set_policy(self, name, auto_approve, updated_by="", note="",
                   auto_approve_for=None):
        self.policies.append((name, auto_approve, updated_by, auto_approve_for))
        return {"secret_name": name, "auto_approve": auto_approve,
                "updated_by": updated_by, "note": note,
                "auto_approve_for": auto_approve_for or ""}

    def write_secret(self, name, value, description=""):
        self.writes.append((name, value, description))
        return {"action": "created", "name": name}

    def delete_secret(self, name):
        return {"deleted": name}

    def request_read(self, name, reason, scope="one_shot", caller="",
                     caller_key=None, caller_agent=None):
        self.requests.append({"name": name, "reason": reason, "scope": scope,
                              "caller": caller, "caller_key": caller_key,
                              "caller_agent": caller_agent})
        return "req-1"

    def poll_read(self, request_id):
        self.polls += 1
        idx = min(self.polls - 1, len(self.sequence) - 1)
        return self.sequence[idx]

    def describe(self, request_id):
        if request_id != "req-1":
            return {"status": "not_found"}
        status, value = self.poll_read(request_id)
        return {"status": status, "value": value, "secret_name": "k",
                "reason": "deploy the staging release", "scope": "one_shot"}


def _tools(backend, **kw):
    return SecretTools(backend, **kw)


# ── list ─────────────────────────────────────────────────────────────────

def test_list_never_returns_a_value_even_if_the_backend_sends_one():
    """Listing is not a read. A backend that over-shares must not turn an
    ungated call into a way around the approval gate."""
    out = _tools(_FakeBackend()).list_secrets()

    assert out["count"] == 1
    assert out["secrets"] == [{"name": "resend_api_key", "description": "Resend",
                               "auto_approve": False, "auto_approve_for": ""}]
    assert "LEAKED" not in str(out)


def test_list_says_which_secrets_no_longer_ask_a_human():
    """A list that hid this would describe the vault as uniformly gated while
    part of it is open — the one fact a reader most needs from the inventory."""
    b = _FakeBackend(secrets=[
        {"name": "gated", "description": ""},
        {"name": "open", "description": "", "auto_approve": True},
    ])
    by_name = {s["name"]: s for s in _tools(b).list_secrets()["secrets"]}

    assert by_name["gated"]["auto_approve"] is False
    assert by_name["open"]["auto_approve"] is True


# ── policy ───────────────────────────────────────────────────────────────

def test_setting_the_policy_reaches_the_backend_not_local_state():
    """The gate is enforced in aw-backend. A flag kept here would be this app
    asking itself for permission while every other caller stayed gated."""
    b = _FakeBackend()
    out = _tools(b).set_policy("resend_api_key", True, updated_by="settings-panel")

    assert out["ok"] is True
    assert b.policies == [("resend_api_key", True, "settings-panel", None)]


def test_setting_the_policy_requires_a_name():
    with pytest.raises(ValueError, match="name is required"):
        _tools(_FakeBackend()).set_policy("  ", True)


def test_policy_is_not_an_mcp_tool():
    """An agent that can switch the gate off can then read the secret unasked,
    which makes the gate a formality. Setting it stays a human action."""
    from secrets_app.mcp import http_handler

    exposed = {t["name"] for t in http_handler.TOOLS_SCHEMA}
    assert "set_policy" not in exposed
    assert "read_secret" in exposed


# ── write ────────────────────────────────────────────────────────────────

def test_write_does_not_ask_for_approval():
    """Deliberate: the caller already holds the value, so a prompt confirms
    nothing. The gate exists to stop a value LEAVING the vault."""
    b = _FakeBackend()
    out = _tools(b).write_secret("k", "v", "desc")

    assert out["ok"] is True
    assert b.writes == [("k", "v", "desc")]
    assert b.requests == [], "write must not create an approval request"


def test_write_refuses_an_empty_value():
    """Otherwise a typo silently blanks a live secret, and the next read
    succeeds with the wrong answer instead of failing."""
    with pytest.raises(ValueError, match="delete_secret"):
        _tools(_FakeBackend()).write_secret("k", "")


def test_write_refuses_a_blank_name():
    with pytest.raises(ValueError, match="name is required"):
        _tools(_FakeBackend()).write_secret("   ", "v")


# ── read: the gated path ─────────────────────────────────────────────────

def test_read_does_not_block_by_default():
    """The default is fire-and-collect. An agent of this platform runs in a
    per-turn container, and the MCP gateway cuts a long call anyway — both
    measured, not assumed."""
    b = _FakeBackend([("pending", None)])
    out = _tools(b).read_secret("k", "deploy the staging release", max_wait_s=0)

    assert out["status"] == "pending"
    assert out["request_id"] == "req-1"
    assert b.polls <= 1, "max_wait_s=0 must not sit in the poll loop"


def test_a_pending_answer_says_what_was_asked():
    """The collector is usually a different process with no memory of the ask."""
    out = _tools(_FakeBackend([("pending", None)])).read_secret(
        "resend_api_key", "deploy staging", max_wait_s=0)

    assert out["name"] == "resend_api_key"
    assert out["reason"] == "deploy staging"
    assert "collect_secret" in out["note"]


def test_read_returns_the_value_when_it_can_wait():
    b = _FakeBackend([("pending", None), ("pending", None), ("approved", "s3cr3t")])
    out = _tools(b).read_secret("k", "deploy the staging release", max_wait_s=30)

    assert out["value"] == "s3cr3t"
    assert b.requests[0]["reason"] == "deploy the staging release"


def test_a_wait_that_runs_out_is_not_an_error():
    """The prompt is still live and still collectable — raising here would
    make an agent give up on something the human is about to approve."""
    b = _FakeBackend([("pending", None)])
    out = _tools(b).read_secret("k", "r", max_wait_s=0)

    assert out["status"] == "pending"
    assert out["ok"] is True


def test_collect_returns_the_value_and_the_context():
    b = _FakeBackend([("approved", "s3cr3t")])
    out = _tools(b).collect_secret("req-1")

    assert out["value"] == "s3cr3t"
    assert out["name"] == "k"
    assert out["reason"] == "deploy the staging release"


def test_collect_on_an_unknown_id_is_reported_as_such():
    with pytest.raises(ApprovalDenied, match="unknown or has expired"):
        _tools(_FakeBackend()).collect_secret("never-existed")


def test_collect_requires_an_id():
    with pytest.raises(ValueError, match="request_id is required"):
        _tools(_FakeBackend()).collect_secret("")


def test_read_requires_a_reason():
    """The reason is the only thing the human sees besides the name. Defaulting
    it would put "agent request" in front of every approval decision."""
    with pytest.raises(ValueError, match="reason is required"):
        _tools(_FakeBackend()).read_secret("k", "")


def test_a_denial_is_reported_as_a_denial():
    b = _FakeBackend([("denied", None)])
    with pytest.raises(ApprovalDenied, match="denied by the human"):
        _tools(b).read_secret("k", "r", max_wait_s=30)


def test_an_expiry_is_distinguishable_from_a_denial():
    b = _FakeBackend([("expired", None)])
    with pytest.raises(ApprovalDenied, match="expired with no answer"):
        _tools(b).read_secret("k", "r", max_wait_s=30)


def test_approved_with_no_value_is_not_an_empty_secret():
    """One-shot delivery already handed the value to someone. Returning "" here
    would look like a secret whose value is the empty string."""
    b = _FakeBackend([("approved", None)])
    with pytest.raises(ApprovalDenied, match="already delivered"):
        _tools(b).read_secret("k", "r", max_wait_s=30)


# ── scope ────────────────────────────────────────────────────────────────

def test_an_unknown_scope_falls_back_to_the_configured_default():
    """A typo must not silently widen the grant — 'sixty_minutes' becoming a
    60-minute window would be the wrong way to fail."""
    b = _FakeBackend()
    _tools(b, default_scope="one_shot").read_secret("k", "r", scope="sixty_minutes", max_wait_s=30)

    assert b.requests[0]["scope"] == "one_shot"


def test_an_explicit_scope_is_passed_through():
    b = _FakeBackend()
    _tools(b).read_secret("k", "r", scope="10min", max_wait_s=30)

    assert b.requests[0]["scope"] == "10min"


# ── no cloud link ────────────────────────────────────────────────────────

def test_no_backend_link_is_its_own_error():
    """A BYOD workspace that never linked has no store at all — that is not the
    same as a secret being missing, and the message must not suggest it is."""
    from secrets_app.backend_client import SecretsBackend

    b = SecretsBackend(backend_url="", workspace="aw", token="")
    with pytest.raises(BackendUnavailable, match="no cloud link"):
        SecretTools(b).list_secrets()


def test_omitting_max_wait_means_do_not_wait(monkeypatch):
    """`poll_timeout_s` is the CEILING for an explicit wait, not the default.
    Reading it as the default made the very first real call block for 30s
    against a docstring that promised the opposite."""
    b = _FakeBackend([("pending", None)])
    out = _tools(b, poll_timeout_s=300).read_secret("k", "r")

    assert out["status"] == "pending"
    assert b.polls <= 1


def test_an_explicit_wait_is_capped_at_the_configured_timeout():
    """A caller asking for an hour must not outlive the server-side expiry —
    it would sit polling a request that died at 300s."""
    import time as _t

    b = _FakeBackend([("pending", None)])
    started = _t.monotonic()
    out = SecretTools(b, poll_timeout_s=1).read_secret("k", "r", max_wait_s=3600)

    assert out["status"] == "pending"
    assert _t.monotonic() - started < 8, "waited past the configured ceiling"


# ── who a window grant belongs to ────────────────────────────────────────

def test_a_read_names_the_caller_a_window_would_belong_to(monkeypatch):
    """`--aw-scope 10min` was silently useless because nothing ever told
    aw-backend who was asking. Every read now carries that identity."""
    monkeypatch.setenv("AW_SESSION_ID", "sess-42")
    b = _FakeBackend()
    _tools(b).read_secret("k", "deploy the staging release", max_wait_s=30)

    assert b.requests[0]["caller_key"] == "session:sess-42"


def test_an_explicit_session_beats_the_environment(monkeypatch):
    """The MCP path: the agent runs in one container and this code in another,
    so the session arrives on the request rather than in the env — and must
    win over whatever env this process happens to have."""
    monkeypatch.setenv("AW_SESSION_ID", "the-wrong-one")
    b = _FakeBackend()
    _tools(b).read_secret("k", "r", max_wait_s=30, session="sess-from-header")

    assert b.requests[0]["caller_key"] == "session:sess-from-header"


def test_a_terminal_is_identified_by_its_shell_not_by_this_process(monkeypatch):
    """Keying on our own pid would make every invocation a different caller —
    the exact failure the old pid matching had."""
    from secrets_app import caller

    monkeypatch.delenv("AW_SESSION_ID", raising=False)
    monkeypatch.delenv("CLAUDE_CODE_SESSION_ID", raising=False)
    key = caller.caller_key(allow_local=True)

    assert key.startswith("proc:")
    assert str(__import__("os").getppid()) in key


def test_an_unidentifiable_caller_gets_no_key(monkeypatch):
    """No key means no window, and every read asks again. Being unidentified
    must never mean sharing whichever window happens to be open."""
    from secrets_app import caller

    monkeypatch.delenv("AW_SESSION_ID", raising=False)
    monkeypatch.delenv("CLAUDE_CODE_SESSION_ID", raising=False)
    monkeypatch.setattr(caller.os, "getppid", lambda: 1)

    assert caller.caller_key(allow_local=True) is None


def test_the_shell_key_survives_a_recycled_pid(monkeypatch):
    """Without the start time, a new shell inheriting a dead one's pid would
    inherit its grants too."""
    from secrets_app import caller

    monkeypatch.delenv("AW_SESSION_ID", raising=False)
    monkeypatch.delenv("CLAUDE_CODE_SESSION_ID", raising=False)
    monkeypatch.setattr(caller, "_proc_start_time", lambda pid: "999")
    first = caller.caller_key(allow_local=True)
    monkeypatch.setattr(caller, "_proc_start_time", lambda pid: "1000")

    assert first != caller.caller_key(allow_local=True)


def test_the_session_is_not_a_tool_argument():
    """An agent that could name its own session could name somebody else's and
    inherit a grant it never earned. It arrives as a header instead."""
    from secrets_app.mcp import http_handler

    read = next(t for t in http_handler.TOOLS_SCHEMA if t["name"] == "read_secret")
    assert "session" not in read["inputSchema"]["properties"]
    assert "caller_key" not in read["inputSchema"]["properties"]


def test_an_unexpanded_placeholder_is_not_an_identity(monkeypatch):
    """AP writes the session header as ${AW_SESSION_ID} so a frozen warm config
    still resolves per turn. A client that does not expand it would send that
    literal string — identical for every agent, and therefore one shared key
    out of the thing meant to keep them apart."""
    from secrets_app import caller

    monkeypatch.delenv("AW_SESSION_ID", raising=False)
    monkeypatch.delenv("CLAUDE_CODE_SESSION_ID", raising=False)
    key = caller.caller_key("${AW_SESSION_ID}")

    assert key is None
    assert "$" not in (key or "")


def test_the_app_never_mints_a_local_key_for_a_remote_caller(monkeypatch):
    """Inside the app's server process, "the parent shell" is the server's own
    supervisor — the same for every REST caller in the workspace. Falling back
    to it would mint one shared key and hand every caller a window the first of
    them earned."""
    from secrets_app import caller

    monkeypatch.delenv("AW_SESSION_ID", raising=False)
    monkeypatch.delenv("CLAUDE_CODE_SESSION_ID", raising=False)

    assert caller.caller_key() is None
    assert caller.caller_key(allow_local=True).startswith("proc:")


def test_a_caller_supplied_key_wins_over_anything_derived(monkeypatch):
    """A CLI in another container is the only party that can see its own shell."""
    monkeypatch.setenv("AW_SESSION_ID", "sess-here")
    b = _FakeBackend()
    _tools(b).read_secret("k", "r", max_wait_s=30, caller_key="proc:other-host:42:99")

    assert b.requests[0]["caller_key"] == "proc:other-host:42:99"


# ── the stable identity an allowlist can name ────────────────────────────

def test_a_read_carries_the_agent_identity(monkeypatch):
    """A session key changes every run and could never be written into an
    allowlist. The agent id is the same next week."""
    monkeypatch.setenv("AW_AGENT_SLUG", "nightly-backup")
    b = _FakeBackend()
    _tools(b).read_secret("k", "r", max_wait_s=30)

    assert b.requests[0]["caller_agent"] == "agent:nightly-backup"


def test_the_agent_identity_has_one_shape(monkeypatch):
    """Whether it arrived already prefixed or bare, what reaches the allowlist
    is identical — so what a human types is what both paths produce."""
    from secrets_app import caller

    monkeypatch.setenv("AW_AGENT_SLUG", "nightly-backup")
    assert caller.agent_identity() == "agent:nightly-backup"
    assert caller.agent_identity("agent:other") == "agent:other"
    assert caller.agent_identity("other") == "agent:other"


def test_an_unexpanded_agent_placeholder_is_no_identity(monkeypatch):
    monkeypatch.delenv("AW_AGENT_SLUG", raising=False)
    from secrets_app import caller

    assert caller.agent_identity("${AW_AGENT_SLUG}") is None


def test_the_agent_is_not_a_tool_argument_either():
    """Same reason as the session: an agent that could name itself could name
    the one on somebody's allowlist."""
    from secrets_app.mcp import http_handler

    read = next(t for t in http_handler.TOOLS_SCHEMA if t["name"] == "read_secret")
    assert "agent" not in read["inputSchema"]["properties"]


def test_the_listing_carries_the_allowlist_to_the_panel():
    """The panel renders one row per secret; a row that showed only the blunt
    flag would call a secret gated while a named caller walks past it."""
    b = _FakeBackend(secrets=[{"name": "k", "description": "",
                               "auto_approve_for": "agent:nightly-backup"}])

    assert _tools(b).list_secrets()["secrets"][0]["auto_approve_for"] \
        == "agent:nightly-backup"


def test_editing_who_does_not_have_to_restate_whether():
    """The panel has two controls on the same row. Saving the allowlist must
    not flip the gate, and flipping the gate must not wipe the allowlist —
    absent means leave it alone."""
    b = _FakeBackend()
    _tools(b).set_policy("k", False, auto_approve_for="agent:x")
    _tools(b).set_policy("k", True)

    assert b.policies[0][3] == "agent:x"
    assert b.policies[1][3] is None
