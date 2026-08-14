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
        self.polls = 0

    def list_secrets(self):
        return self.secrets

    def write_secret(self, name, value, description=""):
        self.writes.append((name, value, description))
        return {"action": "created", "name": name}

    def delete_secret(self, name):
        return {"deleted": name}

    def request_read(self, name, reason, scope="one_shot", caller=""):
        self.requests.append({"name": name, "reason": reason, "scope": scope,
                              "caller": caller})
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
                "reason": "porque sim", "scope": "one_shot"}


def _tools(backend, **kw):
    return SecretTools(backend, **kw)


# ── list ─────────────────────────────────────────────────────────────────

def test_list_never_returns_a_value_even_if_the_backend_sends_one():
    """Listing is not a read. A backend that over-shares must not turn an
    ungated call into a way around the approval gate."""
    out = _tools(_FakeBackend()).list_secrets()

    assert out["count"] == 1
    assert out["secrets"] == [{"name": "resend_api_key", "description": "Resend"}]
    assert "LEAKED" not in str(out)


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
    out = _tools(b).read_secret("k", "porque sim", max_wait_s=0)

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
    out = _tools(b).read_secret("k", "porque sim", max_wait_s=30)

    assert out["value"] == "s3cr3t"
    assert b.requests[0]["reason"] == "porque sim"


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
    assert out["reason"] == "porque sim"


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
