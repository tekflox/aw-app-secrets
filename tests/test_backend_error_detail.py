"""The real reason a downstream call failed must reach the user.

bug:ssh-approval-request-400-error-swallowed: `request_read` used to call
`raise_for_status()` and let httpx's own generic "Client error '400 Bad
Request' for url '...'" become the entire diagnosis. aw-backend's `detail`
(the actual reason — e.g. "could not deliver the approval prompt via the
Agents Platform (500): ...") was thrown away in two places: the backend
client discarded the response body before raising, and `_fail()`'s catch-all
branch discarded the exception's own message in favor of `502: <type>: <str>`.
Fixed at both points; these tests pin each independently and the pair
together end to end.
"""
from __future__ import annotations

import httpx
import pytest
from fastapi.testclient import TestClient

from secrets_app.backend_client import BackendRequestFailed, SecretsBackend
from secrets_app.routes import build_app
from secrets_app.tools import SecretTools

REAL_DETAIL = ("could not deliver the approval prompt via the Agents Platform "
               "(500): Internal Server Error")


class _FakeHTTPResponse:
    def __init__(self, status_code, json_body=None, text=""):
        self.status_code = status_code
        self._json = json_body
        self.text = text

    @property
    def is_error(self):
        return self.status_code >= 400

    def json(self):
        if self._json is None:
            raise ValueError("response body is not JSON")
        return self._json


# ── backend_client.request_read ─────────────────────────────────────────

def test_request_read_carries_aw_backends_real_detail_not_httpxs_generic_one(monkeypatch):
    monkeypatch.setattr(httpx, "post",
                        lambda *a, **kw: _FakeHTTPResponse(400, {"detail": REAL_DETAIL}))
    b = SecretsBackend(backend_url="http://backend", workspace="aw", token="tok")

    with pytest.raises(BackendRequestFailed) as exc_info:
        b.request_read("private_root_aw.tekflox.com", "aw-workspace-cli ssh")

    assert exc_info.value.status_code == 400
    assert exc_info.value.detail == REAL_DETAIL


def test_request_read_falls_back_to_the_raw_body_when_it_is_not_json(monkeypatch):
    monkeypatch.setattr(httpx, "post",
                        lambda *a, **kw: _FakeHTTPResponse(502, None, "Bad Gateway"))
    b = SecretsBackend(backend_url="http://backend", workspace="aw", token="tok")

    with pytest.raises(BackendRequestFailed) as exc_info:
        b.request_read("k", "r")

    assert exc_info.value.detail == "Bad Gateway"


def test_request_read_succeeds_on_a_2xx_as_before(monkeypatch):
    monkeypatch.setattr(httpx, "post",
                        lambda *a, **kw: _FakeHTTPResponse(200, {"request_id": "req-1"}))
    b = SecretsBackend(backend_url="http://backend", workspace="aw", token="tok")

    assert b.request_read("k", "r") == "req-1"


# ── routes._fail ─────────────────────────────────────────────────────────

class _FailingBackend:
    def __init__(self, exc):
        self._exc = exc

    def request_read(self, *a, **kw):
        raise self._exc


def test_the_read_route_returns_aw_backends_real_status_and_detail_not_a_generic_502():
    """This is the exact shape Frederico saw: a 502 with an httpx exception
    repr instead of the 400 + real reason aw-backend actually sent."""
    exc = BackendRequestFailed(400, REAL_DETAIL)
    tools = SecretTools(_FailingBackend(exc))
    client = TestClient(build_app(tools))

    r = client.post("/secrets/private_root_aw.tekflox.com/read", json={"reason": "ssh"})

    assert r.status_code == 400, r.text
    assert r.json()["detail"] == REAL_DETAIL


def test_an_unrecognised_exception_still_falls_back_to_502():
    """The generic branch stays as the last resort for anything that isn't one
    of the named exception types — this is not a widening of what gets a
    friendly status, only BackendRequestFailed does."""
    tools = SecretTools(_FailingBackend(RuntimeError("something else broke")))
    client = TestClient(build_app(tools))

    r = client.post("/secrets/k/read", json={"reason": "r"})

    assert r.status_code == 502
    assert "something else broke" in r.json()["detail"]
