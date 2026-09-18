"""The ``aw-workspace-cli secrets`` command surface.

Everything here runs against a stubbed ``workspace_client.request``, so the
suite never reaches the network and — much more importantly — never sends
anybody a Telegram prompt.

Two of these tests are guarding something that has gone wrong before rather
than something that merely might:

* ``test_cli_imports_with_httpx_and_fastapi_blocked`` — this module runs in
  ``aw-workspace-cli``'s interpreter, which is not the workspace server's and
  has no guarantee of either package. Importing ``.tools`` from the CLI would
  work on the developer's box and fail for everyone else.
* ``test_get_on_an_unknown_name_asks_nobody`` — a read of a name that does not
  exist is a notification on somebody's phone for a secret that was never
  going to be there.
"""
from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import textwrap

import pytest

from secrets_app import caller, cli, pending

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))

INVENTORY = {"secrets": [
    {"name": "resend_api_key", "description": "email", "auto_approve": False},
    {"name": "deploy_env", "description": "", "auto_approve": True},
]}


class Vault:
    """A recording stub for :func:`workspace_client.request`.

    ``reads`` holds every approval request that was actually sent, so a test
    can assert that none was — which is the only way to check "this path does
    not interrupt a human".
    """

    def __init__(self, *, read_replies=None, inventory=None):
        self.reads: list[tuple[str, dict | None]] = []
        self.writes: list[tuple[str, str, dict | None]] = []
        self.polls: list[str] = []
        self.inventory = INVENTORY if inventory is None else inventory
        self.read_replies = list(read_replies or [(200, {"status": "approved",
                                                         "value": "v1"})])

    def __call__(self, method, path, body=None, timeout=None):
        if method == "GET" and path.endswith("/secrets"):
            return 200, self.inventory
        if method == "POST" and path.endswith("/read"):
            self.reads.append((path, body))
            return self._next()
        if method == "GET" and "/requests/" in path:
            self.polls.append(path.rsplit("/", 1)[-1])
            return self._next()
        self.writes.append((method, path, body))
        return 200, {"ok": True, "action": "written"}

    def _next(self):
        return self.read_replies.pop(0) if len(self.read_replies) > 1 \
            else self.read_replies[0]


@pytest.fixture
def vault(monkeypatch):
    v = Vault()
    monkeypatch.setattr(cli, "request", v)
    monkeypatch.setattr(cli.time, "sleep", lambda _s: None)
    return v


# ── flag parsing ─────────────────────────────────────────────────────────

def test_flags_parse_in_both_forms():
    opts, positional = cli._parse(
        ["resend_api_key", "--scope", "60min", "--reason=deploy", "--eval"],
        {"--scope", "--reason", "--eval"})
    assert positional == ["resend_api_key"]
    assert opts == {"scope": "60min", "reason": "deploy", "eval": True}


def test_an_unknown_option_is_refused_not_ignored():
    """``--scpoe 60min`` silently read as one_shot would look like it worked
    and re-prompt an hour later for a reason nobody could trace to a typo."""
    with pytest.raises(cli.CliError, match="unknown option"):
        cli._parse(["k", "--scpoe", "60min"], {"--scope"})


def test_an_option_belonging_to_another_verb_is_refused():
    with pytest.raises(cli.CliError, match="not an option"):
        cli._parse(["k", "--yes"], {"--json"})


def test_a_bad_scope_is_refused_rather_than_widened(vault):
    assert cli.main(["get", "resend_api_key", "--scope", "forever"]) == cli.EXIT_ERROR
    assert vault.reads == []


# ── ls ───────────────────────────────────────────────────────────────────

def test_ls_prints_names_and_no_values(vault, capsys):
    assert cli.main(["ls"]) == cli.EXIT_OK
    out = capsys.readouterr().out
    assert "resend_api_key" in out and "deploy_env" in out
    assert "v1" not in out
    assert vault.reads == []


def test_ls_json_carries_no_value_field(vault, capsys):
    assert cli.main(["list", "--json"]) == cli.EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    assert payload["count"] == 2
    assert all("value" not in entry for entry in payload["secrets"])


# ── get ──────────────────────────────────────────────────────────────────

def test_get_prints_the_value_on_stdout_and_nothing_else(vault, capsys):
    assert cli.main(["get", "resend_api_key", "--reason", "smoke"]) == cli.EXIT_OK
    captured = capsys.readouterr()
    assert captured.out == "v1"
    # Progress belongs on stderr so `secrets get k > keyfile` stays usable.
    assert "requesting" in captured.err


def test_get_sends_the_caller_key_under_the_name_the_backend_reads(vault):
    """``caller_process`` was never one of them, which is why window scopes
    silently never worked at all."""
    cli.main(["get", "resend_api_key", "--scope", "60min"])
    _path, body = vault.reads[0]
    assert body["scope"] == "60min"
    assert "caller_key" in body
    # Client-side polling is the whole design: the tunnel edge cuts any single
    # request at ~30s, so a server-side wait dies before the approval does.
    assert body["max_wait_s"] == 0


def test_get_on_an_unknown_name_asks_nobody(vault, capsys):
    assert cli.main(["get", "typoed_name"]) == cli.EXIT_ERROR
    assert vault.reads == []
    assert "no secret named" in capsys.readouterr().err


def test_get_polls_until_the_human_answers(vault, capsys):
    vault.read_replies = [(200, {"status": "pending", "request_id": "REQ1"}),
                          (200, {"status": "pending", "request_id": "REQ1"}),
                          (200, {"status": "approved", "value": "v1"})]
    assert cli.main(["get", "resend_api_key"]) == cli.EXIT_OK
    assert capsys.readouterr().out == "v1"
    assert vault.polls == ["REQ1", "REQ1"]
    # One request, two polls — not three requests.
    assert len(vault.reads) == 1


def test_a_403_is_a_denial_not_a_traceback(vault, capsys):
    vault.read_replies = [(403, {"detail": "'resend_api_key' was denied by the human."})]
    assert cli.main(["get", "resend_api_key"]) == cli.EXIT_ERROR
    err = capsys.readouterr().err
    assert "denied" in err and "Traceback" not in err


def test_a_503_says_there_is_no_store(vault, capsys):
    vault.read_replies = [(503, {"detail": "no cloud link"})]
    assert cli.main(["get", "resend_api_key"]) == cli.EXIT_ERROR
    assert "no cloud link" in capsys.readouterr().err


def test_no_wait_prints_the_request_id_and_exits_pending(vault, capsys):
    vault.read_replies = [(200, {"status": "pending", "request_id": "REQ7"})]
    assert cli.main(["get", "resend_api_key", "--no-wait"]) == cli.EXIT_PENDING
    captured = capsys.readouterr()
    assert captured.out.strip() == "REQ7"
    assert "collect REQ7" in captured.err
    assert vault.polls == []


def test_an_elapsed_wait_keeps_stdout_empty(vault, capsys):
    """Exit 2, and the id on stderr: stdout was promised a value, and a
    request id landing in a redirect would be captured into a file as if it
    were one."""
    vault.read_replies = [(200, {"status": "pending", "request_id": "REQ8"})]
    assert cli.main(["get", "resend_api_key", "--wait", "0"]) == cli.EXIT_PENDING
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "REQ8" in captured.err


def test_an_outstanding_request_is_resumed_instead_of_asked_again(vault, capsys):
    """Otherwise "run it again" puts a SECOND prompt on their phone for a
    question they already answered."""
    pending.remember("resend_api_key", "REQ9")
    vault.read_replies = [(200, {"status": "approved", "value": "v1"})]

    assert cli.main(["get", "resend_api_key"]) == cli.EXIT_OK
    assert vault.reads == []
    assert vault.polls == ["REQ9"]
    assert capsys.readouterr().out == "v1"
    # Delivery is one-shot server-side, so the spent id must not be polled
    # again on the next run.
    assert pending.get("resend_api_key") is None


def test_a_dead_pending_id_is_dropped_and_a_fresh_request_made(vault):
    pending.remember("resend_api_key", "DEAD")
    vault.read_replies = [(404, {"status": "not_found"}),
                          (200, {"status": "approved", "value": "v1"})]
    assert cli.main(["get", "resend_api_key"]) == cli.EXIT_OK
    assert len(vault.reads) == 1


# ── --eval ───────────────────────────────────────────────────────────────

def test_eval_prefixes_each_line_of_an_env_file(vault, capsys):
    vault.read_replies = [(200, {"status": "approved", "value": "A=1\nB_2=x y\n"})]
    assert cli.main(["get", "resend_api_key", "--eval"]) == cli.EXIT_OK
    assert capsys.readouterr().out == "export A=1\nexport B_2=x y\n"


def test_eval_falls_back_to_one_var_named_after_the_secret(vault, capsys):
    vault.read_replies = [(200, {"status": "approved", "value": "it's-a-token"})]
    assert cli.main(["get", "resend_api_key", "--eval"]) == cli.EXIT_OK
    # Single quotes in the value are escaped the shell's own way, so the line
    # survives `eval` intact.
    assert capsys.readouterr().out == "export RESEND_API_KEY='it'\\''s-a-token'\n"


def test_eval_and_json_together_are_refused(vault, capsys):
    assert cli.main(["get", "resend_api_key", "--eval", "--json"]) == cli.EXIT_ERROR
    assert vault.reads == []


# ── set ──────────────────────────────────────────────────────────────────

def test_set_reads_the_value_from_stdin_never_from_argv(vault, monkeypatch):
    monkeypatch.setattr(sys, "stdin", io.StringIO("s3cret\n"))
    assert cli.main(["set", "new_key", "--description", "for CI"]) == cli.EXIT_OK
    method, path, body = vault.writes[0]
    assert (method, path) == ("POST", "/api/apps/secrets/secrets")
    assert body == {"name": "new_key", "value": "s3cret", "description": "for CI"}


def test_set_refuses_an_empty_stdin(vault, monkeypatch, capsys):
    """An empty pipe must never be a way to blank a secret — that is what `rm`
    is for, and `rm` asks."""
    monkeypatch.setattr(sys, "stdin", io.StringIO("   \n"))
    assert cli.main(["set", "new_key"]) == cli.EXIT_ERROR
    assert vault.writes == []
    assert "nothing on stdin" in capsys.readouterr().err


def test_set_rejects_a_value_passed_as_an_argument(vault, monkeypatch):
    """argv lands in shell history, in `ps`, and in /proc/<pid>/cmdline."""
    monkeypatch.setattr(sys, "stdin", io.StringIO("s3cret"))
    assert cli.main(["set", "new_key", "s3cret"]) == cli.EXIT_ERROR
    assert vault.writes == []


# ── rm ───────────────────────────────────────────────────────────────────

def test_rm_refuses_unattended_without_yes(vault, monkeypatch, capsys):
    monkeypatch.setattr(sys, "stdin", io.StringIO(""))
    assert cli.main(["rm", "resend_api_key"]) == cli.EXIT_ERROR
    assert vault.writes == []
    assert "--yes" in capsys.readouterr().err


def test_rm_with_yes_deletes(vault):
    assert cli.main(["rm", "resend_api_key", "--yes"]) == cli.EXIT_OK
    assert vault.writes == [("DELETE", "/api/apps/secrets/secrets/resend_api_key", None)]


def test_rm_of_an_unknown_name_is_a_sentence_not_a_stack_trace(monkeypatch, capsys):
    def _request(method, path, body=None, timeout=None):
        return 404, {"detail": "secret 'ghost' not found"}
    monkeypatch.setattr(cli, "request", _request)

    assert cli.main(["rm", "ghost", "--yes"]) == cli.EXIT_ERROR
    err = capsys.readouterr().err
    assert "not found" in err and "Traceback" not in err


# ── collect ──────────────────────────────────────────────────────────────

def test_collect_prints_the_value(vault, capsys):
    vault.read_replies = [(200, {"status": "approved", "name": "resend_api_key",
                                 "value": "v1"})]
    assert cli.main(["collect", "REQ7"]) == cli.EXIT_OK
    assert capsys.readouterr().out == "v1"


def test_collect_of_something_unanswered_exits_pending(vault, capsys):
    vault.read_replies = [(200, {"status": "pending", "name": "resend_api_key",
                                 "request_id": "REQ7"})]
    assert cli.main(["collect", "REQ7"]) == cli.EXIT_PENDING
    assert capsys.readouterr().out == ""


# ── caller_key ───────────────────────────────────────────────────────────

def test_caller_key_is_identical_across_two_calls_in_one_process_tree(monkeypatch):
    """An unstable key makes `--scope 60min` re-prompt on every call while
    looking like it works."""
    for var in caller.SESSION_ENV_VARS:
        monkeypatch.delenv(var, raising=False)
    # os.getpid() rather than the real parent: guaranteed > 1 and readable in
    # /proc, so the assertion is about stability and not about what pytest
    # happens to be running under.
    monkeypatch.setattr(os, "getppid", os.getpid)

    first = caller.caller_key(allow_local=True)
    second = caller.caller_key(allow_local=True)
    assert first is not None and first.startswith("proc:")
    assert first == second


def test_an_agent_session_wins_over_the_shell(monkeypatch):
    monkeypatch.setenv("AW_SESSION_ID", "abc-123")
    assert caller.caller_key(allow_local=True) == "session:abc-123"


# ── the import boundary ──────────────────────────────────────────────────

def test_cli_imports_with_httpx_and_fastapi_blocked():
    """A subprocess, not sys.modules surgery: the claim is about what a fresh
    interpreter without those packages can import, and only a fresh
    interpreter can actually prove it.
    """
    probe = textwrap.dedent("""
        import importlib.abc, sys

        class Blocked(importlib.abc.MetaPathFinder):
            def find_spec(self, name, path=None, target=None):
                if name.split(".")[0] in ("httpx", "fastapi"):
                    raise ImportError(f"{name} is not installed in this interpreter")
                return None

        sys.meta_path.insert(0, Blocked())
        sys.path.insert(0, sys.argv[1])
        import secrets_app.cli  # noqa: F401
        assert "httpx" not in sys.modules and "fastapi" not in sys.modules
        print("ok")
    """)
    result = subprocess.run([sys.executable, "-c", probe, REPO_ROOT],
                            capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "ok"


def test_the_shim_stays_trivial():
    """A failure in commands/secrets.py prints a warning in front of EVERY
    aw-workspace-cli invocation workspace-wide, so it must import with nothing
    but the stdlib and must not pull the app in at import time."""
    probe = textwrap.dedent("""
        import importlib.util, sys
        spec = importlib.util.spec_from_file_location("shim", sys.argv[1])
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        assert mod.COMMAND == "secrets" and mod.DESCRIPTION
        assert callable(mod.run)
        assert "secrets_app.cli" not in sys.modules
        print("ok")
    """)
    result = subprocess.run(
        [sys.executable, "-c", probe, os.path.join(REPO_ROOT, "commands", "secrets.py")],
        capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "ok"
