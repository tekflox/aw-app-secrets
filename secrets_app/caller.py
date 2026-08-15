"""Who is asking — the identity a 10min/60min approval is scoped to.

Approving a secret for ten minutes only means something if "the same caller"
is a thing the system can recognise. It was not: the identity aw-backend
understood was a *command line*, which meant `ssh host` and `rsync host:/x`
in one terminal were two different callers, and an agent — whose container is
rebuilt every turn — was never the same caller twice.

Two identities, in priority order:

* ``session:<uuid>`` — an agent. ``AW_SESSION_ID`` is set in the runner
  container and is stable across turns (verified: it is the same uuid the CLI
  is resumed with, and it survived a context compaction mid-conversation). That
  stability is the whole point — the container dies every turn, the session
  does not, so a window granted on turn one is still valid on turn four.
* ``proc:<host>:<ppid>:<starttime>`` — a terminal. The parent is the shell, and
  its pid is stable for every command typed into it. ``starttime`` is included
  because pids get recycled: without it, a new shell inheriting a dead one's
  pid would inherit its grants too. ``host`` because pid 1234 in the workspace
  container is not pid 1234 in a runner.

If neither can be determined, the answer is **no key**, and no key means no
window — every read asks again. Being unidentified must never mean sharing
whichever window happens to be open.

**What this is not.** Every agent and terminal here runs as the same uid, so a
caller key is an identifier, not a credential: nothing stops a process
claiming another's. It exists to stop *accidental* sharing — one caller
silently spending a window another earned — not to defend against a hostile
one, which would need a different trust boundary altogether. Worth being
explicit about, because a window genuinely does widen exposure: for its
duration, anything in that session reads that secret without a prompt.
"""
from __future__ import annotations

import os
import socket

#: The env var an agent runner exports. Set by the Agents Platform for every
#: agent session; absent in a plain terminal.
SESSION_ENV_VARS = ("AW_SESSION_ID", "CLAUDE_CODE_SESSION_ID")

MAX_LEN = 256


def session_id() -> str | None:
    for var in SESSION_ENV_VARS:
        value = (os.environ.get(var) or "").strip()
        if value:
            return value
    return None


def _proc_start_time(pid: int) -> str:
    """Field 22 of /proc/<pid>/stat — the process's start time in clock ticks.

    What makes a pid safe to key on. Reading it can fail (a non-Linux host, a
    process that just exited); an empty marker then simply makes the key less
    specific rather than wrong.
    """
    try:
        with open(f"/proc/{pid}/stat", encoding="utf-8") as fh:
            # The comm field can contain spaces and parentheses, so split after
            # the closing one rather than on whitespace from the left.
            fields = fh.read().rsplit(")", 1)[1].split()
        return fields[19]
    except (OSError, IndexError):
        return "?"


def terminal_key() -> str | None:
    """Identity of the shell that invoked us, not of this process.

    The parent, because this process is new for every command — keying on our
    own pid would make every invocation a different caller, which is the exact
    failure the old pid matching had.
    """
    try:
        ppid = os.getppid()
    except OSError:
        return None
    if ppid <= 1:
        # No meaningful parent: a container entrypoint, or an orphan. Better to
        # be unidentified than to hand a shared key to everything init spawns.
        return None
    return f"proc:{socket.gethostname()}:{ppid}:{_proc_start_time(ppid)}"


def _is_unexpanded(value: str) -> bool:
    """``${AW_SESSION_ID}`` arriving verbatim, because some MCP client did not
    expand it.

    The Agents Platform writes the session header as an env reference so a
    frozen warm-container config can still resolve to the current turn. A
    client that does not do that expansion would send the literal placeholder —
    identical for every agent, which would make one shared key out of what is
    supposed to separate them. Treated as no identity at all: unidentified
    means "ask every time", which is the safe way to be wrong here.
    """
    return "$" in value or "{" in value


def caller_key(session: str | None = None, *, allow_local: bool = False) -> str | None:
    """The key for an approval request, or None when the caller is unidentified.

    ``session`` is an identity the caller learned some other way — the MCP and
    REST paths, where the agent or CLI runs in one container and this code in
    another, so the session arrives on the request rather than in this
    process's env.

    ``allow_local`` decides whether this process may identify ITSELF from its
    own parent shell, and it defaults to **off** for a reason worth stating:
    when this function runs inside the app's server process, "the parent
    shell" is the server's supervisor — identical for every REST caller in the
    workspace. Falling back to it would mint one shared key and hand every
    caller a window the first of them earned. Only a process that IS the
    caller — a CLI in the user's own shell — should pass ``allow_local=True``.
    """
    session = (session or "").strip() or session_id() or ""
    if session and not _is_unexpanded(session):
        return f"session:{session}"[:MAX_LEN]
    return (terminal_key() if allow_local else None)


#: The agent's own id. Unlike the session, it is the same next week — which is
#: what a per-secret allowlist can name ("agent:nightly-backup may read this
#: key without waking anybody"). Injected by the Agents Platform.
AGENT_ENV_VAR = "AW_AGENT_SLUG"


def agent_identity(header: str | None = None) -> str | None:
    """The stable identity an allowlist matches on, or None.

    Always ``agent:<slug>``, whether it came from a forwarded header or from
    this process's own env — one shape, so what a human types into the
    allowlist is what both paths produce.
    """
    value = (header or "").strip() or (os.environ.get(AGENT_ENV_VAR) or "").strip()
    if not value or _is_unexpanded(value):
        return None
    return value if value.startswith("agent:") else f"agent:{value}"


__all__ = ["caller_key", "session_id", "terminal_key", "agent_identity",
           "SESSION_ENV_VARS", "AGENT_ENV_VAR"]
