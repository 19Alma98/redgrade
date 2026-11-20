"""Conversation sessions inside one trial (``{{session_id}}``, ``new_session`` turns).

Memory-poisoning attacks plant something in one conversation and check whether it comes back in
a *later, separate* conversation. Every trial gets its own session id; a turn with
``new_session: true`` starts a new conversation: the runner drops the history it sends and
switches to a fresh id. Map ``{{session_id}}`` into the HTTP body, URL or headers (or declare a
``session_id`` parameter on a function target) when the app keys conversations by session; apps
that keep long-term memory per *user* must keep the same user across those sessions.
"""

from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar

__all__ = ["current_session_id", "session_id_for", "session_scope"]

_SESSION: ContextVar[str] = ContextVar("redgrade_session_id", default="rg-session")


def session_id_for(canary: str, index: int) -> str:
    """Session ``index`` (1-based) of the trial that uses ``canary``."""
    return f"rg-{canary.lower()}-s{index}"


def current_session_id() -> str:
    return _SESSION.get()


@contextmanager
def session_scope(session_id: str) -> Iterator[None]:
    token = _SESSION.set(session_id)
    try:
        yield
    finally:
        _SESSION.reset(token)
