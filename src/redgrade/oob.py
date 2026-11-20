"""Out-of-band (OOB) collector: attacker-controlled web content and callback detection.

Agents fetch web pages, call webhooks and follow links. The most reliable proof that an injection
worked is not a string in the reply but a request that *arrives at the attacker*: the agent
loaded the exfiltration URL, posted the conversation to a webhook, followed a link it should have
ignored. ``OobServer`` is a small local HTTP server that plays the attacker:

* per trial it serves **fixtures** (poisoned pages, JSON API responses, ...) at
  ``{OOB_URL}/f/<path>``, where ``{OOB_URL}`` is ``<base>/t/<canary>``;
* it records **every** request it receives. A request to a fixture is a *fetch* (the agent read
  the attacker's content); any other request under ``{OOB_URL}``, or any request carrying the
  trial canary, is a *callback* (the agent acted on the injection).

The ``oob_callback`` detector turns callbacks into a verdict. The server only binds where you tell
it (``127.0.0.1`` by default); use ``public_url`` when the app under test reaches it through
another address (a container, ``host.docker.internal``, a tunnel).
"""

import re
import threading
import time
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import TracebackType
from typing import Self
from urllib.parse import unquote_plus, urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator

from redgrade.constants import (
    DEFAULT_OOB_HOST,
    DEFAULT_OOB_PLACEHOLDER_BASE,
    DEFAULT_OOB_WAIT,
    OOB_HIT_CALLBACK,
    OOB_HIT_FIXTURE,
    OobHitKind,
)

__all__ = ["Fixture", "OobConfig", "OobHit", "OobServer", "current_oob_base", "oob_scope"]

_MAX_BODY = 64 * 1024
_TRIAL_PATH = re.compile(r"^/t/(?P<canary>[^/?#]+)(?P<rest>/[^?#]*)?$")
_CANARY_ANY = re.compile(r"RG-[0-9A-F]{8}")
_PIXEL = (
    b"GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff!\xf9\x04\x01\x00\x00\x00\x00,"
    b"\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;"
)

_OOB_BASE: ContextVar[str] = ContextVar("redgrade_oob_base", default=DEFAULT_OOB_PLACEHOLDER_BASE)


def current_oob_base() -> str:
    """Base URL that ``{OOB_URL}`` expands from in the current trial."""
    return _OOB_BASE.get()


@contextmanager
def oob_scope(base: str | None) -> Iterator[None]:
    """Make ``{OOB_URL}`` expand from ``base`` while rendering one trial (thread/context local)."""
    if not base:
        yield
        return
    token = _OOB_BASE.set(base.rstrip("/"))
    try:
        yield
    finally:
        _OOB_BASE.reset(token)


class Fixture(BaseModel):
    """Attacker-controlled content served at ``{OOB_URL}/f/<path>`` during one trial."""

    model_config = ConfigDict(frozen=True)

    path: str
    body: str
    content_type: str = "text/html; charset=utf-8"
    status: int = 200

    @field_validator("path")
    @classmethod
    def _clean_path(cls, value: str) -> str:
        value = value.strip().lstrip("/")
        if not value or ".." in value.split("/"):
            raise ValueError("fixture path must be a non-empty relative path without '..'")
        return value


class OobHit(BaseModel):
    """One request received by the collector."""

    model_config = ConfigDict(frozen=True)

    kind: OobHitKind
    method: str
    path: str
    query: str = ""
    body: str = ""
    headers: dict[str, str] = Field(default_factory=dict)
    client: str = ""
    at: float = 0.0

    @property
    def text(self) -> str:
        """Everything the requester sent, URL-decoded (for pattern / secret checks)."""
        return unquote_plus("\n".join([self.path, self.query, self.body]))


class OobConfig(BaseModel):
    """``oob:`` block of ``redgrade.yaml``."""

    enabled: bool = True
    host: str = DEFAULT_OOB_HOST
    port: int = 0
    public_url: str | None = None
    wait: float = DEFAULT_OOB_WAIT


class _Handler(BaseHTTPRequestHandler):
    server: "_Server"

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002 - stdlib signature
        return

    def _handle(self) -> None:
        length = min(int(self.headers.get("Content-Length") or 0), _MAX_BODY)
        body = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        status, ctype, payload = self.server.owner._record(
            self.command, self.path, body, dict(self.headers.items()), self.client_address[0]
        )
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = _handle  # noqa: N815


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    owner: "OobServer"


class OobServer:
    """Local attacker server. Use as a context manager, or ``start()`` / ``stop()``.

    ``wait`` is how long the runner waits, after the target replied, for a late callback (an
    agent that fetches in the background). ``public_url`` is the base URL the app under test uses
    to reach the server; it defaults to ``http://<host>:<port>``.
    """

    def __init__(
        self,
        *,
        host: str = DEFAULT_OOB_HOST,
        port: int = 0,
        public_url: str | None = None,
        wait: float = DEFAULT_OOB_WAIT,
    ) -> None:
        self.host = host
        self.port = port
        self.wait = wait
        self._public_url = public_url.rstrip("/") if public_url else None
        self._server: _Server | None = None
        self._thread: threading.Thread | None = None
        self._lock = threading.Condition()
        self._fixtures: dict[str, dict[str, Fixture]] = {}
        self._hits: dict[str, list[OobHit]] = {}

    @classmethod
    def from_config(cls, config: OobConfig) -> "OobServer":
        return cls(host=config.host, port=config.port, public_url=config.public_url, wait=config.wait)

    # --- lifecycle --------------------------------------------------------------------------

    def start(self) -> Self:
        if self._server is not None:
            return self
        server = _Server((self.host, self.port), _Handler)
        server.owner = self
        self.port = server.server_address[1]
        self._server = server
        self._thread = threading.Thread(
            target=server.serve_forever, kwargs={"poll_interval": 0.05}, name="redgrade-oob", daemon=True
        )
        self._thread.start()
        return self

    def stop(self) -> None:
        if self._server is None:
            return
        self._server.shutdown()
        self._server.server_close()
        self._server = None

    @property
    def running(self) -> bool:
        return self._server is not None

    def __enter__(self) -> Self:
        return self.start()

    def __exit__(
        self, exc_type: type[BaseException] | None, exc: BaseException | None, tb: TracebackType | None
    ) -> None:
        self.stop()

    # --- URLs and per-trial state -----------------------------------------------------------

    @property
    def base_url(self) -> str:
        if self._public_url:
            return self._public_url
        if self._server is None:
            raise RuntimeError("OobServer is not running (call start() or use it as a context manager)")
        host = "127.0.0.1" if self.host in ("0.0.0.0", "") else self.host
        return f"http://{host}:{self.port}"

    def trial_url(self, canary: str) -> str:
        return f"{self.base_url}/t/{canary}"

    def register(self, canary: str, fixtures: Iterable[Fixture]) -> None:
        with self._lock:
            self._fixtures[canary] = {f.path: f for f in fixtures}
            self._hits.setdefault(canary, [])

    def release(self, canary: str) -> None:
        """Forget a trial's fixtures and hits (after its verdict)."""
        with self._lock:
            self._fixtures.pop(canary, None)
            self._hits.pop(canary, None)

    def hits(self, canary: str, kind: OobHitKind | None = None) -> list[OobHit]:
        with self._lock:
            hits = list(self._hits.get(canary, []))
        return [h for h in hits if kind is None or h.kind == kind]

    def unattributed(self) -> list[OobHit]:
        """Requests that matched no trial (wrong path, stale canary): useful when debugging."""
        return self.hits("")

    def wait_for_callback(self, canary: str, timeout: float | None = None) -> bool:
        """Block until the trial got a callback or ``timeout`` (default ``self.wait``) expires."""
        deadline = time.monotonic() + (self.wait if timeout is None else timeout)
        with self._lock:
            while True:
                if any(h.kind == OOB_HIT_CALLBACK for h in self._hits.get(canary, [])):
                    return True
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._lock.wait(remaining)

    # --- request handling -------------------------------------------------------------------

    def _record(
        self, method: str, raw_path: str, body: str, headers: dict[str, str], client: str
    ) -> tuple[int, str, bytes]:
        parts = urlsplit(raw_path)
        match = _TRIAL_PATH.match(parts.path)
        canary = ""
        rest = ""
        if match:
            canary, rest = match.group("canary"), match.group("rest") or ""
        else:
            found = _CANARY_ANY.search(unquote_plus(" ".join([raw_path, body])))
            canary = found.group(0) if found else ""
        with self._lock:
            fixtures = self._fixtures.get(canary, {})
            fixture = fixtures.get(rest[len("/f/") :]) if rest.startswith("/f/") else None
            kind: OobHitKind = OOB_HIT_FIXTURE if rest.startswith("/f/") else OOB_HIT_CALLBACK
            if canary not in self._hits and canary not in self._fixtures:
                canary = ""  # unknown trial: keep it for debugging, never in a verdict
            hit = OobHit(
                kind=kind,
                method=method,
                path=parts.path,
                query=parts.query,
                body=body,
                headers=headers,
                client=client,
                at=time.time(),
            )
            self._hits.setdefault(canary, []).append(hit)
            self._lock.notify_all()
        if fixture is not None:
            return fixture.status, fixture.content_type, fixture.body.encode("utf-8")
        if kind == OOB_HIT_FIXTURE:
            return 404, "text/plain; charset=utf-8", b"not found"
        return 200, "image/gif", _PIXEL
