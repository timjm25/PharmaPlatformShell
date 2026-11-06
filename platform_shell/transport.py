"""HTTP transports used by the gateway proxy, the audit client and health checks.

A transport is any callable that takes an :class:`UpstreamRequest` and returns an
:class:`UpstreamResponse`. Production uses :class:`UrllibTransport` (stdlib, no
extra dependency) or :class:`HttpxTransport`; tests use :class:`WSGITransport`,
which calls Flask apps in-process so the suite never touches the network.
"""
from __future__ import annotations

import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping
from urllib.parse import urlsplit

HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te",
    "trailers", "transfer-encoding", "upgrade", "host", "content-length",
}


class TransportError(Exception):
    """Raised when the upstream cannot be reached at all (DNS, refused, timeout)."""


@dataclass
class UpstreamRequest:
    """One outbound HTTP request."""

    method: str
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    timeout: float = 10.0


@dataclass
class UpstreamResponse:
    """One upstream HTTP response."""

    status: int
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 400

    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")


Transport = Callable[[UpstreamRequest], UpstreamResponse]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:  # noqa: D102
        return None


class UrllibTransport:
    """Stdlib transport. Redirects are returned to the caller, not followed."""

    def __init__(self) -> None:
        self._opener = urllib.request.build_opener(_NoRedirect)

    def __call__(self, req: UpstreamRequest) -> UpstreamResponse:
        data = req.body if req.body or req.method.upper() not in ("GET", "HEAD") else None
        r = urllib.request.Request(req.url, data=data, method=req.method.upper(), headers=req.headers)
        try:
            with self._opener.open(r, timeout=req.timeout) as resp:
                return UpstreamResponse(resp.status, dict(resp.headers.items()), resp.read())
        except urllib.error.HTTPError as e:  # non-2xx still carries a response
            return UpstreamResponse(e.code, dict(e.headers.items()) if e.headers else {}, e.read() or b"")
        except (urllib.error.URLError, OSError, ValueError) as e:
            raise TransportError(str(e)) from e


class HttpxTransport:
    """httpx transport, for deployments that already depend on httpx."""

    def __init__(self, client: Any | None = None) -> None:
        import httpx  # local import: optional dependency

        self._httpx = httpx
        self._client = client or httpx.Client(follow_redirects=False)

    def __call__(self, req: UpstreamRequest) -> UpstreamResponse:
        try:
            r = self._client.request(req.method, req.url, headers=req.headers, content=req.body or None,
                                     timeout=req.timeout)
        except self._httpx.HTTPError as e:
            raise TransportError(str(e)) from e
        return UpstreamResponse(r.status_code, dict(r.headers.items()), r.content)


class WSGITransport:
    """Route requests to in-process WSGI apps by host name (for tests and demos).

    ``apps`` maps ``"host:port"`` (the netloc of the upstream base URL) to a WSGI
    app. A netloc with no app raises :class:`TransportError`, which is how tests
    simulate a service being down.
    """

    def __init__(self, apps: Mapping[str, Any]) -> None:
        from werkzeug.test import Client

        self._clients = {host: Client(app) for host, app in apps.items()}
        self.calls: list[UpstreamRequest] = []

    def __call__(self, req: UpstreamRequest) -> UpstreamResponse:
        self.calls.append(req)
        parts = urlsplit(req.url)
        client = self._clients.get(parts.netloc)
        if client is None:
            raise TransportError(f"connection refused: {parts.netloc}")
        resp = client.open(parts.path or "/", method=req.method, data=req.body,
                           headers=list(req.headers.items()), query_string=parts.query)
        return UpstreamResponse(resp.status_code, dict(resp.headers.items()), resp.get_data())


def filter_headers(headers: Mapping[str, str], drop: set[str] | None = None) -> dict[str, str]:
    """Remove hop-by-hop headers (and any extra names in ``drop``), case-insensitively."""
    drop_l = {h.lower() for h in (drop or set())} | HOP_BY_HOP
    return {k: v for k, v in headers.items() if k.lower() not in drop_l}
