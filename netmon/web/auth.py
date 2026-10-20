"""HTTP Basic authentication for the web dashboard.

Credentials are environment-only so they never enter YAML, SQLite or the
settings API. The middleware reads the live configuration from
``app.state.config`` on every request, so toggling ``web.auth`` in Settings
takes effect immediately. Health checks and static assets stay public.
"""

from __future__ import annotations

import base64
import binascii
import os
import secrets
from typing import Any

from starlette.datastructures import Headers
from starlette.responses import PlainTextResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from netmon.config.settings import NetMonConfig

_USERNAME_ENV = "NETMON_WEB_USERNAME"
_PASSWORD_ENV = "NETMON_WEB_PASSWORD"
_DEFAULT_USERNAME = "admin"
_EXEMPT_PATHS = frozenset({"/api/health"})
_EXEMPT_PREFIXES = ("/static/",)


def credentials_from_env(config: NetMonConfig) -> tuple[str, str] | None:
    """Return ``(username, password)`` when auth is enabled, else ``None``.

    Raises:
        ValueError: if ``web.auth`` is enabled without a non-empty password.
    """
    if not config.web.auth:
        return None
    username = os.environ.get(_USERNAME_ENV, _DEFAULT_USERNAME).strip() or _DEFAULT_USERNAME
    password = os.environ.get(_PASSWORD_ENV, "")
    if not password:
        raise ValueError(f"web.auth is enabled but {_PASSWORD_ENV} is not set")
    return username, password


def _is_exempt(path: str) -> bool:
    return path in _EXEMPT_PATHS or path.startswith(_EXEMPT_PREFIXES)


def _live_config(scope: Scope, app: ASGIApp) -> NetMonConfig | None:
    owner: Any = scope.get("app", app)
    return getattr(getattr(owner, "state", None), "config", None)


class BasicAuthMiddleware:
    """Constant-time HTTP Basic authentication for HTTP and WebSocket scopes."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app
        self.challenge = 'Basic realm="NetMon", charset="UTF-8"'

    @staticmethod
    def _authorized(authorization: str | None, credentials: tuple[str, str]) -> bool:
        if not authorization:
            return False
        scheme, _, encoded = authorization.partition(" ")
        if scheme.lower() != "basic" or not encoded:
            return False
        try:
            decoded = base64.b64decode(encoded, validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError):
            return False
        username, separator, password = decoded.partition(":")
        if not separator:
            return False
        username_ok = secrets.compare_digest(
            username.encode("utf-8"), credentials[0].encode("utf-8")
        )
        password_ok = secrets.compare_digest(
            password.encode("utf-8"), credentials[1].encode("utf-8")
        )
        return username_ok and password_ok

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in {"http", "websocket"} or _is_exempt(scope.get("path", "")):
            await self.app(scope, receive, send)
            return

        config = _live_config(scope, self.app)
        if config is None or not config.web.auth:
            await self.app(scope, receive, send)
            return

        try:
            credentials = credentials_from_env(config)
        except ValueError:
            await self._deny(scope, receive, send, status_code=503)
            return

        assert credentials is not None
        if self._authorized(Headers(scope=scope).get("authorization"), credentials):
            await self.app(scope, receive, send)
            return
        await self._deny(scope, receive, send, status_code=401)

    async def _deny(
        self, scope: Scope, receive: Receive, send: Send, *, status_code: int
    ) -> None:
        if scope["type"] == "websocket":
            code = 1011 if status_code == 503 else 1008
            await send({"type": "websocket.close", "code": code, "reason": "authentication required"})
            return
        response = PlainTextResponse(
            "Authentication required" if status_code == 401 else "Authentication is misconfigured",
            status_code=status_code,
            headers={"WWW-Authenticate": self.challenge} if status_code == 401 else None,
        )
        await response(scope, receive, send)


__all__ = ["BasicAuthMiddleware", "credentials_from_env"]
