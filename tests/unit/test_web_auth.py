"""HTTP Basic auth middleware tests."""

from __future__ import annotations

import base64

import pytest
from fastapi import FastAPI, WebSocket
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from netmon.config.settings import NetMonConfig
from netmon.web.auth import BasicAuthMiddleware, credentials_from_env

CREDENTIALS = ("admin", "correct-horse")


def _header(username: str = "admin", password: str = "correct-horse") -> dict[str, str]:
    token = base64.b64encode(f"{username}:{password}".encode()).decode()
    return {"Authorization": f"Basic {token}"}


LOCAL_CLIENT = ("127.0.0.1", 50000)
REMOTE_CLIENT = ("203.0.113.7", 50001)


def _app(
    monkeypatch: pytest.MonkeyPatch,
    *,
    auth: bool = True,
    password: str | None = "correct-horse",
) -> FastAPI:
    monkeypatch.setenv("NETMON_WEB_USERNAME", CREDENTIALS[0])
    if password is None:
        monkeypatch.delenv("NETMON_WEB_PASSWORD", raising=False)
    else:
        monkeypatch.setenv("NETMON_WEB_PASSWORD", password)

    app = FastAPI()

    @app.get("/")
    async def index() -> dict[str, bool]:
        return {"ok": True}

    @app.get("/api/health")
    async def health() -> dict[str, bool]:
        return {"ok": True}

    @app.get("/static/app.js")
    async def static_asset() -> dict[str, bool]:
        return {"ok": True}

    @app.websocket("/ws/live")
    async def live(websocket: WebSocket) -> None:
        await websocket.accept()
        await websocket.send_json({"ok": True})
        await websocket.close()

    config = NetMonConfig()
    config.web.auth = auth
    app.state.config = config
    app.add_middleware(BasicAuthMiddleware)
    return app


def _client(
    monkeypatch: pytest.MonkeyPatch,
    *,
    auth: bool = True,
    password: str | None = "correct-horse",
) -> TestClient:
    return TestClient(_app(monkeypatch, auth=auth, password=password), client=LOCAL_CLIENT)


def test_requires_valid_basic_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _client(monkeypatch)

    response = client.get("/")
    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"].startswith("Basic")

    assert client.get("/", auth=CREDENTIALS).status_code == 200
    assert client.get("/", auth=("admin", "wrong")).status_code == 401
    assert client.get("/", headers={"Authorization": "Bearer token"}).status_code == 401
    assert client.get("/", headers={"Authorization": "Basic !!!"}).status_code == 401


def test_auth_toggle_takes_effect_live(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _client(monkeypatch)
    assert client.get("/").status_code == 401

    client.app.state.config.web.auth = False
    assert client.get("/").status_code == 200

    client.app.state.config.web.auth = True
    assert client.get("/", auth=CREDENTIALS).status_code == 200


def test_health_is_exempt_for_loopback_only(monkeypatch: pytest.MonkeyPatch) -> None:
    app = _app(monkeypatch)
    local = TestClient(app, client=LOCAL_CLIENT)
    remote = TestClient(app, client=REMOTE_CLIENT)

    assert local.get("/api/health").status_code == 200
    assert remote.get("/api/health").status_code == 401
    assert remote.get("/api/health", auth=CREDENTIALS).status_code == 200
    assert remote.get("/static/app.js").status_code == 200


def test_missing_password_is_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _client(monkeypatch, password=None)

    response = client.get("/")
    assert response.status_code == 503
    assert "misconfigured" in response.text


def test_websocket_requires_auth(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _client(monkeypatch)

    with (
        pytest.raises(WebSocketDisconnect) as exc_info,
        client.websocket_connect("/ws/live"),
    ):
        pass
    assert exc_info.value.code == 1008

    with client.websocket_connect("/ws/live", headers=_header()) as socket:
        assert socket.receive_json() == {"ok": True}


def test_credentials_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    config = NetMonConfig()
    assert credentials_from_env(config) is None

    config.web.auth = True
    monkeypatch.setenv("NETMON_WEB_PASSWORD", "secret")
    monkeypatch.delenv("NETMON_WEB_USERNAME", raising=False)
    assert credentials_from_env(config) == ("admin", "secret")

    monkeypatch.setenv("NETMON_WEB_USERNAME", "operator")
    assert credentials_from_env(config) == ("operator", "secret")

    monkeypatch.delenv("NETMON_WEB_PASSWORD")
    with pytest.raises(ValueError, match="NETMON_WEB_PASSWORD"):
        credentials_from_env(config)
