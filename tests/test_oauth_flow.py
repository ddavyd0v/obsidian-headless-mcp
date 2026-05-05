"""End-to-end OAuth 2.1 flow test.

Drives the OAuth-wrapped ASGI app entirely in-process via httpx ASGITransport.
No Docker, no network, no real MCP server — the inner app is a stub that
returns 200 for any /mcp request so we can verify the bearer is enforced.
"""
import base64
import hashlib
import os
import secrets
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route

from oauth.app import build_app
from oauth.config import OAuthConfig


PASSWORD = "test-password-123"
PUBLIC_URL = "https://mcp.test.example"


def _pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest())
        .rstrip(b"=")
        .decode("ascii")
    )
    return verifier, challenge


def _stub_mcp_app() -> Starlette:
    async def mcp_endpoint(_request):
        return JSONResponse({"ok": True, "tools": ["read_file"]})

    return Starlette(routes=[Route("/mcp", mcp_endpoint, methods=["GET", "POST"])])


@pytest.fixture
async def app_and_client(tmp_path):
    cfg = OAuthConfig(
        enabled=True,
        user_password=PASSWORD,
        token_ttl_seconds=3600,
        refresh_ttl_seconds=14 * 24 * 3600,
        public_url=PUBLIC_URL,
        db_path=str(tmp_path / "oauth.db"),
        static_api_token="",
    )
    app, _storage, _cfg = await build_app(_stub_mcp_app(), cfg=cfg)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url=PUBLIC_URL) as client:
        yield app, client


@pytest.mark.asyncio
async def test_full_flow(app_and_client):
    _app, client = app_and_client

    # 1. Hitting a protected MCP path with no token returns 401 + WWW-Authenticate
    r = await client.get("/mcp")
    assert r.status_code == 401
    www = r.headers["www-authenticate"]
    assert "Bearer" in www
    assert (
        f'resource_metadata="{PUBLIC_URL}/.well-known/oauth-protected-resource"'
        in www
    )

    # 2. Discover protected-resource metadata
    r = await client.get("/.well-known/oauth-protected-resource")
    assert r.status_code == 200
    prm = r.json()
    assert prm["resource"] == PUBLIC_URL
    assert PUBLIC_URL in prm["authorization_servers"]

    # 3. Discover authorization-server metadata
    r = await client.get("/.well-known/oauth-authorization-server")
    assert r.status_code == 200
    asm = r.json()
    assert asm["issuer"] == PUBLIC_URL
    assert asm["authorization_endpoint"] == f"{PUBLIC_URL}/authorize"
    assert asm["token_endpoint"] == f"{PUBLIC_URL}/token"
    assert asm["registration_endpoint"] == f"{PUBLIC_URL}/register"
    assert "S256" in asm["code_challenge_methods_supported"]

    # 4. Dynamic client registration
    redirect_uri = "https://claude.ai/oauth/callback"
    r = await client.post(
        "/register",
        json={"client_name": "Claude Test", "redirect_uris": [redirect_uri]},
    )
    assert r.status_code == 201
    reg = r.json()
    client_id = reg["client_id"]
    client_secret = reg["client_secret"]
    assert reg["redirect_uris"] == [redirect_uri]

    # 5. Start authorization with PKCE
    verifier, challenge = _pkce_pair()
    state = "opaque-state-value"
    auth_params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "state": state,
        "scope": "mcp",
    }
    r = await client.get("/authorize", params=auth_params)
    assert r.status_code == 200
    body = r.text
    assert 'name="code"' in body
    assert 'name="csrf"' in body
    auth_code = body.split('name="code" value="')[1].split('"')[0]
    csrf = body.split('name="csrf" value="')[1].split('"')[0]

    # 6. Submit the password (mocked: we know the value from cfg)
    r = await client.post(
        "/authorize",
        data={"code": auth_code, "csrf": csrf, "password": PASSWORD},
        follow_redirects=False,
    )
    assert r.status_code == 302
    location = r.headers["location"]
    parsed = urlparse(location)
    qs = parse_qs(parsed.query)
    assert qs["code"][0] == auth_code
    assert qs["state"][0] == state

    # 7. Exchange code for tokens
    r = await client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": auth_code,
            "client_id": client_id,
            "client_secret": client_secret,
            "redirect_uri": redirect_uri,
            "code_verifier": verifier,
        },
    )
    assert r.status_code == 200, r.text
    tok = r.json()
    access_token = tok["access_token"]
    refresh_token = tok["refresh_token"]
    assert tok["token_type"] == "Bearer"
    assert tok["expires_in"] == 3600

    # 8. Call protected MCP path with bearer
    r = await client.get(
        "/mcp", headers={"Authorization": f"Bearer {access_token}"}
    )
    assert r.status_code == 200
    assert r.json()["ok"] is True

    # 9. Refresh the token (rotation)
    r = await client.post(
        "/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": client_id,
            "client_secret": client_secret,
        },
    )
    assert r.status_code == 200, r.text
    rotated = r.json()
    assert rotated["access_token"] != access_token
    assert rotated["refresh_token"] != refresh_token

    # 10. Old access token is invalidated by rotation
    r = await client.get(
        "/mcp", headers={"Authorization": f"Bearer {access_token}"}
    )
    assert r.status_code == 401

    # 11. New access token works
    r = await client.get(
        "/mcp", headers={"Authorization": f"Bearer {rotated['access_token']}"}
    )
    assert r.status_code == 200

    # 12. Old refresh token can't be reused
    r = await client.post(
        "/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": client_id,
            "client_secret": client_secret,
        },
    )
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_pkce_failure(app_and_client):
    _app, client = app_and_client

    redirect_uri = "https://claude.ai/oauth/callback"
    r = await client.post(
        "/register",
        json={"client_name": "Claude", "redirect_uris": [redirect_uri]},
    )
    reg = r.json()
    _verifier, challenge = _pkce_pair()

    r = await client.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": reg["client_id"],
            "redirect_uri": redirect_uri,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": "x",
        },
    )
    auth_code = r.text.split('name="code" value="')[1].split('"')[0]
    csrf = r.text.split('name="csrf" value="')[1].split('"')[0]
    await client.post(
        "/authorize",
        data={"code": auth_code, "csrf": csrf, "password": PASSWORD},
        follow_redirects=False,
    )

    # Wrong verifier → invalid_grant
    r = await client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": auth_code,
            "client_id": reg["client_id"],
            "client_secret": reg["client_secret"],
            "redirect_uri": redirect_uri,
            "code_verifier": "wrong-verifier",
        },
    )
    assert r.status_code == 400
    assert r.json()["error"] == "invalid_grant"


@pytest.mark.asyncio
async def test_wrong_password_does_not_redirect(app_and_client):
    _app, client = app_and_client

    redirect_uri = "https://claude.ai/oauth/callback"
    r = await client.post(
        "/register",
        json={"client_name": "Claude", "redirect_uris": [redirect_uri]},
    )
    reg = r.json()
    _verifier, challenge = _pkce_pair()

    r = await client.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": reg["client_id"],
            "redirect_uri": redirect_uri,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        },
    )
    auth_code = r.text.split('name="code" value="')[1].split('"')[0]
    csrf = r.text.split('name="csrf" value="')[1].split('"')[0]

    r = await client.post(
        "/authorize",
        data={"code": auth_code, "csrf": csrf, "password": "wrong"},
        follow_redirects=False,
    )
    # Re-renders the form, no redirect
    assert r.status_code == 200
    assert "Incorrect password" in r.text


@pytest.mark.asyncio
async def test_unknown_client_register_validates_redirect(app_and_client):
    _app, client = app_and_client
    r = await client.post(
        "/register",
        json={"client_name": "Bad", "redirect_uris": ["javascript:alert(1)"]},
    )
    assert r.status_code == 400
    assert r.json()["error"] == "invalid_redirect_uri"


@pytest.mark.asyncio
async def test_static_api_token_bypasses_oauth(tmp_path):
    cfg = OAuthConfig(
        enabled=True,
        user_password=PASSWORD,
        token_ttl_seconds=3600,
        refresh_ttl_seconds=14 * 24 * 3600,
        public_url=PUBLIC_URL,
        db_path=str(tmp_path / "oauth.db"),
        static_api_token="legacy-static-token",
    )
    app, _storage, _cfg = await build_app(_stub_mcp_app(), cfg=cfg)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url=PUBLIC_URL) as client:
        r = await client.get(
            "/mcp", headers={"Authorization": "Bearer legacy-static-token"}
        )
        assert r.status_code == 200
        r = await client.get(
            "/mcp", headers={"Authorization": "Bearer wrong-token"}
        )
        assert r.status_code == 401
