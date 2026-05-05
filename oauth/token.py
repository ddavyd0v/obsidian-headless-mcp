import base64
import hashlib
import secrets
import time

from starlette.requests import Request
from starlette.responses import JSONResponse

from .config import OAuthConfig
from .storage import AccessToken, RefreshToken, Storage


def _error(code: str, description: str, status: int = 400) -> JSONResponse:
    return JSONResponse(
        {"error": code, "error_description": description},
        status_code=status,
        headers={"Cache-Control": "no-store"},
    )


def _verify_pkce_s256(verifier: str, challenge: str) -> bool:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    expected = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return secrets.compare_digest(expected, challenge)


async def _issue_tokens(
    cfg: OAuthConfig, storage: Storage, client_id: str, scope: str | None
) -> dict:
    now = int(time.time())
    access = secrets.token_urlsafe(32)
    refresh = secrets.token_urlsafe(32)
    access_expires_at = now + cfg.token_ttl_seconds
    refresh_expires_at = now + cfg.refresh_ttl_seconds

    await storage.add_access_token(
        AccessToken(
            token=access,
            client_id=client_id,
            scope=scope,
            expires_at=access_expires_at,
        )
    )
    await storage.add_refresh_token(
        RefreshToken(
            token=refresh,
            client_id=client_id,
            access_token=access,
            refresh_expires_at=refresh_expires_at,
        )
    )
    return {
        "access_token": access,
        "token_type": "Bearer",
        "expires_in": cfg.token_ttl_seconds,
        "refresh_token": refresh,
        "scope": scope or "mcp",
    }


def make_token_route(cfg: OAuthConfig, storage: Storage):
    async def token(request: Request) -> JSONResponse:
        form = await request.form()
        grant_type = form.get("grant_type")

        if grant_type == "authorization_code":
            return await _handle_authorization_code(form, cfg, storage)
        if grant_type == "refresh_token":
            return await _handle_refresh_token(form, cfg, storage)
        return _error("unsupported_grant_type", f"Unsupported grant_type: {grant_type!r}")

    return token


async def _handle_authorization_code(form, cfg: OAuthConfig, storage: Storage) -> JSONResponse:
    code = form.get("code") or ""
    client_id = form.get("client_id") or ""
    redirect_uri = form.get("redirect_uri") or ""
    code_verifier = form.get("code_verifier") or ""
    client_secret = form.get("client_secret")

    if not code or not client_id or not redirect_uri or not code_verifier:
        return _error("invalid_request", "Missing required parameter")

    client = await storage.get_client(client_id)
    if client is None:
        return _error("invalid_client", "Unknown client", status=401)

    if client.token_endpoint_auth_method == "client_secret_post":
        if not client_secret or not secrets.compare_digest(
            str(client_secret), client.client_secret
        ):
            return _error("invalid_client", "Bad client_secret", status=401)

    pending = await storage.consume_pending_auth(str(code))
    if pending is None:
        return _error("invalid_grant", "Authorization code not found or already used")
    if pending.expires_at < int(time.time()):
        return _error("invalid_grant", "Authorization code expired")
    if not pending.approved:
        return _error("invalid_grant", "Authorization not approved")
    if pending.client_id != client_id:
        return _error("invalid_grant", "client_id mismatch")
    if pending.redirect_uri != redirect_uri:
        return _error("invalid_grant", "redirect_uri mismatch")
    if not _verify_pkce_s256(str(code_verifier), pending.code_challenge):
        return _error("invalid_grant", "PKCE verification failed")

    payload = await _issue_tokens(cfg, storage, client_id, pending.scope)
    return JSONResponse(payload, headers={"Cache-Control": "no-store"})


async def _handle_refresh_token(form, cfg: OAuthConfig, storage: Storage) -> JSONResponse:
    refresh_token = form.get("refresh_token") or ""
    client_id = form.get("client_id") or ""
    client_secret = form.get("client_secret")

    if not refresh_token or not client_id:
        return _error("invalid_request", "Missing required parameter")

    client = await storage.get_client(client_id)
    if client is None:
        return _error("invalid_client", "Unknown client", status=401)
    if client.token_endpoint_auth_method == "client_secret_post":
        if not client_secret or not secrets.compare_digest(
            str(client_secret), client.client_secret
        ):
            return _error("invalid_client", "Bad client_secret", status=401)

    record = await storage.consume_refresh_token(str(refresh_token))
    if record is None:
        return _error("invalid_grant", "Refresh token not found or already used")
    if record.refresh_expires_at < int(time.time()):
        return _error("invalid_grant", "Refresh token expired")
    if record.client_id != client_id:
        return _error("invalid_grant", "client_id mismatch")

    # Invalidate the old access token tied to this refresh.
    await storage.delete_access_token(record.access_token)

    # Rotate: issue a brand-new pair, but keep the original refresh expiry budget.
    now = int(time.time())
    access = secrets.token_urlsafe(32)
    new_refresh = secrets.token_urlsafe(32)
    access_expires_at = now + cfg.token_ttl_seconds

    await storage.add_access_token(
        AccessToken(
            token=access,
            client_id=client_id,
            scope=None,
            expires_at=access_expires_at,
        )
    )
    await storage.add_refresh_token(
        RefreshToken(
            token=new_refresh,
            client_id=client_id,
            access_token=access,
            refresh_expires_at=record.refresh_expires_at,
        )
    )

    return JSONResponse(
        {
            "access_token": access,
            "token_type": "Bearer",
            "expires_in": cfg.token_ttl_seconds,
            "refresh_token": new_refresh,
            "scope": "mcp",
        },
        headers={"Cache-Control": "no-store"},
    )
