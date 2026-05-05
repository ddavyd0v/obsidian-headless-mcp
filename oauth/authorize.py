import html
import secrets
import time
from urllib.parse import urlencode

from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response

from .config import OAuthConfig
from .storage import PendingAuth, Storage


PENDING_AUTH_TTL_SECONDS = 600
MAX_FAILED_ATTEMPTS = 5
INITIAL_LOCKOUT_SECONDS = 5
MAX_LOCKOUT_ESCALATIONS = 10


_lockout_state: dict[str, dict] = {}


def _is_locked_out(key: str) -> tuple[bool, int]:
    state = _lockout_state.get(key)
    if not state:
        return False, 0
    if state["locked_until"] > time.time():
        return True, int(state["locked_until"] - time.time())
    return False, 0


def _record_failure(key: str) -> None:
    state = _lockout_state.setdefault(
        key, {"failures": 0, "escalations": 0, "locked_until": 0}
    )
    state["failures"] += 1
    if state["failures"] >= MAX_FAILED_ATTEMPTS:
        escalation = min(state["escalations"], MAX_LOCKOUT_ESCALATIONS)
        lockout = INITIAL_LOCKOUT_SECONDS * (2 ** escalation)
        state["locked_until"] = time.time() + lockout
        state["escalations"] += 1
        state["failures"] = 0


def _record_success(key: str) -> None:
    _lockout_state.pop(key, None)


def _render_form(code: str, csrf: str, error: str = "") -> HTMLResponse:
    err_html = (
        f'<p class="error">{html.escape(error)}</p>' if error else ""
    )
    body = f"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8">
<title>Obsidian MCP — Authorize</title>
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; form-action 'self'">
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  body {{ font-family: system-ui, sans-serif; max-width: 420px; margin: 80px auto; padding: 0 20px; color: #222; }}
  h1 {{ font-size: 1.4rem; }}
  p {{ line-height: 1.5; }}
  form {{ display: flex; flex-direction: column; gap: 12px; }}
  input[type=password] {{ padding: 10px; font-size: 1rem; border: 1px solid #999; border-radius: 4px; }}
  button {{ padding: 10px; font-size: 1rem; background: #222; color: white; border: 0; border-radius: 4px; cursor: pointer; }}
  button:hover {{ background: #444; }}
  .error {{ color: #b00; }}
  .hidden {{ position: absolute; opacity: 0; pointer-events: none; height: 0; }}
</style>
</head><body>
<h1>Obsidian MCP</h1>
<p>Enter the server password to grant access to your vault.</p>
{err_html}
<form method="POST" action="/authorize" autocomplete="on">
  <input type="hidden" name="code" value="{html.escape(code)}">
  <input type="hidden" name="csrf" value="{html.escape(csrf)}">
  <input class="hidden" type="text" name="username" value="obsidian-mcp" autocomplete="username" tabindex="-1" aria-hidden="true">
  <input type="password" name="password" placeholder="Password" autocomplete="current-password" autofocus required>
  <button type="submit">Authorize</button>
</form>
</body></html>
"""
    return HTMLResponse(
        body,
        headers={
            "Cache-Control": "no-store",
            "Pragma": "no-cache",
        },
    )


def _bad_request(message: str) -> Response:
    return Response(
        f"Bad request: {message}", status_code=400, media_type="text/plain"
    )


def make_authorize_routes(cfg: OAuthConfig, storage: Storage):
    async def authorize_get(request: Request) -> Response:
        params = request.query_params
        client_id = params.get("client_id")
        redirect_uri = params.get("redirect_uri")
        response_type = params.get("response_type")
        code_challenge = params.get("code_challenge")
        code_challenge_method = params.get("code_challenge_method")
        state = params.get("state")
        scope = params.get("scope")
        resource = params.get("resource")

        if not client_id:
            return _bad_request("missing client_id")
        if response_type != "code":
            return _bad_request("response_type must be 'code'")
        if not code_challenge:
            return _bad_request("missing code_challenge (PKCE required)")
        if code_challenge_method != "S256":
            return _bad_request("code_challenge_method must be 'S256'")
        if not redirect_uri:
            return _bad_request("missing redirect_uri")

        client = await storage.get_client(client_id)
        if client is None:
            return _bad_request("unknown client_id")
        if redirect_uri not in client.redirect_uris:
            return _bad_request("redirect_uri does not match registered URIs")

        code = secrets.token_urlsafe(32)
        csrf = secrets.token_urlsafe(32)
        await storage.add_pending_auth(
            PendingAuth(
                code=code,
                client_id=client_id,
                redirect_uri=redirect_uri,
                code_challenge=code_challenge,
                code_challenge_method=code_challenge_method,
                state=state,
                resource=resource,
                scope=scope,
                csrf=csrf,
                approved=False,
                expires_at=int(time.time()) + PENDING_AUTH_TTL_SECONDS,
            )
        )
        return _render_form(code, csrf)

    async def authorize_post(request: Request) -> Response:
        form = await request.form()
        code = form.get("code") or ""
        csrf = form.get("csrf") or ""
        password = form.get("password") or ""

        if not code:
            return _bad_request("missing code")

        pending = await storage.get_pending_auth(code)
        if pending is None or pending.expires_at < int(time.time()):
            return _bad_request("authorization request not found or expired")

        lockout_key = pending.client_id
        locked, retry_after = _is_locked_out(lockout_key)
        if locked:
            return Response(
                f"Too many attempts; retry after {retry_after}s",
                status_code=429,
                headers={"Retry-After": str(retry_after)},
                media_type="text/plain",
            )

        # CSRF first (constant-time), then password (constant-time).
        csrf_ok = secrets.compare_digest(str(csrf), pending.csrf)
        password_ok = secrets.compare_digest(str(password), cfg.user_password)

        if not (csrf_ok and password_ok):
            _record_failure(lockout_key)
            new_csrf = secrets.token_urlsafe(32)
            await storage.rotate_pending_csrf(code, new_csrf)
            return _render_form(code, new_csrf, error="Incorrect password.")

        _record_success(lockout_key)
        await storage.mark_pending_approved(code)

        redirect_params = {"code": code}
        if pending.state is not None:
            redirect_params["state"] = pending.state
        sep = "&" if "?" in pending.redirect_uri else "?"
        target = f"{pending.redirect_uri}{sep}{urlencode(redirect_params)}"
        return RedirectResponse(target, status_code=302)

    return authorize_get, authorize_post
