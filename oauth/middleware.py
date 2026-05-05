import secrets
import time

from .config import OAuthConfig
from .storage import Storage


PUBLIC_EXACT_PATHS = frozenset({"/authorize", "/register", "/token"})
PUBLIC_PATH_PREFIXES = ("/.well-known/",)


def _is_public_path(path: str) -> bool:
    if path in PUBLIC_EXACT_PATHS:
        return True
    return any(path.startswith(p) for p in PUBLIC_PATH_PREFIXES)


def _matches_static_token(header_token: str, cfg: OAuthConfig) -> bool:
    if not cfg.static_api_token:
        return False
    a = header_token.encode("utf-8")
    b = cfg.static_api_token.encode("utf-8")
    if len(a) != len(b):
        return False
    return secrets.compare_digest(a, b)


class OAuthMiddleware:
    """ASGI middleware enforcing OAuth bearer auth on MCP requests.

    Pass-through paths: /.well-known/*, /authorize, /register, /token.
    Everything else requires either a valid OAuth-issued bearer token
    or (if API_TOKEN is set) the static API_TOKEN as a bearer.
    """

    def __init__(self, app, cfg: OAuthConfig, storage: Storage):
        self.app = app
        self.cfg = cfg
        self.storage = storage

    async def __call__(self, scope, receive, send):
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")

        if not self.cfg.enabled or _is_public_path(path):
            scope = self._normalize_host(scope)
            await self.app(scope, receive, send)
            return

        headers = scope.get("headers", [])
        auth_header = next(
            (v for k, v in headers if k.lower() == b"authorization"), None
        )
        token = None
        if auth_header:
            try:
                decoded = auth_header.decode("latin-1").strip()
            except Exception:
                decoded = ""
            if decoded.lower().startswith("bearer "):
                token = decoded[7:].strip()

        if not token:
            await self._send_401(send, error="invalid_request")
            return

        if _matches_static_token(token, self.cfg):
            scope = self._normalize_host(scope)
            await self.app(scope, receive, send)
            return

        record = await self.storage.get_access_token(token)
        if record is None:
            await self._send_401(send, error="invalid_token")
            return
        if record.expires_at < int(time.time()):
            await self.storage.delete_access_token(token)
            await self._send_401(send, error="invalid_token")
            return

        scope = self._normalize_host(scope)
        await self.app(scope, receive, send)

    def _normalize_host(self, scope):
        """FastMCP enables DNS rebinding protection by default.

        Replace the Host header with localhost so the inner app accepts the
        request. (Public-facing auth is enforced by this middleware.)
        """
        scope = dict(scope)
        new_headers = [(k, v) for k, v in scope.get("headers", []) if k.lower() != b"host"]
        new_headers.append((b"host", b"localhost"))
        scope["headers"] = new_headers
        return scope

    async def _send_401(self, send, error: str = "invalid_token") -> None:
        resource_metadata = f"{self.cfg.public_url.rstrip('/')}/.well-known/oauth-protected-resource"
        www_auth = (
            f'Bearer resource_metadata="{resource_metadata}", error="{error}"'
        )
        await send(
            {
                "type": "http.response.start",
                "status": 401,
                "headers": [
                    (b"www-authenticate", www_auth.encode("ascii")),
                    (b"content-type", b"application/json"),
                ],
            }
        )
        body = (
            b'{"error":"' + error.encode("ascii") + b'",'
            b'"resource_metadata":"' + resource_metadata.encode("ascii") + b'"}'
        )
        await send({"type": "http.response.body", "body": body})
