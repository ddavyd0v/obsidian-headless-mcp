import secrets
import uuid
from urllib.parse import urlparse

from starlette.requests import Request
from starlette.responses import JSONResponse

from .storage import Client, Storage


MAX_REDIRECT_URIS = 5
MAX_URI_LENGTH = 2048


def _is_valid_redirect_uri(uri: str) -> bool:
    if not uri or len(uri) > MAX_URI_LENGTH:
        return False
    try:
        parsed = urlparse(uri)
    except ValueError:
        return False
    if parsed.scheme == "https":
        return bool(parsed.netloc)
    if parsed.scheme == "http":
        return parsed.hostname in ("localhost", "127.0.0.1", "::1")
    return False


def _error(code: str, description: str, status: int = 400) -> JSONResponse:
    return JSONResponse(
        {"error": code, "error_description": description}, status_code=status
    )


def make_register_route(storage: Storage):
    async def register(request: Request) -> JSONResponse:
        try:
            body = await request.json()
        except Exception:
            return _error("invalid_client_metadata", "Body must be JSON")

        if not isinstance(body, dict):
            return _error("invalid_client_metadata", "Body must be a JSON object")

        redirect_uris = body.get("redirect_uris")
        if not isinstance(redirect_uris, list) or not redirect_uris:
            return _error(
                "invalid_redirect_uri",
                "redirect_uris must be a non-empty array",
            )
        if len(redirect_uris) > MAX_REDIRECT_URIS:
            return _error(
                "invalid_redirect_uri",
                f"At most {MAX_REDIRECT_URIS} redirect_uris allowed",
            )
        for uri in redirect_uris:
            if not isinstance(uri, str) or not _is_valid_redirect_uri(uri):
                return _error(
                    "invalid_redirect_uri", f"Invalid redirect_uri: {uri!r}"
                )

        client_name = body.get("client_name")
        if client_name is not None and not isinstance(client_name, str):
            return _error("invalid_client_metadata", "client_name must be a string")

        client = Client(
            client_id=str(uuid.uuid4()),
            client_secret=secrets.token_hex(32),
            client_name=client_name,
            redirect_uris=list(redirect_uris),
            token_endpoint_auth_method="client_secret_post",
        )
        await storage.add_client(client)

        return JSONResponse(
            {
                "client_id": client.client_id,
                "client_secret": client.client_secret,
                "client_name": client.client_name,
                "redirect_uris": client.redirect_uris,
                "token_endpoint_auth_method": client.token_endpoint_auth_method,
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
            },
            status_code=201,
        )

    return register
