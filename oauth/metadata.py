from starlette.requests import Request
from starlette.responses import JSONResponse

from .config import OAuthConfig


def protected_resource_metadata(cfg: OAuthConfig) -> dict:
    return {
        "resource": cfg.resource,
        "authorization_servers": [cfg.issuer],
        "scopes_supported": ["mcp"],
        "bearer_methods_supported": ["header"],
    }


def authorization_server_metadata(cfg: OAuthConfig) -> dict:
    return {
        "issuer": cfg.issuer,
        "authorization_endpoint": f"{cfg.issuer}/authorize",
        "token_endpoint": f"{cfg.issuer}/token",
        "registration_endpoint": f"{cfg.issuer}/register",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["client_secret_post", "none"],
        "scopes_supported": ["mcp"],
    }


def make_metadata_routes(cfg: OAuthConfig):
    async def protected_resource(_request: Request) -> JSONResponse:
        return JSONResponse(protected_resource_metadata(cfg))

    async def authorization_server(_request: Request) -> JSONResponse:
        return JSONResponse(authorization_server_metadata(cfg))

    return protected_resource, authorization_server
