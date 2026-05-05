from contextlib import asynccontextmanager

from starlette.applications import Starlette
from starlette.routing import Mount, Route

from .authorize import make_authorize_routes
from .config import OAuthConfig, load_config
from .metadata import make_metadata_routes
from .middleware import OAuthMiddleware
from .registration import make_register_route
from .storage import Storage
from .token import make_token_route


async def build_app(mcp_asgi_app, cfg: OAuthConfig | None = None):
    """Compose the OAuth-aware ASGI app.

    The MCP streamable HTTP app is mounted at "/" so its existing path layout
    (e.g. /mcp) is preserved. OAuth + .well-known routes are added alongside.
    The whole tree is wrapped in OAuthMiddleware which enforces bearer auth
    on every non-public path.

    FastMCP's streamable HTTP session manager needs its lifespan to run for
    the task group to be initialized, but Starlette's Mount does not propagate
    lifespan events to mounted sub-applications. Chain the inner lifespan
    into the parent so MCP requests work after startup.
    """
    cfg = cfg or load_config()
    storage = Storage(cfg.db_path)
    await storage.init()

    protected_resource, authorization_server = make_metadata_routes(cfg)
    register = make_register_route(storage)
    authorize_get, authorize_post = make_authorize_routes(cfg, storage)
    token = make_token_route(cfg, storage)

    routes = [
        Route(
            "/.well-known/oauth-protected-resource",
            protected_resource,
            methods=["GET"],
        ),
        Route(
            "/.well-known/oauth-authorization-server",
            authorization_server,
            methods=["GET"],
        ),
        Route("/register", register, methods=["POST"]),
        Route("/authorize", authorize_get, methods=["GET"]),
        Route("/authorize", authorize_post, methods=["POST"]),
        Route("/token", token, methods=["POST"]),
        Mount("/", app=mcp_asgi_app),
    ]

    @asynccontextmanager
    async def lifespan(_app):
        async with mcp_asgi_app.router.lifespan_context(mcp_asgi_app):
            yield

    inner = Starlette(routes=routes, lifespan=lifespan)
    return OAuthMiddleware(inner, cfg, storage), storage, cfg
