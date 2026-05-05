import os
from dataclasses import dataclass


@dataclass(frozen=True)
class OAuthConfig:
    enabled: bool
    user_password: str
    token_ttl_seconds: int
    refresh_ttl_seconds: int
    public_url: str
    db_path: str
    static_api_token: str

    @property
    def issuer(self) -> str:
        return self.public_url.rstrip("/")

    @property
    def resource(self) -> str:
        return self.public_url.rstrip("/")


def load_config() -> OAuthConfig:
    enabled = os.getenv("MCP_AUTH_ENABLED", "true").lower() not in ("0", "false", "no")
    public_url = os.getenv("MCP_PUBLIC_URL", "").strip()
    if enabled and not public_url:
        raise RuntimeError(
            "MCP_PUBLIC_URL is required when MCP_AUTH_ENABLED is true "
            "(e.g. https://mcp.example.com)"
        )
    user_password = os.getenv("MCP_USER_PASSWORD", "").strip()
    if enabled and not user_password:
        raise RuntimeError(
            "MCP_USER_PASSWORD is required when MCP_AUTH_ENABLED is true"
        )
    refresh_ttl_days = int(os.getenv("MCP_REFRESH_TTL_DAYS", "14"))
    return OAuthConfig(
        enabled=enabled,
        user_password=user_password,
        token_ttl_seconds=int(os.getenv("MCP_TOKEN_TTL_SECONDS", "3600")),
        refresh_ttl_seconds=refresh_ttl_days * 24 * 3600,
        public_url=public_url,
        db_path=os.getenv("MCP_OAUTH_DB_PATH", "/data/oauth.db"),
        static_api_token=os.getenv("API_TOKEN", "").strip(),
    )
