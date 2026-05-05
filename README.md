# Obsidian Headless + MCP Server

Complete deployment of Obsidian Headless with a REST API wrapper and MCP server for remote access via HTTPS.

## Architecture

```
Internet
  ↓
Traefik (reverse proxy + SSL/TLS)
  ├─ obsidian-api.votredomaine.com   → Node.js API wrapper
  └─ mcp.votredomaine.com             → Python MCP server
       ↓
Obsidian Headless (syncs with Obsidian Sync service)
       ↓
Your vault files
```

## Services

### 1. **Traefik**
- Reverse proxy with automatic SSL/TLS (Let's Encrypt)
- Routes HTTPS traffic to services

### 2. **Obsidian Headless**
- Synchronizes your vault from command line
- Uses Obsidian Sync for end-to-end encrypted backup
- Stores vault in `./vault` directory

### 3. **Obsidian API** (Node.js)
- REST API wrapper around Obsidian Headless
- Endpoints for file operations, search, sync
- Exposed at `https://obsidian-api.DOMAIN`

### 4. **MCP Server** (Python)
- Model Context Protocol server
- Exposes vault as resources and tools to AI models
- Exposed at `https://mcp.DOMAIN`

## Prerequisites

- Docker & Docker Compose installed on Hostinger
- Obsidian Sync subscription (for encryption & backup)
- Valid domain with DNS pointing to your server
- Obsidian account credentials

## Setup

### 1. Clone/Download Files

Get these files:
```
.
├── docker-compose.yml
├── .env.example → rename to .env
├── obsidian-api.js
├── obsidian_mcp.py
└── vault/          (created automatically)
```

### 2. Configure Environment

Copy `.env.example` to `.env` and fill in:

```bash
ACME_EMAIL=your-email@example.com
DOMAIN=yourdomain.com
OBSIDIAN_EMAIL=your-obsidian-email@example.com
OBSIDIAN_PASSWORD=your-account-password           # Password to login to Obsidian
VAULT_PASSWORD=your-vault-encryption-password    # Encryption password for the vault
VAULT_NAME=Your-Vault-Name                       # Exact vault name in Obsidian Sync
```

**Important:** There are two different passwords:
- **OBSIDIAN_PASSWORD**: Your Obsidian account password (for `ob login`)
- **VAULT_PASSWORD**: Your vault encryption password (found in Obsidian → Settings → Sync → Encryption)

### 3. Deploy

In your Hostinger Docker Compose editor (hPanel):

1. Paste the `docker-compose.yml` content
2. Add environment variables (ACME_EMAIL, DOMAIN, etc.)
3. Deploy

The first start will take a minute as services initialize.

## Endpoints

### REST API
```
GET  /api/files                    # List all files
GET  /api/file/{path}              # Read a file
POST /api/file/{path}              # Write/create a file
GET  /api/search?q={query}         # Search vault
POST /api/sync                     # Trigger sync
GET  /api/sync/status              # Get sync status
GET  /health                       # Health check
```

### MCP Server
- `obsidian://files` - Resource listing all files
- `obsidian://health` - Resource checking vault status
- `read_file()` - Tool to read files
- `write_file()` - Tool to create/modify files
- `append_to_file()` - Tool to append content
- `search_vault()` - Tool to search
- `sync_vault()` - Tool to trigger sync
- `get_sync_status()` - Tool to get sync status

## Usage Examples

### Reading a file via API
```bash
curl https://obsidian-api.yourdomain.com/api/file/notes%2Fmy-note.md
```

### Writing a file via API
```bash
curl -X POST https://obsidian-api.yourdomain.com/api/file/notes%2Fnew.md \
  -H "Content-Type: application/json" \
  -d '{"content": "# My Note\n\nContent here"}'
```

### Using with Claude Code

For local clients (Claude Code, MCP Inspector, curl) you can use the static
`API_TOKEN` as a bearer:

```json
{
  "mcpServers": {
    "obsidian": {
      "url": "https://mcp.yourdomain.com",
      "transport": "http",
      "headers": {
        "Authorization": "Bearer <API_TOKEN>"
      }
    }
  }
}
```

### Using with Claude.ai (custom connector, OAuth 2.1)

The MCP server is its own OAuth 2.1 authorization server. Claude.ai discovers
the metadata, dynamically registers itself, and prompts you for a password —
no manual client setup required.

**Setup:**

1. Set `MCP_USER_PASSWORD` in `.env` to a strong secret. This is the password
   you'll type on the authorization page.
2. Make sure `DOMAIN` is set so the public URL resolves to
   `https://mcp.${DOMAIN}`.
3. Deploy / restart docker compose. Verify the metadata endpoints respond:
   ```bash
   curl https://mcp.yourdomain.com/.well-known/oauth-protected-resource
   curl https://mcp.yourdomain.com/.well-known/oauth-authorization-server
   ```
4. In Claude.ai → **Settings → Connectors → Add custom connector**, paste
   `https://mcp.yourdomain.com` as the server URL.

**What you'll see during the OAuth flow:**

1. Claude.ai opens your browser to `https://mcp.yourdomain.com/authorize?...`.
2. The server renders a single password prompt.
3. You enter `MCP_USER_PASSWORD`. After 5 wrong attempts the form locks out
   with exponential backoff (5s, 10s, 20s, …).
4. The server redirects back to Claude.ai with an authorization code.
5. Claude.ai exchanges the code for an access token (1 hour) and a refresh
   token (14 days). It refreshes silently from then on.

**Environment variables for OAuth:**

| Var | Default | Purpose |
|---|---|---|
| `MCP_AUTH_ENABLED` | `true` | Set `false` to disable OAuth and fall back to `API_TOKEN` only |
| `MCP_USER_PASSWORD` | _(required)_ | The password the user types on `/authorize` |
| `MCP_TOKEN_TTL_SECONDS` | `3600` | Access-token lifetime |
| `MCP_REFRESH_TTL_DAYS` | `14` | Refresh-token lifetime |
| `MCP_PUBLIC_URL` | derived from `DOMAIN` | Used to construct OAuth metadata; required when auth is enabled |
| `MCP_OAUTH_DB_PATH` | `/data/oauth.db` | SQLite DB path inside the container (mounted on the `oauth-data` volume) |

The static `API_TOKEN` continues to work as a bearer alongside OAuth, so
local Claude Code / curl setups don't need to change.

## Troubleshooting

### Obsidian Headless not syncing
- Check credentials in `.env`
- Verify vault name matches exactly
- Check logs: `docker logs obsidian-headless`

### API not responding
- Check if obsidian-headless is running first
- Verify Traefik routing: `docker logs traefik`
- Check DOMAIN environment variable matches your DNS

### SSL certificate issues
- Wait 5 minutes for Let's Encrypt challenge
- Check firewall allows port 80 (for ACME validation)
- Verify ACME_EMAIL is correct

## Security Notes

⚠️ **Important:**
- Keep `.env` file secure (never commit to Git)
- Use strong Obsidian passwords and a strong `MCP_USER_PASSWORD`
- OAuth 2.1 with PKCE is enforced by default for the MCP server (Claude.ai connector flow)
- The static `API_TOKEN` is also accepted as a bearer for local clients
- Obsidian Sync provides end-to-end encryption

## Files Reference

### obsidian-api.js
Express server that wraps Obsidian Headless CLI with REST endpoints.

Features:
- File read/write with directory traversal protection
- Full-text search using `grep`
- Sync management
- CORS enabled

### obsidian_mcp.py
FastMCP server exposing vault as Model Context Protocol resources and tools.

Features:
- Resource for listing files
- Tools for common operations
- Streamable HTTP transport for remote access

## License

MIT
