# MCP Server OAuth for Azure + Microsoft Entra ID

A complete guide and reference implementation for deploying MCP (Model Context Protocol) servers on Azure Container Apps with Microsoft Entra ID authentication, compatible with Cursor IDE.

## The Problem

The MCP specification requires OAuth support via RFC 8414, RFC 7591, and RFC 8707. Microsoft Entra ID doesn't support any of these. Cursor IDE (the primary MCP client) strictly enforces all of them. This repo provides the compatibility layer that bridges the gap.

## Who This Is For

- **Engineers** building MCP servers that will be deployed to Azure and accessed via Cursor IDE
- **AI coding agents** (Claude, GPT, etc.) operating in Cursor or similar IDEs, tasked with adding OAuth/Entra ID authentication to MCP servers

## What's In This Repo

```
docs/
├── README.md                          ← You are here
├── azure-mcp-oauth-guide.md           ← Step-by-step deployment guide
├── lessons-learned.md                 ← Gotchas, decision records, debugging playbook
└── reference/
    ├── oauth_compat.py                ← Drop-in OAuth compatibility layer
    ├── identity_middleware.py          ← Drop-in identity extraction middleware
    ├── example_server.py              ← Minimal wiring example
    └── requirements.txt               ← Python dependencies
```

### Start Here

| I want to... | Read this |
|---|---|
| Understand the architecture and set up from scratch | [azure-mcp-oauth-guide.md](azure-mcp-oauth-guide.md) |
| Know what went wrong and why, so I don't repeat it | [lessons-learned.md](lessons-learned.md) |
| Copy working code into my project | [reference/](reference/) |
| Debug a broken OAuth flow | [lessons-learned.md, Section 5](lessons-learned.md#5-the-debugging-playbook) |

## Quick Start

### 1. Prerequisites

- An Azure Container App with your MCP server deployed
- A Microsoft Entra ID app registration with:
  - Redirect URI: `cursor://anysphere.cursor-mcp/oauth/callback` (under "Mobile and desktop")
  - Exposed API scope: `access_as_user`
  - Public client flows: **Enabled**

### 2. Add the OAuth Layer to Your Server

Copy `reference/oauth_compat.py` and `reference/identity_middleware.py` into your project, then wire them in:

```python
from oauth_compat import OAuthCompatConfig, OAuthCompatEndpoints
from identity_middleware import IdentityMiddleware

# Get the Starlette app from your FastMCP server
app = mcp.streamable_http_app()

# Add middleware
app.add_middleware(IdentityMiddleware)

# Add OAuth endpoints
config = OAuthCompatConfig.from_env()
oauth = OAuthCompatEndpoints(config)

app.add_route("/.well-known/oauth-protected-resource", oauth.protected_resource, methods=["GET"])
app.add_route("/.well-known/oauth-authorization-server", oauth.authorization_server, methods=["GET"])
app.add_route("/oauth/register", oauth.client_registration, methods=["POST"])
app.add_route("/oauth/authorize", oauth.authorize_proxy, methods=["GET"])
app.add_route("/oauth/token", oauth.token_proxy, methods=["POST"])
```

See [reference/example_server.py](reference/example_server.py) for a complete minimal example.

### 3. Configure Azure

```bash
# Set Easy Auth to AllowAnonymous (REQUIRED — see guide for why)
az containerapp auth update \
  --name <app> --resource-group <rg> \
  --unauthenticated-client-action AllowAnonymous

# Set environment variables
az containerapp update \
  --name <app> --resource-group <rg> \
  --set-env-vars \
    "OAUTH_RESOURCE_URL=https://<app>.azurecontainerapps.io" \
    "OAUTH_TENANT_ID=<tenant-id>" \
    "OAUTH_CLIENT_ID=<client-id>"
```

### 4. Configure Cursor

```json
{
  "mcpServers": {
    "your-server": {
      "url": "https://<app>.azurecontainerapps.io/mcp",
      "headers": {
        "Accept": "application/json, text/event-stream"
      }
    }
  }
}
```

### 5. Verify

```bash
# All five should succeed before testing in Cursor
curl -s https://<app>/health                                          # → 200
curl -s https://<app>/.well-known/oauth-protected-resource | jq .     # → 200
curl -s https://<app>/.well-known/oauth-authorization-server | jq .   # → 200
curl -s -X POST https://<app>/oauth/register \
  -H "Content-Type: application/json" \
  -d '{}' | jq .                                                      # → 201
curl -D - -X POST https://<app>/mcp                                   # → 401 + WWW-Authenticate
```

## AI Agent Instructions

If you are an AI agent tasked with adding Entra ID OAuth to an MCP server, read [lessons-learned.md, Section 8](lessons-learned.md#8-ai-agent-instructions) first. It contains:

- Pre-flight checklist (what to verify before writing code)
- Implementation checklist (exact order of operations)
- Common mistakes to avoid (7 specific DO NOTs)
- Testing sequence (verify in this exact order)

## How It Works (30-Second Version)

```
Cursor hits /mcp
  → Your middleware returns 401 + WWW-Authenticate header
  → Cursor fetches /.well-known/oauth-protected-resource (your endpoint)
  → Cursor fetches /.well-known/oauth-authorization-server (your proxy of Microsoft's OIDC)
  → Cursor POSTs /oauth/register (your mock — returns your pre-configured client_id)
  → Cursor redirects to /oauth/authorize (your proxy — rewrites scope, 302s to Microsoft)
  → User signs in at Microsoft
  → Microsoft redirects back to Cursor with auth code
  → Cursor POSTs /oauth/token (your proxy — rewrites scope, forwards to Microsoft)
  → Cursor gets access token, calls /mcp with Bearer token
  → Easy Auth validates token, injects X-MS-CLIENT-PRINCIPAL headers
  → Your middleware extracts user identity, request proceeds
```

## Source

GitHub: **[REPO URL — replace after repo creation]**

## License

MIT
