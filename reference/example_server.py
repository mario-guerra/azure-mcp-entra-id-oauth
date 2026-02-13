"""
Minimal Example: Wiring the OAuth compatibility layer into an MCP server.

This shows the integration pattern. Replace the placeholder MCP tools
with your actual implementation.

Usage:
  # Set environment variables first (see requirements below)
  uvicorn example_server:app --host 0.0.0.0 --port 8000

Required environment variables:
  OAUTH_RESOURCE_URL=https://your-app.azurecontainerapps.io
  OAUTH_TENANT_ID=your-entra-tenant-id
  OAUTH_CLIENT_ID=your-entra-client-id

License: MIT
"""

from mcp.server.fastmcp import FastMCP
from starlette.requests import Request
from starlette.responses import JSONResponse

from oauth_compat import OAuthCompatConfig, OAuthCompatEndpoints
from identity_middleware import IdentityMiddleware, get_user_email

# =============================================================================
# 1. Create your MCP server as usual
# =============================================================================

mcp = FastMCP("My MCP Server")


@mcp.tool()
async def hello() -> str:
    """A simple tool that greets the authenticated user."""
    email = get_user_email()
    return f"Hello, {email}!"


# =============================================================================
# 2. Get the Starlette app from FastMCP
# =============================================================================

app = mcp.streamable_http_app()


# =============================================================================
# 3. Add identity middleware (MUST be added before routes)
# =============================================================================

app.add_middleware(IdentityMiddleware, dev_bypass=False)


# =============================================================================
# 4. Add OAuth compatibility endpoints
# =============================================================================

config = OAuthCompatConfig.from_env()
oauth = OAuthCompatEndpoints(config)

app.add_route("/.well-known/oauth-protected-resource", oauth.protected_resource, methods=["GET"])
app.add_route("/.well-known/oauth-authorization-server", oauth.authorization_server, methods=["GET"])
app.add_route("/oauth/register", oauth.client_registration, methods=["POST"])
app.add_route("/oauth/authorize", oauth.authorize_proxy, methods=["GET"])
app.add_route("/oauth/token", oauth.token_proxy, methods=["POST"])


# =============================================================================
# 5. Add health check
# =============================================================================

async def health_check(request: Request) -> JSONResponse:
    return JSONResponse({"status": "healthy"})

app.add_route("/health", health_check, methods=["GET"])
