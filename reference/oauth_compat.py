"""
OAuth Compatibility Layer for MCP Servers on Azure with Microsoft Entra ID

This module bridges the gap between the MCP OAuth specification (as implemented
by Cursor IDE) and Microsoft Entra ID. It provides six endpoint handlers that
you wire into your Starlette/FastAPI application.

Endpoints provided:
  1. GET  /.well-known/oauth-protected-resource   → RFC 9728 metadata
  2. GET  /.well-known/oauth-authorization-server  → RFC 8414 metadata (proxied from OIDC)
  3. POST /oauth/register                          → RFC 7591 mock client registration
  4. GET  /oauth/authorize                         → Scope-rewriting proxy (302 redirect)
  5. POST /oauth/token                             → Scope-rewriting proxy (forwarded POST)

Why this exists:
  - Microsoft Entra ID uses OIDC discovery, not RFC 8414
  - Microsoft Entra ID does not support dynamic client registration (RFC 7591)
  - Microsoft Entra ID v2.0 requires fully qualified scopes (api://<client-id>/<scope>)
    and does not support the RFC 8707 `resource` parameter
  - Cursor IDE requires all of the above

Usage:
  config = OAuthCompatConfig.from_env()
  endpoints = OAuthCompatEndpoints(config)

  app.add_route("/.well-known/oauth-protected-resource", endpoints.protected_resource, methods=["GET"])
  app.add_route("/.well-known/oauth-authorization-server", endpoints.authorization_server, methods=["GET"])
  app.add_route("/oauth/register", endpoints.client_registration, methods=["POST"])
  app.add_route("/oauth/authorize", endpoints.authorize_proxy, methods=["GET"])
  app.add_route("/oauth/token", endpoints.token_proxy, methods=["POST"])

Required environment variables:
  OAUTH_RESOURCE_URL  - Full URL of your MCP server (e.g., https://ca-myapp.azurecontainerapps.io)
  OAUTH_TENANT_ID     - Microsoft Entra ID tenant/directory ID
  OAUTH_CLIENT_ID     - Microsoft Entra ID client/application ID

Optional environment variables:
  OAUTH_SCOPES          - Comma-separated scopes (default: access_as_user)
  OAUTH_ISSUER_BASE_URL - Issuer base URL (default: https://login.microsoftonline.com)

Dependencies:
  pip install httpx starlette

License: MIT
"""

import os
import logging
from dataclasses import dataclass, field
from typing import List, Optional
from urllib.parse import urlencode, parse_qs

import httpx
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse

logger = logging.getLogger(__name__)


# =============================================================================
# Configuration
# =============================================================================

@dataclass
class OAuthCompatConfig:
    """
    Configuration for the OAuth compatibility layer.

    All values should come from environment variables in production.
    """
    resource_url: str          # https://your-app.azurecontainerapps.io
    tenant_id: str             # Entra ID tenant/directory ID
    client_id: str             # Entra ID client/application ID
    scopes: List[str] = field(default_factory=lambda: ["access_as_user"])
    issuer_base_url: str = "https://login.microsoftonline.com"

    def is_configured(self) -> bool:
        """Check if all required fields are non-empty."""
        return bool(
            self.resource_url and self.resource_url.strip()
            and self.tenant_id and self.tenant_id.strip()
            and self.client_id and self.client_id.strip()
        )

    @classmethod
    def from_env(cls) -> "OAuthCompatConfig":
        """
        Load configuration from environment variables.

        Environment variables:
          OAUTH_RESOURCE_URL     (required in production)
          OAUTH_TENANT_ID        (required in production)
          OAUTH_CLIENT_ID        (required in production)
          OAUTH_SCOPES           (optional, comma-separated, default: access_as_user)
          OAUTH_ISSUER_BASE_URL  (optional, default: https://login.microsoftonline.com)
        """
        scopes_str = os.environ.get("OAUTH_SCOPES", "access_as_user").strip()
        scopes = [s.strip() for s in scopes_str.split(",") if s.strip()] or ["access_as_user"]

        config = cls(
            resource_url=os.environ.get("OAUTH_RESOURCE_URL", "").strip(),
            tenant_id=os.environ.get("OAUTH_TENANT_ID", "").strip(),
            client_id=os.environ.get("OAUTH_CLIENT_ID", "").strip(),
            scopes=scopes,
            issuer_base_url=os.environ.get(
                "OAUTH_ISSUER_BASE_URL", "https://login.microsoftonline.com"
            ).strip(),
        )

        if config.is_configured():
            logger.info("OAuth compat layer configured for %s", config.resource_url)
        else:
            logger.warning(
                "OAuth compat layer not fully configured. "
                "Set OAUTH_RESOURCE_URL, OAUTH_TENANT_ID, and OAUTH_CLIENT_ID."
            )

        return config


# =============================================================================
# Helpers
# =============================================================================

def _qualify_scopes(scopes: List[str], client_id: str) -> List[str]:
    """
    Convert short-form scopes to Microsoft Entra ID fully qualified format.

    Microsoft v2.0 requires custom scopes in the format: api://<client-id>/<scope>
    Standard OIDC scopes (openid, profile, email, offline_access) are left as-is.
    """
    result = []
    for scope in scopes:
        if scope in ("openid", "profile", "email", "offline_access"):
            result.append(scope)
        elif scope.startswith("api://"):
            result.append(scope)
        else:
            result.append(f"api://{client_id}/{scope}")
    return result


def _rewrite_scope_param(scope_string: str, client_id: str) -> str:
    """Rewrite a space-separated scope string to fully qualified format."""
    return " ".join(_qualify_scopes(scope_string.split(), client_id))


async def _fetch_oidc_metadata(issuer_url: str) -> Optional[dict]:
    """
    Fetch OpenID Connect discovery metadata from Microsoft Entra ID.

    Args:
        issuer_url: e.g., https://login.microsoftonline.com/<tenant>/v2.0
    """
    oidc_url = f"{issuer_url.rstrip('/')}/.well-known/openid-configuration"
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(oidc_url)
            if response.status_code == 200:
                return response.json()
            logger.warning("OIDC metadata fetch failed: %s → %d", oidc_url, response.status_code)
            return None
    except Exception as e:
        logger.error("OIDC metadata fetch error: %s → %s", oidc_url, e)
        return None


def _service_unavailable(message: str) -> JSONResponse:
    """Return a 503 Service Unavailable response."""
    return JSONResponse(
        status_code=503,
        content={"error": "Service Unavailable", "message": message},
        media_type="application/json",
    )


# =============================================================================
# Endpoint Handlers
# =============================================================================

class OAuthCompatEndpoints:
    """
    All six OAuth compatibility endpoints in a single class.

    Usage:
        config = OAuthCompatConfig.from_env()
        endpoints = OAuthCompatEndpoints(config)

        app.add_route("/.well-known/oauth-protected-resource", endpoints.protected_resource, methods=["GET"])
        app.add_route("/.well-known/oauth-authorization-server", endpoints.authorization_server, methods=["GET"])
        app.add_route("/oauth/register", endpoints.client_registration, methods=["POST"])
        app.add_route("/oauth/authorize", endpoints.authorize_proxy, methods=["GET"])
        app.add_route("/oauth/token", endpoints.token_proxy, methods=["POST"])
    """

    def __init__(self, config: OAuthCompatConfig):
        self.config = config
        self._oidc_cache: dict = {}

    # -------------------------------------------------------------------------
    # 1. RFC 9728 — Protected Resource Metadata
    # -------------------------------------------------------------------------

    async def protected_resource(self, request: Request) -> JSONResponse:
        """
        GET /.well-known/oauth-protected-resource

        Tells MCP clients which authorization server to use and what scopes
        are supported. This is the entry point for OAuth discovery.

        IMPORTANT: authorization_servers points to YOUR server (not Microsoft).
        Your server hosts the RFC 8414 metadata proxy at
        /.well-known/oauth-authorization-server.
        """
        if not self.config.is_configured():
            return _service_unavailable("OAuth is not configured.")

        return JSONResponse(
            status_code=200,
            content={
                "resource": self.config.resource_url,
                "authorization_servers": [self.config.resource_url.rstrip("/")],
                "token_endpoint_auth_methods_supported": ["none"],
                "scopes_supported": _qualify_scopes(self.config.scopes, self.config.client_id),
                "bearer_methods_supported": ["header"],
            },
            media_type="application/json",
        )

    # -------------------------------------------------------------------------
    # 2. RFC 8414 — Authorization Server Metadata (proxied from OIDC)
    # -------------------------------------------------------------------------

    async def authorization_server(self, request: Request) -> JSONResponse:
        """
        GET /.well-known/oauth-authorization-server

        Fetches Microsoft's OIDC discovery metadata and transforms it to
        RFC 8414 format. Caches the OIDC response in memory.

        IMPORTANT: authorization_endpoint and token_endpoint point to YOUR
        proxy endpoints (/oauth/authorize and /oauth/token), not Microsoft's
        directly. This is what enables scope rewriting.
        """
        if not self.config.is_configured():
            return _service_unavailable("OAuth is not configured.")

        issuer_url = f"{self.config.issuer_base_url.rstrip('/')}/{self.config.tenant_id}/v2.0"

        # Fetch and cache OIDC metadata
        if issuer_url not in self._oidc_cache:
            oidc = await _fetch_oidc_metadata(issuer_url)
            if oidc:
                self._oidc_cache[issuer_url] = oidc

        oidc = self._oidc_cache.get(issuer_url)
        if not oidc:
            return _service_unavailable("Unable to fetch authorization server metadata.")

        base_url = self.config.resource_url.rstrip("/")

        metadata = {
            "issuer": oidc.get("issuer"),
            "authorization_endpoint": f"{base_url}/oauth/authorize",
            "token_endpoint": f"{base_url}/oauth/token",
            "jwks_uri": oidc.get("jwks_uri"),
            "registration_endpoint": f"{base_url}/oauth/register",
            "scopes_supported": _qualify_scopes(self.config.scopes, self.config.client_id),
            "response_types_supported": oidc.get("response_types_supported", ["code"]),
            "response_modes_supported": oidc.get("response_modes_supported", ["query"]),
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "token_endpoint_auth_methods_supported": ["none"],
            "code_challenge_methods_supported": ["S256"],
        }

        # Optional OIDC fields
        for key in ("userinfo_endpoint", "end_session_endpoint", "device_authorization_endpoint"):
            if key in oidc:
                metadata[key] = oidc[key]

        return JSONResponse(status_code=200, content=metadata, media_type="application/json")

    # -------------------------------------------------------------------------
    # 3. RFC 7591 — Dynamic Client Registration (mock)
    # -------------------------------------------------------------------------

    async def client_registration(self, request: Request) -> JSONResponse:
        """
        POST /oauth/register

        Cursor requires dynamic client registration (RFC 7591). Microsoft
        Entra ID doesn't support it. This mock endpoint returns the
        pre-configured client_id for any registration request.

        All MCP clients get the same Entra ID app registration — this is
        by design (one app per MCP server).
        """
        if not self.config.is_configured():
            return _service_unavailable("OAuth is not configured.")

        try:
            body = await request.json()
            redirect_uris = body.get("redirect_uris", [])
            client_name = body.get("client_name", "MCP Client")
            logger.info("Client registration: name=%s, redirect_uris=%s", client_name, redirect_uris)
        except Exception:
            redirect_uris = []

        return JSONResponse(
            status_code=201,  # MUST be 201 per RFC 7591
            content={
                "client_id": self.config.client_id,
                "client_id_issued_at": 0,
                "token_endpoint_auth_method": "none",
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
                "redirect_uris": redirect_uris or ["cursor://anysphere.cursor-mcp/oauth/callback"],
            },
            media_type="application/json",
        )

    # -------------------------------------------------------------------------
    # 4. Authorize Proxy — Scope Rewriter (302 redirect)
    # -------------------------------------------------------------------------

    async def authorize_proxy(self, request: Request) -> RedirectResponse:
        """
        GET /oauth/authorize

        Intercepts the authorization request from Cursor, rewrites the scope
        from short form (access_as_user) to Microsoft's fully qualified format
        (api://<client-id>/access_as_user), removes the unsupported `resource`
        parameter (RFC 8707), and issues a 302 redirect to Microsoft.
        """
        params = dict(request.query_params)

        if "scope" in params:
            params["scope"] = _rewrite_scope_param(params["scope"], self.config.client_id)

        params.pop("resource", None)

        ms_authorize = (
            f"{self.config.issuer_base_url.rstrip('/')}"
            f"/{self.config.tenant_id}/oauth2/v2.0/authorize"
        )
        redirect_url = f"{ms_authorize}?{urlencode(params)}"

        logger.info("Authorize proxy: scope=%s", params.get("scope", ""))
        return RedirectResponse(url=redirect_url, status_code=302)

    # -------------------------------------------------------------------------
    # 5. Token Proxy — Scope Rewriter (forwarded POST)
    # -------------------------------------------------------------------------

    async def token_proxy(self, request: Request) -> JSONResponse:
        """
        POST /oauth/token

        Intercepts the token exchange request from Cursor, rewrites the scope,
        removes the `resource` parameter, and forwards to Microsoft's token
        endpoint. Returns Microsoft's response as-is.
        """
        body = await request.body()
        params = parse_qs(body.decode(), keep_blank_values=True)
        flat = {k: v[0] if len(v) == 1 else v for k, v in params.items()}

        if "scope" in flat:
            flat["scope"] = _rewrite_scope_param(flat["scope"], self.config.client_id)

        flat.pop("resource", None)

        ms_token = (
            f"{self.config.issuer_base_url.rstrip('/')}"
            f"/{self.config.tenant_id}/oauth2/v2.0/token"
        )

        logger.info("Token proxy: scope=%s", flat.get("scope", ""))

        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                ms_token,
                data=flat,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )

        return JSONResponse(
            status_code=response.status_code,
            content=response.json(),
            media_type="application/json",
        )
