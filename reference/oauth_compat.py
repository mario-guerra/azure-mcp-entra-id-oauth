"""
OAuth Compatibility Layer for MCP Servers on Azure with Microsoft Entra ID

This module bridges the gap between the MCP OAuth specification (as implemented
by Cursor IDE) and Microsoft Entra ID. It provides five endpoint handlers that
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
import time
import logging
from dataclasses import dataclass, field
from typing import List, Optional, Tuple, Dict, Any, Set
from urllib.parse import urlencode, parse_qs, urlparse

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
    allowed_hosts: Set[str] = field(default_factory=lambda: {"login.microsoftonline.com"})

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

        # Custom host allowlist (comma-separated, default: login.microsoftonline.com)
        allowed_hosts_str = os.environ.get("OAUTH_ALLOWED_HOSTS", "login.microsoftonline.com").strip()
        allowed_hosts = {h.strip() for h in allowed_hosts_str.split(",") if h.strip()}
        
        # Ensure the netloc of the issuer_base_url is also allowed
        issuer_netloc = urlparse(os.environ.get("OAUTH_ISSUER_BASE_URL", "https://login.microsoftonline.com")).netloc
        if issuer_netloc:
            allowed_hosts.add(issuer_netloc)

        config = cls(
            resource_url=os.environ.get("OAUTH_RESOURCE_URL", "").strip(),
            tenant_id=os.environ.get("OAUTH_TENANT_ID", "").strip(),
            client_id=os.environ.get("OAUTH_CLIENT_ID", "").strip(),
            scopes=scopes,
            issuer_base_url=os.environ.get(
                "OAUTH_ISSUER_BASE_URL", "https://login.microsoftonline.com"
            ).strip(),
            allowed_hosts=allowed_hosts,
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

def rewrite_mcp_scopes(scope_string: str, client_id: str) -> str:
    """
    Centralized scope rewriting logic.
    Microsoft v2.0 requires custom scopes in the format: api://<client-id>/<scope>
    Standard OIDC scopes are left as-is.
    """
    scopes = scope_string.split()
    result = []
    for s in scopes:
        if s in ("openid", "profile", "email", "offline_access"):
            result.append(s)
        elif s.startswith("api://"):
            result.append(s)
        else:
            result.append(f"api://{client_id}/{s}")
    return " ".join(result)


def _qualify_scopes(scopes: List[str], client_id: str) -> List[str]:
    """Convert short-form scopes to fully qualified format (uses centralized logic)."""
    return rewrite_mcp_scopes(" ".join(scopes), client_id).split()


async def _fetch_oidc_metadata(issuer_url: str, allowed_hosts: Set[str]) -> Optional[dict]:
    """
    Fetch OpenID Connect discovery metadata from Microsoft Entra ID.

    Args:
        issuer_url: e.g., https://login.microsoftonline.com/<tenant>/v2.0
        allowed_hosts: Set of trusted hosts to prevent SSRF
    """
    oidc_url = f"{issuer_url.rstrip('/')}/.well-known/openid-configuration"
    
    # Security: Host validation to prevent SSRF
    parsed_url = urlparse(oidc_url)
    if parsed_url.netloc not in allowed_hosts:
        logger.error("Security: SSRF attempt blocked. Untrusted OIDC issuer host: %s", parsed_url.netloc)
        return None

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
    All five OAuth compatibility endpoints in a single class.

    Usage:
        config = OAuthCompatConfig.from_env()
        endpoints = OAuthCompatEndpoints(config)

        app.add_route("/.well-known/oauth-protected-resource", endpoints.protected_resource, methods=["GET"])
        app.add_route("/.well-known/oauth-authorization-server", endpoints.authorization_server, methods=["GET"])
        app.add_route("/oauth/register", endpoints.client_registration, methods=["POST"])
        app.add_route("/oauth/authorize", endpoints.authorize_proxy, methods=["GET"])
        app.add_route("/oauth/token", endpoints.token_proxy, methods=["POST"])
    """

    # Default cache TTL: 1 hour. OIDC metadata rarely changes, but key rotations
    # and endpoint updates do happen. 1 hour balances freshness with performance.
    DEFAULT_CACHE_TTL_SECONDS: float = 3600.0

    def __init__(self, config: OAuthCompatConfig, cache_ttl: float = DEFAULT_CACHE_TTL_SECONDS):
        self.config = config
        self._cache_ttl = cache_ttl
        # Cache stores (metadata_dict, monotonic_timestamp) tuples
        self._oidc_cache: dict[str, Tuple[dict, float]] = {}

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

        # Fetch and cache OIDC metadata with TTL expiration.
        # Re-fetches when cache is missing or stale to pick up key rotations.
        cached = self._oidc_cache.get(issuer_url)
        now = time.monotonic()
        if cached is None or (now - cached[1]) > self._cache_ttl:
            oidc = await _fetch_oidc_metadata(issuer_url, self.config.allowed_hosts)
            if oidc:
                self._oidc_cache[issuer_url] = (oidc, now)
            elif cached is not None:
                # Fetch failed but we have stale data — use it rather than returning 503
                logger.warning("OIDC metadata refresh failed; serving stale cache for %s", issuer_url)

        cached = self._oidc_cache.get(issuer_url)
        oidc = cached[0] if cached else None
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

        NOTE: This endpoint has no built-in rate limiting. The client_id it
        returns is semi-public (required for OAuth flows), but you should
        add rate limiting at the infrastructure level (e.g., Azure API
        Management, Container App IP restrictions, or a reverse proxy)
        to prevent abuse.
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
            params["scope"] = rewrite_mcp_scopes(params["scope"], self.config.client_id)

        params.pop("resource", None)

        ms_authorize = (
            f"{self.config.issuer_base_url.rstrip('/')}"
            f"/{self.config.tenant_id}/oauth2/v2.0/authorize"
        )

        # Security: Host validation to prevent Open-Redirect
        parsed_url = urlparse(ms_authorize)
        if parsed_url.netloc not in self.config.allowed_hosts:
            logger.error("Security: Open-Redirect blocked. Untrusted issuer host: %s", parsed_url.netloc)
            return JSONResponse(
                status_code=400, 
                content={"error": "invalid_request", "message": "Untrusted issuer host."}
            )

        redirect_url = f"{ms_authorize}?{urlencode(params)}"

        logger.info("Authorize proxy: scope=%s", params.get("scope", ""))
        return RedirectResponse(url=redirect_url, status_code=302)

    # -------------------------------------------------------------------------
    # 5. Token Proxy — Scope Rewriter (forwarded POST)
    # -------------------------------------------------------------------------

    # Parameters that are expected in OAuth token exchange requests.
    # Only these are forwarded to Microsoft to prevent parameter injection.
    ALLOWED_TOKEN_PARAMS = frozenset({
        "grant_type",       # authorization_code or refresh_token
        "code",             # Authorization code from callback
        "redirect_uri",     # Must match the authorize request
        "client_id",        # Public client identifier
        "scope",            # Will be rewritten by this proxy
        "code_verifier",    # PKCE proof
        "refresh_token",    # For token refresh flows
    })

    async def token_proxy(self, request: Request) -> JSONResponse:
        """
        POST /oauth/token
        
        Intercepts the token exchange request, rewrites scope, verifies client_id,
        and forwards to Microsoft with host validation and audit logging.
        """
        try:
            body = await request.body()
            params = parse_qs(body.decode(), keep_blank_values=True)
            flat = {k: v[0] if len(v) == 1 else v for k, v in params.items()}

            # Audit: Token request audit log
            logger.info("Audit: Token exchange request for client_id: %s", flat.get("client_id"))

            # Security: Verify client_id matches configuration
            if flat.get("client_id") != self.config.client_id:
                logger.warning("Security: Blocked token proxy for unauthorized client_id: %s", flat.get("client_id"))
                return JSONResponse(status_code=400, content={"error": "invalid_client"})

            if "scope" in flat:
                flat["scope"] = rewrite_mcp_scopes(flat["scope"], self.config.client_id)

            flat.pop("resource", None)

            # Only forward allowed OAuth parameters
            flat = {k: v for k, v in flat.items() if k in self.ALLOWED_TOKEN_PARAMS}

            ms_token_url = f"{self.config.issuer_base_url.rstrip('/')}/{self.config.tenant_id}/oauth2/v2.0/token"
            
            # Security: Host validation for upstream call
            parsed_url = urlparse(ms_token_url)
            if parsed_url.netloc not in self.config.allowed_hosts:
                logger.error("Security: Untrusted issuer host detected: %s. Allowed hosts: %s", 
                             parsed_url.netloc, self.config.allowed_hosts)
                return JSONResponse(status_code=400, content={"error": "invalid_request", "message": "Untrusted issuer host."})

            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.post(
                    ms_token_url,
                    data=flat,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )
                response.raise_for_status()
                
            return JSONResponse(status_code=response.status_code, content=response.json())

        except httpx.HTTPStatusError as e:
            logger.error("Audit: Upstream token error %d: %s", e.response.status_code, e.response.text)
            return JSONResponse(status_code=e.response.status_code, content=e.response.json() if "application/json" in e.response.headers.get("Content-Type", "") else {"error": "upstream_error"})
        except Exception as e:
            logger.error("Audit: Internal error in token_proxy: %s", e)
            return JSONResponse(status_code=500, content={"error": "server_error"})
