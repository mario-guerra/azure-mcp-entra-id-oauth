# Deploying an MCP Server with Microsoft Entra ID OAuth on Azure Container Apps

> **Audience**: Human engineers and AI agents (Cursor, Claude, etc.) tasked with building and deploying MCP servers on Azure with OAuth authentication.
>
> **Last verified**: February 2026 with Cursor IDE ~v2.2.x, MCP spec 2025-06-18, Azure Container Apps.

---

## Table of Contents

1. [Overview](#1-overview)
2. [The Problem: Why This Is Hard](#2-the-problem-why-this-is-hard)
3. [Architecture](#3-architecture)
4. [Prerequisites](#4-prerequisites)
5. [Step 1: Register an App in Microsoft Entra ID](#5-step-1-register-an-app-in-microsoft-entra-id)
6. [Step 2: Implement the OAuth Compatibility Layer](#6-step-2-implement-the-oauth-compatibility-layer)
7. [Step 3: Implement Identity Middleware](#7-step-3-implement-identity-middleware)
8. [Step 4: Wire It All Into the MCP Server](#8-step-4-wire-it-all-into-the-mcp-server)
9. [Step 5: Configure Azure Container Apps](#9-step-5-configure-azure-container-apps)
10. [Step 6: Set Environment Variables](#10-step-6-set-environment-variables)
11. [Step 7: Build and Deploy](#11-step-7-build-and-deploy)
12. [Step 8: Configure Cursor IDE](#12-step-8-configure-cursor-ide)
13. [Verifying Authentication Enforcement](#13-verifying-authentication-enforcement)
14. [Troubleshooting](#14-troubleshooting)
15. [Quick Reference: Endpoints](#15-quick-reference-endpoints)
16. [Quick Reference: Environment Variables](#16-quick-reference-environment-variables)
17. [Security Considerations](#17-security-considerations)

---

## 1. Overview

This guide documents how to deploy a Python-based MCP (Model Context Protocol) server on Azure Container Apps with Microsoft Entra ID authentication, accessible from Cursor IDE via OAuth.

The MCP specification (2025-06-18) requires servers to support:
- **RFC 9728**: OAuth 2.0 Protected Resource Metadata
- **RFC 8414**: OAuth 2.0 Authorization Server Metadata
- **RFC 7591**: OAuth 2.0 Dynamic Client Registration
- **RFC 8707**: Resource Indicators for OAuth 2.0

Microsoft Entra ID does **not** natively support RFC 8414, RFC 7591, or RFC 8707. This guide shows how to bridge these gaps with a lightweight OAuth compatibility layer.

---

## 2. The Problem: Why This Is Hard

There are **four incompatibilities** between the MCP OAuth spec (as implemented by Cursor) and Microsoft Entra ID:

### Incompatibility 1: Discovery Metadata Format
- **MCP expects**: `/.well-known/oauth-authorization-server` (RFC 8414)
- **Microsoft provides**: `/.well-known/openid-configuration` (OIDC)
- **Solution**: Proxy endpoint that fetches Microsoft's OIDC metadata and transforms it to RFC 8414 format.

### Incompatibility 2: Dynamic Client Registration
- **MCP expects**: `POST /registration_endpoint` (RFC 7591) that returns a `client_id`
- **Microsoft provides**: Nothing. App registrations are manual.
- **Solution**: Mock registration endpoint that returns the pre-configured `client_id` from your Entra ID app registration.
- **Critical detail**: If `registration_endpoint` is present in metadata but set to `null`, Cursor throws a Zod validation error (`expected string, received null`). Either omit the field entirely or point it to a real endpoint.

### Incompatibility 3: Scope Format (RFC 8707 vs v2.0)
- **MCP clients send**: `scope=access_as_user&resource=https://your-server.com` (RFC 8707)
- **Microsoft v2.0 needs**: `scope=api://<client-id>/access_as_user` (fully qualified, no `resource` param)
- **Solution**: Proxy authorize and token endpoints that rewrite `scope` and strip the `resource` parameter before forwarding to Microsoft.

### Incompatibility 4: Easy Auth Blocks Discovery
- **Easy Auth** with `unauthenticatedClientAction: Return401` blocks OAuth metadata endpoints.
- **Solution**: Set Easy Auth to `AllowAnonymous` and let your application handle 401 responses with proper `WWW-Authenticate` headers.

---

## 3. Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Cursor IDE (MCP Client)                      │
│                                                                      │
│  1. Hits /mcp → gets 401 with WWW-Authenticate header               │
│  2. Fetches /.well-known/oauth-protected-resource                    │
│  3. Fetches /.well-known/oauth-authorization-server                  │
│  4. POST /oauth/register → gets client_id                            │
│  5. Redirects to /oauth/authorize → 302 to Microsoft                 │
│  6. User authenticates at Microsoft                                  │
│  7. Microsoft redirects to cursor://...callback with code            │
│  8. Cursor POST /oauth/token → proxy forwards to Microsoft           │
│  9. Cursor now has access_token, calls /mcp with Bearer token        │
│ 10. Easy Auth validates token, injects X-MS-CLIENT-PRINCIPAL-*       │
│ 11. IdentityMiddleware extracts user, request proceeds               │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│                    Your MCP Server (Container App)                    │
│                                                                      │
│  Endpoints (no auth required):                                       │
│    GET  /.well-known/oauth-protected-resource   ← RFC 9728           │
│    GET  /.well-known/oauth-authorization-server ← RFC 8414 proxy     │
│    POST /oauth/register                         ← RFC 7591 mock      │
│    GET  /oauth/authorize                        ← Scope rewrite proxy│
│    POST /oauth/token                            ← Scope rewrite proxy│
│    GET  /health                                 ← Health check        │
│                                                                      │
│  Endpoints (auth required):                                          │
│    POST /mcp                                    ← MCP protocol        │
│    GET  /mcp                                    ← MCP protocol        │
│    DELETE /mcp                                  ← MCP protocol        │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│                   Azure Container Apps Easy Auth                     │
│                                                                      │
│  Mode: AllowAnonymous (passes all requests through)                  │
│  When Bearer token IS present: validates it, injects headers         │
│  When Bearer token is NOT present: passes request through as-is      │
│  Headers injected on valid token:                                    │
│    X-MS-CLIENT-PRINCIPAL (base64 JSON with claims)                   │
│    X-MS-CLIENT-PRINCIPAL-NAME (user email/UPN)                       │
│    X-MS-CLIENT-PRINCIPAL-ID (Azure AD object ID)                     │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│                      Microsoft Entra ID                              │
│                                                                      │
│  /oauth2/v2.0/authorize  ← User authentication                      │
│  /oauth2/v2.0/token      ← Token exchange                           │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 4. Prerequisites

- Azure subscription with permissions to create Container Apps and App Registrations
- Azure CLI (`az`) installed and authenticated
- Python 3.12+
- Docker (for local testing)
- Cursor IDE (for end-to-end testing)

---

## 5. Step 1: Register an App in Microsoft Entra ID

### 5.1 Create the App Registration

1. Go to Azure Portal → Microsoft Entra ID → App registrations
2. Click **New registration**
3. Configure:
   - **Name**: `<Your MCP Server Name>` (e.g., `My Team MCP Server`)
   - **Supported account types**: Single tenant
   - **Redirect URI**: Skip for now (we'll add it next)
4. Click **Register**
5. Note the **Application (client) ID** and **Directory (tenant) ID**

### 5.2 Add Redirect URIs

Go to **Authentication** → **Add a platform** → **Mobile and desktop applications**:

Add this redirect URI:
```
cursor://anysphere.cursor-mcp/oauth/callback
```

> **CRITICAL**: This must be under "Mobile and desktop applications" (public client), NOT "Web". Cursor uses a custom URI scheme.

Under **Advanced settings**:
- Set **Allow public client flows** to **Yes**

### 5.3 Expose an API

Go to **Expose an API**:

1. Set **Application ID URI**: `api://<client-id>` (click "Set" next to the empty URI)
2. Click **Add a scope**:
   - **Scope name**: `access_as_user`
   - **Who can consent**: Admins and users
   - **Admin consent display name**: `Access MCP Server`
   - **Admin consent description**: `Allows the app to access the MCP server on behalf of the signed-in user`
   - **State**: Enabled
3. Click **Add scope**

### 5.4 (Optional) Add a Client Secret for Easy Auth

If you plan to use Easy Auth (recommended for token validation at the infrastructure level):

Go to **Certificates & secrets** → **New client secret**:
- **Description**: `Easy Auth`
- **Expires**: Choose an appropriate duration

Note the **secret value** (you'll need it for Easy Auth configuration).

> **Important**: This secret is used by Azure Easy Auth infrastructure, NOT by your application code. Your app never sees or needs this secret.

---

## 6. Step 2: Implement the OAuth Compatibility Layer

This is the core of the solution. You need a single module (`oauth_metadata.py`) that provides six endpoint factories.

### Required Dependencies

```
httpx>=0.28.0
starlette>=0.27.0
```

### 6.1 Configuration Data Class

```python
from dataclasses import dataclass, field
from typing import List

@dataclass
class OAuthMetadataConfig:
    resource_url: str          # https://your-app.azurecontainerapps.io
    tenant_id: str             # Entra ID tenant/directory ID
    client_id: str             # Entra ID client/application ID
    scopes: List[str] = field(default_factory=lambda: ["access_as_user"])
    issuer_base_url: str = "https://login.microsoftonline.com"

    def is_configured(self) -> bool:
        return bool(self.resource_url and self.tenant_id and self.client_id)
```

### 6.2 Endpoint: Protected Resource Metadata (RFC 9728)

`GET /.well-known/oauth-protected-resource`

```python
def generate_oauth_metadata(config: OAuthMetadataConfig) -> dict:
    # IMPORTANT: Point authorization_servers to YOUR server, not Microsoft directly.
    # Your server hosts the RFC 8414 metadata that proxies Microsoft's OIDC data.
    auth_server_url = config.resource_url.rstrip('/')

    # IMPORTANT: Use fully qualified scopes (api://<client-id>/<scope>)
    full_scopes = []
    for scope in config.scopes:
        if scope in ("openid", "profile", "email", "offline_access"):
            full_scopes.append(scope)
        elif scope.startswith("api://"):
            full_scopes.append(scope)
        else:
            full_scopes.append(f"api://{config.client_id}/{scope}")

    return {
        "resource": config.resource_url,
        "authorization_servers": [auth_server_url],
        "token_endpoint_auth_methods_supported": ["none"],
        "scopes_supported": full_scopes,
        "bearer_methods_supported": ["header"]
    }
```

### 6.3 Endpoint: Authorization Server Metadata (RFC 8414)

`GET /.well-known/oauth-authorization-server`

This fetches Microsoft's OIDC metadata and transforms it to RFC 8414 format:

```python
async def fetch_oidc_metadata(issuer_url: str) -> dict | None:
    oidc_url = f"{issuer_url.rstrip('/')}/.well-known/openid-configuration"
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.get(oidc_url)
        return response.json() if response.status_code == 200 else None

def transform_oidc_to_rfc8414(oidc_metadata: dict, config) -> dict:
    base_url = config.resource_url.rstrip('/')
    full_scopes = [f"api://{config.client_id}/{s}" for s in config.scopes
                   if s not in ("openid", "profile", "email", "offline_access")]

    return {
        "issuer": oidc_metadata["issuer"],
        "authorization_endpoint": f"{base_url}/oauth/authorize",    # YOUR proxy
        "token_endpoint": f"{base_url}/oauth/token",                # YOUR proxy
        "jwks_uri": oidc_metadata["jwks_uri"],
        "registration_endpoint": f"{base_url}/oauth/register",      # YOUR mock
        "scopes_supported": full_scopes,
        "response_types_supported": oidc_metadata.get("response_types_supported", ["code"]),
        "response_modes_supported": oidc_metadata.get("response_modes_supported", ["query"]),
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "token_endpoint_auth_methods_supported": ["none"],
        "code_challenge_methods_supported": ["S256"],
    }
```

> **CRITICAL**: `authorization_endpoint` and `token_endpoint` must point to YOUR proxy endpoints, not Microsoft's directly. This is what allows scope rewriting.

### 6.4 Endpoint: Dynamic Client Registration (RFC 7591 Mock)

`POST /oauth/register`

```python
async def client_registration_handler(request):
    body = await request.json()
    redirect_uris = body.get("redirect_uris", [])

    return JSONResponse(
        status_code=201,  # MUST be 201 per RFC 7591
        content={
            "client_id": config.client_id,    # Return your pre-configured client_id
            "client_id_issued_at": 0,
            "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "redirect_uris": redirect_uris,
        }
    )
```

### 6.5 Endpoint: Authorize Proxy (Scope Rewriter)

`GET /oauth/authorize`

```python
async def authorize_proxy_handler(request):
    params = dict(request.query_params)

    # Rewrite scope: short form → fully qualified
    if "scope" in params:
        scopes = params["scope"].split()
        rewritten = []
        for s in scopes:
            if s in ("openid", "profile", "email", "offline_access"):
                rewritten.append(s)
            elif s.startswith("api://"):
                rewritten.append(s)
            else:
                rewritten.append(f"api://{config.client_id}/{s}")
        params["scope"] = " ".join(rewritten)

    # Remove unsupported resource parameter
    params.pop("resource", None)

    ms_authorize_url = f"{config.issuer_base_url}/{config.tenant_id}/oauth2/v2.0/authorize"
    redirect_url = f"{ms_authorize_url}?{urlencode(params)}"
    return RedirectResponse(url=redirect_url, status_code=302)
```

### 6.6 Endpoint: Token Proxy (Scope Rewriter)

`POST /oauth/token`

```python
async def token_proxy_handler(request):
    body = await request.body()
    params = parse_qs(body.decode(), keep_blank_values=True)
    flat_params = {k: v[0] if len(v) == 1 else v for k, v in params.items()}

    # Same scope rewriting as authorize
    if "scope" in flat_params:
        scopes = flat_params["scope"].split()
        rewritten = [
            s if s in ("openid", "profile", "email", "offline_access") or s.startswith("api://")
            else f"api://{config.client_id}/{s}"
            for s in scopes
        ]
        flat_params["scope"] = " ".join(rewritten)

    flat_params.pop("resource", None)

    ms_token_url = f"{config.issuer_base_url}/{config.tenant_id}/oauth2/v2.0/token"
    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.post(ms_token_url, data=flat_params,
                                     headers={"Content-Type": "application/x-www-form-urlencoded"})

    return JSONResponse(status_code=response.status_code, content=response.json())
```

---

## 7. Step 3: Implement Identity Middleware

The identity middleware intercepts every request, extracts the user identity from Easy Auth headers, and makes it available to MCP tools.

### Key Design Points

1. **Excluded paths** (no auth required): `/health`, `/healthz`, `/`, `/.well-known/*`, `/oauth/*`
2. **401 response** MUST include `WWW-Authenticate` header per RFC 9728:
   ```
   WWW-Authenticate: Bearer resource_metadata="https://your-app/.well-known/oauth-protected-resource"
   ```
3. **Identity storage**: Use Python's `ContextVar` for request-scoped identity access
4. **Easy Auth headers**: When a valid Bearer token is present, Azure injects:
   - `X-MS-CLIENT-PRINCIPAL`: Base64-encoded JSON with all claims
   - `X-MS-CLIENT-PRINCIPAL-NAME`: User email/UPN
   - `X-MS-CLIENT-PRINCIPAL-ID`: Azure AD object ID

### Security: Always validate X-MS-CLIENT-PRINCIPAL

Do NOT trust `X-MS-CLIENT-PRINCIPAL-NAME` alone. Require that `X-MS-CLIENT-PRINCIPAL` (the base64 payload) exists and is valid JSON. Only Easy Auth sets this header — it cannot be spoofed by clients.

---

## 8. Step 4: Wire It All Into the MCP Server

Register all six endpoints with your Starlette/FastAPI app:

```python
# After creating the Starlette app from FastMCP:
app = mcp.streamable_http_app()

# 1. Identity middleware
app.add_middleware(IdentityMiddleware, identity_provider=identity_provider)

# 2. OAuth metadata endpoints
app.add_route("/.well-known/oauth-protected-resource", protected_resource_handler, methods=["GET"])
app.add_route("/.well-known/oauth-authorization-server", auth_server_handler, methods=["GET"])
app.add_route("/oauth/register", registration_handler, methods=["POST"])
app.add_route("/oauth/authorize", authorize_proxy_handler, methods=["GET"])
app.add_route("/oauth/token", token_proxy_handler, methods=["POST"])

# 3. Health check
app.add_route("/health", health_check, methods=["GET"])
```

---

## 9. Step 5: Configure Azure Container Apps

### 9.1 Easy Auth Configuration

**CRITICAL**: Set `unauthenticatedClientAction` to `AllowAnonymous`.

```bash
az containerapp auth update \
  --name <container-app-name> \
  --resource-group <resource-group> \
  --unauthenticated-client-action AllowAnonymous
```

Configure the Entra ID identity provider:
```bash
az containerapp auth microsoft update \
  --name <container-app-name> \
  --resource-group <resource-group> \
  --client-id <entra-client-id> \
  --client-secret-setting-name microsoft-provider-authentication-secret \
  --issuer "https://login.microsoftonline.com/<tenant-id>/v2.0" \
  --allowed-audiences "api://<client-id>"
```

> **Why AllowAnonymous?** If set to `Return401`, Azure blocks ALL unauthenticated requests — including OAuth discovery and the `/oauth/*` proxy endpoints that Cursor needs BEFORE it has a token. With `AllowAnonymous`, unauthenticated requests pass through to your app, where the identity middleware returns proper 401s with `WWW-Authenticate` headers. When a valid token IS present, Easy Auth still validates it and injects the `X-MS-CLIENT-PRINCIPAL-*` headers.

### 9.2 Excluded Paths (Belt and Suspenders)

Even though we're using `AllowAnonymous`, set excluded paths for extra safety:

```bash
az containerapp auth update \
  --name <container-app-name> \
  --resource-group <resource-group> \
  --set globalValidation.excludedPaths='[/.well-known/*,/health,/healthz,/,/oauth/*]'
```

---

## 10. Step 6: Set Environment Variables

```bash
az containerapp update \
  --name <container-app-name> \
  --resource-group <resource-group> \
  --set-env-vars \
    "RUNNING_IN_PRODUCTION=true" \
    "OAUTH_RESOURCE_URL=https://<your-app>.azurecontainerapps.io" \
    "OAUTH_TENANT_ID=<entra-tenant-id>" \
    "OAUTH_CLIENT_ID=<entra-client-id>"
```

---

## 11. Step 7: Build and Deploy

```bash
# Use a unique tag (Azure caches :latest)
TAG="v$(date +%Y%m%d%H%M%S)"

# Build and push to ACR
az acr build --registry <acr-name> --image <image-name>:$TAG ./src

# Update container app with new tag
az containerapp update \
  --name <container-app-name> \
  --resource-group <resource-group> \
  --image <acr-name>.azurecr.io/<image-name>:$TAG
```

> **Important**: Do NOT use `:latest` for Azure Container App updates. Azure caches the `:latest` digest and won't pull a new image even if you push a new one. Always use unique tags.

### Verify Deployment

```bash
# Health check
curl https://<your-app>.azurecontainerapps.io/health

# Protected resource metadata
curl https://<your-app>.azurecontainerapps.io/.well-known/oauth-protected-resource

# Auth server metadata
curl https://<your-app>.azurecontainerapps.io/.well-known/oauth-authorization-server

# Client registration
curl -X POST https://<your-app>.azurecontainerapps.io/oauth/register \
  -H "Content-Type: application/json" \
  -d '{"redirect_uris":["cursor://anysphere.cursor-mcp/oauth/callback"]}'

# Unauthenticated MCP request (should return 401 with WWW-Authenticate)
curl -D - -X POST https://<your-app>.azurecontainerapps.io/mcp
```

---

## 12. Step 8: Configure Cursor IDE

Add to `~/.cursor/mcp.json` (or via Settings → Tools & Integrations → Add Custom MCP):

```json
{
  "mcpServers": {
    "your-server-name": {
      "url": "https://<your-app>.azurecontainerapps.io/mcp",
      "headers": {
        "Accept": "application/json, text/event-stream"
      }
    }
  }
}
```

> **Do NOT include**: `X-API-Key`, `X-User-Email`, `Authorization`, or any auth headers. Cursor handles OAuth automatically.

**After saving**:
1. The server should appear with a **Connect** button (not "Needs login" — this is a Cursor UI detail)
2. Click **Connect**
3. A browser window opens for Microsoft sign-in
4. Complete authentication
5. Tools should load within seconds

---

## 13. Verifying Authentication Enforcement

After deployment, verify that your server correctly rejects unauthenticated requests.

### Test 1: No Token (Should Return 401)

```bash
curl -D - -X POST https://<your-app>.azurecontainerapps.io/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream"
```

Expected response:
```
HTTP/2 401
www-authenticate: Bearer resource_metadata="https://<your-app>.azurecontainerapps.io/.well-known/oauth-protected-resource"
content-type: application/json

{"error":"Unauthorized","message":"Authentication required. Ensure you are authenticated via Microsoft Entra ID."}
```

Verify:
- Status code is **401** (not 200, not 403)
- `WWW-Authenticate` header is present with the `resource_metadata` URL
- The `resource_metadata` URL matches your `/.well-known/oauth-protected-resource` endpoint

### Test 2: Fake/Invalid Token (Should Also Return 401)

```bash
curl -D - -X POST https://<your-app>.azurecontainerapps.io/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "Authorization: Bearer fake-token-12345"
```

This should also return 401. Easy Auth validates the token at the infrastructure level — an invalid token means Easy Auth will NOT inject the `X-MS-CLIENT-PRINCIPAL` headers, so the identity middleware sees no identity and rejects the request.

### Why Both Tests Matter

- **Test 1** confirms your middleware correctly rejects requests with no token and returns the `WWW-Authenticate` header (required for Cursor's OAuth discovery).
- **Test 2** confirms Easy Auth is active and validating tokens. If test 2 returned 200, it would mean Easy Auth is misconfigured or disabled, and anyone could bypass authentication by sending requests without a token.

---

## 14. Troubleshooting

### "Loading tools" forever, no login prompt
- Check that `unauthenticatedClientAction` is `AllowAnonymous`
- Check that `/.well-known/oauth-protected-resource` returns 200 (not 401)
- Check that `/.well-known/oauth-authorization-server` returns 200 with valid JSON
- Restart Cursor completely (quit and reopen)

### `registration_endpoint: expected string, received null`
- The `registration_endpoint` field in auth server metadata is `null`
- Fix: Either omit the field entirely, or point it to your `/oauth/register` endpoint

### `Incompatible auth server: does not support dynamic client registration`
- The `registration_endpoint` field is missing from auth server metadata
- Fix: Add `/oauth/register` endpoint and include it in metadata

### `OAuth callback received without code parameter`
- Microsoft returned an error instead of an authorization code
- Most common cause: `scope` is not fully qualified
  - Wrong: `scope=access_as_user`
  - Right: `scope=api://<client-id>/access_as_user`
- Other causes: redirect URI not registered, consent not granted
- Check: Is `/oauth/authorize` rewriting the scope correctly? Test with curl.

### 401 on /mcp after successful OAuth login
- Check Container App logs for identity extraction errors
- Ensure Easy Auth has the correct `allowedAudiences` including `api://<client-id>`
- Verify the `X-MS-CLIENT-PRINCIPAL` header is being injected

### Azure caches old image
- Don't use `:latest` tag
- Use unique tags: `v$(date +%Y%m%d%H%M%S)`
- Use `az containerapp update --image <full-path>:<unique-tag>` to force a new revision

---

## 15. Quick Reference: Endpoints

| Endpoint | Method | Auth Required | Purpose |
|---|---|---|---|
| `/.well-known/oauth-protected-resource` | GET | No | RFC 9728 metadata |
| `/.well-known/oauth-authorization-server` | GET | No | RFC 8414 metadata (proxied) |
| `/oauth/register` | POST | No | RFC 7591 client registration (mock) |
| `/oauth/authorize` | GET | No | Proxy to Microsoft authorize (rewrites scope) |
| `/oauth/token` | POST | No | Proxy to Microsoft token (rewrites scope) |
| `/health` | GET | No | Health check |
| `/mcp` | POST/GET/DELETE | Yes | MCP protocol |

---

## 16. Quick Reference: Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `RUNNING_IN_PRODUCTION` | Yes (prod) | `false` | Enables production mode |
| `OAUTH_RESOURCE_URL` | Yes (prod) | `""` | Full URL of your MCP server |
| `OAUTH_TENANT_ID` | Yes (prod) | `""` | Entra ID tenant/directory ID |
| `OAUTH_CLIENT_ID` | Yes (prod) | `""` | Entra ID client/application ID |
| `OAUTH_SCOPES` | No | `access_as_user` | Comma-separated OAuth scopes |
| `OAUTH_ISSUER_BASE_URL` | No | `https://login.microsoftonline.com` | Issuer base URL |
| `AUTH_DEV_BYPASS` | No | `false` | Enable X-User-Email header (dev only) |

---

## 17. Security Considerations

1. **Easy Auth + Application Middleware = Defense in Depth**: Easy Auth validates tokens at the infrastructure level. Your middleware extracts identity from the validated headers. Neither is sufficient alone.

2. **AllowAnonymous is intentional**: This does NOT mean your app is unprotected. Your identity middleware rejects unauthenticated requests to `/mcp` with 401. Easy Auth still validates any Bearer tokens that ARE present.

3. **Never trust X-MS-CLIENT-PRINCIPAL-NAME alone**: Always require `X-MS-CLIENT-PRINCIPAL` (base64 JSON) to be present and valid. This header can only be set by Easy Auth, not by clients.

4. **Dev bypass is production-blocked**: The `DevBypassIdentityProvider` refuses to activate when `RUNNING_IN_PRODUCTION=true`, even if `AUTH_DEV_BYPASS=true` is set.

5. **Client secret is for Easy Auth only**: The Entra ID client secret is used by Azure's Easy Auth infrastructure to validate tokens. Your application code never needs or sees this secret.

6. **Scope rewriting is safe**: The proxy only transforms scope format. It doesn't bypass any authorization — Microsoft still validates the scope, audience, and user permissions.

7. **The mock registration endpoint returns a fixed client_id**: All MCP clients get the same Entra ID app registration. This is by design — there's one app per MCP server.
