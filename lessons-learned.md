# Lessons Learned: MCP Server OAuth with Microsoft Entra ID

> **Purpose**: This document captures hard-won knowledge from integrating a Python MCP server with Microsoft Entra ID authentication on Azure Container Apps, targeting Cursor IDE as the client. It is written for both human engineers and AI agents who will implement this pattern on future servers.
>
> **Date**: February 2026

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [What Went Wrong and Why](#2-what-went-wrong-and-why)
3. [Key Decision Record](#3-key-decision-record)
4. [The Five Things That Will Bite You](#4-the-five-things-that-will-bite-you)
5. [The Debugging Playbook](#5-the-debugging-playbook)
6. [Protocol Translation Reference](#6-protocol-translation-reference)
7. [What the MCP Spec Says vs What Cursor Actually Does](#7-what-the-mcp-spec-says-vs-what-cursor-actually-does)
8. [AI Agent Instructions](#8-ai-agent-instructions)

---

## 1. Executive Summary

We migrated an MCP server from API key authentication to Microsoft Entra ID with Azure Container Apps' built-in authentication ("Easy Auth"). The migration itself was straightforward. What was NOT straightforward was making Cursor IDE's OAuth flow work with Microsoft Entra ID. This required building an OAuth compatibility layer consisting of 5 proxy/mock endpoints.

**Total time to working solution**: ~8 hours of iterative debugging across 17+ deployment cycles.

**Root cause of all difficulties**: The MCP specification's OAuth requirements (RFC 8414 + RFC 7591 + RFC 8707) and Microsoft Entra ID's OAuth implementation (OIDC + v2.0 scopes + no dynamic registration) are fundamentally incompatible. No configuration change can fix this — you need code.

---

## 2. What Went Wrong and Why

### Iteration 1: "Just enable Easy Auth"
**Assumption**: Enable Easy Auth on the Container App, expose `/.well-known/oauth-protected-resource`, point Cursor at it.
**What happened**: Cursor stuck on "loading tools" with no login prompt.
**Root cause**: Easy Auth with `Return401` blocked the metadata endpoints. Cursor never got the discovery metadata it needed.

### Iteration 2: "Exclude paths from Easy Auth"
**Assumption**: Excluding `/.well-known/*` would fix discovery.
**What happened**: Discovery worked, but Cursor tried to fetch `/.well-known/oauth-authorization-server` from OUR server (not Microsoft's).
**Root cause**: We pointed `authorization_servers` to `https://login.microsoftonline.com/{tenant}/v2.0` but Cursor appends `/.well-known/oauth-authorization-server` to that URL. Microsoft doesn't serve RFC 8414 at that path — only OIDC discovery at `/.well-known/openid-configuration`.

### Iteration 3: "Add RFC 8414 proxy"
**Assumption**: Proxy Microsoft's OIDC to RFC 8414 format on our server.
**What happened**: Cursor threw `registration_endpoint: expected string, received null`.
**Root cause**: We set `registration_endpoint: None` in the metadata. Cursor uses Zod for schema validation and expected either a string or the field to be absent entirely. `null` failed validation.

### Iteration 4: "Omit registration_endpoint"
**Assumption**: Just leave it out of the metadata.
**What happened**: Cursor logs showed `Incompatible auth server: does not support dynamic client registration`.
**Root cause**: Cursor requires RFC 7591 dynamic client registration. Microsoft doesn't support it. We had to mock it.

### Iteration 5: "Add mock registration + proxy endpoints"
**Assumption**: Mock the registration endpoint, proxy authorize and token with scope rewriting.
**What happened**: Browser opened for Microsoft login, but Cursor timed out — `OAuth callback received without code parameter`.
**Root cause**: Two problems:
1. The `WWW-Authenticate` header was missing from 401 responses (Cursor needs this to trigger OAuth)
2. Scopes were still in short form (`access_as_user`) instead of fully qualified (`api://<client-id>/access_as_user`)

### Iteration 6: "Fix WWW-Authenticate + scope rewriting"
**What happened**: Everything worked.
**What it took**: `AllowAnonymous` Easy Auth mode + middleware 401 with `WWW-Authenticate` header + scope rewriting in authorize and token proxies.

---

## 3. Key Decision Record

### Decision 1: AllowAnonymous Instead of Return401

**Context**: Azure Easy Auth's `Return401` mode blocks ALL unauthenticated requests, including OAuth discovery endpoints needed before authentication.

**Decision**: Set Easy Auth to `AllowAnonymous` and handle 401 responses in application middleware.

**Consequence**: The application is responsible for returning 401 on protected endpoints. This is more code but gives full control over the response, including the `WWW-Authenticate` header that Cursor requires.

**Alternative considered**: Using `excludedPaths` with `Return401`. Rejected because the excluded paths list doesn't support enough granularity and the 401 response from Easy Auth doesn't include the `WWW-Authenticate` header.

### Decision 2: Proxy Endpoints Instead of Direct Microsoft URLs

**Context**: Cursor sends `scope=access_as_user` and `resource=<server-url>` per RFC 8707. Microsoft v2.0 requires `scope=api://<client-id>/access_as_user` and doesn't support the `resource` parameter.

**Decision**: Point `authorization_endpoint` and `token_endpoint` in our metadata to proxy endpoints on our server that rewrite scopes and strip the `resource` parameter before forwarding to Microsoft.

**Consequence**: All OAuth traffic flows through our server, adding a hop. This is minimal overhead (the authorize endpoint is just a 302 redirect, the token endpoint is a single forwarded POST).

**Alternative considered**: Putting fully qualified scopes in `scopes_supported` and hoping Cursor would use them. Rejected because Cursor sends whatever scope it has, not necessarily what's in the metadata. The proxy approach is more robust.

### Decision 3: Mock Dynamic Client Registration

**Context**: Cursor requires RFC 7591 dynamic client registration. Microsoft Entra ID doesn't support it.

**Decision**: Implement a mock endpoint that accepts any registration request and returns our pre-configured `client_id`.

**Consequence**: All MCP clients using our server share the same Entra ID app registration. This is fine — Entra ID authenticates users, not clients. The "client" is just the container for the redirect URI and permissions.

### Decision 4: Defense in Depth (Easy Auth + Application Middleware)

**Context**: With `AllowAnonymous`, Easy Auth doesn't block unauthenticated requests. Should we rely solely on our middleware?

**Decision**: Keep Easy Auth enabled. It validates tokens when present and injects trusted headers. Our middleware checks for those headers.

**Consequence**: Two layers of auth — Easy Auth at infrastructure level, middleware at application level. If one fails, the other catches it. The `X-MS-CLIENT-PRINCIPAL` header can only be set by Easy Auth, so checking for it in middleware is a reliable signal that the token was validated.

### Decision 5: Unique Docker Image Tags

**Context**: Azure Container Apps caches the `:latest` tag digest and doesn't re-pull even after pushing a new image.

**Decision**: Use timestamped tags (`v20260212143000`) for every build and explicitly update the container app with the new tag.

**Consequence**: Every deployment creates a new Container App revision. This is actually desirable — you get revision history and can roll back.

---

## 4. The Five Things That Will Bite You

### 1. Azure Container Apps caches Docker `:latest`
You will push a new image, restart the container app, and see old code running. Use unique tags.

### 2. Cursor's Zod validation is strict on metadata
If you include `registration_endpoint: null`, it will fail schema validation. If you omit `registration_endpoint`, it will say the auth server is incompatible. You must include a real URL to a real (or mock) endpoint.

### 3. Microsoft v2.0 scope format is non-standard
Most OAuth servers accept `scope=access_as_user`. Microsoft v2.0 requires `scope=api://<client-id>/access_as_user`. If you get the scope wrong, Microsoft silently returns an error page instead of a code callback, and Cursor reports `callback received without code parameter`.

### 4. Easy Auth's built-in 401 is not MCP-compatible
Easy Auth's `Return401` response does NOT include the `WWW-Authenticate` header with `resource_metadata`. MCP/Cursor needs this header to discover OAuth metadata. You must generate the 401 yourself.

### 5. The redirect URI MUST be under "Mobile and desktop" in Entra ID
`cursor://anysphere.cursor-mcp/oauth/callback` is a custom URI scheme. If you register it under "Web" in Entra ID, the token endpoint will return `AADSTS9002325: Cross-origin token redemption is permitted only for the 'Single-Page Application'...`. It must be under "Mobile and desktop applications" (public client flow).

---

## 5. The Debugging Playbook

When the Cursor OAuth flow doesn't work, follow this sequence:

### Step 1: Verify Discovery Chain
```bash
# Should return 200 with resource metadata
curl -s https://YOUR-APP/.well-known/oauth-protected-resource | jq .

# Should return 200 with auth server metadata
curl -s https://YOUR-APP/.well-known/oauth-authorization-server | jq .

# Should return 201 with client_id
curl -s -X POST https://YOUR-APP/oauth/register \
  -H "Content-Type: application/json" \
  -d '{"redirect_uris":["cursor://anysphere.cursor-mcp/oauth/callback"]}' | jq .
```

### Step 2: Verify 401 Response
```bash
# Should return 401 with WWW-Authenticate header
curl -D - -X POST https://YOUR-APP/mcp
```

Look for:
```
HTTP/2 401
www-authenticate: Bearer resource_metadata="https://YOUR-APP/.well-known/oauth-protected-resource"
```

### Step 3: Verify Scope Rewriting
```bash
# Should 302 redirect with fully qualified scope
curl -v "https://YOUR-APP/oauth/authorize?scope=access_as_user&client_id=TEST&redirect_uri=http://localhost&response_type=code"
```

Look for the `Location` header and verify the scope is rewritten to `api://<client-id>/access_as_user`.

### Step 4: Check Container App Logs
```bash
az containerapp logs show \
  --name <container-app-name> \
  --resource-group <resource-group> \
  --follow
```

Look for:
- `Proxying authorize request: rewritten scope=...`
- `Proxying token request: rewritten scope=...`
- `Authentication failed: No identity extracted`
- `Client registration request: name=...`

### Step 5: Check Entra ID Sign-ins
Azure Portal → Entra ID → Enterprise applications → Sign-in logs

Look for:
- Failed sign-ins with error codes
- `AADSTS65001` (consent required)
- `AADSTS700016` (app not found in tenant)
- `AADSTS50011` (redirect URI mismatch)

---

## 6. Protocol Translation Reference

This table shows exactly how each protocol element is mapped:

| What Cursor sends | What Microsoft needs | How the proxy handles it |
|---|---|---|
| `GET /.well-known/oauth-authorization-server` | `GET /.well-known/openid-configuration` | Fetch OIDC, transform to RFC 8414 |
| `POST /register { redirect_uris: [...] }` | (not supported) | Return pre-configured client_id |
| `scope=access_as_user` | `scope=api://<client-id>/access_as_user` | Rewrite in authorize and token proxies |
| `resource=https://server-url` | (not supported in v2.0) | Strip from both authorize and token |
| `GET /authorize?...` | `GET /oauth2/v2.0/authorize?...` | 302 redirect with rewritten params |
| `POST /token grant_type=authorization_code&...` | `POST /oauth2/v2.0/token` | Forward with rewritten scope |

---

## 7. What the MCP Spec Says vs What Cursor Actually Does

This section documents observed Cursor behavior as of ~v2.2.x (February 2026). Cursor's implementation may change.

| MCP Spec Expectation | Cursor's Actual Behavior |
|---|---|
| Client discovers auth via 401 + `WWW-Authenticate` | Yes, Cursor looks for `resource_metadata` in the header |
| Client fetches `/.well-known/oauth-protected-resource` | Yes |
| Client follows `authorization_servers[0]` and fetches RFC 8414 from there | Yes, appends `/.well-known/oauth-authorization-server` to the URL |
| Dynamic client registration (RFC 7591) is optional | **Required** — Cursor will fail without a `registration_endpoint` |
| Resource indicators (RFC 8707) `resource` parameter | Yes, Cursor sends `resource=<server-url>` |
| Scopes from `scopes_supported` are used as-is | **Sometimes** — Cursor may send short-form scope names |
| PKCE (`code_challenge_methods_supported: ["S256"]`) | Yes, Cursor uses PKCE |
| `token_endpoint_auth_methods_supported: ["none"]` | Yes, public client flow |

---

## 8. AI Agent Instructions

> This section is for AI coding agents (Claude, GPT, etc.) operating in Cursor or similar IDEs. Follow these instructions when asked to add OAuth/Entra ID authentication to an MCP server on Azure.

### Pre-flight Checklist

Before writing any code, verify you have:
- [ ] The Entra ID **tenant ID** (directory ID)
- [ ] The Entra ID **client ID** (application ID)
- [ ] The Azure Container App **URL** (e.g., `https://ca-myapp.region.azurecontainerapps.io`)
- [ ] Confirmation that the app registration has `cursor://anysphere.cursor-mcp/oauth/callback` as a redirect URI under "Mobile and desktop"
- [ ] Confirmation that the app registration exposes a scope (e.g., `access_as_user`)

### Implementation Checklist

When implementing, create or modify these components in this order:

1. **`oauth_metadata.py`** (or equivalent):
   - `OAuthMetadataConfig` dataclass
   - `generate_oauth_metadata()` → RFC 9728 Protected Resource Metadata
   - `fetch_oidc_metadata()` + `transform_oidc_to_rfc8414()` → RFC 8414 proxy
   - `create_client_registration_endpoint()` → RFC 7591 mock
   - `create_authorize_proxy_endpoint()` → scope rewriter (302 redirect)
   - `create_token_proxy_endpoint()` → scope rewriter (forwarded POST)

2. **Identity middleware**:
   - Exclude paths: `/health`, `/healthz`, `/`, `/.well-known/*`, `/oauth/*`
   - 401 response MUST include: `WWW-Authenticate: Bearer resource_metadata="<url>"`
   - Extract identity from `X-MS-CLIENT-PRINCIPAL` + `X-MS-CLIENT-PRINCIPAL-NAME`
   - Store in `ContextVar` for tool access

3. **Server routes** (6 total):
   - `GET /.well-known/oauth-protected-resource`
   - `GET /.well-known/oauth-authorization-server`
   - `POST /oauth/register`
   - `GET /oauth/authorize`
   - `POST /oauth/token`
   - `GET /health`

4. **Environment variables** (production):
   - `RUNNING_IN_PRODUCTION=true`
   - `OAUTH_RESOURCE_URL=<container-app-url>`
   - `OAUTH_TENANT_ID=<tenant-id>`
   - `OAUTH_CLIENT_ID=<client-id>`

5. **Azure Container Apps configuration**:
   - Easy Auth: `AllowAnonymous`
   - Allowed audiences: `api://<client-id>`
   - Issuer: `https://login.microsoftonline.com/<tenant-id>/v2.0`

### Common Mistakes to Avoid

- **DO NOT** set `registration_endpoint: null` — omit it or provide a real URL
- **DO NOT** use `:latest` Docker tag — use unique timestamped tags
- **DO NOT** point `authorization_endpoint`/`token_endpoint` directly to Microsoft — point to your proxy endpoints
- **DO NOT** use short-form scopes in metadata — always use `api://<client-id>/<scope>`
- **DO NOT** trust `X-MS-CLIENT-PRINCIPAL-NAME` without verifying `X-MS-CLIENT-PRINCIPAL` exists
- **DO NOT** set Easy Auth to `Return401` — use `AllowAnonymous`
- **DO NOT** register the Cursor redirect URI under "Web" in Entra ID — use "Mobile and desktop"

### Testing Sequence

After deployment, verify in this exact order:
1. `curl /health` → 200
2. `curl /.well-known/oauth-protected-resource` → 200 with correct JSON
3. `curl /.well-known/oauth-authorization-server` → 200 with correct JSON
4. `curl -X POST /oauth/register` → 201 with client_id
5. `curl -D - -X POST /mcp` → 401 with `WWW-Authenticate` header
6. `curl -v /oauth/authorize?scope=access_as_user&...` → 302 with rewritten scope in Location
7. Remove server from Cursor, restart Cursor, re-add, click Connect → browser opens → sign in → tools load
