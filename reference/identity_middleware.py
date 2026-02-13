"""
Identity Middleware for MCP Servers on Azure with Easy Auth

This middleware extracts user identity from Azure Easy Auth headers and
enforces authentication on protected routes. It returns 401 responses
with the WWW-Authenticate header required by the MCP OAuth specification.

How it works:
  1. Azure Easy Auth (set to AllowAnonymous) validates Bearer tokens at
     the infrastructure level. Valid tokens cause Easy Auth to inject
     X-MS-CLIENT-PRINCIPAL-* headers into the request.
  2. This middleware checks for those headers on protected routes.
  3. If the headers are missing (no token or invalid token), it returns
     a 401 with a WWW-Authenticate header pointing to the OAuth metadata.
  4. If the headers are present, it extracts the user identity and makes
     it available to MCP tools via a ContextVar.

Usage:
  from identity_middleware import IdentityMiddleware, get_user_email

  app.add_middleware(IdentityMiddleware)

  # In your MCP tool:
  email = get_user_email()  # Returns the authenticated user's email

Dependencies:
  pip install fastapi starlette email-validator

License: MIT
"""

import os
import base64
import json
import logging
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Callable, Optional, Set

from fastapi import Request, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from email_validator import validate_email, EmailNotValidError

logger = logging.getLogger(__name__)


# =============================================================================
# Data Classes
# =============================================================================

@dataclass
class UserIdentity:
    """
    Represents an authenticated user extracted from Easy Auth headers.

    Attributes:
        email: User's email address or UPN
        object_id: Azure AD object ID (optional)
        name: Display name (optional)
        raw_claims: Full decoded claims from X-MS-CLIENT-PRINCIPAL (optional)
    """
    email: str
    object_id: Optional[str] = None
    name: Optional[str] = None
    raw_claims: Optional[dict] = None


# Context variable — access this from MCP tools to get the current user
_user_identity: ContextVar[Optional[UserIdentity]] = ContextVar("user_identity", default=None)


# =============================================================================
# Public Accessors
# =============================================================================

def get_user_identity() -> UserIdentity:
    """
    Get the full user identity from the current request context.

    Returns:
        UserIdentity for the authenticated user

    Raises:
        ValueError: If called outside of an authenticated request
    """
    identity = _user_identity.get()
    if identity is None:
        raise ValueError("No authenticated user in context. Is IdentityMiddleware installed?")
    return identity


def get_user_email() -> str:
    """
    Get the authenticated user's email address.

    Convenience wrapper around get_user_identity().

    Returns:
        Email address string

    Raises:
        ValueError: If called outside of an authenticated request
    """
    return get_user_identity().email


# =============================================================================
# Middleware
# =============================================================================

class IdentityMiddleware(BaseHTTPMiddleware):
    """
    Middleware that extracts user identity from Azure Easy Auth headers
    and enforces authentication on protected routes.

    Excluded paths (no auth required):
      /health, /healthz, /
      /.well-known/*
      /oauth/*

    Protected paths return 401 with WWW-Authenticate header if no identity
    can be extracted.
    """

    # Easy Auth header names
    PRINCIPAL_HEADER = "X-MS-CLIENT-PRINCIPAL"
    PRINCIPAL_NAME_HEADER = "X-MS-CLIENT-PRINCIPAL-NAME"
    PRINCIPAL_ID_HEADER = "X-MS-CLIENT-PRINCIPAL-ID"

    # Paths that don't require authentication
    EXCLUDED_PATHS: Set[str] = {"/health", "/healthz", "/"}
    EXCLUDED_PREFIXES: Set[str] = {"/.well-known/", "/oauth/"}

    def __init__(self, app, dev_bypass: bool = False):
        """
        Args:
            app: The Starlette/FastAPI application
            dev_bypass: If True AND RUNNING_IN_PRODUCTION is not set, accept
                        X-User-Email header for local development. NEVER enable
                        this in production.
        """
        super().__init__(app)
        self._dev_bypass = dev_bypass and not os.environ.get("RUNNING_IN_PRODUCTION")
        if self._dev_bypass:
            logger.warning("DEV BYPASS ENABLED — X-User-Email header will be accepted")

    async def dispatch(self, request: Request, call_next: Callable):
        # Skip auth for excluded paths
        if self._is_excluded(request.url.path):
            return await call_next(request)

        # Try to extract identity
        identity = self._extract_identity(request)

        if identity is None:
            # Return 401 with WWW-Authenticate header (required by MCP spec)
            scheme = request.url.scheme
            host = request.headers.get("host", request.url.netloc)
            metadata_url = f"{scheme}://{host}/.well-known/oauth-protected-resource"

            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={
                    "error": "Unauthorized",
                    "message": "Authentication required. Ensure you are authenticated via Microsoft Entra ID.",
                },
                headers={
                    # RFC 9728 Section 5.1
                    "WWW-Authenticate": f'Bearer resource_metadata="{metadata_url}"',
                },
            )

        # Store identity in context for MCP tool access
        token = _user_identity.set(identity)
        try:
            return await call_next(request)
        finally:
            _user_identity.set(None)

    def _is_excluded(self, path: str) -> bool:
        """Check if the path is excluded from authentication."""
        if path in self.EXCLUDED_PATHS:
            return True
        return any(path.startswith(prefix) for prefix in self.EXCLUDED_PREFIXES)

    def _extract_identity(self, request: Request) -> Optional[UserIdentity]:
        """
        Extract user identity from Easy Auth headers.

        Security: Requires X-MS-CLIENT-PRINCIPAL to exist and contain valid
        base64-encoded JSON. This header can only be set by Easy Auth — it
        cannot be spoofed by clients. Do NOT trust X-MS-CLIENT-PRINCIPAL-NAME
        alone.

        Falls back to X-User-Email if dev bypass is enabled (development only).
        """
        headers = request.headers

        # --- Easy Auth extraction ---
        principal_b64 = headers.get(self.PRINCIPAL_HEADER)
        if principal_b64:
            claims = self._decode_principal(principal_b64)
            if claims is not None:
                email = headers.get(self.PRINCIPAL_NAME_HEADER, "").strip()
                if email:
                    return UserIdentity(
                        email=email,
                        object_id=(headers.get(self.PRINCIPAL_ID_HEADER) or "").strip() or None,
                        name=self._extract_name(claims),
                        raw_claims=claims,
                    )

        # --- Dev bypass (local development only) ---
        if self._dev_bypass:
            email = headers.get("X-User-Email", "").strip()
            if email and self._is_valid_email(email):
                logger.warning("DEV BYPASS: Accepting X-User-Email for %s", email)
                return UserIdentity(email=email)

        return None

    @staticmethod
    def _decode_principal(b64_value: str) -> Optional[dict]:
        """Decode and validate the base64-encoded principal JSON."""
        try:
            decoded = base64.b64decode(b64_value).decode("utf-8")
            claims = json.loads(decoded)
            return claims if isinstance(claims, dict) else None
        except Exception:
            return None

    @staticmethod
    def _extract_name(claims: dict) -> Optional[str]:
        """Extract display name from Easy Auth claims."""
        try:
            for claim in claims.get("claims", []):
                if claim.get("typ") == "name":
                    return claim.get("val")
        except Exception:
            pass
        return None

    @staticmethod
    def _is_valid_email(email: str) -> bool:
        """Validate email format."""
        try:
            validate_email(email, check_deliverability=False)
            return True
        except EmailNotValidError:
            return False
