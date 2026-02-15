"""
Development Identity Middleware for MCP Servers

This middleware is intended ONLY for local development. It allows bypassing
Microsoft Entra ID authentication by providing an X-User-Email header.

DANGER: Do NOT use this in production.
"""

import os
import logging
from typing import Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

# Import SecureIdentityMiddleware to reuse data classes if needed
from identity_middleware import UserIdentity, _user_identity

logger = logging.getLogger(__name__)

class DevIdentityMiddleware(BaseHTTPMiddleware):
    """
    Middleware that accepts X-User-Email for local development.
    Fails loudly if RUNNING_IN_PRODUCTION is set.
    """
    def __init__(self, app):
        super().__init__(app)
        # Safety check
        if os.environ.get("RUNNING_IN_PRODUCTION") == "true":
            logger.critical("SECURITY ALERT: DevIdentityMiddleware attempted to start in PRODUCTION!")
            raise RuntimeError("CRITICAL SECURITY ERROR: DevIdentityMiddleware cannot be used in production.")

    async def dispatch(self, request: Request, call_next: Callable):
        email = request.headers.get("X-User-Email", "").strip()
        
        if email:
            logger.warning("DEV AUTH BYPASS: Using X-User-Email=%s", email)
            # Create a mock identity
            identity = UserIdentity(
                email=email,
                name=f"Dev User ({email})",
                object_id="00000000-0000-0000-0000-000000000000"
            )
            
            # Store in context
            token = _user_identity.set(identity)
            try:
                return await call_next(request)
            finally:
                _user_identity.set(None)
        
        # If no email provided, proceed without identity (likely for public routes)
        # Note: In dev mode, we might want to still require auth or let it fail downstream
        return await call_next(request)
