"""API authentication for operator endpoints (approve/reject, submit review)."""
from __future__ import annotations

import hmac
from typing import Optional

from fastapi import Header, HTTPException, status

from config.settings import get_settings


def require_api_key(x_api_key: Optional[str] = Header(default=None)) -> str:
    settings = get_settings()
    expected = settings.review_api_key
    if not expected:
        if settings.is_development:
            return "dev"
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "REVIEW_API_KEY is not configured.")
    if not x_api_key or not hmac.compare_digest(x_api_key, expected):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or missing X-API-Key.")
    return "api-key"
