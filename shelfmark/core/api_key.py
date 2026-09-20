"""Static API-key authentication backed by the API_KEY environment variable.

When ``API_KEY`` is set, a request carrying that value as a Bearer token (or in
``X-Api-Key``) is treated as an admin for that request only. A value that does
not match is ignored so that bearer tokens forwarded by reverse proxies keep
working. The key is never logged.
"""

from __future__ import annotations

import hmac

from shelfmark.config.env import API_KEY


def extract_api_key_candidate(
    authorization_header: str | None, api_key_header: str | None
) -> str | None:
    """Return the credential a client presented, if any. Bearer wins over X-Api-Key."""
    if authorization_header:
        scheme, _, token = authorization_header.strip().partition(" ")
        token = token.strip()
        if scheme.lower() == "bearer" and token:
            return token
    if api_key_header:
        token = api_key_header.strip()
        if token:
            return token
    return None


def matches_api_key(candidate: str) -> bool:
    """Constant-time comparison against the configured key. False when unset."""
    if not API_KEY or not candidate:
        return False
    return hmac.compare_digest(candidate.encode("utf-8"), API_KEY.encode("utf-8"))
