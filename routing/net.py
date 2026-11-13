"""Shared HTTPS redirect handlers used when fetching sources and release assets."""
from __future__ import annotations

import urllib.parse
import urllib.request
from typing import Any

from .errors import RoutingError


class HTTPSRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse any downgrade from HTTPS to HTTP on redirect."""

    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> Any:
        if urllib.parse.urlsplit(newurl).scheme != "https":
            raise RoutingError("Refusing an HTTP downgrade redirect")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class CredentialSafeRedirect(HTTPSRedirect):
    """Drop the Authorization header when a redirect changes the host."""

    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> Any:
        redirected = super().redirect_request(req, fp, code, msg, headers, newurl)
        if redirected is not None and urllib.parse.urlsplit(req.full_url).netloc != urllib.parse.urlsplit(newurl).netloc:
            redirected.remove_header("Authorization")
        return redirected
