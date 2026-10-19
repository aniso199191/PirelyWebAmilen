"""Framework adapters.

Both adapters are deliberately thin: build a RequestContext, ask the shield,
translate the decision into a response. No framework-specific detection.
"""
from __future__ import annotations

import json

from .context import RequestContext

DENY_BODY = json.dumps({"error": {"message": "已被封禁，请不要做任何违规做法"}}, ensure_ascii=False)
CHALLENGE_BODY = json.dumps({"error": {"message": "请完成验证后重试"}}, ensure_ascii=False)
DENY_STATUS = 403
DENY_HEADERS = {"Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store"}


class StarletteShield:
    """ASGI middleware for FastAPI / Starlette.

    Usage::

        app.add_middleware(StarletteShield, shield=shield)
    """

    def __init__(self, app, shield, skip_prefixes=("/health", "/static")) -> None:
        self.app = app
        self.shield = shield
        self.skip = tuple(skip_prefixes)

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope.get("path", "").startswith(self.skip):
            return await self.app(scope, receive, send)

        headers = {k.decode("latin-1"): v.decode("latin-1") for k, v in scope.get("headers", [])}
        client = scope.get("client") or ("", 0)
        ctx = RequestContext.from_headers(
            client[0], headers, method=scope.get("method", "GET"), path=scope.get("path", "/")
        )
        decision = self.shield.evaluate(ctx)

        if decision.blocked:
            body = DENY_BODY.encode()
            await send({
                "type": "http.response.start",
                "status": DENY_STATUS,
                "headers": [(k.lower().encode(), v.encode()) for k, v in DENY_HEADERS.items()]
                + [(b"content-length", str(len(body)).encode())],
            })
            await send({"type": "http.response.body", "body": body})
            return

        if decision.challenged:
            body = CHALLENGE_BODY.encode()
            await send({
                "type": "http.response.start",
                "status": 429,
                "headers": [(k.lower().encode(), v.encode()) for k, v in DENY_HEADERS.items()]
                + [(b"content-length", str(len(body)).encode())],
            })
            await send({"type": "http.response.body", "body": body})
            return

        return await self.app(scope, receive, send)


class FlaskShield:
    """``before_request`` hook for Flask."""

    def __init__(self, app, shield, skip_prefixes=("/health", "/static")) -> None:
        self.shield = shield
        self.skip = tuple(skip_prefixes)
        app.before_request(self._check)

    def _check(self):
        from flask import Response, request

        if request.path.startswith(self.skip):
            return None
        ctx = RequestContext.from_headers(
            request.remote_addr or "",
            request.headers,
            method=request.method,
            path=request.path,
            payload=request.get_data(cache=True, as_text=True)[:8192],
        )
        decision = self.shield.evaluate(ctx)
        if decision.blocked:
            return Response(DENY_BODY, status=DENY_STATUS, headers=DENY_HEADERS)
        if decision.challenged:
            return Response(CHALLENGE_BODY, status=429, headers=DENY_HEADERS)
        return None
