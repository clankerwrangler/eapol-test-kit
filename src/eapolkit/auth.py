"""Local password authentication and same-origin request protection."""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import threading
import time
from dataclasses import dataclass
from urllib.parse import urlsplit

from starlette.requests import Request
from starlette.responses import JSONResponse

from .settings import Settings
from .storage import Store

COOKIE_NAME = "eapolkit_session"


@dataclass
class Session:
    csrf: str
    expires: float


class Auth:
    def __init__(self, store: Store, settings: Settings):
        self.store = store
        self.settings = settings
        self._sessions: dict[str, Session] = {}
        self._lock = threading.RLock()
        self._failures: list[float] = []

    @property
    def setup_required(self) -> bool:
        return self.store.setting("password_hash") is None

    def session(self, token: str | None) -> Session | None:
        if not token:
            return None
        digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
        with self._lock:
            result = self._sessions.get(digest)
            if result and result.expires <= time.time():
                del self._sessions[digest]
                return None
            return result

    def create(self) -> tuple[str, Session]:
        token = secrets.token_urlsafe(32)
        session = Session(secrets.token_urlsafe(32), time.time() + self.settings.session_seconds)
        with self._lock:
            self._sessions = {key: value for key, value in self._sessions.items() if value.expires > time.time()}
            if len(self._sessions) >= 64:
                oldest = min(self._sessions, key=lambda key: self._sessions[key].expires)
                del self._sessions[oldest]
            self._sessions[hashlib.sha256(token.encode("utf-8")).hexdigest()] = session
        return token, session

    def logout(self, token: str | None) -> None:
        if token:
            with self._lock:
                self._sessions.pop(hashlib.sha256(token.encode("utf-8")).hexdigest(), None)

    @staticmethod
    def _hash(password: str, salt: bytes) -> bytes:
        return hashlib.scrypt(password.encode("utf-8"), salt=salt, n=16384, r=8, p=1, dklen=32)

    def setup(self, password: str) -> tuple[str, Session]:
        with self._lock:
            if not self.setup_required:
                raise FileExistsError("Setup is already complete")
            salt = secrets.token_bytes(16)
            encoded = json.dumps({"algorithm": "scrypt", "salt": salt.hex(), "hash": self._hash(password, salt).hex()})
            if not self.store.set_setting_if_missing("password_hash", encoded):
                raise FileExistsError("Setup is already complete")
        return self.create()

    def login(self, password: str) -> tuple[str, Session]:
        with self._lock:
            now = time.monotonic()
            self._failures = [stamp for stamp in self._failures if now - stamp < 60]
            if len(self._failures) >= 10:
                raise TimeoutError("Too many login attempts; try again in one minute")
            encoded = self.store.setting("password_hash")
            if encoded is None:
                raise PermissionError("Authentication failed")
            stored = json.loads(encoded)
            valid = hmac.compare_digest(self._hash(password, bytes.fromhex(stored["salt"])).hex(), stored["hash"])
            if not valid:
                self._failures.append(now)
                raise PermissionError("Authentication failed")
            self._failures.clear()
        return self.create()

    def shape(self, session: Session | None) -> dict:
        return {"setup_required": self.setup_required, "authenticated": session is not None, "csrf_token": session.csrf if session else None}


class SecurityMiddleware:
    def __init__(self, app, *, settings: Settings):
        self.app = app
        self.settings = settings

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        request = Request(scope, receive)
        async def reject(code: int, detail: str):
            await JSONResponse({"detail": detail}, status_code=code)(scope, receive, secured_send)

        async def secured_send(message):
            if message["type"] == "http.response.start":
                message["headers"] = list(message["headers"]) + [
                    (b"x-content-type-options", b"nosniff"),
                    (b"referrer-policy", b"no-referrer"),
                    (b"x-frame-options", b"DENY"),
                    (b"content-security-policy", b"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"),
                    (b"cache-control", b"no-store"),
                ]
            await send(message)

        raw_headers = scope.get("headers", [])
        if sum(key.lower() == b"host" for key, _ in raw_headers) != 1 or sum(key.lower() == b"origin" for key, _ in raw_headers) > 1:
            await reject(400, "Invalid request authority")
            return
        try:
            authority = urlsplit("//" + request.headers.get("host", ""))
            host = authority.hostname
            port = authority.port
            if authority.username or authority.password or authority.path or authority.query or authority.fragment:
                raise ValueError
            if host is None or host.lower() not in self.settings.allowed_hosts:
                raise ValueError
        except ValueError:
            await reject(400, "Unexpected host")
            return
        origin = request.headers.get("origin")
        if origin is not None:
            try:
                parsed = urlsplit(origin)
                default_port = 443 if scope.get("scheme") == "https" else 80
                if parsed.scheme != scope.get("scheme") or parsed.hostname != host or (parsed.port or default_port) != (port or default_port) or parsed.path or parsed.query or parsed.fragment or parsed.username or parsed.password:
                    raise ValueError
            except ValueError:
                await reject(403, "Foreign origin is not allowed")
                return
        path = scope["path"]
        if path.startswith("/api/"):
            auth = scope["app"].state.auth
            session = auth.session(request.cookies.get(COOKIE_NAME))
            public_path = path in {"/api/session", "/api/setup", "/api/login"}
            if not public_path and session is None:
                await reject(401, "Authentication required")
                return
            if scope["method"] not in {"GET", "HEAD", "OPTIONS"}:
                if request.headers.get("x-eapolkit-request") != "1":
                    await reject(403, "Request marker required")
                    return
                if session is not None and not hmac.compare_digest(request.headers.get("x-csrf-token", "").encode("utf-8"), session.csrf.encode("ascii")):
                    await reject(403, "CSRF token required")
                    return
            scope.setdefault("state", {})["session"] = session
        if scope["method"] not in {"GET", "HEAD", "OPTIONS"}:
            length = request.headers.get("content-length")
            if length is not None:
                try:
                    if int(length) < 0 or int(length) > self.settings.request_limit:
                        raise ValueError
                except ValueError:
                    await reject(413, "Request body exceeds the upload limit")
                    return
            chunks = []
            total = 0
            while True:
                message = await receive()
                if message["type"] == "http.disconnect":
                    return
                chunk = message.get("body", b"")
                total += len(chunk)
                if total > self.settings.request_limit:
                    await reject(413, "Request body exceeds the upload limit")
                    return
                chunks.append(chunk)
                if not message.get("more_body", False):
                    break
            body = b"".join(chunks)
            sent = False
            async def buffered_receive():
                nonlocal sent
                if not sent:
                    sent = True
                    return {"type": "http.request", "body": body, "more_body": False}
                return await receive()
            await self.app(scope, buffered_receive, secured_send)
        else:
            await self.app(scope, receive, secured_send)
