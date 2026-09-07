"""Authenticated local web API for eapol_test."""
from __future__ import annotations

from contextlib import asynccontextmanager
import json
from pathlib import Path
import secrets
import shutil

from fastapi import FastAPI, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles

from . import __version__
from .auth import Auth, COOKIE_NAME, SecurityMiddleware
from .attributes import migrate_history, migrate_records, prepare_rows, public_profile, public_target
from .certificates import CertificateService
from .configuration import preview
from .models import CAInput, ClientInput, CSRInput, ExportInput, DuplicateInput, PasswordInput, ProfileInput, RunInput, TargetInput, presets
from .runner import RunConflict, RunManager
from .settings import Settings
from .storage import Store, public


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings()

    @asynccontextmanager
    async def lifespan(application):
        store = Store(settings.data_dir)
        runs = None
        try:
            migrate_records(store, "target")
            migrate_records(store, "profile")
            migrate_history(store)
            application.state.store = store
            application.state.auth = Auth(store, settings)
            application.state.certificates = CertificateService(store)
            runs = RunManager(store, application.state.certificates, settings)
            application.state.runs = runs
            yield
        finally:
            try:
                if runs is not None:
                    await runs.shutdown()
            finally:
                store.close()

    application = FastAPI(title="Eapol test kit", version=__version__, lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    application.add_middleware(SecurityMiddleware, settings=settings)

    @application.exception_handler(RequestValidationError)
    async def invalid_request(request, exc):
        # FastAPI's default validation errors include input values, including write-only secrets.
        details = [{"loc": error["loc"], "msg": error["msg"], "type": error["type"]} for error in exc.errors()]
        return JSONResponse({"detail": details}, status_code=422)

    @application.exception_handler(KeyError)
    async def missing_object(request, exc):
        return JSONResponse({"detail": "Object not found"}, status_code=404)

    @application.exception_handler(ValueError)
    async def invalid_value(request, exc):
        return JSONResponse({"detail": str(exc)}, status_code=422)

    @application.exception_handler(RunConflict)
    async def run_conflict(request, exc):
        return JSONResponse({"detail": str(exc)}, status_code=409)

    def session_response(auth, token, session):
        response = JSONResponse(auth.shape(session))
        response.set_cookie(COOKIE_NAME, token, max_age=settings.session_seconds, secure=settings.secure_cookies, httponly=True, samesite="strict", path="/")
        return response

    @application.get("/api/session")
    def session(request: Request):
        return request.app.state.auth.shape(request.state.session)

    @application.post("/api/setup")
    def setup(data: PasswordInput, request: Request):
        auth = request.app.state.auth
        try:
            token, current = auth.setup(data.password)
        except FileExistsError:
            raise HTTPException(409, "Setup is already complete") from None
        return session_response(auth, token, current)

    @application.post("/api/login")
    def login(data: PasswordInput, request: Request):
        auth = request.app.state.auth
        try:
            token, current = auth.login(data.password)
        except PermissionError:
            raise HTTPException(401, "Authentication failed") from None
        except TimeoutError:
            raise HTTPException(429, "Too many login attempts; try again in one minute") from None
        return session_response(auth, token, current)

    @application.post("/api/logout")
    def logout(request: Request):
        auth = request.app.state.auth
        auth.logout(request.cookies.get(COOKIE_NAME))
        response = JSONResponse(auth.shape(None))
        response.delete_cookie(COOKIE_NAME, path="/", secure=settings.secure_cookies, httponly=True, samesite="strict")
        return response

    @application.get("/api/status")
    def status(request: Request):
        return {"version": __version__, "eapol_test_available": shutil.which(settings.binary) is not None, "active_run_id": request.app.state.runs.active_run_id}

    @application.get("/api/presets")
    def starting_profiles():
        return presets()

    def save_object(kind, data, request, object_id=None):
        store = request.app.state.store
        with store.transaction():
            previous = store.get(kind, object_id) if object_id else {}
            secret_name = "secret" if kind == "target" else "password"
            supplied = getattr(data, secret_name)
            if secret_name in data.model_fields_set and supplied is None:
                raise HTTPException(422, "A supplied credential must not be empty; omit it to preserve the saved value")
            record = data.model_dump(exclude={secret_name})
            record["id"] = object_id or secrets.token_hex(16)
            encrypted_field = "_" + secret_name
            if supplied is not None:
                record[encrypted_field] = store.encrypt(supplied)
            elif encrypted_field in previous:
                record[encrypted_field] = previous[encrypted_field]
            record["has_" + secret_name] = encrypted_field in record
            if kind == "profile":
                incoming = [row.model_dump(exclude_unset=True) for row in data.extra_attributes] if "extra_attributes" in data.model_fields_set else None
                record["extra_attributes"] = prepare_rows(store, incoming, previous.get("extra_attributes", []))
                for field, kinds in (("ca_certificate_id", {"trust", "ca"}), ("client_identity_id", {"identity"})):
                    if record.get(field):
                        asset = store.get("certificate", record[field])
                        if asset["kind"] not in kinds:
                            raise HTTPException(422, "Certificate asset has the wrong purpose")
            store.put(kind, record)
            return public_target(store, record) if kind == "target" else public_profile(store, record)

    @application.get("/api/targets")
    def targets(request: Request):
        return [public_target(request.app.state.store, record) for record in request.app.state.store.list("target")]

    @application.post("/api/targets")
    def create_target(data: TargetInput, request: Request):
        return save_object("target", data, request)

    @application.put("/api/targets/{object_id}")
    def update_target(object_id: str, data: TargetInput, request: Request):
        return save_object("target", data, request, object_id)

    @application.delete("/api/targets/{object_id}")
    def delete_target(object_id: str, request: Request):
        request.app.state.store.delete("target", object_id)
        return {"deleted": True}

    @application.get("/api/profiles")
    def profiles(request: Request):
        return [public_profile(request.app.state.store, record) for record in request.app.state.store.list("profile")]

    @application.post("/api/profiles")
    def create_profile(data: ProfileInput, request: Request):
        return save_object("profile", data, request)

    @application.put("/api/profiles/{object_id}")
    def update_profile(object_id: str, data: ProfileInput, request: Request):
        return save_object("profile", data, request, object_id)

    @application.delete("/api/profiles/{object_id}")
    def delete_profile(object_id: str, request: Request):
        request.app.state.store.delete("profile", object_id)
        return {"deleted": True}

    @application.post("/api/profiles/{object_id}/duplicate")
    def duplicate_profile(object_id: str, request: Request, data: DuplicateInput | None = None):
        store = request.app.state.store
        with store.transaction():
            record = store.get("profile", object_id)
            record["id"] = secrets.token_hex(16)
            record["name"] = data.name if data and data.name is not None else record["name"][:113] + " (copy)"
            return public_profile(store, store.put("profile", record))

    @application.get("/api/profiles/{object_id}/preview")
    def configuration_preview(object_id: str, request: Request):
        return preview(request.app.state.store.get("profile", object_id), request.app.state.certificates)

    @application.get("/api/certificates")
    def certificates(request: Request):
        return request.app.state.certificates.list()

    async def upload(file: UploadFile | None):
        if file is None:
            return None
        try:
            value = await file.read(settings.upload_limit + 1)
            if len(value) > settings.upload_limit:
                raise HTTPException(413, "Certificate upload exceeds the limit")
            if not value:
                raise HTTPException(422, "Certificate uploads must not be empty")
            return value
        finally:
            await file.close()

    @application.post("/api/certificates/import")
    async def import_certificate(request: Request, name: str = Form(min_length=1, max_length=120), kind: str = Form(), certificate: UploadFile | None = File(default=None), private_key: UploadFile | None = File(default=None), pfx: UploadFile | None = File(default=None), passphrase: str | None = Form(default=None, max_length=4096)):
        if kind not in {"trust", "identity"}:
            raise HTTPException(422, "Import kind must be trust or identity")
        # Parse and validate bounded public/private uploads; never retain import passphrases.
        from starlette.concurrency import run_in_threadpool
        return await run_in_threadpool(request.app.state.certificates.import_asset, name=name, kind=kind, certificate=await upload(certificate), private_key=await upload(private_key), pfx=await upload(pfx), passphrase=passphrase)

    @application.post("/api/certificates/generate-ca")
    def generate_ca(data: CAInput, request: Request):
        return request.app.state.certificates.generate_ca(data.model_dump())

    @application.post("/api/certificates/generate-client")
    def generate_client(data: ClientInput, request: Request):
        return request.app.state.certificates.generate_client(data.model_dump())

    @application.post("/api/certificates/generate-csr")
    def generate_csr(data: CSRInput, request: Request):
        return request.app.state.certificates.generate_csr(data.model_dump())

    @application.post("/api/certificates/{object_id}/complete")
    async def complete_certificate(object_id: str, request: Request, certificate: UploadFile = File()):
        from starlette.concurrency import run_in_threadpool
        return await run_in_threadpool(request.app.state.certificates.complete, object_id, await upload(certificate))

    @application.get("/api/certificates/{object_id}/download")
    def download_certificate(object_id: str, request: Request, format: str = Query(default="certificate", pattern="^(certificate|csr)$")):
        content, media_type, filename = request.app.state.certificates.download(object_id, format)
        return Response(content, media_type=media_type, headers={"Content-Disposition": f'attachment; filename="{filename}"'})

    @application.post("/api/certificates/{object_id}/export-pfx")
    def export_identity(object_id: str, data: ExportInput, request: Request):
        content = request.app.state.certificates.export_pfx(object_id, data.passphrase)
        return Response(content, media_type="application/x-pkcs12", headers={"Content-Disposition": 'attachment; filename="client-identity.p12"'})

    @application.delete("/api/certificates/{object_id}")
    def delete_certificate(object_id: str, request: Request):
        request.app.state.certificates.delete(object_id)
        return {"deleted": True}

    @application.post("/api/runs")
    async def create_run(data: RunInput, request: Request):
        return await request.app.state.runs.start(data.target_id, data.profile_id)

    @application.get("/api/runs")
    def runs(request: Request, limit: int = Query(default=50, ge=1, le=100)):
        return request.app.state.runs.list(limit)

    @application.get("/api/runs/{object_id}")
    def run(object_id: str, request: Request, after: int = Query(default=0, ge=0)):
        return request.app.state.runs.get(object_id, after)

    @application.post("/api/runs/{object_id}/cancel")
    async def cancel_run(object_id: str, request: Request):
        return await request.app.state.runs.cancel(object_id)

    @application.get("/api/runs/{object_id}/export")
    def export_run(object_id: str, request: Request):
        result = request.app.state.runs.get(object_id)
        return Response(json.dumps(result, ensure_ascii=True, indent=2), media_type="application/json", headers={"Content-Disposition": 'attachment; filename="eapol-test-run.json"'})

    @application.delete("/api/runs/{object_id}")
    def delete_run(object_id: str, request: Request):
        request.app.state.runs.delete(object_id)
        return {"deleted": True}

    static_dir = Path(__file__).parent / "static"
    if static_dir.is_dir():
        application.mount("/static", StaticFiles(directory=static_dir), name="static")

    @application.get("/")
    def index():
        index_file = static_dir / "index.html"
        if not index_file.is_file():
            raise HTTPException(404, "The UI assets are not installed")
        return FileResponse(index_file)

    return application


app = create_app()
