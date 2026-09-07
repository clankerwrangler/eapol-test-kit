from safe_assertions import require

import json
import os
from pathlib import Path
import secrets

import pytest
from fastapi.testclient import TestClient

from eapolkit.app import create_app
from eapolkit.settings import Settings


@pytest.fixture
def api(tmp_path):
    os.chmod(tmp_path, 0o700)
    settings = Settings(data_dir=tmp_path / "data", allowed_hosts=("testserver",), binary="/nonexistent/eapol_test")
    app = create_app(settings)
    with TestClient(app) as client:
        yield client, app, settings


def authenticate(client):
    password = secrets.token_urlsafe(24)
    response = client.post("/api/setup", json={"password": password}, headers={"X-EapolKit-Request": "1"})
    require(response.status_code == 200)
    client.headers.update({"X-EapolKit-Request": "1", "X-CSRF-Token": response.json()["csrf_token"]})
    return password


def no_credentials(content, values):
    clean = all(value.encode() not in content for value in values)
    require(clean, "A credential was exposed")


def test_authentication_csrf_and_origin_boundaries(api):
    client, app, settings = api
    require(client.get("/api/session").json() == {"setup_required": True, "authenticated": False, "csrf_token": None})
    require(client.get("/api/targets").status_code == 401)
    password = secrets.token_urlsafe(24)
    require(client.post("/api/setup", json={"password": password}).status_code == 403)
    require(client.post("/api/setup", json={"password": password}, headers={"X-EapolKit-Request": "1", "Origin": "https://foreign.invalid"}).status_code == 403)
    response = client.post("/api/setup", json={"password": password}, headers={"X-EapolKit-Request": "1"})
    require(response.status_code == 200)
    require("httponly" in response.headers["set-cookie"].lower())
    require("samesite=strict" in response.headers["set-cookie"].lower())
    csrf = response.json()["csrf_token"]
    marker = {"X-EapolKit-Request": "1"}
    require(client.post("/api/targets", json={"name": "test", "host": "127.0.0.1"}, headers=marker).status_code == 403)
    headers = dict(marker, **{"X-CSRF-Token": csrf})
    require(client.post("/api/targets", json={"name": "test", "host": "127.0.0.1"}, headers=headers).status_code == 200)
    require(client.get("/api/targets", headers={"Host": "foreign.invalid"}).status_code == 400)
    require(client.get("/api/targets", headers={"Origin": "http://testserver:81"}).status_code == 403)
    require(client.get("/api/targets", headers={"Origin": "http://testserver"}).status_code == 200)
    require(client.post("/api/setup", json={"password": password}, headers=headers).status_code == 409)
    require(client.post("/api/logout", headers=headers).status_code == 200)
    require(client.get("/api/targets").status_code == 401)
    require(client.get("/api/session").json()["csrf_token"] is None)
    require(client.post("/api/login", json={"password": secrets.token_urlsafe(24)}, headers=marker).status_code == 401)
    require(client.post("/api/login", json={"password": password}, headers=marker).status_code == 200)


def test_persistence_write_only_secrets_and_duplicate(api):
    client, app, settings = api
    admin = authenticate(client)
    radius = secrets.token_urlsafe(32)
    password = secrets.token_urlsafe(32) + '\n"\\'
    target_input = {"name": "Lab", "host": "radius.example.test", "secret": radius}
    target = client.post("/api/targets", json=target_input).json()
    require(target["has_secret"] is True)
    require("secret" not in target)
    target_id = target["id"]
    encrypted = app.state.store.get("target", target_id)["_secret"]
    update = client.put(f"/api/targets/{target_id}", json={"name": "Updated", "host": "127.0.0.1"})
    require(update.status_code == 200)
    unchanged = app.state.store.get("target", target_id)["_secret"] == encrypted
    require(unchanged)
    require(client.put(f"/api/targets/{target_id}", json={"name": "Updated", "host": "127.0.0.1", "secret": ""}).status_code == 422)
    profile = client.post("/api/profiles", json={"name": "Recipe", "method": "ttls-pap", "identity": "test-user", "password": password}).json()
    require(profile["has_password"] is True)
    require(profile["ca_certificate_id"] is None)
    duplicate = client.post(f"/api/profiles/{profile['id']}/duplicate", json={"name": "Copied recipe"})
    require(duplicate.status_code == 200)
    copied = duplicate.json()
    require(copied["id"] != profile["id"])
    require(copied["name"] == "Copied recipe")
    require(copied["has_password"] is True)
    same_ciphertext = app.state.store.get("profile", copied["id"])["_password"] == app.state.store.get("profile", profile["id"])["_password"]
    require(same_ciphertext)
    no_credentials(json.dumps([target, profile, copied]).encode(), [admin, radius, password])
    no_credentials((settings.data_dir / "eapolkit.sqlite3").read_bytes(), [admin, radius, password])
    require(len(client.get("/api/presets").json()) == 4)
    require({item["method"] for item in client.get("/api/presets").json()} == {"eap-tls", "peap-mschapv2", "ttls-pap", "ttls-mschapv2"})
    preview = client.get(f"/api/profiles/{profile['id']}/preview")
    require(preview.status_code == 200)
    require(preview.json()["warnings"])
    no_credentials(preview.content, [password])
    require(client.post("/api/runs", json={"target_id": target_id, "profile_id": profile["id"]}).status_code == 422)


def test_validation_never_echoes_credentials(api):
    client, app, settings = api
    authenticate(client)
    sentinel = secrets.token_urlsafe(32)
    response = client.post("/api/targets", json={"name": "Lab", "host": "127.0.0.1", "secret": sentinel + "\x00"})
    require(response.status_code == 422)
    no_credentials(response.content, [sentinel])
    for host in ("-h", "localhost;touch /tmp/owned", "localhost\nother", "https://localhost", "foo/bar", "a..b"):
        response = client.post("/api/targets", json={"name": "Lab", "host": host})
        require(response.status_code == 422)
    for attribute in ({"id": 1, "type": "hex", "value": "0x00"}, {"id": 1, "type": "integer", "value": "4294967296"}, {"id": 4, "type": "ipaddr", "value": "::1"}):
        require(client.post("/api/profiles", json={"name": "Lab", "method": "ttls-pap", "extra_attributes": [attribute]}).status_code == 422)
    require(client.post("/api/profiles", json={"name": "Bad range", "method": "eap-tls", "tls_min_version": "1.3", "tls_max_version": "1.2"}).status_code == 422)


def test_restart_keeps_password_and_data_but_revokes_sessions(tmp_path):
    os.chmod(tmp_path, 0o700)
    settings = Settings(data_dir=tmp_path / "data", allowed_hosts=("testserver",), binary="/nonexistent/eapol_test")
    with TestClient(create_app(settings)) as client:
        password = authenticate(client)
        target = client.post("/api/targets", json={"name": "Lab", "host": "127.0.0.1"}).json()
        cookie = client.cookies.get("eapolkit_session")
    with TestClient(create_app(settings)) as client:
        client.cookies.set("eapolkit_session", cookie)
        require(client.get("/api/session").json() == {"setup_required": False, "authenticated": False, "csrf_token": None})
        require(client.get("/api/targets").status_code == 401)
        response = client.post("/api/login", json={"password": password}, headers={"X-EapolKit-Request": "1"})
        require(response.status_code == 200)
        require(client.get("/api/targets").json()[0]["id"] == target["id"])


def test_request_body_limit(tmp_path):
    settings = Settings(data_dir=tmp_path / "data", allowed_hosts=("testserver",), request_limit=1024)
    with TestClient(create_app(settings)) as client:
        response = client.post("/api/setup", content=b"x" * 1025, headers={"X-EapolKit-Request": "1", "Content-Type": "application/json"})
        require(response.status_code == 413)
        require(client.get("/api/session").json()["setup_required"])


def test_certificate_http_lifecycle(api):
    client, app, settings = api
    authenticate(client)
    ca_response = client.post("/api/certificates/generate-ca", json={"name": "Client issuer", "common_name": "Ephemeral client issuer", "days": 10, "key_type": "ec-p256"})
    require(ca_response.status_code == 200)
    ca = ca_response.json()
    response = client.post("/api/certificates/generate-client", json={"issuer_id": ca["id"], "name": "Client", "common_name": "Ephemeral client", "days": 30, "key_type": "ec-p256", "san_email": ["client@example.test"]})
    require(response.status_code == 200)
    identity = response.json()
    require(identity["kind"] == "identity")
    require(identity["has_private_key"])
    require("_private_key" not in identity)
    public_pem = client.get(f"/api/certificates/{identity['id']}/download").content
    require(b"BEGIN CERTIFICATE" in public_pem)
    require(b"PRIVATE KEY" not in public_pem)
    require(client.get(f"/api/certificates/{identity['id']}/export-pfx").status_code == 405)
    require(client.post(f"/api/certificates/{identity['id']}/export-pfx", json={"passphrase": ""}).status_code == 422)
    export_phrase = secrets.token_urlsafe(24)
    export = client.post(f"/api/certificates/{identity['id']}/export-pfx", json={"passphrase": export_phrase})
    require(export.status_code == 200)
    imported = client.post("/api/certificates/import", data={"name": "Imported", "kind": "identity", "passphrase": export_phrase}, files={"pfx": ("identity.p12", export.content, "application/x-pkcs12")})
    require(imported.status_code == 200)
    require(imported.json()["fingerprint_sha256"] == identity["fingerprint_sha256"])
    trust_pem = client.get(f"/api/certificates/{ca['id']}/download").content
    trust_response = client.post("/api/certificates/import", data={"name": "Server trust", "kind": "trust"}, files={"certificate": ("trust.pem", trust_pem, "application/x-pem-file")})
    require(trust_response.status_code == 200)
    trust = trust_response.json()
    profile = client.post("/api/profiles", json={"name": "TLS recipe", "method": "eap-tls", "identity": "client", "server_name": "radius.example.test", "ca_certificate_id": trust["id"], "client_identity_id": identity["id"]}).json()
    require(client.delete(f"/api/certificates/{trust['id']}").status_code in {409, 422})
    require(client.delete(f"/api/profiles/{profile['id']}").status_code == 200)
    require(client.delete(f"/api/certificates/{trust['id']}").status_code == 200)
    no_credentials((settings.data_dir / "eapolkit.sqlite3").read_bytes(), [export_phrase])


def test_csr_completion_over_http(api):
    from datetime import datetime, timedelta, timezone
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.x509.oid import ExtendedKeyUsageOID

    client, app, settings = api
    authenticate(client)
    issuer = client.post("/api/certificates/generate-ca", json={"name": "Issuer", "common_name": "Test issuer", "key_type": "ec-p256"}).json()
    generated = client.post("/api/certificates/generate-csr", json={"name": "Enrollment", "common_name": "Test enrolled client", "key_type": "ec-p256", "san_dns": ["client.example.test"]})
    require(generated.status_code == 200)
    pending = generated.json()
    require(pending["kind"] == "csr")
    downloaded = client.get(f"/api/certificates/{pending['id']}/download?format=csr")
    require(downloaded.status_code == 200)
    csr = x509.load_pem_x509_csr(downloaded.content)
    material = app.state.certificates.material(issuer["id"])
    issuer_certificate = x509.load_pem_x509_certificate(material["certificate"])
    issuer_key = serialization.load_pem_private_key(material["private_key"], password=None)
    now = datetime.now(timezone.utc)
    certificate = (x509.CertificateBuilder().subject_name(csr.subject).issuer_name(issuer_certificate.subject)
                   .public_key(csr.public_key()).serial_number(x509.random_serial_number())
                   .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=1))
                   .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                   .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
                   .sign(issuer_key, hashes.SHA256()))
    completed = client.post(f"/api/certificates/{pending['id']}/complete", files={"certificate": ("signed.pem", certificate.public_bytes(serialization.Encoding.PEM), "application/x-pem-file")})
    require(completed.status_code == 200)
    require(completed.json()["id"] == pending["id"])
    require(completed.json()["kind"] == "identity")
    require(completed.json()["has_private_key"])
    require(len(client.get("/api/certificates").json()) == 2)
