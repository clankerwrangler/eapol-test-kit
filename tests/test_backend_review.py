"""Independent contract checks with private, synthetic execution fixtures."""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from itertools import permutations
import json
import os
from pathlib import Path
import secrets
import sys
import time

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from fastapi.testclient import TestClient

from eapolkit.app import create_app
from eapolkit.certificates import CertificateService
from eapolkit.configuration import radius_attribute_file, render, validate_runnable
from eapolkit.models import ProfileInput, TargetInput
from eapolkit.runner import Evidence, RunManager, verdict
from eapolkit.settings import Settings
from eapolkit.storage import Store


ACCEPT = "EAPOL_TEST_RESULT accept=1 reject=0 timeout=0 mppe_ok=1 mppe_mismatch=0 cert_error=0"


def _require(condition, message):
    # Do not let assertion rewriting display credential-bearing operands.
    if not condition:
        pytest.fail(message, pytrace=False)


def _private_write(path, content, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(fd, "wb") as output:
        output.write(content)
    return path


def _program(tmp_path, name, body):
    os.chmod(tmp_path, 0o700)
    return _private_write(tmp_path / name, (f"#!{sys.executable}\n" + body).encode(), 0o700)


def _success_program(tmp_path):
    return _program(tmp_path, "fixture-eapol", f"print({ACCEPT!r})\nprint('SUCCESS')\n")


def _settings(tmp_path, binary, **changes):
    return Settings(data_dir=tmp_path / "data", binary=str(binary), allowed_hosts=("testserver",), **changes)


def _authenticate(client):
    password = secrets.token_urlsafe(32)
    response = client.post("/api/setup", json={"password": password}, headers={"X-EapolKit-Request": "1"})
    _require(response.status_code == 200, "Synthetic setup failed")
    client.headers.update({"X-EapolKit-Request": "1", "X-CSRF-Token": response.json()["csrf_token"]})
    return password


def _recipe(store, certificates, host="127.0.0.1", method="ttls-pap"):
    issuer = certificates.generate_ca({"name": "Review issuer", "common_name": "Review issuer", "key_type": "ec-p256"})
    target = TargetInput(name="Review target", host=host, timeout_seconds=5).model_dump(exclude={"secret"})
    target.update(id=secrets.token_hex(16), has_secret=True, _secret=store.encrypt(secrets.token_urlsafe(32)))
    profile = ProfileInput(name="Review recipe", method=method, identity="review-client", server_name="radius.example.test", ca_certificate_id=issuer["id"]).model_dump(exclude={"password"})
    profile.update(id=secrets.token_hex(16), has_password=True, _password=store.encrypt(secrets.token_urlsafe(32)))
    store.put("target", target)
    store.put("profile", profile)
    return target, profile, issuer


def _wait(client, run_id, seconds=8):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        response = client.get(f"/api/runs/{run_id}")
        _require(response.status_code == 200, "Run detail became unavailable")
        record = response.json()
        if record["status"] not in {"queued", "running"}:
            return record
        time.sleep(0.02)
    pytest.fail("The synthetic run exceeded the test deadline", pytrace=False)


def _wait_file(path, seconds=3):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if path.exists():
            return
        time.sleep(0.02)
    pytest.fail("The synthetic process did not reach its readiness marker", pytrace=False)


def _not_live(pid):
    try:
        state = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0]
    except FileNotFoundError:
        return True
    # A grandchild can await reaping by the enclosing process supervisor.
    return state in {"Z", "X"}


@pytest.mark.parametrize("tail", ["", " ", "\t", "diagnostic after terminal status"])
def test_a_terminal_footer_cannot_precede_trailing_output(tail):
    evidence = Evidence()
    for line in (ACCEPT, "SUCCESS", tail):
        evidence.observe(line)
    _require(evidence.finish(0)[0] != "accept", "Trailing output preserved an earlier success assertion")


def test_an_overlong_suppressed_line_invalidates_terminal_success(tmp_path):
    binary = _program(tmp_path, "fixture-eapol", f"print({ACCEPT!r})\nprint('SUCCESS')\nprint('x' * 6000)\n")
    app = create_app(_settings(tmp_path, binary))
    with TestClient(app) as client:
        _authenticate(client)
        target, profile, _ = _recipe(app.state.store, app.state.certificates)
        response = client.post("/api/runs", json={"target_id": target["id"], "profile_id": profile["id"]})
        _require(response.status_code == 200, "The synthetic run was not accepted")
        record = _wait(client, response.json()["id"])
        _require(record["outcome"] != "accept", "Suppressed trailing output preserved an earlier success assertion")


def test_cancel_terminates_a_descendant_that_ignores_sigterm(tmp_path):
    audit = tmp_path / "parent.json"
    child_ready = tmp_path / "child.json"
    child_code = (
        "import json,os,signal,time\nfrom pathlib import Path\n"
        "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
        f"Path({str(child_ready)!r}).write_text(json.dumps({{'pid':os.getpid(),'group':os.getpgrp()}}))\n"
        "time.sleep(60)\n"
    )
    body = (
        "import json,os,subprocess,sys,time\nfrom pathlib import Path\n"
        f"child=subprocess.Popen([sys.executable,'-c',{child_code!r}])\n"
        f"Path({str(audit)!r}).write_text(json.dumps({{'pid':os.getpid(),'directory':os.getcwd(),'group':os.getpgrp()}}))\n"
        "print('fixture waiting',flush=True)\ntime.sleep(60)\n"
    )
    binary = _program(tmp_path, "fixture-eapol", body)
    app = create_app(_settings(tmp_path, binary))
    with TestClient(app) as client:
        _authenticate(client)
        target, profile, _ = _recipe(app.state.store, app.state.certificates)
        response = client.post("/api/runs", json={"target_id": target["id"], "profile_id": profile["id"]})
        _require(response.status_code == 200, "The synthetic run was not accepted")
        run_id = response.json()["id"]
        _wait_file(audit)
        _wait_file(child_ready)
        parent = json.loads(audit.read_text())
        child = json.loads(child_ready.read_text())
        _require(parent["group"] == parent["pid"] == child["group"], "The fixture did not share the owned process group")
        cancelled = client.post(f"/api/runs/{run_id}/cancel")
        _require(cancelled.status_code == 200, "Owned cancellation failed")
        _require(cancelled.json()["status"] == "cancelled", "Cancellation did not become terminal")
        _require(_not_live(parent["pid"]) and _not_live(child["pid"]), "An owned process remained live after cancellation")
        _require(not Path(parent["directory"]).exists(), "Cancellation retained private run files")
        _require(client.get("/api/status").json()["active_run_id"] is None, "Cancellation did not release the active slot")


def test_cancel_before_execution_starts_releases_slot_without_launch(tmp_path):
    launched = tmp_path / "launched"
    binary = _program(tmp_path, "fixture-eapol", f"from pathlib import Path\nPath({str(launched)!r}).touch()\nprint({ACCEPT!r})\nprint('SUCCESS')\n")
    settings = _settings(tmp_path, binary)
    store = Store(settings.data_dir)
    certificates = CertificateService(store)
    manager = RunManager(store, certificates, settings)
    target, profile, _ = _recipe(store, certificates)

    async def scenario():
        try:
            queued = await manager.start(target["id"], profile["id"])
            _require(queued["status"] == "queued", "The early-cancellation fixture was not queued")
            cancelled = await asyncio.wait_for(manager.cancel(queued["id"]), timeout=3)
            _require(cancelled["status"] == "cancelled" and cancelled["outcome"] == "cancelled", "Queued cancellation did not finish")
            _require(cancelled["started_at"] is None and cancelled["exit_code"] is None, "Queued cancellation reported a process launch")
            _require(not launched.exists(), "Queued cancellation launched authentication")
            _require(manager.active_run_id is None and not list(manager._temporary_root.glob("run-*")), "Queued cancellation retained owned state")
            following = await manager.start(target["id"], profile["id"])
            deadline = time.monotonic() + 3
            while manager.active_run_id is not None and time.monotonic() < deadline:
                await asyncio.sleep(0.02)
            _require(manager.get(following["id"])["outcome"] == "accept", "A cancelled queue prevented the next authentication run")
        finally:
            await manager.shutdown()

    try:
        asyncio.run(scenario())
    finally:
        store.close()


@pytest.mark.parametrize("ending", ["cancel", "timeout"])
def test_dns_preparation_is_cancellable_and_uses_the_overall_deadline(tmp_path, monkeypatch, ending):
    resolver_ready = tmp_path / "resolver.json"
    authentication_started = tmp_path / "authentication-started"
    resolver = _program(tmp_path, "fixture-resolver", (
        "import json,os,time\nfrom pathlib import Path\n"
        f"Path({str(resolver_ready)!r}).write_text(json.dumps({{'pid':os.getpid(),'directory':os.getcwd()}}))\n"
        "time.sleep(60)\n"
    ))
    binary = _program(tmp_path, "fixture-eapol", f"from pathlib import Path\nPath({str(authentication_started)!r}).touch()\n")
    app = create_app(_settings(tmp_path, binary))
    with TestClient(app) as client:
        _authenticate(client)
        target, profile, _ = _recipe(app.state.store, app.state.certificates, host="radius.example.invalid")
        manager = app.state.runs
        original_spawn = manager._spawn

        async def controlled_spawn(*arguments, directory):
            if arguments[0] == sys.executable and arguments[1] == "-c":
                return await original_spawn(str(resolver), directory=directory)
            return await original_spawn(*arguments, directory=directory)

        monkeypatch.setattr(manager, "_spawn", controlled_spawn)
        started = time.monotonic()
        response = client.post("/api/runs", json={"target_id": target["id"], "profile_id": profile["id"]})
        _require(response.status_code == 200, "DNS fixture run was not accepted")
        run_id = response.json()["id"]
        _wait_file(resolver_ready)
        probe = time.monotonic()
        _require(client.get("/api/status").json()["active_run_id"] == run_id, "DNS preparation did not reserve the active run")
        _require(time.monotonic() - probe < 1, "DNS preparation blocked HTTP status handling")
        if ending == "cancel":
            result = client.post(f"/api/runs/{run_id}/cancel")
            _require(result.status_code == 200, "DNS preparation could not be cancelled")
        record = _wait(client, run_id)
        _require(record["outcome"] == ("cancelled" if ending == "cancel" else "timeout"), "DNS preparation produced the wrong terminal outcome")
        _require(record["outcome"] in {"cancelled", "timeout"}, "DNS failure produced an authentication result")
        _require(time.monotonic() - started < 7, "The overall deadline did not bound DNS preparation")
        details = json.loads(resolver_ready.read_text())
        _require(_not_live(details["pid"]), "DNS preparation left a live resolver")
        _require(not Path(details["directory"]).exists(), "DNS preparation retained private run files")
        _require(not authentication_started.exists(), "Authentication launched after cancelled or timed-out DNS preparation")


def test_csrf_tokens_belong_to_their_session_and_logout_revokes_cookie(tmp_path):
    settings = _settings(tmp_path, _success_program(tmp_path), secure_cookies=True)
    app = create_app(settings)
    with TestClient(app, base_url="https://testserver") as client:
        password = _authenticate(client)
        first_cookie = client.cookies.get("eapolkit_session")
        first_csrf = client.headers["X-CSRF-Token"]
        _require(client.get("/api/session").json()["authenticated"], "HTTPS did not retain the secure session cookie")
        client.cookies.clear()
        client.headers.pop("X-CSRF-Token")
        response = client.post("/api/login", json={"password": password})
        _require(response.status_code == 200, "The second synthetic login failed")
        _require("secure" in response.headers["set-cookie"].lower(), "HTTPS session cookie omitted Secure")
        second_csrf = response.json()["csrf_token"]
        client.headers["X-CSRF-Token"] = first_csrf
        rejected = client.post("/api/targets", json={"name": "CSRF probe", "host": "127.0.0.1"})
        _require(rejected.status_code == 403 and not client.get("/api/targets").json(), "A CSRF token from another session authorized a mutation")
        client.headers["X-CSRF-Token"] = second_csrf
        second_cookie = client.cookies.get("eapolkit_session")
        _require(client.post("/api/logout").status_code == 200, "Logout failed")
        client.cookies.set("eapolkit_session", second_cookie)
        _require(client.get("/api/targets").status_code == 401, "A revoked session cookie remained valid")
        client.cookies.clear()
        client.cookies.set("eapolkit_session", first_cookie)
        _require(client.get("/api/session").json()["authenticated"], "Logout revoked an unrelated active session")


@pytest.mark.parametrize("headers,code", [
    ([("Host", "testserver"), ("Host", "foreign.invalid")], 400),
    ([("Origin", "http://testserver"), ("Origin", "http://foreign.invalid")], 400),
    ([("Origin", "http://testserver@foreign.invalid")], 403),
    ([("Origin", "null")], 403),
])
def test_ambiguous_request_authority_is_rejected_before_setup(tmp_path, headers, code):
    with TestClient(create_app(_settings(tmp_path, _success_program(tmp_path)))) as client:
        response = client.post("/api/setup", json={"password": secrets.token_urlsafe(32)}, headers=[("X-EapolKit-Request", "1"), *headers])
        _require(response.status_code == code, "An ambiguous request authority passed the boundary")
        _require(client.get("/api/session").json()["setup_required"], "A rejected authority changed setup state")


@pytest.mark.parametrize("method", ["eap-tls", "peap-mschapv2", "ttls-pap", "ttls-mschapv2"])
def test_configuration_round_trips_strong_characters_without_directives(method):
    identity = secrets.token_urlsafe(20) + '\n}\nnetwork={\nengine=1\n"\\#=é☃\x00'
    anonymous = secrets.token_urlsafe(20) + '\nload_dynamic_eap="not-a-module"\n'
    password = secrets.token_urlsafe(32) + '\n"\\#=é☃\x00'
    profile = ProfileInput(name="Encoding review", method=method, identity=identity, anonymous_identity=anonymous, server_name="radius.example.test", ca_certificate_id="public-reference", allow_expired_client_certificate=True).model_dump(exclude={"password"})
    configuration = render(profile, {"ca_certificate": "asset:public-reference:certificate"}, password.encode())
    fields = dict(line.strip().split("=", 1) for line in configuration.splitlines()[1:-1] if "=" in line)
    _require(fields.get("key_mgmt") == "IEEE8021X" and fields.get("eapol_flags") == "0", "The generated configuration did not select the RADIUS EAPOL client mode")
    expected_eap = {"eap-tls": "TLS", "peap-mschapv2": "PEAP", "ttls-pap": "TTLS", "ttls-mschapv2": "TTLS"}
    expected_phase2 = None if method == "eap-tls" else '"auth=PAP"' if method == "ttls-pap" else '"auth=MSCHAPV2"'
    _require(fields.get("eap") == expected_eap[method] and fields.get("phase2") == expected_phase2, "The generated configuration selected a different EAP or inner method")
    _require(bytes.fromhex(fields["identity"]) == identity.encode(), "Identity encoding changed the supplied bytes")
    _require(bytes.fromhex(fields["anonymous_identity"]) == anonymous.encode(), "Anonymous identity encoding changed the supplied bytes")
    if method != "eap-tls":
        _require(bytes.fromhex(fields["password"]) == password.encode(), "Password encoding changed the supplied bytes")
    _require(configuration.count("network={") == 1 and configuration.count("\n}") == 1, "An input introduced a network block")
    _require(not {"engine", "load_dynamic_eap", "openssl_ciphers", "private_key_passwd"}.intersection(fields), "An input introduced a configuration directive")
    _require("tls_disable_time_checks" not in configuration and fields["domain_match"] == '"radius.example.test"', "Expired-client permission disabled server validation")


@pytest.mark.parametrize("method,minimum,maximum,tls13,disable12", [
    ("eap-tls", "1.2", "auto", None, False),
    ("peap-mschapv2", "1.2", "auto", None, False),
    ("ttls-pap", "1.2", "auto", None, False),
    ("ttls-mschapv2", "1.2", "auto", None, False),
    ("ttls-mschapv2", "1.2", "1.2", "1", False),
    ("ttls-mschapv2", "1.2", "1.3", "0", False),
    ("ttls-mschapv2", "1.3", "auto", "0", True),
    ("eap-tls", "1.3", "1.3", "0", True),
])
def test_tls_bounds_preserve_upstream_auto_and_enable_explicit_tls13(method, minimum, maximum, tls13, disable12):
    profile = ProfileInput(name="TLS review", method=method, tls_min_version=minimum, tls_max_version=maximum).model_dump(exclude={"password"})
    configuration = render(profile, {}, redacted=True)
    phase1 = next(line.strip().split("=", 1)[1].strip('"') for line in configuration.splitlines() if line.strip().startswith("phase1="))
    parameters = dict(item.split("=", 1) for item in phase1.split())
    _require(parameters.get("tls_disable_tlsv1_0") == parameters.get("tls_disable_tlsv1_1") == "1", "A supported profile enabled obsolete TLS versions")
    _require(parameters.get("tls_disable_tlsv1_3") == tls13, "TLS 1.3 selection changed an upstream default or ignored an explicit bound")
    _require((parameters.get("tls_disable_tlsv1_2") == "1") == disable12, "The minimum TLS version did not control TLS 1.2")
    _require("tls_disable_time_checks" not in parameters, "TLS bounds disabled server-certificate time validation")


def test_radius_attribute_file_preserves_unicode_and_delimiters():
    text = "é:' ,;\\$(not-a-command)"
    target = TargetInput(name="Attribute review", host="127.0.0.1", nas_identifier=text, nas_ip_address="192.0.2.44").model_dump(exclude={"secret"})
    profile = ProfileInput(name="Attribute review", method="ttls-pap", calling_station_id=text, extra_attributes=[
        {"id": 18, "type": "string", "value": text},
        {"id": 27, "type": "integer", "value": "4294967295"},
        {"id": 33, "type": "hex", "value": "00ff80"},
        {"id": 8, "type": "ipaddr", "value": "192.0.2.45"},
    ]).model_dump(exclude={"password"})
    content = radius_attribute_file(target, profile["extra_attributes"], profile)
    rows = content.decode("ascii").splitlines()
    _require(len(rows) == 7 and content.endswith(b"\n"), "Attribute input altered private-file row boundaries")
    values = {}
    for row in rows:
        attribute, encoding, encoded = row.split(":")
        _require(encoding == "x", "A RADIUS attribute used delimiter-sensitive encoding")
        values[int(attribute)] = bytes.fromhex(encoded)
    _require(values[18] == values[31] == values[32] == text.encode(), "String attributes did not preserve UTF-8 bytes")
    _require(values[27] == b"\xff" * 4 and values[33] == b"\x00\xff\x80", "Numeric or hex attribute encoding changed the payload")
    _require(values[4] == b"\xc0\x00\x02\x2c" and values[8] == b"\xc0\x00\x02\x2d", "IP attributes did not use network-order IPv4 bytes")


@pytest.fixture
def certificate_store(tmp_path):
    os.chmod(tmp_path, 0o700)
    store = Store(tmp_path / "data")
    try:
        yield CertificateService(store), store
    finally:
        store.close()


def _issue(public_key, issuer, issuer_key, *, ca=False, before=None, after=None,
           common_name="Review certificate", key_identifier=None, authority=None, serial_number=None):
    now = datetime.now(timezone.utc)
    builder = (x509.CertificateBuilder()
               .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
               .issuer_name(issuer.subject).public_key(public_key)
               .serial_number(serial_number if serial_number is not None else x509.random_serial_number())
               .not_valid_before(before or now - timedelta(minutes=1))
               .not_valid_after(after or now + timedelta(days=1))
               .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
               .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False))
    if key_identifier is not None:
        builder = builder.add_extension(x509.SubjectKeyIdentifier(key_identifier), critical=False)
    if authority is not None:
        builder = builder.add_extension(authority, critical=False)
    return builder.sign(issuer_key, hashes.SHA256())


def _issuer_material(service):
    issuer = service.generate_ca({"name": "Issuer", "common_name": "Review issuer", "key_type": "ec-p256"})
    material = service.material(issuer["id"])
    certificate = x509.load_pem_x509_certificate(material["certificate"])
    key = serialization.load_pem_private_key(material["private_key"], None)
    return issuer, certificate, key


def test_csr_completion_rejects_ca_and_invalid_chain_then_completes_same_key(tmp_path):
    app = create_app(_settings(tmp_path, _success_program(tmp_path)))
    with TestClient(app) as client:
        _authenticate(client)
        service = app.state.certificates
        _, issuer, issuer_key = _issuer_material(service)
        pending = client.post("/api/certificates/generate-csr", json={"name": "Enrollment", "common_name": "Review client", "key_type": "ec-p256", "san_dns": ["client.example.test"]}).json()
        csr_pem = client.get(f"/api/certificates/{pending['id']}/download?format=csr").content
        csr = x509.load_pem_x509_csr(csr_pem)
        _require(csr.is_signature_valid, "The generated CSR signature did not verify")
        _require(csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName) == ["client.example.test"], "The CSR omitted a requested SAN")
        _require(ExtendedKeyUsageOID.CLIENT_AUTH in csr.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value, "The CSR omitted clientAuth usage")
        wrong_signer = ec.generate_private_key(ec.SECP256R1())
        ca_leaf = _issue(csr.public_key(), issuer, issuer_key, ca=True)
        invalid_leaf = _issue(csr.public_key(), issuer, wrong_signer)
        for chain in (ca_leaf.public_bytes(serialization.Encoding.PEM), invalid_leaf.public_bytes(serialization.Encoding.PEM) + issuer.public_bytes(serialization.Encoding.PEM)):
            response = client.post(f"/api/certificates/{pending['id']}/complete", files={"certificate": ("signed.pem", chain, "application/x-pem-file")})
            _require(response.status_code == 422, "CSR completion accepted the wrong certificate purpose or an invalid chain")
            _require(service.get(pending["id"])["kind"] == "csr", "Failed completion destroyed the pending enrollment")
            _require(client.get(f"/api/certificates/{pending['id']}/download?format=csr").content == csr_pem, "Failed completion replaced the pending CSR")
        leaf = _issue(csr.public_key(), issuer, issuer_key)
        chain = leaf.public_bytes(serialization.Encoding.PEM) + issuer.public_bytes(serialization.Encoding.PEM)
        response = client.post(f"/api/certificates/{pending['id']}/complete", files={"certificate": ("signed.pem", chain, "application/x-pem-file")})
        _require(response.status_code == 200 and response.json()["id"] == pending["id"] and response.json()["kind"] == "identity", "A valid completion did not preserve the enrollment ID")
        downloaded = client.get(f"/api/certificates/{pending['id']}/download").content
        completed = x509.load_pem_x509_certificate(downloaded)
        completed.verify_directly_issued_by(issuer)
        _require(completed.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo) == csr.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo), "Completion replaced the retained enrollment key")
        _require(client.post(f"/api/certificates/{pending['id']}/complete", files={"certificate": ("signed.pem", chain)}).status_code == 422, "A completed identity was enrollable again")


def test_failed_encrypted_key_import_does_not_reflect_or_persist_secrets(tmp_path):
    app = create_app(_settings(tmp_path, _success_program(tmp_path)))
    with TestClient(app) as client:
        _authenticate(client)
        service = app.state.certificates
        _, issuer, issuer_key = _issuer_material(service)
        key = ec.generate_private_key(ec.SECP256R1())
        phrase = secrets.token_urlsafe(32)
        wrong_phrase = secrets.token_urlsafe(32)
        encrypted_key = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.BestAvailableEncryption(phrase.encode()))
        certificate = _issue(key.public_key(), issuer, issuer_key).public_bytes(serialization.Encoding.PEM)
        original_count = len(service.list())
        files = {"certificate": ("certificate.pem", certificate), "private_key": ("key.pem", encrypted_key)}
        response = client.post("/api/certificates/import", data={"name": "Protected key", "kind": "identity", "passphrase": wrong_phrase}, files=files)
        _require(response.status_code == 422, "Incorrect PEM protection was accepted")
        _require(len(service.list()) == original_count, "A failed import persisted a partial identity")
        plaintext = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        protected_values = [phrase.encode(), wrong_phrase.encode(), encrypted_key, plaintext]
        _require(all(value not in response.content for value in protected_values), "An import error reflected private material")
        good = client.post("/api/certificates/import", data={"name": "Protected key", "kind": "identity", "passphrase": phrase}, files=files)
        _require(good.status_code == 200, "A valid protected PEM identity could not be imported")
        ordinary = client.get("/api/certificates").content
        database = (app.state.store.directory / "eapolkit.sqlite3").read_bytes()
        _require(all(value not in ordinary and value not in database for value in protected_values), "A PEM passphrase or private key reached an ordinary response or plaintext storage")
        _require(client.get(f"/api/certificates/{good.json()['id']}/download?format=private_key").status_code == 422, "A public download accepted a private-key format")
        _require(client.get(f"/api/certificates/{good.json()['id']}/export-pfx").status_code == 405, "A GET request exported a private identity")


@pytest.mark.parametrize("state", ["expired", "future"])
def test_expired_client_permission_does_not_allow_future_clients_or_missing_server_trust(certificate_store, state):
    service, store = certificate_store
    target, profile, issuer_metadata = _recipe(store, service, method="eap-tls")
    material = service.material(issuer_metadata["id"])
    issuer = x509.load_pem_x509_certificate(material["certificate"])
    issuer_key = serialization.load_pem_private_key(material["private_key"], None)
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(timezone.utc)
    before, after = ((now - timedelta(days=2), now - timedelta(days=1)) if state == "expired" else (now + timedelta(days=1), now + timedelta(days=2)))
    leaf = _issue(key.public_key(), issuer, issuer_key, before=before, after=after)
    identity = service.import_asset("Time-bound client", "identity", certificate=leaf.public_bytes(serialization.Encoding.PEM), private_key=key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    profile["client_identity_id"] = identity["id"]
    with pytest.raises(ValueError):
        validate_runnable(profile, target, service, store)
    profile["allow_expired_client_certificate"] = True
    if state == "future":
        with pytest.raises(ValueError, match="not yet valid"):
            validate_runnable(profile, target, service, store)
    else:
        validate_runnable(profile, target, service, store)
        for field in ("ca_certificate_id", "server_name"):
            with pytest.raises(ValueError, match="explicit server CA"):
                validate_runnable(dict(profile, **{field: None if field.endswith("_id") else ""}), target, service, store)


def test_expired_issuer_cannot_sign_a_new_client(certificate_store, monkeypatch):
    import eapolkit.certificates as module

    service, store = certificate_store
    issuer_metadata, issuer, _ = _issuer_material(service)
    count = len(service.list())
    monkeypatch.setattr(module, "_now", lambda: issuer.not_valid_after_utc + timedelta(seconds=1))
    with pytest.raises(ValueError, match="not currently valid"):
        service.generate_client({"issuer_id": issuer_metadata["id"], "name": "Client", "common_name": "Review client", "key_type": "ec-p256"})
    _require(len(service.list()) == count, "An expired issuer persisted a newly signed client")


@pytest.mark.parametrize("kind", ["malformed", "symlink"])
def test_invalid_master_key_is_not_replaced_or_followed(tmp_path, kind):
    os.chmod(tmp_path, 0o700)
    directory = tmp_path / "data"
    Store(directory).close()
    key = directory / "secrets/master.key"
    key.unlink()
    original = secrets.token_bytes(17)
    if kind == "symlink":
        outside = _private_write(tmp_path / "unrelated-key", original)
        key.symlink_to(outside)
    else:
        _private_write(key, original)
    with pytest.raises(RuntimeError, match="symlink" if kind == "symlink" else "Invalid installation master key"):
        Store(directory)
    _require(key.read_bytes() == original, "Invalid installation-key handling replaced key material")
    _require(key.is_symlink() == (kind == "symlink"), "Invalid installation-key handling changed the key path")


def test_restart_recovers_queued_and_running_records_without_following_stale_links(tmp_path):
    binary = _success_program(tmp_path)
    settings = _settings(tmp_path, binary)
    store = Store(settings.data_dir)
    manager = RunManager(store, CertificateService(store), settings)
    ids = {state: secrets.token_hex(16) for state in ("queued", "running", "completed")}
    for state, run_id in ids.items():
        store.put("run", {"id": run_id, "status": state, "outcome": "accept" if state == "completed" else None, "verdict": "pass" if state == "completed" else None, "started_at": None, "log_lines": [], "next_seq": 0, "truncated": False})
    unrelated = tmp_path / "unrelated"
    unrelated.mkdir(mode=0o700)
    sentinel = _private_write(unrelated / "sentinel", secrets.token_bytes(32))
    stale = manager._temporary_root / ("run-" + ids["queued"])
    stale.symlink_to(unrelated, target_is_directory=True)
    active_stale = manager._temporary_root / ("run-" + ids["running"])
    active_stale.mkdir(mode=0o700)
    _private_write(active_stale / "radius.secret", secrets.token_bytes(32))
    asyncio.run(manager.shutdown())
    store.close()
    recovered_store = Store(settings.data_dir)
    recovered = RunManager(recovered_store, CertificateService(recovered_store), settings)
    try:
        for state in ("queued", "running"):
            record = recovered.get(ids[state])
            _require(record["status"] == record["outcome"] == "interrupted", "Restart did not interrupt an unfinished record")
            _require(record["finished_at"] is not None, "Restart recovery omitted a terminal timestamp")
        _require(recovered.get(ids["completed"])["outcome"] == "accept", "Restart changed an already completed result")
        _require(recovered.active_run_id is None, "Restart replayed an unfinished authentication")
        _require(not stale.is_symlink() and not active_stale.exists() and sentinel.exists(), "Restart cleanup crossed an owned-run boundary")
    finally:
        asyncio.run(recovered.shutdown())
        recovered_store.close()



def _authority(certificate):
    try:
        identifier = certificate.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest
    except x509.ExtensionNotFound:
        identifier = None
    return x509.AuthorityKeyIdentifier(identifier, [x509.DirectoryName(certificate.issuer)], certificate.serial_number)


def _pfx_chain(service):
    _, root, root_key = _issuer_material(service)
    chain, keys = [root], [root_key]
    for label, ca in (("Review upper issuer", True), ("Review lower issuer", True), ("Review enrolled client", False)):
        key = ec.generate_private_key(ec.SECP256R1())
        certificate = _issue(key.public_key(), chain[0], keys[0], ca=ca, common_name=label,
                             key_identifier=x509.SubjectKeyIdentifier.from_public_key(key.public_key()).digest,
                             authority=_authority(chain[0]))
        chain.insert(0, certificate)
        keys.insert(0, key)
    return chain, keys


def _import_pfx(service, key, leaf, bags, *, accepted):
    # Keep fixture failures and import errors secret-free even if construction fails.
    phrase = secrets.token_urlsafe(32)
    try:
        encoded = pkcs12.serialize_key_and_certificates(b"Review identity", key, leaf, bags,
                                                       serialization.BestAvailableEncryption(phrase.encode()))
    except Exception:
        pytest.fail("The synthetic PFX could not be constructed", pytrace=False)
    before = {item["id"] for item in service.list()}
    try:
        imported = service.import_asset("Imported review identity", "identity", pfx=encoded, passphrase=phrase)
    except ValueError:
        _require(not accepted, "A valid PFX issuer path was rejected")
        _require({item["id"] for item in service.list()} == before, "A rejected PFX persisted a partial identity")
        return None
    except Exception:
        pytest.fail("PFX import raised an unexpected exception", pytrace=False)
    _require(accepted, "An invalid or ambiguous PFX issuer path was accepted")
    _require(imported["kind"] == "identity" and imported["has_private_key"], "PFX import did not retain the selected private identity")
    return imported


def _require_usable_chain(service, imported, chain):
    public_pem = service.download(imported["id"], "certificate")[0]
    expected_pem = b"".join(certificate.public_bytes(serialization.Encoding.PEM) for certificate in chain)
    _require(public_pem == expected_pem, "PFX bag order changed the normalized public chain")
    challenge = secrets.token_bytes(32)
    try:
        material = service.material(imported["id"])
        key = serialization.load_pem_private_key(material["private_key"], None)
        signature = key.sign(challenge, ec.ECDSA(hashes.SHA256()))
        chain[0].public_key().verify(signature, challenge, ec.ECDSA(hashes.SHA256()))
        for certificate, issuer in zip(chain, chain[1:]):
            certificate.verify_directly_issued_by(issuer)
    except Exception:
        pytest.fail("The imported PFX identity or chain was not cryptographically usable", pytrace=False)


@pytest.mark.parametrize("duplicate_bags", [False, True])
def test_pfx_all_bag_permutations_produce_the_same_usable_chain(certificate_store, duplicate_bags):
    service, store = certificate_store
    chain, keys = _pfx_chain(service)
    for order in permutations(chain[1:]):
        bags = list(order)
        if duplicate_bags:
            bags.extend([chain[0], chain[1], chain[-1]])
        imported = _import_pfx(service, keys[0], chain[0], bags, accepted=True)
        _require_usable_chain(service, imported, chain)


@pytest.mark.parametrize("defect", ["unmatched-private-key", "wrong-issuer-key", "wrong-signature", "ambiguous", "unrelated"])
def test_pfx_normalization_rejects_invalid_or_ambiguous_material(certificate_store, defect):
    service, store = certificate_store
    chain, keys = _pfx_chain(service)
    leaf, key, bags = chain[0], keys[0], list(reversed(chain[1:]))
    if defect == "unmatched-private-key":
        key = ec.generate_private_key(ec.SECP256R1())
        leaf = None
        bags.append(chain[0])
    elif defect == "wrong-issuer-key":
        wrong_key = ec.generate_private_key(ec.SECP256R1())
        impostor = _issue(wrong_key.public_key(), chain[2], keys[2], ca=True,
                          common_name="Review lower issuer", serial_number=chain[1].serial_number,
                          key_identifier=chain[1].extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest,
                          authority=_authority(chain[2]))
        bags = [impostor, *chain[2:]]
    elif defect == "wrong-signature":
        encoded = leaf.public_bytes(serialization.Encoding.DER)
        leaf = x509.load_der_x509_certificate(encoded[:-1] + bytes([encoded[-1] ^ 1]))
    elif defect == "ambiguous":
        # Both distinct certificates have the same issuer-facing name and public key.
        leaf = _issue(keys[0].public_key(), chain[1], keys[1])
        alternate = _issue(keys[1].public_key(), chain[2], keys[2], ca=True,
                           common_name="Review lower issuer", authority=_authority(chain[2]))
        bags.append(alternate)
    else:
        unrelated_key = ec.generate_private_key(ec.SECP256R1())
        bags.append(_issue(unrelated_key.public_key(), chain[-1], keys[-1], ca=True, common_name="Unrelated branch"))
    _import_pfx(service, key, leaf, bags, accepted=False)


@pytest.mark.parametrize("mismatch", ["key-identifier", "authority-serial", "authority-issuer"])
def test_pfx_authority_identifiers_cannot_contradict_the_supplied_issuer(certificate_store, mismatch):
    service, store = certificate_store
    chain, keys = _pfx_chain(service)
    valid = _authority(chain[1])
    key_identifier = secrets.token_bytes(20) if mismatch == "key-identifier" else valid.key_identifier
    serial = valid.authority_cert_serial_number + 1 if mismatch == "authority-serial" else valid.authority_cert_serial_number
    names = [x509.DirectoryName(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Wrong issuing authority")]))] if mismatch == "authority-issuer" else valid.authority_cert_issuer
    authority = x509.AuthorityKeyIdentifier(key_identifier, names, serial)
    leaf = _issue(keys[0].public_key(), chain[1], keys[1], authority=authority)
    _import_pfx(service, keys[0], leaf, list(reversed(chain[1:])), accepted=False)


@pytest.mark.parametrize("identify_issuer", [False, True])
def test_pfx_authority_serial_disambiguates_same_name_and_key_only_when_present(certificate_store, identify_issuer):
    service, store = certificate_store
    _, root, issuer_key = _issuer_material(service)
    identifier = root.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest
    lower = _issue(issuer_key.public_key(), root, issuer_key, ca=True, common_name="Review issuer",
                   key_identifier=identifier, authority=_authority(root))
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    authority = _authority(lower) if identify_issuer else x509.AuthorityKeyIdentifier(identifier, None, None)
    leaf = _issue(leaf_key.public_key(), lower, issuer_key, authority=authority)
    for bags in ([root, lower], [lower, root]):
        imported = _import_pfx(service, leaf_key, leaf, bags, accepted=identify_issuer)
        if identify_issuer:
            _require_usable_chain(service, imported, [leaf, lower, root])



def test_native_counters_ignore_forged_certificate_diagnostics():
    evidence = Evidence()
    for line in (
        "CTRL-EVENT-EAP-TLS-CERT-ERROR reason=1 depth=0 untrusted diagnostic",
        "EAPOL_TEST_RESULT accept=0 reject=0 timeout=0 mppe_ok=0 mppe_mismatch=0 cert_error=1",
        "untrusted intervening text",
        "EAPOL_TEST_RESULT accept=0 reject=1 timeout=0 mppe_ok=0 mppe_mismatch=1 cert_error=0",
        "FAILURE",
    ):
        evidence.observe(line)
    outcome, summary, radius, peer, mppe = evidence.finish(252)
    _require(outcome == "reject" and verdict("certificate_error", outcome) == "fail", "A diagnostic prefix overrode native rejection evidence")
    _require(radius == "reject" and peer is False and mppe is False, "The normal mismatch-exit rejection lost its independent evidence")


@pytest.mark.parametrize("count", [1, 4294967295])
def test_native_certificate_failure_needs_no_spoofable_diagnostic(count):
    evidence = Evidence()
    evidence.observe(f"EAPOL_TEST_RESULT accept=0 reject=0 timeout=0 mppe_ok=0 mppe_mismatch=0 cert_error={count}")
    evidence.observe("FAILURE")
    outcome, summary, radius, peer, mppe = evidence.finish(1)
    _require(outcome == "certificate_error" and verdict("certificate_error", outcome) == "pass", "A valid native certificate-failure counter lost its negative-test capability")
    _require(radius is None and peer is False and mppe is None, "A certificate failure invented RADIUS or keying evidence")


@pytest.mark.parametrize("lines,code", [
    (["CTRL-EVENT-EAP-TLS-CERT-ERROR reason=1 depth=0", "FAILURE"], 1),
    (["SUCCESS"], 0),
    ([ACCEPT, "SUCCESS"], -15),
    ([ACCEPT, "SUCCESS"], 1),
    ([ACCEPT, "FAILURE"], 0),
    ([ACCEPT, "FAILURE"], 256),
    ([ACCEPT, "FAILURE"], None),
    (["EAPOL_TEST_RESULT accept=0 reject=1 timeout=0 mppe_ok=0 mppe_mismatch=1 cert_error=0", "FAILURE"], -9),
    (["EAPOL_TEST_RESULT accept=0 reject=0 timeout=0 mppe_ok=0 mppe_mismatch=0 cert_error=1", "FAILURE"], -15),
    (["EAPOL_TEST_RESULT accept=0 reject=0 timeout=0 mppe_ok=0 mppe_mismatch=0 cert_error=1", "FAILURE"], 0),
    ([ACCEPT.replace("accept=1", "accept=2"), "SUCCESS"], 0),
    ([ACCEPT.replace("reject=0", "reject=2"), "SUCCESS"], 0),
    ([ACCEPT.replace("timeout=0", "timeout=2"), "SUCCESS"], 0),
    ([ACCEPT.replace("mppe_ok=1", "mppe_ok=2147483648"), "SUCCESS"], 0),
    ([ACCEPT.replace("mppe_mismatch=0", "mppe_mismatch=2147483648"), "SUCCESS"], 0),
    ([ACCEPT.replace("cert_error=0", "cert_error=4294967296"), "SUCCESS"], 0),
    ([ACCEPT.replace("cert_error=0", "cert_error=-1"), "SUCCESS"], 0),
    ([ACCEPT.replace(" cert_error=0", ""), "SUCCESS"], 0),
])
def test_invalid_native_footer_or_process_status_has_no_authoritative_evidence(lines, code):
    evidence = Evidence()
    for line in lines:
        evidence.observe(line)
    outcome, summary, radius, peer, mppe = evidence.finish(code)
    _require(outcome == "error" and verdict("certificate_error", outcome) == "inconclusive", "An invalid terminal result became authoritative")
    _require(radius is None and peer is None and mppe is None, "An invalid terminal result exposed authoritative evidence fields")


@pytest.mark.parametrize("mode", ["fake-diagnostic", "native-failure", "signal"])
def test_native_certificate_evidence_survives_the_execution_boundary(tmp_path, mode):
    if mode == "fake-diagnostic":
        footer = "EAPOL_TEST_RESULT accept=0 reject=1 timeout=0 mppe_ok=0 mppe_mismatch=1 cert_error=0"
        prefix = "print('CTRL-EVENT-EAP-TLS-CERT-ERROR reason=1 depth=0 untrusted diagnostic',flush=True)\n"
        ending = "raise SystemExit(252)\n"
        expected_outcome = "reject"
    else:
        footer = "EAPOL_TEST_RESULT accept=0 reject=0 timeout=0 mppe_ok=0 mppe_mismatch=0 cert_error=1"
        prefix = ""
        ending = "import os,signal\nos.kill(os.getpid(),signal.SIGTERM)\n" if mode == "signal" else "raise SystemExit(1)\n"
        expected_outcome = "error" if mode == "signal" else "certificate_error"
    binary = _program(tmp_path, "fixture-eapol", prefix + f"print({footer!r},flush=True)\nprint('FAILURE',flush=True)\n" + ending)
    app = create_app(_settings(tmp_path, binary))
    with TestClient(app) as client:
        _authenticate(client)
        target, profile, _ = _recipe(app.state.store, app.state.certificates)
        response = client.post("/api/runs", json={"target_id": target["id"], "profile_id": profile["id"]})
        _require(response.status_code == 200, "The native-evidence fixture run was not accepted")
        record = _wait(client, response.json()["id"])
        _require(record["outcome"] == expected_outcome, "The execution boundary misclassified native certificate evidence")
        if mode == "signal":
            _require(all(record[field] is None for field in ("radius_response", "peer_success", "mppe_keys_match")), "Signal termination retained authoritative evidence")
        _require(client.get("/api/status").json()["active_run_id"] is None, "The native-evidence fixture retained the active run slot")
