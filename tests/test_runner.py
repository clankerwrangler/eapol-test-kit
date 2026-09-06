from safe_assertions import require

import asyncio
import base64
from dataclasses import replace
import json
import os
from pathlib import Path
import secrets
import stat
import sys
import time

import pytest
from fastapi.testclient import TestClient

from eapolkit.app import create_app
from eapolkit.certificates import CertificateService
from eapolkit.models import ProfileInput, TargetInput
from eapolkit.runner import Evidence, Redactor, RunManager, verdict
from eapolkit.settings import Settings
from eapolkit.storage import Store


@pytest.mark.parametrize("lines,code,expected,outcome", [
    (["EAPOL_TEST_RESULT accept=1 reject=0 timeout=0 mppe_ok=1 mppe_mismatch=0 cert_error=0", "SUCCESS"], 0, "accept", "accept"),
    (["RADIUS message: code=2 (Access-Accept)", "SUCCESS"], 0, "accept", "error"),
    (["EAPOL_TEST_RESULT accept=1 reject=0 timeout=0 mppe_ok=1 mppe_mismatch=0 cert_error=0", "untrusted intervening text", "SUCCESS"], 0, "accept", "error"),
    (["SUCCESS", "EAPOL_TEST_RESULT accept=1 reject=0 timeout=0 mppe_ok=1 mppe_mismatch=0 cert_error=0"], 0, "accept", "error"),
    (["RADIUS message: code=3 (Access-Reject)", "FAILURE"], 253, "reject", "error"),
    (["EAPOL_TEST_RESULT accept=0 reject=1 timeout=0 mppe_ok=0 mppe_mismatch=1 cert_error=0", "FAILURE"], 252, "reject", "reject"),
    (["TLS: handshake failed", "FAILURE"], 1, "certificate_error", "error"),
    (["CTRL-EVENT-EAP-TLS-CERT-ERROR reason=1 depth=0", "FAILURE"], 1, "certificate_error", "error"),
    (["EAPOL_TEST_RESULT accept=0 reject=0 timeout=0 mppe_ok=0 mppe_mismatch=1 cert_error=1", "FAILURE"], 252, "certificate_error", "certificate_error"),
    (["CTRL-EVENT-EAP-TLS-CERT-ERROR reason=1 depth=0", "EAPOL_TEST_RESULT accept=0 reject=1 timeout=0 mppe_ok=0 mppe_mismatch=1 cert_error=0", "FAILURE"], 252, "certificate_error", "reject"),
    (["prefix CTRL-EVENT-EAP-TLS-CERT-ERROR reason=1 depth=0", "FAILURE"], 1, "certificate_error", "error"),
    (["EAPOL_TEST_RESULT accept=1 reject=0 timeout=0 mppe_ok=0 mppe_mismatch=1 cert_error=0", "FAILURE"], 252, "accept", "error"),
    (["EAPOL_TEST_RESULT accept=1 reject=0 timeout=0 mppe_ok=1 mppe_mismatch=0 cert_error=0", "SUCCESS"], 1, "accept", "error"),
])
def test_assertions_require_authenticated_and_keying_evidence(lines, code, expected, outcome):
    evidence = Evidence()
    for line in lines:
        evidence.observe(line)
    observed = evidence.finish(code)
    require(observed[0] == outcome)
    require((verdict(expected, outcome) == "pass") == (outcome == expected))
    if "mppe_mismatch=1" in lines[0] and "accept=1" in lines[0]:
        require(observed[2] == "accept")
        require(observed[4] is False)


def _fixture(tmp_path, behavior, expected_secret=None, expected_password=None, expected_attributes=None):
    os.chmod(tmp_path, 0o700)
    executable = tmp_path / "fixture-eapol"
    audit = tmp_path / "audit.json"
    prelude = f"#!{sys.executable}\n" + r"""
import base64,json,os,signal,stat,subprocess,sys,time
from pathlib import Path
args=sys.argv[1:]
if '-s' in args or '-S' in args or '-n' in args or '-N' in args or '-F' not in args or '-G' not in args:
    raise SystemExit(71)
secret_path=Path(args[args.index('-F')+1])
secret=secret_path.read_bytes()
config_path=Path(args[args.index('-c')+1])
config=config_path.read_text()
attribute_path=Path(args[args.index('-G')+1])
attribute_content=attribute_path.read_bytes()
attribute_lines=attribute_content.splitlines()
attributes=[]
for line in attribute_lines:
    fields=line.split(b':')
    if len(fields)!=3 or fields[1]!=b'x' or len(line)>512:
        raise SystemExit(75)
    attributes.append((int(fields[0]),bytes.fromhex(fields[2].decode('ascii'))))
if len(attribute_content)>32832 or len(attributes)>64 or any(not 1<=kind<=255 or len(value)>253 for kind,value in attributes):
    raise SystemExit(76)
if stat.S_IMODE(attribute_path.stat().st_mode)!=0o600 or attribute_path.parent!=secret_path.parent:
    raise SystemExit(77)
valid=(all(secret not in arg.encode() for arg in args) and stat.S_IMODE(secret_path.stat().st_mode)==0o600
       and stat.S_IMODE(secret_path.parent.stat().st_mode)==0o700 and '\nengine=' not in config
       and '\nload_dynamic_eap=' not in config and 'tls_disable_time_checks' not in config)
if not valid:
    raise SystemExit(72)
password=bytes.fromhex(next(line.strip().split('=',1)[1] for line in config.splitlines() if line.strip().startswith('password=')))
"""
    prelude += f"Path({str(audit)!r}).write_text(json.dumps({{'pid':os.getpid(),'safe_arguments':valid,'run_directory':str(secret_path.parent)}}))\n"
    if expected_secret is not None:
        expected_path = tmp_path / "expected-secret"
        fd = os.open(expected_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as output:
            output.write(expected_secret)
        prelude += f"if secret != Path({str(expected_path)!r}).read_bytes(): raise SystemExit(73)\n"
    if expected_password is not None:
        expected_path = tmp_path / "expected-password"
        fd = os.open(expected_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as output:
            output.write(expected_password)
        prelude += f"if password != Path({str(expected_path)!r}).read_bytes(): raise SystemExit(74)\n"
    if expected_attributes is not None:
        expected_path = tmp_path / "expected-attributes"
        fd = os.open(expected_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as output:
            output.write(expected_attributes)
        prelude += f"if attribute_content != Path({str(expected_path)!r}).read_bytes(): raise SystemExit(78)\n"
    executable.write_text(prelude + behavior)
    executable.chmod(0o700)
    settings = Settings(data_dir=tmp_path / "data", binary=str(executable), allowed_hosts=("testserver",), max_log_lines=24, max_log_bytes=4096)
    return settings, audit


def _setup(client, radius=None, eap=None):
    password = secrets.token_urlsafe(24)
    response = client.post("/api/setup", json={"password": password}, headers={"X-EapolKit-Request": "1"})
    require(response.status_code == 200)
    client.headers.update({"X-EapolKit-Request": "1", "X-CSRF-Token": response.json()["csrf_token"]})
    radius = radius if radius is not None else secrets.token_urlsafe(32)
    eap = eap if eap is not None else secrets.token_urlsafe(32) + '\nengine=1\nload_dynamic_eap="not-a-module"\n"\\'
    ca = client.post("/api/certificates/generate-ca", json={"name": "Fixture CA", "common_name": "Fixture CA", "key_type": "ec-p256"}).json()
    target = client.post("/api/targets", json={"name": "Fixture target", "host": "127.0.0.1", "timeout_seconds": 5, "secret": radius}).json()
    profile = client.post("/api/profiles", json={"name": "Fixture profile", "method": "ttls-pap", "identity": "fixture-user", "password": eap, "server_name": "radius.example.test", "ca_certificate_id": ca["id"]}).json()
    return target, profile, [password, radius, eap]


def _wait(client, run_id, seconds=8):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        response = client.get(f"/api/runs/{run_id}")
        require(response.status_code == 200)
        record = response.json()
        if record["status"] not in {"queued", "running"}:
            return record
        time.sleep(0.03)
    pytest.fail("The fixture run did not finish within its deadline", pytrace=False)


def test_subprocess_result_redaction_history_and_cleanup(tmp_path):
    behavior = """
print(secret.decode(),flush=True)
print(secret.hex(),flush=True)
print(base64.b64encode(secret).decode(),flush=True)
print(password.decode(),flush=True)
print('challenge: ' + os.urandom(32).hex(),flush=True)
print('x'*4090+secret.decode(),flush=True)
for number in range(50):
    print('safe progress '+str(number),flush=True)
print('EAPOL_TEST_RESULT accept=1 reject=0 timeout=0 mppe_ok=1 mppe_mismatch=0 cert_error=0',flush=True)
print('SUCCESS',flush=True)
"""
    settings, audit = _fixture(tmp_path, behavior)
    with TestClient(create_app(settings)) as client:
        target, profile, credentials = _setup(client)
        response = client.post("/api/runs", json={"target_id": target["id"], "profile_id": profile["id"]})
        require(response.status_code == 200)
        run_id = response.json()["id"]
        record = _wait(client, run_id)
        require(record["outcome"] == "accept")
        require(record["verdict"] == "pass")
        require(record["radius_response"] == "accept")
        require(record["peer_success"] is True)
        require(record["mppe_keys_match"] is True)
        require(record["truncated"] is True)
        require(len(record["log_lines"]) <= settings.max_log_lines)
        require(record["snapshot"]["target"]["has_secret"])
        require("_secret" not in record["snapshot"]["target"])
        exported = client.get(f"/api/runs/{run_id}/export")
        require(exported.status_code == 200)
        persisted = (settings.data_dir / "eapolkit.sqlite3").read_bytes()
        forms = [value.encode() for value in credentials] + [credentials[1].encode().hex().encode(), base64.b64encode(credentials[1].encode())]
        clean = all(form not in exported.content and form not in persisted for form in forms)
        require(clean, "A credential reached history or export")
        require(client.get(f"/api/runs/{run_id}?after={record['next_seq']}").json()["log_lines"] == [])
        require(client.get("/api/runs").json()[0]["id"] == run_id)
        details = json.loads(audit.read_text())
        require(details["safe_arguments"])
        require(not Path(details["run_directory"]).exists())
        require(client.delete(f"/api/runs/{run_id}").status_code == 200)
        require(client.get(f"/api/runs/{run_id}").status_code == 404)


def test_one_active_run_live_polling_and_owned_cancellation(tmp_path):
    settings, audit = _fixture(tmp_path, "print('waiting for fixture',flush=True)\ntime.sleep(120)\n")
    with TestClient(create_app(settings)) as client:
        target, profile, credentials = _setup(client)
        response = client.post("/api/runs", json={"target_id": target["id"], "profile_id": profile["id"]})
        require(response.status_code == 200)
        run_id = response.json()["id"]
        require(client.post("/api/runs", json={"target_id": target["id"], "profile_id": profile["id"]}).status_code == 409)
        require(client.delete(f"/api/runs/{run_id}").status_code == 409)
        require(client.post("/api/runs/not-owned/cancel").status_code == 404)
        deadline = time.monotonic() + 2
        while not audit.exists() and time.monotonic() < deadline:
            time.sleep(0.02)
        require(audit.exists())
        started = time.monotonic()
        require(client.get("/api/status").json()["active_run_id"] == run_id)
        require(time.monotonic() - started < 1)
        cancelled = client.post(f"/api/runs/{run_id}/cancel")
        require(cancelled.status_code == 200)
        require(cancelled.json()["status"] == "cancelled")
        require(cancelled.json()["outcome"] == "cancelled")
        require(cancelled.json()["verdict"] == "inconclusive")
        require(cancelled.json()["exit_code"] is not None)
        details = json.loads(audit.read_text())
        require(not Path(details["run_directory"]).exists())
        require(not Path(f"/proc/{details['pid']}").exists())
        require(client.get("/api/status").json()["active_run_id"] is None)


def test_overall_timeout_cleans_and_reaps_process(tmp_path):
    settings, audit = _fixture(tmp_path, "time.sleep(120)\n")
    with TestClient(create_app(settings)) as client:
        target, profile, credentials = _setup(client)
        started = time.monotonic()
        run_id = client.post("/api/runs", json={"target_id": target["id"], "profile_id": profile["id"], "expected_outcome": "reject"}).json()["id"]
        record = _wait(client, run_id)
        require(record["outcome"] == "timeout")
        require(record["verdict"] != "pass")
        require(time.monotonic() - started < 7)
        details = json.loads(audit.read_text())
        require(not Path(details["run_directory"]).exists())
        require(not Path(f"/proc/{details['pid']}").exists())


def test_restart_recovery_does_not_replay_and_removes_stale_files(tmp_path):
    os.chmod(tmp_path, 0o700)
    settings = Settings(data_dir=tmp_path / "data", binary="/nonexistent/fixture")
    store = Store(settings.data_dir)
    manager = RunManager(store, CertificateService(store), settings)
    run_id = secrets.token_hex(16)
    store.put("run", {"id": run_id, "status": "running", "log_lines": [], "next_seq": 0, "truncated": False})
    stale = manager._temporary_root / ("run-" + run_id)
    stale.mkdir(mode=0o700)
    fd = os.open(stale / "radius.secret", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(secrets.token_bytes(32))
    asyncio.run(manager.shutdown())
    store.close()
    store = Store(settings.data_dir)
    manager = RunManager(store, CertificateService(store), settings)
    recovered = manager.get(run_id)
    require(recovered["status"] == "interrupted")
    require(recovered["outcome"] == "interrupted")
    require(recovered["verdict"] == "inconclusive")
    require(manager.active_run_id is None)
    require(not stale.exists())
    asyncio.run(manager.shutdown())
    store.close()


@pytest.mark.parametrize("maximum", [False, True])
def test_radius_secret_exact_bytes_survive_api_to_private_file(tmp_path, maximum):
    prefix, suffix = " \r\n", "\n\r "
    radius = prefix + (secrets.token_urlsafe(4096)[:4096 - len(prefix) - len(suffix)] if maximum else secrets.token_urlsafe(32) + "\u03bb\"\\") + suffix
    behavior = "print('EAPOL_TEST_RESULT accept=1 reject=0 timeout=0 mppe_ok=1 mppe_mismatch=0 cert_error=0',flush=True)\nprint('SUCCESS',flush=True)\n"
    settings, audit = _fixture(tmp_path, behavior, expected_secret=radius.encode("utf-8"))
    with TestClient(create_app(settings)) as client:
        target, profile, credentials = _setup(client, radius=radius)
        require(target["has_secret"])
        run = client.post("/api/runs", json={"target_id": target["id"], "profile_id": profile["id"]})
        require(run.status_code == 200)
        record = _wait(client, run.json()["id"])
        require(record["outcome"] == "accept")
        require(record["verdict"] == "pass")
        require(record["exit_code"] == 0)
        if maximum:
            require(len(radius.encode("utf-8")) == 4096)
            oversized = client.put(f"/api/targets/{target['id']}", json={"name": "Oversized", "host": "127.0.0.1", "secret": radius + "x"})
            require(oversized.status_code == 422)
        clean = radius.encode() not in json.dumps(record).encode() and radius.encode() not in (settings.data_dir / "eapolkit.sqlite3").read_bytes()
        require(clean, "A RADIUS credential reached an ordinary response or plaintext storage")


def test_maximum_profile_password_keeps_exact_utf8_hex_bytes(tmp_path):
    password = "".join(chr(0x1F300 + secrets.randbelow(0x300)) for _ in range(4096))
    behavior = "print('EAPOL_TEST_RESULT accept=1 reject=0 timeout=0 mppe_ok=1 mppe_mismatch=0 cert_error=0',flush=True)\nprint('SUCCESS',flush=True)\n"
    settings, audit = _fixture(tmp_path, behavior, expected_password=password.encode("utf-8"))
    with TestClient(create_app(settings)) as client:
        target, profile, credentials = _setup(client, eap=password)
        response = client.post("/api/runs", json={"target_id": target["id"], "profile_id": profile["id"]})
        require(response.status_code == 200)
        record = _wait(client, response.json()["id"])
        require(record["outcome"] == "accept")
        require(record["exit_code"] == 0)
        require(len(password) == 4096 and len(password.encode("utf-8")) == 16384)
        exported = client.get(f"/api/runs/{record['id']}/export").content
        forms = [password.encode(), password.encode().hex().encode(), json.dumps(password)[1:-1].encode()]
        clean = all(form not in exported and form not in (settings.data_dir / "eapolkit.sqlite3").read_bytes() for form in forms)
        require(clean, "A maximum-length credential reached history or plaintext storage")


@pytest.mark.parametrize("exit_code,marker", [(-9, "FAILURE"), (-11, "FAILURE"), (0, "FAILURE"), (252, "SUCCESS"), (256, "FAILURE")])
def test_abnormal_or_inconsistent_completion_has_no_authoritative_evidence(exit_code, marker):
    evidence = Evidence()
    evidence.observe("EAPOL_TEST_RESULT accept=0 reject=1 timeout=0 mppe_ok=0 mppe_mismatch=1 cert_error=1")
    evidence.observe(marker)
    result = evidence.finish(exit_code)
    require(result[0] == "error")
    require(result[2:] == (None, None, None))
    require(verdict("certificate_error", result[0]) == "inconclusive")


@pytest.mark.parametrize("field,value", [("accept", "2"), ("reject", "2"), ("timeout", "2"), ("mppe_ok", "2147483648"), ("mppe_mismatch", "2147483648"), ("cert_error", "4294967296"), ("cert_error", "-1")])
def test_native_footer_domains_are_validated_as_a_whole(field, value):
    values = {"accept": "0", "reject": "1", "timeout": "0", "mppe_ok": "0", "mppe_mismatch": "1", "cert_error": "0"}
    values[field] = value
    evidence = Evidence()
    evidence.observe("EAPOL_TEST_RESULT " + " ".join(f"{key}={item}" for key, item in values.items()))
    evidence.observe("FAILURE")
    result = evidence.finish(252)
    require(result[0] == "error")
    require(result[2:] == (None, None, None))


def test_private_and_public_attributes_reach_only_the_protected_file(tmp_path):
    private = secrets.token_urlsafe(32)
    private_hex = private.encode().hex()
    public_vsa = "00000009010664656d6f"
    expected = ("32:x:" + "eapol-test-kit".encode().hex() + "\n31:x:" + "02:00:00:00:00:01".encode().hex() + "\n26:x:" + public_vsa + "\n241:x:01" + private_hex + "\n").encode()
    behavior = "for kind,value in attributes:\n    if kind==241:\n        print(value.hex(),flush=True)\n        print(base64.b64encode(value).decode(),flush=True)\nprint('EAPOL_TEST_RESULT accept=1 reject=0 timeout=0 mppe_ok=1 mppe_mismatch=0 cert_error=0',flush=True)\nprint('SUCCESS',flush=True)\n"
    settings, audit = _fixture(tmp_path, behavior, expected_attributes=expected)
    with TestClient(create_app(settings)) as client:
        target, profile, credentials = _setup(client)
        changed = client.put(f"/api/targets/{target['id']}", json={"name": "Attribute wire", "host": "127.0.0.1", "extra_attributes": [{"id":26,"type":"hex","value":public_vsa,"sensitivity":"public"},{"id":241,"type":"hex","value":"01"+private_hex}]})
        require(changed.status_code==200)
        rows = changed.json()["extra_attributes"]
        require(rows[0]["value"]==public_vsa)
        require(rows[1]["sensitivity"]=="private" and "value" not in rows[1] and rows[1]["has_value"])
        run = client.post("/api/runs", json={"target_id":target["id"],"profile_id":profile["id"]})
        require(run.status_code==200)
        record = _wait(client,run.json()["id"])
        require(record["outcome"]=="accept" and record["exit_code"]==0)
        require("value" not in record["snapshot"]["target"]["extra_attributes"][1])
        dump=client.get(f"/api/runs/{record['id']}/export").content
        forms=[private.encode(),private_hex.encode(),("01"+private_hex).encode(),base64.b64encode(b"\x01"+private.encode())]
        clean=all(form not in dump and form not in (settings.data_dir/"eapolkit.sqlite3").read_bytes() for form in forms)
        require(clean,"A private attribute reached ordinary history or plaintext storage")


def test_marker_bearing_credentials_are_redacted_in_the_live_api_path(tmp_path):
    radius=secrets.token_urlsafe(24)+"[redacted]"+secrets.token_urlsafe(24)
    password="[redacted]"+secrets.token_urlsafe(24)
    behavior="print(secret.decode(),flush=True)\nprint(secret.hex(),flush=True)\nprint(base64.b64encode(secret).decode(),flush=True)\nprint(password.decode(),flush=True)\nprint(password.hex(),flush=True)\nprint('EAPOL_TEST_RESULT accept=1 reject=0 timeout=0 mppe_ok=1 mppe_mismatch=0 cert_error=0',flush=True)\nprint('SUCCESS',flush=True)\n"
    settings,audit=_fixture(tmp_path,behavior,expected_secret=radius.encode(),expected_password=password.encode())
    with TestClient(create_app(settings)) as client:
        target,profile,credentials=_setup(client,radius=radius,eap=password)
        response=client.post("/api/runs",json={"target_id":target["id"],"profile_id":profile["id"]})
        require(response.status_code==200)
        record=_wait(client,response.json()["id"])
        require(record["outcome"]=="accept" and record["exit_code"]==0)
        exported=client.get(f"/api/runs/{record['id']}/export").content
        database=(settings.data_dir/"eapolkit.sqlite3").read_bytes()
        forms=[radius.encode(),radius.encode().hex().encode(),base64.b64encode(radius.encode()),password.encode(),password.encode().hex().encode()]
        clean=all(form not in exported and form not in database for form in forms)
        require(clean,"A marker-bearing credential escaped live log or history redaction")
