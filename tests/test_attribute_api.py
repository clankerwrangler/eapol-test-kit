import json
import os
import secrets

from fastapi.testclient import TestClient

from eapolkit.app import create_app
from eapolkit.models import TargetInput
from eapolkit.settings import Settings
from eapolkit.storage import Store
from safe_assertions import require


def _login(client, password=None):
    password = password or secrets.token_urlsafe(24)
    path = "/api/setup" if client.get("/api/session").json()["setup_required"] else "/api/login"
    response = client.post(path, json={"password": password}, headers={"X-EapolKit-Request": "1"})
    require(response.status_code == 200)
    client.headers.update({"X-EapolKit-Request": "1", "X-CSRF-Token": response.json()["csrf_token"]})
    return password


def test_http_attribute_privacy_preservation_and_scoped_keys(tmp_path):
    os.chmod(tmp_path, 0o700)
    settings = Settings(data_dir=tmp_path / "data", allowed_hosts=("testserver",))
    app = create_app(settings)
    hidden = secrets.token_urlsafe(32)
    replacement = secrets.token_urlsafe(32)
    with TestClient(app) as client:
        _login(client)
        original = client.post("/api/targets", json={"name":"Rows","host":"127.0.0.1","extra_attributes":[{"id":27,"type":"integer","value":"00042"},{"id":1,"type":"string","value":hidden,"sensitivity":"private"},{"id":26,"type":"hex","value":"00000009010664656d6f","sensitivity":"public"}]} )
        require(original.status_code == 200)
        target = original.json()
        rows = target["extra_attributes"]
        require(rows[0]["value"] == "00042")
        require(rows[1]["has_value"] and "value" not in rows[1])
        require(rows[2]["sensitivity"] == "public")
        require(len({row["key"] for row in rows}) == 3)
        stored = app.state.store.get("target", target["id"])["extra_attributes"]
        require(all("value" not in row and "_value" in row for row in stored))
        clean = hidden.encode() not in (settings.data_dir / "eapolkit.sqlite3").read_bytes()
        require(clean, "A private attribute reached plaintext storage")
        endpoint = f"/api/targets/{target['id']}"
        keep = [{key: row[key] for key in ("key", "id", "type")} for row in rows]
        changed = client.put(endpoint, json={"name":"Reordered","host":"127.0.0.1","extra_attributes":list(reversed(keep))})
        require(changed.status_code == 200)
        require(changed.json()["extra_attributes"][0]["key"] == rows[2]["key"])
        require(changed.json()["extra_attributes"][0]["value"] == rows[2]["value"])
        require("value" not in changed.json()["extra_attributes"][1])
        unchanged = client.put(endpoint, json={"name":"List omitted","host":"127.0.0.1"})
        require(unchanged.status_code == 200 and len(unchanged.json()["extra_attributes"]) == 3)
        second = client.post("/api/targets", json={"name":"Other","host":"127.0.0.1"}).json()
        cross = client.put(f"/api/targets/{second['id']}", json={"name":"Other","host":"127.0.0.1","extra_attributes":[keep[1]]})
        require(cross.status_code == 422)
        duplicate = client.put(endpoint, json={"name":"Duplicate","host":"127.0.0.1","extra_attributes":[keep[0],keep[0]]})
        require(duplicate.status_code == 422)
        bad_identity = client.put(endpoint, json={"name":"Wrong encoding","host":"127.0.0.1","extra_attributes":[{**keep[1],"type":"hex"}]})
        require(bad_identity.status_code == 422)
        disclose = client.put(endpoint, json={"name":"No replacement","host":"127.0.0.1","extra_attributes":[{**keep[1],"sensitivity":"public"}]})
        require(disclose.status_code == 422)
        public = client.put(endpoint, json={"name":"Replacement","host":"127.0.0.1","extra_attributes":[{**keep[1],"sensitivity":"public","value":replacement}]})
        require(public.status_code == 200)
        require(public.json()["extra_attributes"][0]["value"] == replacement)
        old_absent = hidden not in public.text
        require(old_absent, "A metadata change disclosed the saved private value")
        cleared = client.put(endpoint, json={"name":"Cleared","host":"127.0.0.1","extra_attributes":[]})
        require(cleared.status_code == 200 and cleared.json()["extra_attributes"] == [])


def test_http_opaque_and_known_credential_classification(tmp_path):
    settings = Settings(data_dir=tmp_path / "data", allowed_hosts=("testserver",))
    value = secrets.token_urlsafe(32)
    with TestClient(create_app(settings)) as client:
        _login(client)
        denied = client.post("/api/targets", json={"name":"Known","host":"127.0.0.1","extra_attributes":[{"id":2,"type":"string","value":value,"sensitivity":"public"}]})
        require(denied.status_code == 422)
        clean = value not in denied.text
        require(clean, "A rejected classification reflected a credential")
        response = client.post("/api/targets", json={"name":"Opaque","host":"127.0.0.1","extra_attributes":[{"id":26,"type":"hex","value":"00"}]})
        require(response.status_code == 200)
        target = response.json()
        row = target["extra_attributes"][0]
        require(row["sensitivity"] == "private" and "value" not in row)
        public = client.put(f"/api/targets/{target['id']}", json={"name":"Public replacement","host":"127.0.0.1","extra_attributes":[{"key":row["key"],"id":26,"type":"hex","sensitivity":"public","value":""}]})
        require(public.status_code == 200)
        require(public.json()["extra_attributes"][0]["value"] == "")
        require(public.json()["extra_attributes"][0]["has_value"])


def test_http_startup_migration_preserves_public_legacy_bytes_and_keys(tmp_path):
    settings = Settings(data_dir=tmp_path / "data", allowed_hosts=("testserver",))
    legacy_value = secrets.token_bytes(32).hex().upper()
    store = Store(settings.data_dir)
    row = TargetInput(name="Legacy", host="127.0.0.1").model_dump(exclude={"secret"})
    row.update(id="legacy", has_secret=False, extra_attributes=[{"id":26,"type":"hex","value":legacy_value}])
    store.put("target", row)
    store.close()
    with TestClient(create_app(settings)) as client:
        password = _login(client)
        migrated = client.get("/api/targets").json()[0]["extra_attributes"][0]
        require(migrated["value"] == legacy_value and migrated["sensitivity"] == "public")
        key = migrated["key"]
        changed = client.put("/api/targets/legacy", json={"name":"Still public","host":"127.0.0.1","extra_attributes":[{"key":key,"id":26,"type":"hex"}]})
        require(changed.status_code == 200)
        require(changed.json()["extra_attributes"][0]["value"] == legacy_value)
        clean = legacy_value.encode() not in (settings.data_dir / "eapolkit.sqlite3").read_bytes()
        require(clean, "Migration retained its plaintext value copy")
    with TestClient(create_app(settings)) as client:
        _login(client, password)
        persisted = client.get("/api/targets").json()[0]["extra_attributes"][0]
        require(persisted["key"] == key and persisted["value"] == legacy_value)
