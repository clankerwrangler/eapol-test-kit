import base64
import json
import os
import secrets
from copy import deepcopy

import pytest
from fastapi.testclient import TestClient

from eapolkit.app import create_app
from eapolkit.attributes import migrate_history, migrate_targets, prepare_rows, public_rows
from eapolkit.models import TargetInput
from eapolkit.redaction import Redactor
from eapolkit.settings import Settings
from eapolkit.storage import Store
from safe_assertions import require


def _auth(client):
    response=client.post("/api/setup",json={"password":secrets.token_urlsafe(24)},headers={"X-EapolKit-Request":"1"})
    require(response.status_code==200)
    client.headers.update({"X-EapolKit-Request":"1","X-CSRF-Token":response.json()["csrf_token"]})


@pytest.mark.parametrize("target_state", ["legacy", "already_migrated", "changed", "deleted"])
def test_recognized_legacy_history_is_private_in_http_and_closed_database(tmp_path, target_state):
    os.chmod(tmp_path,0o700)
    directory=tmp_path/"data"
    store=Store(directory)
    private=secrets.token_urlsafe(32)
    visible=secrets.token_urlsafe(24)
    target=TargetInput(name="Historic target",host="127.0.0.1").model_dump(exclude={"secret"})
    target.update(id="target",has_secret=False,extra_attributes=[{"id":2,"type":"string","value":private},{"id":26,"type":"string","value":visible}])
    historic={"id":"history","target_id":"target","profile_id":"profile","target_name":"Historic target","profile_name":"Historic profile","status":"completed","expected_outcome":"reject","outcome":"reject","verdict":"pass","created_at":"2026-01-01T00:00:00Z","started_at":"2026-01-01T00:00:01Z","finished_at":"2026-01-01T00:00:02Z","exit_code":252,"duration_seconds":1,"summary":"Diagnostic "+private,"snapshot":{"target":deepcopy(target),"profile":{"id":"profile","name":"Historic profile","method":"ttls-pap","identity":private},"configuration":"identity="+private.encode().hex()},"log_lines":[{"seq":1,"line":"public diagnostic remains"},{"seq":2,"line":"returned value "+private},{"seq":3,"line":base64.b64encode(private.encode()).decode()}],"next_seq":3,"truncated":False}
    store.put("target",target)
    store.put("run",historic)
    if target_state in {"already_migrated","changed"}:
        migrate_targets(store)
    if target_state=="changed":
        current=store.get("target","target")
        current["extra_attributes"]=prepare_rows(store,[{"id":2,"type":"string","value":secrets.token_urlsafe(32)}])
        store.put("target",current)
    if target_state=="deleted":
        store.delete("target","target")
    store.close()
    app=create_app(Settings(data_dir=directory,allowed_hosts=("testserver",)))
    with TestClient(app) as client:
        _auth(client)
        response=client.get("/api/runs/history")
        exported=client.get("/api/runs/history/export")
        require(response.status_code==200 and exported.status_code==200)
        record=response.json()
        for field in ("id","target_id","profile_id","status","outcome","verdict","created_at","started_at","finished_at","exit_code","duration_seconds","next_seq"):
            require(record[field]==historic[field])
        rows=record["snapshot"]["target"]["extra_attributes"]
        require(rows[0]["sensitivity"]=="private" and rows[0]["has_value"] and "value" not in rows[0])
        require(rows[1]["sensitivity"]=="public" and rows[1]["value"]==visible)
        require(record["log_lines"][0]==historic["log_lines"][0])
        forms=[private.encode(),private.encode().hex().encode(),base64.b64encode(private.encode())]
        clean=all(form not in response.content and form not in exported.content for form in forms)
        require(clean,"Recognized historical credentials reached HTTP or export")
        unchanged=deepcopy(app.state.store.get("run","history"))
        require(migrate_history(app.state.store)==0)
        require(app.state.store.get("run","history")==unchanged)
    database=(directory/"eapolkit.sqlite3").read_bytes()
    clean=all(form not in database for form in forms)
    require(clean,"Recognized historical credentials remain in the closed active database")
    require(not list(directory.glob("*-wal")))


def test_matching_private_live_row_scrubs_missing_snapshot_value(tmp_path):
    store=Store(tmp_path/"data")
    private=secrets.token_urlsafe(32)
    rows=prepare_rows(store,[{"id":25,"type":"string","value":private,"sensitivity":"private"}])
    store.put("target",{"id":"target","extra_attributes":rows})
    store.put("run",{"id":"run","target_id":"target","status":"completed","snapshot":{"target":{"id":"target","extra_attributes":public_rows(store,rows)}},"log_lines":[{"seq":1,"line":private}]})
    require(migrate_history(store)==1)
    clean=private not in json.dumps(store.get("run","run"))
    require(clean,"Matching live private value remained in retained diagnostics")
    require(migrate_history(store)==0)
    store.close()


def test_unknown_history_schema_is_not_guessed_or_destroyed(tmp_path):
    store=Store(tmp_path/"data")
    original={"id":"run","status":"completed","snapshot":{"target":{"extra_attributes":[{"id":26,"type":"hex","unexpected":"schema"}]}},"log_lines":[]}
    store.put("run",original)
    require(migrate_history(store)==0)
    require(store.get("run","run")==original)
    store.close()


def test_redaction_is_bounded_and_idempotent_for_short_values():
    redactor=Redactor(["a","e","redacted"])
    first=redactor.text("a e [redacted]")
    require(first=="[redacted] [redacted] [redacted]")
    require(redactor.text(first)==first)
    require(redactor.line("[sensitive diagnostic suppressed]")=="[sensitive diagnostic suppressed]")


def test_unrelated_history_fields_do_not_block_recognized_private_rows(tmp_path):
    store=Store(tmp_path/"data")
    private=secrets.token_urlsafe(32)
    unknown={"id":26,"type":"hex","unexpected":"preserve this public data"}
    row={"id":2,"type":"string","value":private,"public_note":"keep the note"}
    record={"id":"record","target_id":"deleted","status":"completed","outcome":"reject","unrelated":{"public":"keep"},"snapshot":{"target":{"extra_attributes":[unknown,row]}},"log_lines":[{"seq":1,"line":"public line"},{"seq":2,"line":private}],"next_seq":2}
    store.put("run",record)
    require(migrate_history(store)==1)
    result=store.get("run","record")
    require(result["unrelated"]==record["unrelated"])
    require(result["snapshot"]["target"]["extra_attributes"][0]==unknown)
    migrated=result["snapshot"]["target"]["extra_attributes"][1]
    require(migrated["public_note"]=="keep the note" and "value" not in migrated)
    clean=private not in json.dumps(result)
    require(clean,"An unrelated field prevented recognized private history sanitation")
    require(migrate_history(store)==0)
    store.close()


@pytest.mark.parametrize("placement", ["middle", "prefix", "suffix", "partial"])
def test_supported_credentials_containing_or_crossing_redaction_markers_are_hidden(placement):
    nonce=secrets.token_urlsafe(24)
    if placement=="middle":
        private=nonce+"[redacted]"+secrets.token_urlsafe(24)
        text=private
    elif placement=="prefix":
        private="[redacted]"+nonce
        text=private
    elif placement=="suffix":
        private=nonce+"[redacted]"
        text=private
    else:
        private="redacted]"+nonce
        text="["+private
    redactor=Redactor([private])
    for result in (redactor.text(text),redactor.line(text),redactor.object({"line":text})["line"]):
        clean=private not in result
        require(clean,"A credential containing a marker bypassed redaction")
        require(redactor.text(result)==result)
