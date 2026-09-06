from safe_assertions import require

import ipaddress
import json
import os
import secrets
from uuid import uuid4

import pytest

from eapolkit.attributes import decoded_rows, encode_value, migrate_targets, prepare_rows, public_rows, public_target
from eapolkit.storage import Store


@pytest.fixture
def store(tmp_path):
    os.chmod(tmp_path, 0o700)
    instance = Store(tmp_path / "data")
    try:
        yield instance
    finally:
        instance.close()


def reference(row, **changes):
    return {**{field: row[field] for field in ("key", "id", "type")}, **changes}


def text_value():
    return secrets.token_urlsafe(24)


def test_public_and_private_reads_use_one_encrypted_value(store):
    public_value, private_value = text_value(), text_value()
    incoming = [{"id": 32, "type": "string", "value": public_value},
                {"id": 1, "type": "string", "value": private_value, "sensitivity": "private"}]
    rows = prepare_rows(store, incoming, [])
    store.put("target", {"id": uuid4().hex, "extra_attributes": rows})
    read = public_rows(store, rows)
    require(read[0]["value"] == public_value)
    require(read[0]["sensitivity"] == "public")
    require(read[1]["sensitivity"] == "private" and "value" not in read[1])
    require(all(row["has_value"] is True for row in read))
    require(private_value not in json.dumps(read), "Private value reached a read object")
    for row, original in zip(rows, (public_value, private_value)):
        require(set(row) == {"key", "id", "type", "sensitivity", "_value"})
        require(store.decrypt(row["_value"]).decode("utf-8") == original)
        require(original not in json.dumps(rows), "Plaintext value reached canonical rows")
        require(original.encode("utf-8") not in (store.directory / "eapolkit.sqlite3").read_bytes(),
                "Plaintext value reached encrypted storage")
    decoded = decoded_rows(store, rows)
    require([row["value"] for row in decoded] == [public_value, private_value])
    require(all(set(row) == {"key", "id", "type", "sensitivity", "value"} for row in decoded))
    require(all("value" not in row for row in rows), "Decoding mutated canonical storage")


def test_private_reads_do_not_decrypt(store, monkeypatch):
    rows = prepare_rows(store, [{"id": 1, "type": "string", "value": text_value(), "sensitivity": "private"}])

    def forbidden_decrypt(_):
        raise AssertionError("Private read attempted decryption")

    monkeypatch.setattr(store, "decrypt", forbidden_decrypt)
    read = public_rows(store, rows)
    require(read[0]["has_value"] is True and "value" not in read[0])


def test_public_omission_preserves_value_and_stable_key(store):
    values = [text_value(), text_value()]
    rows = prepare_rows(store, [{"id": 32, "type": "string", "value": value} for value in values])
    require(rows[0]["key"] != rows[1]["key"])
    require(all(isinstance(row["key"], str) and row["key"] for row in rows))
    omitted = prepare_rows(store, None, rows)
    require(omitted == rows and omitted is not rows)
    require(all(new is not old for new, old in zip(omitted, rows)))
    reordered = prepare_rows(store, [reference(row) for row in reversed(rows)], rows)
    require(reordered == list(reversed(rows)))
    require([row["value"] for row in public_rows(store, reordered)] == list(reversed(values)))
    require(prepare_rows(store, [], rows) == [])
    require(prepare_rows(store, None) == [])


@pytest.mark.parametrize("supplied", [False, True])
def test_unknown_and_cross_target_keys_are_rejected(store, supplied):
    first = prepare_rows(store, [{"id": 32, "type": "string", "value": text_value()}])
    second = prepare_rows(store, [{"id": 32, "type": "string", "value": text_value()}])
    for key in (first[0]["key"], uuid4().hex):
        update = reference(first[0], key=key)
        if supplied:
            update["value"] = text_value()
        with pytest.raises(ValueError, match="does not belong to this target"):
            prepare_rows(store, [update], second)
        with pytest.raises(ValueError, match="does not belong to this target"):
            prepare_rows(store, [update], [])


@pytest.mark.parametrize("supplied", [False, True])
def test_duplicate_keys_are_rejected(store, supplied):
    rows = prepare_rows(store, [{"id": 32, "type": "string", "value": text_value()}])
    update = reference(rows[0])
    if supplied:
        update["value"] = text_value()
    with pytest.raises(ValueError, match="must not be duplicated"):
        prepare_rows(store, [update, dict(update)], rows)


@pytest.mark.parametrize("change", [{"id": 31}, {"type": "hex"}, {"key": None}])
def test_omitted_value_requires_exact_row_identity(store, change):
    rows = prepare_rows(store, [{"id": 32, "type": "string", "value": text_value()}])
    with pytest.raises(ValueError, match="unchanged row key, ID, and encoding"):
        prepare_rows(store, [reference(rows[0], **change)], rows)
    require(public_rows(store, rows)[0]["has_value"] is True)


def test_new_values_are_required_and_null_is_not_omission(store):
    with pytest.raises(ValueError, match="unchanged row key, ID, and encoding"):
        prepare_rows(store, [{"id": 32, "type": "string"}])
    rows = prepare_rows(store, [{"id": 32, "type": "string", "value": text_value()}])
    with pytest.raises(ValueError, match="supplied as text"):
        prepare_rows(store, [reference(rows[0], value=None)], rows)
    with pytest.raises(ValueError, match="supplied as text"):
        prepare_rows(store, [{"id": 32, "type": "string", "value": None}])
    empty = str()
    for sensitivity in ("public", "private"):
        for encoding in ("string", "hex"):
            saved = prepare_rows(store, [{"id": 32, "type": encoding, "value": empty, "sensitivity": sensitivity}])
            read = public_rows(store, saved)[0]
            require(read["has_value"] is True)
            require(decoded_rows(store, saved)[0]["value"] == empty)
            require(("value" in read) == (sensitivity == "public"))


def test_supplied_replacement_can_change_id_and_encoding_without_changing_key(store):
    rows = prepare_rows(store, [{"id": 32, "type": "string", "value": text_value()}])
    payload = secrets.token_bytes(17)
    replacement = reference(rows[0], id=31, type="hex", value=payload.hex().upper())
    updated = prepare_rows(store, [replacement], rows)
    require(updated[0]["key"] == rows[0]["key"])
    require(updated[0]["_value"] != rows[0]["_value"])
    require(encode_value(decoded_rows(store, updated)[0]) == payload)
    require(public_rows(store, updated)[0]["value"] == replacement["value"])


def test_private_to_public_never_reveals_saved_value_by_metadata(store):
    original = text_value()
    rows = prepare_rows(store, [{"id": 32, "type": "string", "value": original, "sensitivity": "private"}])
    with pytest.raises(ValueError, match="replacement value"):
        prepare_rows(store, [reference(rows[0], sensitivity="public")], rows)
    require("value" not in public_rows(store, rows)[0])
    replacement = text_value()
    still_private = prepare_rows(store, [reference(rows[0], value=replacement)], rows)
    require(still_private[0]["sensitivity"] == "private")
    published = prepare_rows(store, [reference(rows[0], sensitivity="public", value=replacement)], rows)
    read = public_rows(store, published)
    require(read[0]["value"] == replacement and original not in json.dumps(read),
            "Public classification exposed the saved private value")
    hidden = prepare_rows(store, [reference(published[0], sensitivity="private")], published)
    require(hidden[0]["key"] == rows[0]["key"] and hidden[0]["_value"] == published[0]["_value"])
    require("value" not in public_rows(store, hidden)[0])
    with pytest.raises(ValueError, match="replacement value"):
        prepare_rows(store, [reference(hidden[0], sensitivity="public")], hidden)


@pytest.mark.parametrize("attribute_id", [2, 3, 24, 60, 69, 79, 80, 103, 105, 106, 107, 112, 113, 116, 117, 118])
def test_known_credentials_are_always_private_but_usable(store, attribute_id):
    value = text_value()
    incoming = {"id": attribute_id, "type": "string", "value": value}
    with pytest.raises(ValueError, match="must remain private"):
        prepare_rows(store, [{**incoming, "sensitivity": "public"}])
    rows = prepare_rows(store, [incoming])
    require(rows[0]["sensitivity"] == "private")
    require("value" not in public_rows(store, rows)[0])
    require(decoded_rows(store, rows)[0]["value"] == value)
    for update in (reference(rows[0], sensitivity="public"),
                   reference(rows[0], sensitivity="public", value=text_value())):
        with pytest.raises(ValueError, match="must remain private"):
            prepare_rows(store, [update], rows)
    require(prepare_rows(store, [reference(rows[0])], rows) == rows)
    require(prepare_rows(store, [reference(rows[0], sensitivity="private")], rows) == rows)
    replaced = prepare_rows(store, [reference(rows[0], sensitivity="private", value=text_value())], rows)
    require(replaced[0]["key"] == rows[0]["key"] and replaced[0]["sensitivity"] == "private")


@pytest.mark.parametrize("attribute_id", [26, 241, 242, 243, 244, 245, 246])
def test_opaque_containers_support_private_and_explicit_public_values(store, attribute_id):
    for length in (0, 1, 253):
        payload = secrets.token_bytes(length)
        row = {"id": attribute_id, "type": "hex", "value": payload.hex()}
        private = prepare_rows(store, [row])
        require(private[0]["sensitivity"] == "private")
        require("value" not in public_rows(store, private)[0])
        with pytest.raises(ValueError, match="replacement value"):
            prepare_rows(store, [reference(private[0], sensitivity="public")], private)
        public = prepare_rows(store, [{**row, "sensitivity": "public"}])
        require(public_rows(store, public)[0]["value"] == payload.hex())
        preserved = prepare_rows(store, [reference(public[0])], public)
        require(preserved == public)
        require(encode_value(decoded_rows(store, preserved)[0]) == payload)
        published = prepare_rows(store, [reference(private[0], sensitivity="public", value=payload.hex())], private)
        require(public_rows(store, published)[0]["value"] == payload.hex())
        require(published[0]["key"] == private[0]["key"])


@pytest.mark.parametrize("old_id,new_id,encoding,default", [
    (32, 26, "string", "private"), (26, 241, "string", "private"),
    (26, 26, "hex", "private"), (26, 32, "string", "public"),
    (32, 32, "hex", "public"), (32, 2, "string", "private"),
    (2, 32, "string", "public"),
])
def test_changed_identity_uses_new_defaults_without_implicit_disclosure(store, old_id, new_id, encoding, default):
    classifications = ("private",) if old_id == 2 else ("public", "private")
    for sensitivity in classifications:
        original = text_value()
        rows = prepare_rows(store, [{"id": old_id, "type": "string", "value": original, "sensitivity": sensitivity}])
        changed = reference(rows[0], id=new_id, type=encoding)
        with pytest.raises(ValueError, match="unchanged row key, ID, and encoding"):
            prepare_rows(store, [changed], rows)
        replacement = secrets.token_hex(17) if encoding == "hex" else text_value()
        updated = prepare_rows(store, [{**changed, "value": replacement}], rows)
        expected = "private" if sensitivity == "private" else default
        require(updated[0]["sensitivity"] == expected and updated[0]["key"] == rows[0]["key"])
        require(decoded_rows(store, updated)[0]["value"] == replacement)
        if expected == "private":
            require("value" not in public_rows(store, updated)[0])
        explicit = {**changed, "sensitivity": "public", "value": replacement}
        if new_id == 2:
            with pytest.raises(ValueError, match="must remain private"):
                prepare_rows(store, [explicit], rows)
        else:
            published = public_rows(store, prepare_rows(store, [explicit], rows))
            require(published[0]["value"] == replacement and original not in json.dumps(published),
                    "Changing attribute identity disclosed its previous private value")


def test_every_legitimate_id_supports_all_four_exact_encodings():
    payload = secrets.token_bytes(4)
    string = text_value() + "".join(chr(number) for number in (0, 9, 10, 13, 127, 233, 0x1F9EA)) + text_value()
    samples = {"string": (string, string.encode("utf-8")),
               "integer": (str(int.from_bytes(payload, "big")), payload),
               "hex": (payload.hex().upper(), payload),
               "ipaddr": (str(ipaddress.IPv4Address(payload)), payload)}
    for attribute_id in range(1, 256):
        for encoding, (value, expected) in samples.items():
            require(encode_value({"id": attribute_id, "type": encoding, "value": value}) == expected,
                    "RADIUS encoding did not preserve exact bytes")
    for number in (0, 0xFFFFFFFF):
        require(encode_value({"id": 1, "type": "integer", "value": str(number)}) == number.to_bytes(4, "big"))


def test_payload_size_is_measured_in_encoded_bytes():
    byte = secrets.token_hex(1)[0]
    for size in (0, 253):
        payload = secrets.token_bytes(size)
        require(encode_value({"id": 26, "type": "hex", "value": payload.hex()}) == payload)
        require(encode_value({"id": 1, "type": "string", "value": byte * size}) == (byte * size).encode("utf-8"))
    for row in ({"id": 26, "type": "hex", "value": secrets.token_hex(254)},
                {"id": 1, "type": "string", "value": byte * 254},
                {"id": 1, "type": "string", "value": chr(233) * 127}):
        with pytest.raises(ValueError, match="253 encoded bytes"):
            encode_value(row)


def test_invalid_encodings_raise_fixed_value_free_errors():
    random_hex = secrets.token_hex(3)
    invalid = [("integer", str(-1)), ("integer", str(1 << 32)),
               ("integer", chr(32) + str(1)), ("integer", chr(43) + str(1)),
               ("integer", str(1.5)), ("integer", chr(0x0661)),
               ("hex", random_hex + random_hex[0]), ("hex", chr(103) * 2),
               ("hex", random_hex + chr(32) * 2),
               ("ipaddr", str(ipaddress.IPv6Address(secrets.token_bytes(16)))),
               ("ipaddr", text_value()), ("string", chr(0xD800))]
    for encoding, value in invalid:
        with pytest.raises(ValueError) as error:
            encode_value({"id": 1, "type": encoding, "value": value})
        require(str(error.value).startswith("RADIUS "))
        require(value not in str(error.value), "Validation error included a supplied value")
    for attribute_id in (0, 256, -1, True, None, 1.0):
        with pytest.raises(ValueError, match="ID must be an integer"):
            encode_value({"id": attribute_id, "type": "string", "value": text_value()})
    with pytest.raises(ValueError, match="encoding is invalid"):
        encode_value({"id": 1, "type": text_value(), "value": text_value()})
    with pytest.raises(ValueError, match="sensitivity must be public or private"):
        prepare_rows(None, [{"id": 1, "type": "string", "value": text_value(), "sensitivity": text_value()}])


def test_invalid_ciphertext_raises_a_fixed_error(store):
    rows = prepare_rows(store, [{"id": 1, "type": "string", "value": text_value()}])
    rows[0]["_value"] = text_value()
    with pytest.raises(ValueError, match="Stored RADIUS attribute value cannot be decoded"):
        public_rows(store, rows)
    with pytest.raises(ValueError, match="Stored RADIUS attribute value cannot be decoded"):
        decoded_rows(store, rows)


def test_storage_preserves_original_text_for_every_encoding(store):
    payload = secrets.token_bytes(4)
    text = "".join(chr(number) for number in (32, 0, 9, 10, 13, 127, 233, 101, 0x0301, 0x1F9EA)) + text_value() + chr(32)
    originals = {"string": text, "integer": str(int.from_bytes(payload, "big")).zfill(10),
                 "hex": payload.hex().upper(), "ipaddr": str(ipaddress.IPv4Address(payload))}
    for sensitivity in ("public", "private"):
        incoming = [{"id": 32, "type": encoding, "value": value, "sensitivity": sensitivity, "has_value": False}
                    for encoding, value in originals.items()]
        rows = prepare_rows(store, incoming)
        decoded = decoded_rows(store, rows)
        require([row["value"] for row in decoded] == list(originals.values()))
        require([encode_value(row) for row in decoded] == [encode_value(row) for row in incoming])
        read = public_rows(store, rows)
        require(all(row["has_value"] is True for row in read))
        if sensitivity == "public":
            require([row["value"] for row in read] == list(originals.values()))
        else:
            require(all("value" not in row for row in read))


def test_migration_preserves_public_text_and_encrypts_the_only_stored_copy(store):
    payload = secrets.token_bytes(4)
    originals = {"string": text_value(), "integer": str(int.from_bytes(payload, "big")).zfill(10),
                 "hex": payload.hex().upper(), "ipaddr": str(ipaddress.IPv4Address(payload))}
    legacy = [{"id": 32, "type": encoding, "value": value} for encoding, value in originals.items()]
    target = {"id": uuid4().hex, "name": text_value(), "extra_attributes": legacy,
              "_secret": store.encrypt(text_value()), "has_secret": True}
    store.put("target", target)
    database = store.directory / "eapolkit.sqlite3"
    require(originals["string"].encode("utf-8") in database.read_bytes())
    require(migrate_targets(store) == 1)
    migrated = store.get("target", target["id"])
    require({key: value for key, value in migrated.items() if key != "extra_attributes"}
            == {key: value for key, value in target.items() if key != "extra_attributes"})
    rows = migrated["extra_attributes"]
    read = public_rows(store, rows)
    require([row["value"] for row in read] == list(originals.values()))
    require(all(row["sensitivity"] == "public" and row["has_value"] for row in read))
    require(len({row["key"] for row in rows}) == len(legacy))
    require(all(set(row) == {"key", "id", "type", "sensitivity", "_value"} for row in rows))
    require(originals["string"].encode("utf-8") not in database.read_bytes(),
            "Legacy plaintext remained in storage after migration")
    require([encode_value(row) for row in decoded_rows(store, rows)] == [encode_value(row) for row in legacy])
    require(prepare_rows(store, [reference(row) for row in rows], rows) == rows)
    stable_database = database.read_bytes()
    require(migrate_targets(store) == 0)
    require(store.get("target", target["id"]) == migrated)
    require(database.read_bytes() == stable_database, "Repeated migration rewrote canonical storage")


def test_migration_keeps_legacy_opaque_rows_public_but_new_rows_default_private(store):
    legacy = [{"id": attribute_id, "type": "hex", "value": secrets.token_hex(19)}
              for attribute_id in (26, 241, 242, 243, 244, 245, 246)]
    target = {"id": uuid4().hex, "extra_attributes": legacy}
    store.put("target", target)
    require(migrate_targets(store) == 1)
    rows = store.get("target", target["id"])["extra_attributes"]
    read = public_rows(store, rows)
    require([row["value"] for row in read] == [row["value"] for row in legacy])
    require(all(row["sensitivity"] == "public" for row in read))
    require(prepare_rows(store, None, rows) == rows)
    require(prepare_rows(store, [reference(row) for row in rows], rows) == rows)
    new = prepare_rows(store, legacy)
    require(all(row["sensitivity"] == "private" and "value" not in row for row in public_rows(store, new)))


def test_migration_keeps_known_credential_rows_private(store):
    legacy = [{"id": attribute_id, "type": "string", "value": text_value()}
              for attribute_id in (2, 3, 24, 60, 69, 79, 80, 103, 105, 106, 107, 112, 113, 116, 117, 118)]
    target = {"id": uuid4().hex, "extra_attributes": legacy}
    store.put("target", target)
    require(migrate_targets(store) == 1)
    rows = store.get("target", target["id"])["extra_attributes"]
    require(all(row["sensitivity"] == "private" and "value" not in row for row in public_rows(store, rows)))
    require([row["value"] for row in decoded_rows(store, rows)] == [row["value"] for row in legacy])
    require(all(row["value"] not in json.dumps(rows) for row in legacy),
            "Migrated credential value remained in canonical plaintext")


def test_migration_preserves_existing_encrypted_private_rows_without_decryption(store, monkeypatch):
    existing = prepare_rows(store, [
        {"id": 32, "type": "string", "value": text_value(), "sensitivity": "private"},
        {"id": 26, "type": "string", "value": text_value(), "sensitivity": "public"},
    ])
    legacy = {"id": 31, "type": "string", "value": text_value()}
    target = {"id": uuid4().hex, "extra_attributes": [existing[0], legacy, existing[1]]}
    store.put("target", target)

    def forbidden_decrypt(_):
        raise AssertionError("Migration attempted to decrypt an existing value")

    with monkeypatch.context() as context:
        context.setattr(store, "decrypt", forbidden_decrypt)
        require(migrate_targets(store) == 1)
    rows = store.get("target", target["id"])["extra_attributes"]
    require(rows[0] == existing[0] and rows[2] == existing[1])
    require("value" not in public_rows(store, rows)[0])
    require(public_rows(store, rows)[1]["value"] == legacy["value"])
    require(migrate_targets(store) == 0)


@pytest.mark.parametrize("shape", ["private_metadata", "public_metadata", "row_key", "extra_field",
                                  "missing_value", "hybrid", "invalid_value", "not_list"])
def test_migration_rejects_unknown_or_malformed_schemas_before_any_write(store, shape):
    row = {"id": 32, "type": "string", "value": text_value()}
    if shape == "private_metadata":
        row["sensitivity"] = "private"
    elif shape == "public_metadata":
        row["sensitivity"] = "public"
    elif shape == "row_key":
        row["key"] = uuid4().hex
    elif shape == "extra_field":
        row["has_value"] = True
    elif shape == "missing_value":
        row.pop("value")
    elif shape == "hybrid":
        row = {**prepare_rows(store, [row])[0], "value": text_value()}
    elif shape == "invalid_value":
        row["value"] = None
    invalid = {"id": uuid4().hex, "extra_attributes": row if shape == "not_list" else [row]}
    valid = {"id": uuid4().hex, "extra_attributes": [{"id": 32, "type": "string", "value": text_value()}]}
    store.put("target", invalid)
    store.put("target", valid)
    with pytest.raises(ValueError):
        migrate_targets(store)
    require(store.get("target", valid["id"]) == valid, "Invalid migration partially changed another target")
    require(store.get("target", invalid["id"]) == invalid, "Migration guessed an unknown row schema")


def test_migration_does_not_add_or_rewrite_absent_or_empty_lists(store):
    targets = [{"id": uuid4().hex}, {"id": uuid4().hex, "extra_attributes": []}]
    for target in targets:
        store.put("target", target)
    require(migrate_targets(store) == 0)
    require(all(store.get("target", target["id"]) == target for target in targets))


def test_public_target_is_the_shared_secret_free_target_shape(store):
    public_value, private_value = text_value(), text_value()
    rows = prepare_rows(store, [
        {"id": 32, "type": "string", "value": public_value},
        {"id": 1, "type": "string", "value": private_value, "sensitivity": "private"},
    ])
    target = {"id": uuid4().hex, "name": text_value(), "has_secret": True,
              "_secret": store.encrypt(text_value()), "extra_attributes": rows}
    before = json.dumps(target)
    read = public_target(store, target)
    require(set(read) == {"id", "name", "has_secret", "extra_attributes"})
    require(read["id"] == target["id"] and read["name"] == target["name"] and read["has_secret"] is True)
    require(read["extra_attributes"] == public_rows(store, rows))
    require(read["extra_attributes"][0]["value"] == public_value)
    require(private_value not in json.dumps(read) and "value" not in read["extra_attributes"][1],
            "Private attribute reached the ordinary target serializer")
    require(all(row["_value"] not in json.dumps(read) for row in rows),
            "Encrypted attribute storage reached a read object")
    require(json.dumps(target) == before, "Target serialization changed stored data")
    require(public_target(store, {"id": uuid4().hex})["extra_attributes"] == [])
