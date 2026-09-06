"""Canonical encrypted target attributes and recognized startup migrations."""
from __future__ import annotations

import ipaddress
from copy import deepcopy
import re
from uuid import uuid4

from cryptography.fernet import InvalidToken

from .redaction import Redactor
from .storage import Store, public


PRIVATE_IDS = frozenset({2, 3, 24, 60, 69, 79, 80, 103, 105, 106, 107, 112, 113, 116, 117, 118})
OPAQUE_IDS = frozenset({26, 241, 242, 243, 244, 245, 246})
ENCODINGS = frozenset({"string", "integer", "hex", "ipaddr"})


def _identity(row: dict) -> tuple[int, str]:
    if not isinstance(row, dict):
        raise ValueError("RADIUS attribute must be an object")
    attribute_id, encoding = row.get("id"), row.get("type")
    if type(attribute_id) is not int or not 1 <= attribute_id <= 255:
        raise ValueError("RADIUS attribute ID must be an integer from 1 through 255")
    if not isinstance(encoding, str) or encoding not in ENCODINGS:
        raise ValueError("RADIUS attribute encoding is invalid")
    return attribute_id, encoding


def encode_value(row: dict) -> bytes:
    """Encode one supplied value without interpreting nested attribute layouts."""
    _, encoding = _identity(row)
    value = row.get("value")
    if not isinstance(value, str):
        raise ValueError("RADIUS attribute value must be supplied as text")
    if encoding == "integer":
        if not re.fullmatch(r"[0-9]{1,10}", value) or int(value) > 0xFFFFFFFF:
            raise ValueError("RADIUS integer must be an unsigned 32-bit decimal value")
        encoded = int(value).to_bytes(4, "big")
    elif encoding == "hex":
        if len(value) % 2 or not re.fullmatch(r"[0-9a-fA-F]*", value):
            raise ValueError("RADIUS hex must contain complete hexadecimal bytes")
        encoded = bytes.fromhex(value)
    elif encoding == "ipaddr":
        try:
            encoded = ipaddress.IPv4Address(value).packed
        except ValueError:
            raise ValueError("RADIUS ipaddr must be an IPv4 address") from None
    else:
        try:
            encoded = value.encode("utf-8")
        except UnicodeError:
            raise ValueError("RADIUS string must be valid UTF-8 text") from None
    if len(encoded) > 253:
        raise ValueError("RADIUS attribute exceeds 253 encoded bytes")
    return encoded


def _stored_rows(rows: list[dict]) -> list[dict]:
    if not isinstance(rows, list):
        raise ValueError("Stored RADIUS attributes must be a list")
    result = []
    keys = set()
    for row in rows:
        attribute_id, encoding = _identity(row)
        key = row.get("key")
        if not isinstance(key, str) or not key or key in keys:
            raise ValueError("Stored RADIUS attribute keys must be unique nonempty strings")
        keys.add(key)
        sensitivity = row.get("sensitivity")
        if sensitivity not in ("public", "private"):
            raise ValueError("Stored RADIUS attribute sensitivity is invalid")
        if attribute_id in PRIVATE_IDS:
            sensitivity = "private"
        encrypted = row.get("_value")
        if not isinstance(encrypted, str) or not encrypted or "value" in row:
            raise ValueError("Stored RADIUS attributes require encrypted values; migrate legacy rows first")
        result.append({"key": key, "id": attribute_id, "type": encoding,
                       "sensitivity": sensitivity, "_value": encrypted})
    return result


def prepare_rows(
    store: Store, incoming: list[dict] | None, previous: list[dict] | None = None
) -> list[dict]:
    """Prepare canonical rows using only this target's previous rows for keys.

    Pass None for an omitted list. Pass an empty list to remove all rows.
    Omit value to preserve an exact key, ID, and encoding. Pass only explicitly
    supplied sensitivity fields so that classification remains intentional.
    """
    if incoming is not None and not isinstance(incoming, list):
        raise ValueError("RADIUS attributes must be a list")
    previous = _stored_rows([] if previous is None else previous)
    if incoming is None:
        return previous
    by_key = {row["key"]: row for row in previous}
    seen = set()
    result = []
    for row in incoming:
        attribute_id, encoding = _identity(row)
        key = row.get("key")
        old = None
        if key is not None:
            if not isinstance(key, str) or key not in by_key:
                raise ValueError("RADIUS attribute key does not belong to this target")
            if key in seen:
                raise ValueError("RADIUS attribute keys must not be duplicated")
            seen.add(key)
            old = by_key[key]
        supplied = "value" in row
        same_identity = old is not None and (attribute_id, encoding) == (old["id"], old["type"])
        if not supplied and not same_identity:
            raise ValueError("Preserving a RADIUS value requires an unchanged row key, ID, and encoding")
        requested = row.get("sensitivity")
        if requested is not None and requested not in ("public", "private"):
            raise ValueError("RADIUS attribute sensitivity must be public or private")
        if attribute_id in PRIVATE_IDS:
            if requested == "public":
                raise ValueError("Credential-bearing RADIUS attributes must remain private")
            sensitivity = "private"
        elif requested is not None:
            sensitivity = requested
        elif old is not None and (same_identity or old["sensitivity"] == "private"):
            sensitivity = old["sensitivity"]
        else:
            sensitivity = "private" if attribute_id in OPAQUE_IDS else "public"
        public_container = same_identity and old["sensitivity"] == "public"
        if sensitivity == "public" and (
            (old is not None and old["sensitivity"] == "private")
            or (attribute_id in OPAQUE_IDS and not public_container)
        ):
            if requested != "public" or not supplied:
                raise ValueError("Public classification requires explicit public sensitivity and a replacement value")
        if supplied:
            encode_value(row)
            encrypted = store.encrypt(row["value"])
        else:
            encrypted = old["_value"]
        result.append({"key": key if old is not None else uuid4().hex,
                       "id": attribute_id, "type": encoding,
                       "sensitivity": sensitivity, "_value": encrypted})
    return result


def _value(store: Store, row: dict) -> str:
    try:
        value = store.decrypt(row["_value"]).decode("utf-8")
    except (InvalidToken, ValueError, UnicodeError):
        raise ValueError("Stored RADIUS attribute value cannot be decoded") from None
    encode_value({"id": row["id"], "type": row["type"], "value": value})
    return value


def _metadata(row: dict) -> dict:
    return {field: row[field] for field in ("key", "id", "type", "sensitivity")}


def public_rows(store: Store, stored_rows: list[dict]) -> list[dict]:
    """Return read objects without decrypting or returning private values."""
    result = []
    for row in _stored_rows(stored_rows):
        visible = {**_metadata(row), "has_value": bool(row["_value"])}
        if row["sensitivity"] == "public":
            visible["value"] = _value(store, row)
        result.append(visible)
    return result


def public_target(store: Store, target: dict) -> dict:
    """Return the ordinary target shape shared by API responses and snapshots."""
    return {**public(target), "extra_attributes": public_rows(store, target.get("extra_attributes", []))}


def decoded_rows(store: Store, stored_rows: list[dict]) -> list[dict]:
    """Return ephemeral plaintext rows only for protected native-file preparation.

    Never persist these rows or include them in responses, snapshots, or logs.
    """
    return [{**_metadata(row), "value": _value(store, row)} for row in _stored_rows(stored_rows)]


def migrate_targets(store: Store) -> int:
    """Convert legacy plaintext rows before serving requests; return changed targets.

    Recognize only the legacy id/type/value shape and canonical encrypted rows.
    Legacy rows retain historical public readability, including opaque containers,
    except for IDs that are always private. Do not reinterpret other schemas.
    Repeated calls preserve canonical keys and ciphertext without rewriting them.
    """
    changes = []
    with store.transaction():
        for target in store.list("target"):
            rows = target.get("extra_attributes", [])
            if not isinstance(rows, list):
                raise ValueError("Stored RADIUS attributes must be a list")
            converted = []
            changed = False
            for row in rows:
                if not isinstance(row, dict):
                    raise ValueError("Stored RADIUS attribute schema is not recognized")
                if set(row) == {"id", "type", "value"}:
                    attribute_id, _ = _identity(row)
                    sensitivity = "private" if attribute_id in PRIVATE_IDS else "public"
                    converted.extend(prepare_rows(store, [{**row, "sensitivity": sensitivity}]))
                    changed = True
                elif set(row) == {"key", "id", "type", "sensitivity", "_value"}:
                    converted.append(row)
                else:
                    raise ValueError("Stored RADIUS attribute schema is not recognized")
            canonical = _stored_rows(converted)
            if changed:
                changes.append({**target, "extra_attributes": canonical})
        # Validate every target before the first write; keep other Store users serialized.
        for target in changes:
            store.put("target", target)
    return len(changes)


def migrate_history(store: Store) -> int:
    """Sanitize recognized historical fields without guessing unknown schemas.

    The scan is independent of target upgrades. Each run is written completely;
    identifiers, recorded outcomes, and unrelated data are never rewritten.
    """
    changed = 0
    for original in store.list("run"):
        snapshot = original.get("snapshot")
        target = snapshot.get("target") if isinstance(snapshot, dict) else None
        rows = target.get("extra_attributes") if isinstance(target, dict) else None
        if not isinstance(rows, list):
            continue
        live_rows = []
        target_id = original.get("target_id")
        if target_id and target.get("id", target_id) == target_id:
            try:
                live_rows = _stored_rows(store.get("target", target_id).get("extra_attributes", []))
            except (KeyError, ValueError):
                pass
        values, visible = [], []
        for row in rows:
            if not isinstance(row, dict) or not ("value" in row or "_value" in row or {"key", "sensitivity", "has_value"}.issubset(row)):
                visible.append(deepcopy(row))
                continue
            try:
                attribute_id, encoding = _identity(row)
            except ValueError:
                visible.append(deepcopy(row))
                continue
            if attribute_id in PRIVATE_IDS:
                sensitivity = "private"
            elif row.get("sensitivity") in ("public", "private"):
                sensitivity = row["sensitivity"]
            elif "sensitivity" not in row and "value" in row and "_value" not in row:
                sensitivity = "public"
            else:
                visible.append(deepcopy(row))
                continue
            supplied_values = []
            try:
                if "value" in row:
                    encode_value(row)
                    supplied_values.append(row["value"])
                if "_value" in row:
                    supplied_values.append(_value(store, row))
            except (ValueError, TypeError):
                # No supported version writes an undecodable historical value.
                # Preserve that row, but do not let it block recognized siblings.
                visible.append(deepcopy(row))
                continue
            item = deepcopy(row)
            key = item.get("key")
            if key is None:
                key = uuid4().hex
                item["key"] = key
            item["sensitivity"] = sensitivity
            item["has_value"] = bool(supplied_values) or item.get("has_value", False)
            if sensitivity == "private":
                item.pop("value", None)
                item.pop("_value", None)
                for value in supplied_values:
                    values.extend((value, encode_value({"id": attribute_id, "type": encoding, "value": value})))
                for live in live_rows:
                    if (live["key"], live["id"], live["type"], live["sensitivity"]) == (key, attribute_id, encoding, "private"):
                        try:
                            live_value = _value(store, live)
                        except ValueError:
                            continue
                        values.extend((live_value, encode_value({"id": attribute_id, "type": encoding, "value": live_value})))
            elif supplied_values:
                item["value"] = supplied_values[0]
                item.pop("_value", None)
            visible.append(item)
        record = deepcopy(original)
        record["snapshot"]["target"]["extra_attributes"] = visible
        if values:
            redactor = Redactor(values)
            for field in ("summary", "target_name", "profile_name"):
                if isinstance(record.get(field), str):
                    record[field] = redactor.text(record[field])
            if isinstance(record["snapshot"].get("configuration"), str):
                record["snapshot"]["configuration"] = redactor.text(record["snapshot"]["configuration"])
            for kind, fields in (("target", ("name", "host", "nas_identifier", "nas_ip_address", "calling_station_id")), ("profile", ("name", "identity", "anonymous_identity", "server_name"))):
                display = record["snapshot"].get(kind)
                if isinstance(display, dict):
                    for field in fields:
                        if isinstance(display.get(field), str):
                            display[field] = redactor.text(display[field])
            logs = record.get("log_lines")
            if isinstance(logs, list):
                for entry in logs:
                    if isinstance(entry, dict) and isinstance(entry.get("line"), str):
                        entry["line"] = redactor.line(entry["line"])
        if record != original:
            store.put("run", record)
            changed += 1
    return changed
