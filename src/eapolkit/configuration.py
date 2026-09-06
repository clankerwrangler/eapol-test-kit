"""Allowlisted wpa network configuration with exact TLS peer validation."""
from __future__ import annotations

from datetime import datetime, timezone
import ipaddress

from cryptography import x509

from .models import ProfileInput, TargetInput
from .attributes import encode_value

METHODS = {"eap-tls": "TLS", "peap-mschapv2": "PEAP", "ttls-pap": "TTLS", "ttls-mschapv2": "TTLS"}


def _asset(certificates, object_id, kinds):
    try:
        asset = certificates.material(object_id)
    except KeyError:
        raise ValueError("A referenced certificate asset is missing") from None
    if asset["metadata"]["kind"] not in kinds or not asset["certificate"]:
        raise ValueError("A referenced certificate has the wrong purpose")
    return asset


def validate_runnable(profile, target, certificates, store):
    # Revalidate stored editable input before it can reach a process argument or configuration.
    ProfileInput.model_validate({key: value for key, value in profile.items() if key not in {"id", "has_password"} and not key.startswith("_")})
    TargetInput.model_validate({key: value for key, value in target.items() if key not in {"id", "has_secret", "extra_attributes"} and not key.startswith("_")})
    if not profile.get("identity"):
        raise ValueError("Set a nonempty EAP identity before running")
    if not profile.get("server_name") or not profile.get("ca_certificate_id"):
        raise ValueError("Choose an explicit server CA and expected server name before running")
    _asset(certificates, profile["ca_certificate_id"], {"trust", "ca"})
    if not target.get("_secret") or not store.decrypt(target["_secret"]):
        raise ValueError("Save a RADIUS shared secret before running")
    if profile["method"] != "eap-tls" and (not profile.get("_password") or not store.decrypt(profile["_password"])):
        raise ValueError("Save an EAP password before running this method")
    if profile["method"] == "eap-tls" and not profile.get("client_identity_id"):
        raise ValueError("Choose a private client identity for EAP-TLS")
    if profile.get("client_identity_id"):
        client = _asset(certificates, profile["client_identity_id"], {"identity"})
        if not client["private_key"]:
            raise ValueError("Client identity has no private key")
        leaf = x509.load_pem_x509_certificate(client["certificate"])
        now = datetime.now(timezone.utc)
        if leaf.not_valid_before_utc > now:
            raise ValueError("Client identity certificate is not yet valid")
        if leaf.not_valid_after_utc <= now and not profile.get("allow_expired_client_certificate", False):
            raise ValueError("Client identity has expired; explicitly allow an expired client only for an intentional negative test")


def render(profile, paths, password=None, *, redacted=False):
    lines = ["network={", "    key_mgmt=IEEE8021X", "    eapol_flags=0", f"    eap={METHODS[profile['method']]}", f"    identity={profile.get('identity', '').encode('utf-8').hex()}"]
    if profile.get("anonymous_identity"):
        lines.append(f"    anonymous_identity={profile['anonymous_identity'].encode('utf-8').hex()}")
    if profile.get("ca_certificate_id"):
        lines.append(f'    ca_cert="{paths["ca_certificate"]}"')
    if profile.get("server_name"):
        lines.append(f'    domain_match="{profile["server_name"]}"')
    if profile.get("client_identity_id"):
        lines.extend([f'    client_cert="{paths["client_certificate"]}"', f'    private_key="{paths["private_key"]}"'])
    phase1 = ["tls_disable_tlsv1_0=1", "tls_disable_tlsv1_1=1"]
    if profile.get("tls_min_version", "1.2") == "1.3":
        phase1.append("tls_disable_tlsv1_2=1")
    if profile.get("tls_max_version") == "1.2":
        phase1.append("tls_disable_tlsv1_3=1")
    elif profile.get("tls_min_version") == "1.3" or profile.get("tls_max_version") == "1.3":
        phase1.append("tls_disable_tlsv1_3=0")
    lines.append('    phase1="' + " ".join(phase1) + '"')
    if profile["method"] != "eap-tls":
        phase2 = "auth=PAP" if profile["method"] == "ttls-pap" else "auth=MSCHAPV2"
        lines.append(f'    phase2="{phase2}"')
        lines.append("    password=" + ("<redacted>" if redacted else (password or b"").hex()))
    lines.append(f"    fragment_size={profile.get('fragment_size', 1398)}")
    return "\n".join(lines + ["}", ""])


def preview(profile, certificates):
    warnings = []
    if not profile.get("identity"):
        warnings.append("Set a nonempty EAP identity before running.")
    if not profile.get("ca_certificate_id") or not profile.get("server_name"):
        warnings.append("An explicit server CA and expected server name are required before running.")
    if profile["method"] != "eap-tls" and not profile.get("has_password"):
        warnings.append("Save an EAP password before running this method.")
    if profile["method"] == "eap-tls" and not profile.get("client_identity_id"):
        warnings.append("Choose a private client identity for EAP-TLS.")
    for field in ("ca_certificate_id", "client_identity_id"):
        if profile.get(field):
            try:
                warnings.extend(certificates.get(profile[field])["warnings"])
            except KeyError:
                warnings.append("A referenced certificate is missing.")
    if profile.get("allow_expired_client_certificate"):
        warnings.append("Expired client certificates are allowed for this recipe. Server certificate validation remains enabled.")
    paths = {"ca_certificate": f"asset:{profile.get('ca_certificate_id')}:certificate", "client_certificate": f"asset:{profile.get('client_identity_id')}:certificate", "private_key": f"asset:{profile.get('client_identity_id')}:private-key"}
    return {"configuration": render(profile, paths, redacted=True), "warnings": warnings}


def radius_attribute_file(target, rows):
    """Encode all attributes for the protected native -G input, never argv."""
    attributes = [(32, target.get("nas_identifier", "eapol-test-kit").encode("utf-8")), (31, target.get("calling_station_id", "02:00:00:00:00:01").encode("utf-8"))]
    if target.get("nas_ip_address"):
        attributes.append((4, ipaddress.IPv4Address(target["nas_ip_address"]).packed))
    attributes.extend((row["id"], encode_value(row)) for row in rows)
    if len(attributes) > 64:
        raise ValueError("Native attribute input exceeds 64 rows including generated attributes")
    lines = []
    for attribute_id, encoded in attributes:
        if not 1 <= attribute_id <= 255 or len(encoded) > 253:
            raise ValueError("Native RADIUS attribute ID or payload exceeds its bounds")
        line = f"{attribute_id}:x:{encoded.hex()}".encode("ascii")
        if len(line) > 512:
            raise ValueError("Native attribute row exceeds 512 bytes")
        lines.append(line)
    content = b"\n".join(lines) + (b"\n" if lines else b"")
    if len(content) > 32832:
        raise ValueError("Native attribute input exceeds its total file bound")
    return content
