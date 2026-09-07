from safe_assertions import require

import secrets

import pytest

from eapolkit.configuration import radius_attribute_file, render
from eapolkit.models import ProfileInput, TargetInput


@pytest.mark.parametrize("method,phase2", [("eap-tls", None), ("peap-mschapv2", "auth=MSCHAPV2"), ("ttls-pap", "auth=PAP"), ("ttls-mschapv2", "auth=MSCHAPV2")])
def test_generated_methods_keep_exact_server_validation_and_safe_encoding(method, phase2):
    password = (secrets.token_urlsafe(24) + '\nengine=1\nload_dynamic_eap="not-a-module"\n"\\').encode()
    profile = ProfileInput(name="Test", method=method, identity="domain\\user", ca_certificate_id="server-trust", client_identity_id="client" if method == "eap-tls" else None, server_name="radius.example.test").model_dump(exclude={"password"})
    config = render(profile, {"ca_certificate": "/owned/server-ca.pem", "client_certificate": "/owned/client.pem", "private_key": "/owned/client-key.pem"}, password)
    require("key_mgmt=IEEE8021X" in config)
    require("eapol_flags=0" in config)
    require('domain_match="radius.example.test"' in config)
    require('ca_cert="/owned/server-ca.pem"' in config)
    require("tls_disable_tlsv1_0=1 tls_disable_tlsv1_1=1" in config)
    require("tls_disable_time_checks" not in config)
    require("tls_disable_tlsv1_3=" not in config)
    require("engine=1" not in config)
    require("load_dynamic_eap=" not in config)
    if phase2:
        require(f'phase2="{phase2}"' in config)
        line = next(line.strip() for line in config.splitlines() if line.strip().startswith("password="))
        matched = bytes.fromhex(line.split("=", 1)[1]) == password
        require(matched, "Credential encoding changed the supplied bytes")
        require("hash:" not in line)
    else:
        require("phase2=" not in config)
        require("password=" not in config)


def test_explicit_tls_bounds_and_exact_radius_attribute_bytes():
    profile = ProfileInput(name="Test", method="ttls-pap", tls_min_version="1.3", tls_max_version="1.3").model_dump(exclude={"password"})
    config = render(profile, {}, b"")
    require("tls_disable_tlsv1_2=1" in config)
    require("tls_disable_tlsv1_3=0" in config)
    target = TargetInput(name="Test", host="::1", nas_identifier="Lab \u03bb", nas_ip_address="192.0.2.7").model_dump(exclude={"secret"})
    profile = ProfileInput(name="Test", method="ttls-pap", extra_attributes=[{"id": 27, "type": "integer", "value": "4294967295"}]).model_dump(exclude={"password"})
    content = radius_attribute_file(target, profile["extra_attributes"], profile).decode("ascii")
    require("32:x:" + "Lab \u03bb".encode().hex() in content)
    require("4:x:c0000207" in content)
    require("27:x:ffffffff" in content)
    require("-A" not in content)


@pytest.mark.parametrize("attribute_id", [2, 3, 24, 26, 60, 69, 79, 80, 103, 241])
def test_credential_bearing_and_opaque_attributes_use_private_file_encoding(attribute_id):
    profile = ProfileInput(name="Test", method="ttls-pap", extra_attributes=[{"id": attribute_id, "type": "hex", "value": "00"}])
    content = radius_attribute_file(TargetInput(name="Test", host="127.0.0.1").model_dump(exclude={"secret"}), [row.model_dump(exclude_unset=True) for row in profile.extra_attributes], profile.model_dump(exclude={"password"}))
    require(f"{attribute_id}:x:00\n".encode() in content)
