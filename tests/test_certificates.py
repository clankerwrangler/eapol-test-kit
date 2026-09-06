from safe_assertions import require

from datetime import datetime, timedelta, timezone
import os
import secrets

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from eapolkit.certificates import CertificateService
from eapolkit.storage import Store


@pytest.fixture
def certificates(tmp_path):
    os.chmod(tmp_path, 0o700)
    store = Store(tmp_path / "data")
    yield CertificateService(store), store
    store.close()


@pytest.mark.parametrize("key_type", ["rsa2048", "rsa3072", "ec-p256"])
def test_signing_key_types_extensions_validity_and_encryption(certificates, key_type):
    service, store = certificates
    ca = service.generate_ca({"name": "Issuer", "common_name": "Ephemeral issuer", "key_type": key_type, "days": 2})
    client = service.generate_client({"issuer_id": ca["id"], "name": "Client", "common_name": "Ephemeral client", "key_type": key_type, "days": 30, "san_dns": ["client.example.test"], "san_email": ["client@example.test"], "san_uri": ["urn:eapolkit:test:client"]})
    issuer = x509.load_pem_x509_certificate(service.material(ca["id"])["certificate"])
    material = service.material(client["id"])
    leaf = x509.load_pem_x509_certificate(material["certificate"])
    leaf.verify_directly_issued_by(issuer)
    require(leaf.not_valid_after_utc <= issuer.not_valid_after_utc)
    require(issuer.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
    require(not leaf.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
    require(ExtendedKeyUsageOID.CLIENT_AUTH in leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value)
    usage = leaf.extensions.get_extension_for_class(x509.KeyUsage).value
    require(usage.digital_signature)
    require(not usage.key_cert_sign)
    require(client["key_type"] == key_type)
    require(client["san_dns"] == ["client.example.test"])
    require(client["eku"] == ["clientAuth"])
    require("PRIVATE KEY" not in service.download(client["id"], "certificate")[0].decode())
    private_record = store.get("certificate", client["id"])
    safe = material["private_key"] not in (store.directory / "eapolkit.sqlite3").read_bytes()
    require(safe, "A private key reached plaintext SQLite storage")
    require(not private_record["_private_key"].startswith("-----BEGIN"))


def test_import_rejects_key_mismatch_and_preserves_store(certificates):
    service, store = certificates
    ca = service.generate_ca({"name": "Issuer", "common_name": "Issuer", "key_type": "ec-p256"})
    first = service.generate_client({"issuer_id": ca["id"], "name": "First", "common_name": "First", "key_type": "ec-p256"})
    second = service.generate_client({"issuer_id": ca["id"], "name": "Second", "common_name": "Second", "key_type": "ec-p256"})
    with pytest.raises(ValueError, match="does not match"):
        service.import_asset("Mismatch", "identity", certificate=service.material(first["id"])["certificate"], private_key=service.material(second["id"])["private_key"])
    require(len(service.list()) == 3)
    imported = service.import_asset("Correct import", "identity", certificate=service.material(first["id"])["certificate"], private_key=service.material(first["id"])["private_key"])
    require(imported["fingerprint_sha256"] == first["fingerprint_sha256"])
    with pytest.raises(ValueError, match="only public"):
        service.import_asset("Wrong trust", "trust", certificate=service.material(ca["id"])["certificate"], private_key=service.material(ca["id"])["private_key"])


def test_pfx_requires_protection_and_discards_import_passphrase(certificates):
    service, store = certificates
    ca = service.generate_ca({"name": "Issuer", "common_name": "Issuer", "key_type": "ec-p256"})
    client = service.generate_client({"issuer_id": ca["id"], "name": "Client", "common_name": "Client", "key_type": "ec-p256"})
    phrase = secrets.token_urlsafe(32)
    exported = service.export_pfx(client["id"], phrase)
    with pytest.raises(ValueError):
        pkcs12.load_key_and_certificates(exported, None)
    with pytest.raises(ValueError):
        service.export_pfx(client["id"], "")
    with pytest.raises(ValueError, match="Only private client"):
        service.export_pfx(ca["id"], phrase)
    imported = service.import_asset("Imported PFX", "identity", pfx=exported, passphrase=phrase)
    require(imported["has_private_key"])
    require(imported["fingerprint_sha256"] == client["fingerprint_sha256"])
    absent = phrase.encode() not in (store.directory / "eapolkit.sqlite3").read_bytes()
    require(absent, "An import/export passphrase was persisted")


def test_csr_wrong_key_does_not_destroy_pending_enrollment(certificates):
    service, store = certificates
    pending = service.generate_csr({"name": "Request", "common_name": "Requested client", "key_type": "ec-p256"})
    csr = x509.load_pem_x509_csr(service.download(pending["id"], "csr")[0])
    require(csr.is_signature_valid)
    unrelated_key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Unrelated")])
    now = datetime.now(timezone.utc)
    certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(unrelated_key.public_key())
                   .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1))
                   .not_valid_after(now + timedelta(days=1)).sign(unrelated_key, hashes.SHA256()))
    with pytest.raises(ValueError, match="does not match"):
        service.complete(pending["id"], certificate.public_bytes(serialization.Encoding.PEM))
    require(service.get(pending["id"])["kind"] == "csr")
    require(service.get(pending["id"])["has_private_key"])
    require(service.download(pending["id"], "csr")[0] == csr.public_bytes(serialization.Encoding.PEM))


def test_upload_bounds_and_referenced_asset_deletion(certificates):
    service, store = certificates
    with pytest.raises(ValueError, match="exceeds"):
        service.import_asset("Oversized", "trust", certificate=b"x" * (2 * 1024 * 1024 + 1))
    ca = service.generate_ca({"name": "Issuer", "common_name": "Issuer", "key_type": "ec-p256"})
    store.put("profile", {"id": "reference", "ca_certificate_id": ca["id"]})
    with pytest.raises(ValueError, match="references"):
        service.delete(ca["id"])
    require(service.get(ca["id"])["kind"] == "ca")
