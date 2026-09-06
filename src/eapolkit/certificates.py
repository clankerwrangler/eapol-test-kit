"""Certificate enrollment, import, and protected identity storage."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import re
import secrets

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


MAX_UPLOAD = 2 * 1024 * 1024
PEM_CERT = re.compile(rb"-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----")


def _now():
    return datetime.now(timezone.utc)


def _iso(value):
    return value.isoformat().replace("+00:00", "Z") if value else None


def _label(value, maximum=120):
    if not isinstance(value, str) or not 1 <= len(value) <= maximum or any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError("Certificate labels must be nonempty printable text within the length limit")
    return value


def _key(key_type):
    if key_type == "rsa2048":
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)
    if key_type == "rsa3072":
        return rsa.generate_private_key(public_exponent=65537, key_size=3072)
    if key_type == "ec-p256":
        return ec.generate_private_key(ec.SECP256R1())
    raise ValueError("Unsupported key type")


def _public_key(key):
    return key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def _pem_key(key):
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


def _certificates(data):
    if not isinstance(data, bytes) or not data or len(data) > MAX_UPLOAD:
        raise ValueError("Certificate upload is empty or exceeds 2 MiB")
    chunks = PEM_CERT.findall(data)
    if not chunks or PEM_CERT.sub(b"", data).strip():
        raise ValueError("Upload must contain only PEM certificates")
    try:
        return [x509.load_pem_x509_certificate(chunk) for chunk in chunks]
    except ValueError:
        raise ValueError("Invalid PEM certificate") from None


def _pem_chain(chain):
    return b"".join(cert.public_bytes(serialization.Encoding.PEM) for cert in chain)


def _check_chain(chain):
    for certificate, issuer in zip(chain, chain[1:]):
        try:
            certificate.verify_directly_issued_by(issuer)
        except (ValueError, TypeError):
            raise ValueError("Identity certificate chain does not verify in leaf-to-issuer order") from None
        except Exception:
            raise ValueError("Identity certificate chain signature does not verify") from None



def _issuer_matches(certificate, issuer):
    if certificate.issuer != issuer.subject:
        return False
    try:
        certificate.verify_directly_issued_by(issuer)
    except (InvalidSignature, UnsupportedAlgorithm, ValueError, TypeError):
        return False
    try:
        authority = certificate.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value
    except x509.ExtensionNotFound:
        return True
    if authority.key_identifier is not None:
        try:
            subject_key = issuer.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest
        except x509.ExtensionNotFound:
            subject_key = None
        if subject_key is not None and subject_key != authority.key_identifier:
            return False
    if authority.authority_cert_serial_number is not None and authority.authority_cert_serial_number != issuer.serial_number:
        return False
    if authority.authority_cert_issuer is not None:
        names = [x509.DirectoryName(issuer.issuer)]
        try:
            names.extend(issuer.extensions.get_extension_for_class(x509.IssuerAlternativeName).value)
        except x509.ExtensionNotFound:
            pass
        if not any(name in names for name in authority.authority_cert_issuer):
            return False
    return True


def _normalize_pfx_chain(chain):
    """Order unordered public bags only when they supply one verified issuer path."""
    leaf = chain[0]
    leaf_der = leaf.public_bytes(serialization.Encoding.DER)
    # Repeated identical bags do not create distinct issuer paths.
    remaining = {certificate.public_bytes(serialization.Encoding.DER): certificate for certificate in chain[1:]}
    remaining.pop(leaf_der, None)
    ordered = [leaf]
    while remaining:
        candidates = [(encoded, issuer) for encoded, issuer in remaining.items() if _issuer_matches(ordered[-1], issuer)]
        if not candidates:
            raise ValueError("PFX contains an unrelated certificate or an unverifiable issuer path")
        if len(candidates) != 1:
            raise ValueError("PFX contains an ambiguous issuer path")
        encoded, issuer = candidates[0]
        ordered.append(issuer)
        del remaining[encoded]
    return ordered


def _is_ca(certificate):
    try:
        return certificate.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    except x509.ExtensionNotFound:
        return False


def _sans(data):
    result = []
    for field, constructor in (("san_dns", x509.DNSName), ("san_email", x509.RFC822Name), ("san_uri", x509.UniformResourceIdentifier)):
        values = data.get(field, [])
        if not isinstance(values, list) or len(values) > 32:
            raise ValueError("Each SAN list must contain at most 32 values")
        for value in values:
            _label(value, 2048)
            try:
                if field == "san_dns":
                    value = value.encode("idna").decode("ascii")
                result.append(constructor(value))
            except (ValueError, UnicodeError):
                raise ValueError("Invalid subject alternative name") from None
    return result


def _metadata(object_id, name, kind, certificate=None, csr=None, has_key=False):
    item = certificate or csr
    public_key = item.public_key() if item else None
    key_type = (f"rsa{public_key.key_size}" if isinstance(public_key, rsa.RSAPublicKey) else
                "ec-p256" if isinstance(public_key, ec.EllipticCurvePublicKey) and isinstance(public_key.curve, ec.SECP256R1) else
                "ec-" + public_key.curve.name if isinstance(public_key, ec.EllipticCurvePublicKey) else
                type(public_key).__name__.replace("PublicKey", "").lower() if public_key else None)
    metadata = {
        "key_type": key_type,
        "id": object_id, "name": name, "kind": kind,
        "subject": item.subject.rfc4514_string() if item else None,
        "issuer": certificate.issuer.rfc4514_string() if certificate else None,
        "not_before": _iso(certificate.not_valid_before_utc) if certificate else None,
        "not_after": _iso(certificate.not_valid_after_utc) if certificate else None,
        "fingerprint_sha256": certificate.fingerprint(hashes.SHA256()).hex() if certificate else None,
        "san_dns": [], "san_email": [], "san_uri": [], "eku": [],
        "has_private_key": has_key, "warnings": [],
    }
    if item:
        try:
            san = item.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            metadata["san_dns"] = san.get_values_for_type(x509.DNSName)
            metadata["san_email"] = san.get_values_for_type(x509.RFC822Name)
            metadata["san_uri"] = san.get_values_for_type(x509.UniformResourceIdentifier)
        except x509.ExtensionNotFound:
            pass
    if certificate:
        try:
            eku = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
            metadata["eku"] = ["clientAuth" if oid == ExtendedKeyUsageOID.CLIENT_AUTH else "serverAuth" if oid == ExtendedKeyUsageOID.SERVER_AUTH else oid.dotted_string for oid in eku]
        except x509.ExtensionNotFound:
            pass
        if certificate.not_valid_after_utc <= _now():
            metadata["warnings"].append("Certificate has expired")
        if certificate.not_valid_before_utc > _now():
            metadata["warnings"].append("Certificate is not yet valid")
        if kind == "identity" and metadata["eku"] and "clientAuth" not in metadata["eku"]:
            metadata["warnings"].append("Certificate does not declare clientAuth usage")
    if kind == "ca":
        metadata["warnings"].append("Client issuer CA: configure the RADIUS server to trust this CA separately. Generating it does not configure server trust.")
    if kind == "trust":
        metadata["warnings"].append("Server trust asset: use this to verify the RADIUS server certificate, not to configure its client issuer trust.")
    return metadata


class CertificateService:
    def __init__(self, store):
        self.store = store

    def list(self):
        return [self.get(item["id"]) for item in self.store.list("certificate")]

    def get(self, object_id):
        record = self.store.get("certificate", object_id)
        certificate = _certificates(record["_certificate"] .encode())[0] if record.get("_certificate") else None
        csr = x509.load_pem_x509_csr(record["_csr"].encode()) if record.get("_csr") and certificate is None else None
        return _metadata(object_id, record["name"], record["kind"], certificate, csr, bool(record.get("_private_key")))

    def material(self, object_id):
        record = self.store.get("certificate", object_id)
        return {
            "certificate": record["_certificate"].encode() if record.get("_certificate") else None,
            "private_key": self.store.decrypt(record["_private_key"]) if record.get("_private_key") else None,
            "metadata": self.get(object_id),
        }

    def _save(self, name, kind, chain=None, key=None, csr=None, object_id=None):
        object_id = object_id or secrets.token_hex(16)
        metadata = _metadata(object_id, _label(name), kind, chain[0] if chain else None, csr, key is not None)
        record = dict(metadata)
        if chain:
            record["_certificate"] = _pem_chain(chain).decode("ascii")
        if key is not None:
            record["_private_key"] = self.store.encrypt(_pem_key(key))
        if csr is not None:
            record["_csr"] = csr.public_bytes(serialization.Encoding.PEM).decode("ascii")
        self.store.put("certificate", record)
        return metadata

    def import_asset(self, name, kind, certificate=None, private_key=None, pfx=None, passphrase=None):
        _label(name)
        for data in (certificate, private_key, pfx):
            if data is not None and (not isinstance(data, bytes) or not data or len(data) > MAX_UPLOAD):
                raise ValueError("Certificate upload is empty or exceeds 2 MiB")
        if passphrase is not None and (not isinstance(passphrase, str) or len(passphrase) > 4096):
            raise ValueError("Import passphrase exceeds the length limit")
        if kind == "trust":
            if private_key is not None or pfx is not None or passphrase:
                raise ValueError("Server trust imports accept only public PEM certificates")
            chain = _certificates(certificate)
            if not all(_is_ca(cert) for cert in chain):
                raise ValueError("Server trust imports must contain CA certificates")
            return self._save(name, kind, chain)
        if kind != "identity":
            raise ValueError("Import kind must be trust or identity")
        password = passphrase.encode("utf-8") if passphrase else None
        if pfx is not None:
            if certificate is not None or private_key is not None:
                raise ValueError("Choose either PFX or PEM certificate and key, not both")
            try:
                key, leaf, additional = pkcs12.load_key_and_certificates(pfx, password)
            except (ValueError, TypeError):
                raise ValueError("PFX could not be opened; check its format and passphrase") from None
            if key is None or leaf is None:
                raise ValueError("PFX must contain a certificate and private key")
            chain = [leaf] + list(additional or [])
        else:
            if certificate is None or private_key is None:
                raise ValueError("Identity import requires a PEM certificate and matching private key")
            chain = _certificates(certificate)
            try:
                key = serialization.load_pem_private_key(private_key, password=password)
            except (ValueError, TypeError):
                raise ValueError("Private key could not be opened; check its format and passphrase") from None
        if _public_key(key.public_key()) != _public_key(chain[0].public_key()):
            raise ValueError("Private key does not match the identity certificate")
        if _is_ca(chain[0]):
            raise ValueError("A client identity must not be a CA certificate")
        if pfx is not None:
            chain = _normalize_pfx_chain(chain)
        _check_chain(chain)
        return self._save(name, kind, chain, key)

    def generate_ca(self, data):
        name = _label(data.get("name"))
        common_name = _label(data.get("common_name"), 64)
        days = data.get("days", 3650)
        if not isinstance(days, int) or not 1 <= days <= 36500:
            raise ValueError("CA validity must be between 1 and 36500 days")
        key = _key(data.get("key_type", "rsa3072"))
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
        now = _now()
        certificate = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=days))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False, data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True, encipher_only=None, decipher_only=None), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), critical=False)
            .sign(key, hashes.SHA256()))
        return self._save(name, "ca", [certificate], key)

    def generate_client(self, data):
        name = _label(data.get("name"))
        common_name = _label(data.get("common_name"), 64)
        days = data.get("days", 365)
        if not isinstance(days, int) or not 1 <= days <= 36500:
            raise ValueError("Client validity must be between 1 and 36500 days")
        material = self.material(data.get("issuer_id"))
        if material["metadata"]["kind"] != "ca" or material["private_key"] is None:
            raise ValueError("Client issuer must be a generated CA with a protected signing key")
        chain = _certificates(material["certificate"])
        issuer = chain[0]
        now = _now()
        if not issuer.not_valid_before_utc <= now < issuer.not_valid_after_utc:
            raise ValueError("Client issuer CA is not currently valid")
        issuer_key = serialization.load_pem_private_key(material["private_key"], password=None)
        key = _key(data.get("key_type", "rsa3072"))
        builder = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
            .issuer_name(issuer.subject).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(max(now - timedelta(minutes=5), issuer.not_valid_before_utc))
            .not_valid_after(min(now + timedelta(days=days), issuer.not_valid_after_utc))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=isinstance(key, rsa.RSAPrivateKey), data_encipherment=False, key_agreement=False, key_cert_sign=False, crl_sign=False, encipher_only=None, decipher_only=None), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), critical=False))
        sans = _sans(data)
        if sans:
            builder = builder.add_extension(x509.SubjectAlternativeName(sans), critical=False)
        certificate = builder.sign(issuer_key, hashes.SHA256())
        return self._save(name, "identity", [certificate] + chain, key)

    def generate_csr(self, data):
        name = _label(data.get("name"))
        common_name = _label(data.get("common_name"), 64)
        key = _key(data.get("key_type", "rsa3072"))
        builder = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        sans = _sans(data)
        if sans:
            builder = builder.add_extension(x509.SubjectAlternativeName(sans), critical=False)
        builder = builder.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
        return self._save(name, "csr", key=key, csr=builder.sign(key, hashes.SHA256()))

    def complete(self, object_id, certificate):
        record = self.store.get("certificate", object_id)
        if record["kind"] != "csr":
            raise ValueError("Only a pending CSR can be completed")
        chain = _certificates(certificate)
        key = serialization.load_pem_private_key(self.store.decrypt(record["_private_key"]), password=None)
        if _public_key(key.public_key()) != _public_key(chain[0].public_key()):
            raise ValueError("Signed certificate does not match the retained CSR key")
        if _is_ca(chain[0]):
            raise ValueError("CSR completion requires a client identity, not a CA certificate")
        _check_chain(chain)
        return self._save(record["name"], "identity", chain, key, object_id=object_id)

    def download(self, object_id, format):
        record = self.store.get("certificate", object_id)
        if format == "certificate" and record.get("_certificate"):
            purpose = "server-trust" if record["kind"] == "trust" else "client-issuer-ca" if record["kind"] == "ca" else "client-certificate"
            return record["_certificate"].encode(), "application/x-pem-file", f"{purpose}-{record['id']}.pem"
        if format == "csr" and record.get("_csr"):
            return record["_csr"].encode(), "application/pkcs10", f"client-request-{record['id']}.csr"
        raise ValueError("Requested public material is not available for this asset")

    def export_pfx(self, object_id, passphrase):
        if not isinstance(passphrase, str) or not 8 <= len(passphrase) <= 4096:
            raise ValueError("Export passphrase must contain at least eight characters")
        material = self.material(object_id)
        if material["metadata"]["kind"] != "identity" or material["private_key"] is None:
            raise ValueError("Only private client identities can be exported as PFX")
        chain = _certificates(material["certificate"])
        key = serialization.load_pem_private_key(material["private_key"], password=None)
        try:
            return pkcs12.serialize_key_and_certificates(material["metadata"]["name"].encode(), key, chain[0], chain[1:] or None, serialization.BestAvailableEncryption(passphrase.encode("utf-8")))
        except (ValueError, TypeError):
            raise ValueError("PFX export could not be encrypted with this passphrase") from None

    def delete(self, object_id):
        with self.store.transaction():
            self.store.get("certificate", object_id)
            if any(object_id in {profile.get("ca_certificate_id"), profile.get("client_identity_id")} for profile in self.store.list("profile")):
                raise ValueError("A saved profile references this certificate; remove the reference first")
            self.store.delete("certificate", object_id)
