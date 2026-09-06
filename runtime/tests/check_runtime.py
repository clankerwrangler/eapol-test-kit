#!/usr/bin/env python3
"""Exercise the real binary with private, runtime-generated UDP fixtures.

These fixtures validate input handling, method startup, and result evidence.
They do not claim a completed authenticated EAP exchange.
"""
import argparse
import base64
import hashlib
import hmac
import os
import re
from pathlib import Path
import secrets
import signal
import socket
import ssl
import struct
import subprocess
import tempfile
import unittest

BINARY = None


def attr(kind, value):
    return bytes((kind, len(value) + 2)) + value


def eap_attributes(eap):
    return b"".join(attr(79, eap[i:i + 253]) for i in range(0, len(eap), 253))


def der(tag, value):
    size = len(value)
    length = bytes((size,)) if size < 128 else bytes((0x82, size >> 8, size & 0xff))
    return bytes((tag,)) + length + value


class RuntimeChecks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root_temp = tempfile.TemporaryDirectory(prefix="eapol-runtime-")
        cls.root = Path(cls.root_temp.name)
        cls.cert = cls.root / "fixture.pem"
        cls.key = cls.root / "fixture.key"
        result = subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-subj", "/CN=runtime-fixture.invalid", "-days", "1",
            "-addext", "subjectAltName=DNS:runtime-fixture.invalid",
            "-addext", "basicConstraints=critical,CA:TRUE",
            "-keyout", str(cls.key), "-out", str(cls.cert),
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, umask=0o077)
        if result.returncode:
            raise RuntimeError("Could not generate the private runtime TLS fixture")

    @classmethod
    def tearDownClass(cls):
        cls.root_temp.cleanup()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=self.root)
        self.run_dir = Path(self.temp.name)
        self.secret = secrets.token_hex(32).encode() + b" !'\"\\ "
        self.password = secrets.token_hex(32).encode() + b" !'\"\\\n" + "é".encode()
        self.identity = secrets.token_hex(12).encode() + b"'\"\\\n@example.invalid"
        self.secret_file = self.run_dir / "radius-secret"
        self.private_write(self.secret_file, self.secret)
        self.process = None
        self.private_attributes = ()
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.bind(("127.0.0.1", 0))
        self.udp.settimeout(5)

    def tearDown(self):
        if self.process is not None and self.process.poll() is None:
            os.killpg(self.process.pid, signal.SIGKILL)
            self.process.communicate(timeout=3)
        self.udp.close()
        self.temp.cleanup()

    @staticmethod
    def private_write(path, data):
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as output:
            output.write(data)
        path.chmod(0o600)

    def config(self, method="TTLS", inner="PAP", wrong_name=False):
        settings = [
            "network={", "key_mgmt=IEEE8021X", "eap=" + method,
            "identity=" + self.identity.hex(), "password=" + self.password.hex(),
            'ca_cert="' + str(self.cert) + '"',
            'domain_match="' + ("other.invalid" if wrong_name else "runtime-fixture.invalid") + '"',
            'phase1="tls_disable_tlsv1_0=1 tls_disable_tlsv1_1=1 tls_disable_tlsv1_3=1"',
            "fragment_size=1398", "eapol_flags=0",
        ]
        if method == "TLS":
            settings += ['client_cert="' + str(self.cert) + '"',
                         'private_key="' + str(self.key) + '"']
        else:
            settings += ['phase2="auth=' + inner + '"']
        settings += ["}", ""]
        conf = self.run_dir / "network.conf"
        self.private_write(conf, "\n".join(settings).encode())
        return conf

    def argv(self, conf=None, extra=()):
        return [str(BINARY), "-c", str(conf or self.config()), "-a", "127.0.0.1",
                "-p", str(self.udp.getsockname()[1]), "-F", str(self.secret_file),
                "-t", "3", "-r", "0", *extra]

    def assert_no_disclosure(self, output, additional_sentinels=()):
        for sentinel in (self.secret, self.password, *self.private_attributes, *additional_sentinels):
            forms = (sentinel, sentinel.hex().encode(), sentinel.hex().upper().encode(),
                     base64.b64encode(sentinel), sentinel.hex(" ").encode())
            for form in forms:
                self.assertTrue(form not in output, "A runtime-generated credential appeared in child output")
        for marker in (b"MS-MPPE-Send-Key", b"MS-MPPE-Recv-Key", b"PMK from EAPOL",
                       b"TLS: TLS Master Secret", b"MSCHAPV2: NT-Response"):
            self.assertTrue(marker not in output, "A known key dump appeared in file-input mode")

    def start(self, conf=None, extra=()):
        self.process = subprocess.Popen(self.argv(conf, extra), stdout=subprocess.PIPE,
                                        stderr=subprocess.STDOUT, start_new_session=True,
                                        env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                                             "LANG": "C", "LC_ALL": "C"}, umask=0o077)
        cmdline = Path("/proc") / str(self.process.pid) / "cmdline"
        if cmdline.exists():
            for sentinel in (self.secret, self.password, *self.private_attributes):
                self.assertTrue(sentinel not in cmdline.read_bytes(), "A credential appeared in arguments")

    def finish(self):
        output, _ = self.process.communicate(timeout=8)
        self.assert_no_disclosure(output)
        self.assertTrue(len(output) < 128 * 1024, "Unexpectedly large runtime output")
        return output

    def receive(self):
        packet, peer = self.udp.recvfrom(65535)
        self.assertTrue(len(packet) >= 20 and packet[0] == 1, "Expected Access-Request")
        self.assertTrue(struct.unpack("!H", packet[2:4])[0] == len(packet), "Bad RADIUS length")
        zeroed = bytearray(packet)
        attrs = []
        pos = 20
        authenticators = []
        while pos < len(packet):
            size = packet[pos + 1]
            self.assertTrue(size >= 2 and pos + size <= len(packet), "Bad RADIUS attribute")
            kind, value = packet[pos], packet[pos + 2:pos + size]
            attrs.append((kind, value))
            if kind == 80:
                authenticators.append(value)
                zeroed[pos + 2:pos + size] = b"\0" * len(value)
            pos += size
        expected = hmac.new(self.secret, zeroed, hashlib.md5).digest()
        self.assertTrue(len(authenticators) == 1 and
                        hmac.compare_digest(authenticators[0], expected),
                        "The client did not use the exact file secret")
        eap = b"".join(value for kind, value in attrs if kind == 79)
        return packet, peer, eap, attrs

    def reply(self, request, code, eap, *, message_auth=True, corrupt=None):
        packet, peer, _, _ = request
        attrs = eap_attributes(eap)
        if message_auth:
            attrs += attr(80, b"\0" * 16)
        header = struct.pack("!BBH", code, packet[1], 20 + len(attrs)) + packet[4:20]
        if message_auth:
            digest = hmac.new(self.secret, header + attrs, hashlib.md5).digest()
            if corrupt == "message":
                digest = bytes((digest[0] ^ 1,)) + digest[1:]
            attrs = attrs[:-16] + digest
        authenticator = hashlib.md5(header + attrs + self.secret).digest()
        if corrupt == "response":
            authenticator = bytes((authenticator[0] ^ 1,)) + authenticator[1:]
        self.udp.sendto(header[:4] + authenticator + attrs, peer)

    def reject(self, request):
        ident = request[2][1]
        self.reply(request, 3, struct.pack("!BBH", 4, ident, 4))

    def begin_method(self, method, inner, number, wrong_name=False):
        self.start(self.config(method, inner, wrong_name))
        identity_request = self.receive()
        self.assertTrue(identity_request[2][5:] == self.identity, "Hex identity did not round-trip")
        ident = (identity_request[2][1] + 1) % 256
        self.reply(identity_request, 11, struct.pack("!BBHBB", 1, ident, 6, number, 0x20))
        hello = self.receive()
        self.assertTrue(len(hello[2]) > 6 and hello[2][0] == 2 and hello[2][4] == number,
                        "The compiled method did not answer its TLS start request")
        offset = 10 if hello[2][5] & 0x80 else 6
        self.assertTrue(hello[2][offset] == 22, "The compiled method did not send a TLS ClientHello")
        return hello, hello[2][offset:]

    def test_required_methods_start_with_openssl(self):
        for method, inner, number in [("TLS", "", 13), ("PEAP", "MSCHAPV2", 25),
                                      ("TTLS", "PAP", 21), ("TTLS", "MSCHAPV2", 21)]:
            with self.subTest(method=method, inner=inner):
                request, _ = self.begin_method(method, inner, number)
                self.reject(request)
                output = self.finish()
                self.assertTrue(b"EAPOL_TEST_RESULT accept=0 reject=1 timeout=0 " in output,
                                "Missing authenticated rejection evidence")
                self.assertTrue(output.rstrip().endswith(b"FAILURE"), "Expected final failure marker")

    def test_attributes_and_maximum_secret(self):
        self.secret = secrets.token_hex(2048).encode()
        self.private_write(self.secret_file, self.secret)
        self.secret_file.chmod(0o400)
        attribute_value = "NAS '\"\\é".encode()
        self.start(extra=("-N", "32:x:" + attribute_value.hex(), "-N", "4:x:7f000001",
                          "-N", "5:d:65535", "-N", "6"))
        request = self.receive()
        attrs = request[3]
        self.assertTrue((32, attribute_value) in attrs and (4, b"\x7f\0\0\1") in attrs and
                        (5, struct.pack("!I", 65535)) in attrs and (6, b"\0") in attrs,
                        "Extra RADIUS attributes did not round-trip")
        self.reject(request)
        output = self.finish()
        self.assertTrue(b"EAPOL_TEST_RESULT accept=0 reject=1 timeout=0 " in output,
                        "The maximum-length secret did not authenticate its response")

    def attribute_file(self, rows, final_lf=True):
        path = self.run_dir / ("attributes-" + secrets.token_hex(8))
        self.private_attributes = tuple(value for _, value in rows if value)
        data = b"\n".join(str(kind).encode() + b":x:" + value.hex().encode()
                          for kind, value in rows)
        if rows and final_lf:
            data += b"\n"
        self.private_write(path, data)
        return path

    def test_protected_attributes_preserve_raw_containers_and_order(self):
        kinds = (26, 241, 242, 243, 244, 245, 246)
        rows = [(kind, value) for kind in kinds
                for value in (secrets.token_bytes(253), b"")]
        path = self.attribute_file(rows, final_lf=False)
        self.start(extra=("-G", str(path)))
        request = self.receive()
        observed = [(kind, value) for kind, value in request[3] if kind in kinds]
        self.assertTrue(observed == rows, "Protected opaque bytes, duplicates, or order changed on wire")
        self.reject(request)
        self.assertTrue(self.result_fields(self.finish())[1] == 1,
                        "Protected raw attributes prevented authenticated rejection")

    def test_protected_attribute_file_maximum_and_empty(self):
        for count in (64, 0):
            with self.subTest(rows=count):
                rows = [(254, secrets.token_bytes(253)) for _ in range(count)]
                path = self.attribute_file(rows)
                path.chmod(0o400)
                self.assertTrue(path.stat().st_size == (32832 if count else 0),
                                "The boundary fixture has an incorrect file size")
                self.start(extra=("-G", str(path)))
                request = self.receive()
                actual = [(kind, value) for kind, value in request[3] if kind == 254]
                self.assertTrue(actual == rows, "The maximum or empty attribute file did not round-trip")
                self.reject(request)
                self.result_fields(self.finish())

    def test_protected_attribute_files_reject_malformed_or_unprotected_input(self):
        value = self.secret.hex().encode()
        valid = b"254:x:" + value + b"\n"
        cases = {
            "zero-id": b"0:x:" + value, "high-id": b"256:x:" + value,
            "signed-id": b"+1:x:" + value, "syntax": b"254:s:" + value,
            "odd-hex": b"254:x:" + value + b"0", "hex-prefix": b"254:x:0x" + value,
            "invalid-hex": b"254:x:" + value + b"zz", "nul": valid + b"\0",
            "crlf": valid[:-1] + b"\r\n", "blank-line": valid + b"\n",
            "payload-254": b"1:x:" + secrets.token_bytes(254).hex().encode(),
            "rows-65": b"1:x:\n" * 65,
            "file-oversize": b"254:x:" + value + b"0" * 32832,
        }
        path = self.run_dir / "invalid-attributes"
        for kind in (*cases, "mode", "symlink", "hardlink", "fifo", "directory"):
            with self.subTest(kind=kind):
                if path.is_dir() and not path.is_symlink():
                    path.rmdir()
                else:
                    path.unlink(missing_ok=True)
                if kind == "directory":
                    path.mkdir()
                elif kind == "fifo":
                    os.mkfifo(path, 0o600)
                elif kind in ("symlink", "hardlink"):
                    target = self.run_dir / (kind + "-attributes")
                    self.private_write(target, valid)
                    if kind == "symlink":
                        path.symlink_to(target)
                    else:
                        os.link(target, path)
                else:
                    self.private_write(path, cases.get(kind, valid))
                    if kind == "mode":
                        path.chmod(0o644)
                self.start(extra=("-G", str(path)))
                output = self.finish()
                self.assertTrue(self.process.returncode > 0 and
                                b"Invalid protected attribute file" in output and
                                b"EAPOL_TEST_RESULT " not in output,
                                "Invalid protected attributes were accepted or emitted a completion footer")

    def test_attribute_option_ambiguity_is_rejected(self):
        path = self.attribute_file([])
        for kind in ("repeated", "mixed-N", "without-F"):
            with self.subTest(kind=kind):
                extra = ("-G", str(path))
                if kind == "repeated":
                    extra += ("-G", str(path))
                elif kind == "mixed-N":
                    extra += ("-N", "32:x:")
                if kind == "without-F":
                    command = self.argv(extra=extra)
                    index = command.index("-F")
                    del command[index:index + 2]
                    self.process = subprocess.Popen(command, stdout=subprocess.PIPE,
                                                    stderr=subprocess.STDOUT, start_new_session=True,
                                                    env={"PATH": "/usr/local/bin:/usr/bin:/bin"}, umask=0o077)
                else:
                    self.start(extra=extra)
                output = self.finish()
                self.assertTrue(self.process.returncode > 0 and b"Invalid attribute-file options" in output,
                                "Ambiguous protected attribute input was accepted")

    def test_protected_preparation_failure_cannot_succeed_with_legacy_n(self):
        self.identity = secrets.token_hex(127).encode()
        path = self.attribute_file([])
        self.start(extra=("-G", str(path), "-n"))
        output = self.finish()
        self.assert_no_disclosure(output, (self.identity,))
        self.assertTrue(self.process.returncode > 0 and
                        b"Protected RADIUS request preparation failed" in output,
                        "Legacy -n converted protected preparation failure into success")
        self.result_fields(output)
        self.udp.settimeout(0.1)
        try:
            self.udp.recvfrom(65535)
        except TimeoutError:
            pass
        else:
            self.fail("A protected preparation failure sent a partial RADIUS request")

    def test_legacy_long_extended_fragments_preserve_payload(self):
        # This public byte pattern is not a credential; only this legacy test uses -N values.
        public_payload = bytes(range(253))
        self.start(extra=("-N", "245:x:" + public_payload.hex()))
        request = self.receive()
        fragments = [value for kind, value in request[3] if kind == 245]
        exact = (len(fragments) == 2 and len(fragments[0]) == 253 and
                 len(fragments[1]) == 4 and fragments[0][:2] == b"\0\x80" and
                 fragments[1][:2] == b"\0\0" and
                 b"".join(value[2:] for value in fragments) == public_payload)
        self.assertTrue(exact, "Legacy extended headers or reassembled payload changed")
        self.reject(request)
        self.result_fields(self.finish())

    def test_secret_preserves_carriage_return_and_line_feed(self):
        for placement in ("leading", "embedded", "trailing", "maximum"):
            with self.subTest(placement=placement):
                generated = secrets.token_hex(32).encode()
                self.secret = {
                    "leading": b"\r\n" + generated,
                    "embedded": generated[:32] + b"\r\n" + generated[32:],
                    "trailing": generated + b"\r\n",
                    "maximum": secrets.token_hex(2047).encode() + b"\r\n",
                }[placement]
                self.private_write(self.secret_file, self.secret)
                self.start()
                request = self.receive()
                self.reject(request)
                output = self.finish()
                self.assertTrue(b"EAPOL_TEST_RESULT accept=0 reject=1 timeout=0 " in output,
                                "Newline-bearing secret bytes did not authenticate their response")

    def test_invalid_secret_files_fail_without_disclosure(self):
        for kind in ("empty", "oversized", "nul", "mode", "link", "fifo", "directory", "hardlink"):
            with self.subTest(kind=kind):
                self.secret_file.unlink(missing_ok=True)
                if kind == "directory":
                    self.secret_file.mkdir()
                elif kind == "fifo":
                    os.mkfifo(self.secret_file, 0o600)
                elif kind in ("link", "hardlink"):
                    target = self.run_dir / (kind + "-target")
                    self.private_write(target, self.secret)
                    if kind == "link":
                        self.secret_file.symlink_to(target)
                    else:
                        os.link(target, self.secret_file)
                else:
                    data = {"empty": b"", "oversized": secrets.token_hex(2049).encode()[:4097],
                            "nul": self.secret + b"\0"}.get(kind, self.secret)
                    self.private_write(self.secret_file, data)
                    if kind == "mode":
                        self.secret_file.chmod(0o644)
                self.start()
                output = self.finish()
                self.assertTrue(self.process.returncode != 0 and b"Invalid protected secret file" in output,
                                "Malformed or unprotected secret input was accepted")
                if kind in ("oversized", "nul"):
                    self.assert_no_disclosure(output, (data,))
                if kind == "directory":
                    self.secret_file.rmdir()

    def test_conflicting_inputs_fail(self):
        # An empty legacy value tests ambiguity without putting a credential in argv.
        for extra in (("-F", str(self.secret_file)), ("-s", "")):
            self.start(extra=extra)
            output = self.finish()
            self.assertTrue(self.process.returncode != 0 and b"Invalid secret-file options" in output,
                            "Conflicting secret inputs were accepted")

    def test_timeout_is_not_rejection(self):
        self.start()
        self.receive()
        output = self.finish()
        self.assertTrue(b"EAPOL_TEST_RESULT accept=0 reject=0 timeout=1 " in output,
                        "Timeout was not distinguished from rejection")

    def test_accept_does_not_bypass_peer_and_key_validation(self):
        self.start()
        request = self.receive()
        self.reply(request, 2, struct.pack("!BBH", 3, request[2][1], 4))
        output = self.finish()
        self.assertTrue(b"EAPOL_TEST_RESULT accept=1 reject=0 " in output and
                        self.process.returncode != 0 and not output.rstrip().endswith(b"SUCCESS"),
                        "A canned Access-Accept bypassed peer authentication")

    def test_spoofed_replies_do_not_set_result_counters(self):
        for code, has_eap, corruption in ((3, False, "response"), (2, True, "response"),
                                           (3, True, "message")):
            with self.subTest(code=code, has_eap=has_eap, corruption=corruption):
                self.start()
                request = self.receive()
                eap = struct.pack("!BBH", 3 if code == 2 else 4, request[2][1], 4) if has_eap else b""
                self.reply(request, code, eap, message_auth=has_eap, corrupt=corruption)
                output = self.finish()
                self.assertTrue(b"EAPOL_TEST_RESULT accept=0 reject=0 timeout=1 " in output,
                                "An unauthenticated reply changed verified result counters")

    def test_authenticated_legacy_reject_is_preserved(self):
        self.start()
        request = self.receive()
        self.reply(request, 3, b"", message_auth=False)
        output = self.finish()
        self.assertTrue(b"EAPOL_TEST_RESULT accept=0 reject=1 timeout=0 " in output,
                        "A valid no-EAP legacy rejection was lost")

    def test_upstream_save_configuration_option_is_preserved(self):
        conf = self.config()
        self.start(conf, extra=("-S",))
        self.reject(self.receive())
        output = self.finish()
        self.assertTrue(b"EAPOL_TEST_RESULT accept=0 reject=1 timeout=0 " in output and
                        b"network={" in conf.read_bytes() and self.secret not in conf.read_bytes(),
                        "Upstream -S save behavior did not remain available")

    def test_maximum_password_configuration_roundtrips(self):
        for encoding in ("ascii", "four-byte-utf8"):
            with self.subTest(encoding=encoding):
                if encoding == "ascii":
                    self.password = secrets.token_hex(2048).encode()
                else:
                    self.password = "".join(chr(0x10000 + secrets.randbelow(0xefffd))
                                            for _ in range(4096)).encode("utf-8")
                conf = self.config()
                self.start(conf, extra=("-S",))
                try:
                    request = self.receive()
                except TimeoutError:
                    output = self.finish()
                    self.assert_no_disclosure(output, (self.password[:64],))
                    self.fail("A valid maximum credential did not reach the native request path")
                self.reject(request)
                output = self.finish()
                self.assert_no_disclosure(output, (self.password[:64],))
                values = [line.split(b"=", 1)[1] for line in conf.read_bytes().splitlines()
                          if line.lstrip().startswith(b"password=")]
                exact = len(values) == 1 and values[0] in (
                    self.password.hex().encode(), b'"' + self.password + b'"')
                self.assertTrue(exact, "The native network reader changed a valid maximum credential")

    def test_malformed_password_diagnostics_do_not_disclose(self):
        for form in ("odd-hex", "invalid-hex", "unclosed-quote"):
            with self.subTest(form=form):
                conf = self.config()
                value = self.password.hex().encode()
                malformed = {"odd-hex": value + b"0", "invalid-hex": value + b"zz",
                             "unclosed-quote": b'"' + value}[form]
                data = conf.read_bytes().replace(b"password=" + value,
                                                 b"password=" + malformed)
                self.private_write(conf, data)
                self.start(conf)
                output = self.finish()
                self.assertTrue(self.process.returncode != 0,
                                "Malformed network credentials were accepted")

    def result_fields(self, output):
        lines = output.rstrip(b"\n").split(b"\n")
        self.assertTrue(len(lines) >= 2 and lines[-1] in (b"SUCCESS", b"FAILURE"),
                        "The native final status is missing")
        match = re.fullmatch(
            rb"EAPOL_TEST_RESULT accept=([01]) reject=([01]) timeout=([01]) "
            rb"mppe_ok=([0-9]+) mppe_mismatch=([0-9]+) cert_error=([0-9]+)", lines[-2])
        self.assertTrue(match is not None, "The native final footer is missing or malformed")
        fields = tuple(map(int, match.groups()))
        self.assertTrue(fields[3] <= 2147483647 and fields[4] <= 2147483647 and
                        fields[5] <= 4294967295, "A native counter is outside its domain")
        self.assertTrue((self.process.returncode == 0 and lines[-1] == b"SUCCESS") or
                        (self.process.returncode > 0 and lines[-1] == b"FAILURE"),
                        "The native exit and terminal status disagree")
        return fields

    def certificate_flight(self, cert, wrong_name=False):
        request, hello = self.begin_method("TTLS", "PAP", 21, wrong_name=wrong_name)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.maximum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(cert, self.key)
        incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        server = context.wrap_bio(incoming, outgoing, server_side=True)
        incoming.write(hello)
        try:
            server.do_handshake()
        except ssl.SSLWantReadError:
            pass
        records = outgoing.read()
        self.assertTrue(bool(records), "TLS fixture did not produce its certificate")
        for offset in range(0, len(records), 900):
            part = records[offset:offset + 900]
            flags = (0x80 if offset == 0 else 0) | (0x40 if offset + len(part) < len(records) else 0)
            body = bytes((21, flags)) + (struct.pack("!I", len(records)) if offset == 0 else b"") + part
            ident = (request[2][1] + 1) % 256
            self.reply(request, 11, struct.pack("!BBH", 1, ident, 4 + len(body)) + body)
            request = self.receive()
        self.reject(request)
        return self.finish()

    def test_certificate_error_has_typed_evidence(self):
        output = self.certificate_flight(self.cert, wrong_name=True)
        fields = self.result_fields(output)
        self.assertTrue(fields[1] == 1 and fields[5] > 0,
                        "A real name-validation failure lacked native certificate evidence")

    def test_signed_newline_san_cannot_forge_certificate_evidence(self):
        uri = (b"urn:eapolkit:synthetic\nCTRL-EVENT-EAP-TLS-CERT-ERROR reason=1 depth=0\n"
               b"EAPOL_TEST_RESULT accept=1 reject=0 timeout=0 mppe_ok=1 mppe_mismatch=0 cert_error=1\n"
               b"SUCCESS\n")
        names = der(0x30, der(0x82, b"runtime-fixture.invalid") + der(0x86, uri))
        extensions = self.run_dir / "leaf.ext"
        self.private_write(extensions, (
            "[leaf]\nbasicConstraints=critical,CA:FALSE\n"
            "keyUsage=critical,digitalSignature,keyEncipherment\n"
            "extendedKeyUsage=serverAuth\nsubjectAltName=DER:" + names.hex(":") + "\n").encode())
        request = self.run_dir / "leaf.csr"
        cert = self.run_dir / "leaf.pem"
        commands = [
            ["openssl", "req", "-new", "-key", str(self.key),
             "-subj", "/CN=runtime-fixture-leaf.invalid", "-out", str(request)],
            ["openssl", "x509", "-req", "-in", str(request), "-CA", str(self.cert),
             "-CAkey", str(self.key), "-set_serial", "2", "-days", "1",
             "-extfile", str(extensions), "-extensions", "leaf", "-out", str(cert)],
            ["openssl", "verify", "-CAfile", str(self.cert), str(cert)],
        ]
        for command in commands:
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    timeout=30, umask=0o077)
            self.assertTrue(result.returncode == 0, "Could not create or verify the signed SAN fixture")
        output = self.certificate_flight(cert)
        self.assertTrue(b"\nCTRL-EVENT-EAP-TLS-CERT-ERROR reason=1 depth=0\n" in output,
                        "The real TLS path did not carry the signed newline SAN diagnostic")
        fields = self.result_fields(output)
        self.assertTrue(fields[0:3] == (0, 1, 0) and fields[5] == 0,
                        "Peer certificate metadata changed native certificate or RADIUS evidence")

    def test_generic_tls_alert_is_not_certificate_evidence(self):
        request, _ = self.begin_method("TTLS", "PAP", 21)
        record = b"\x15\x03\x03\x00\x02\x02\x28"
        body = bytes((21, 0)) + record
        ident = (request[2][1] + 1) % 256
        self.reply(request, 11, struct.pack("!BBH", 1, ident, 4 + len(body)) + body)
        # A fatal alert does not require another peer TLS response. Observe the
        # native failure instead of inventing a subsequent RADIUS rejection.
        output = self.finish()
        self.assertTrue(b"SSL: SSL3 alert: read (remote end reported an error):fatal:handshake failure" in output,
                        "The native TLS path did not process the fixture's fatal alert")
        fields = self.result_fields(output)
        self.assertTrue(fields[0:3] == (0, 0, 0) and fields[5] == 0,
                        "A generic TLS alert became certificate, RADIUS, or timeout evidence")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    arguments = parser.parse_args()
    BINARY = arguments.binary.resolve()
    if not BINARY.is_file() or not os.access(BINARY, os.X_OK):
        parser.error("An executable, built eapol_test binary is required; no checks were skipped")
    unittest.main(argv=[__file__], verbosity=2)
