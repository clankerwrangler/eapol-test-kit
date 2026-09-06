"""Optional browser-to-real-backend test with no RADIUS infrastructure.

Set EAPOLKIT_UI_BACKEND_PYTHON to a Python executable with this project's backend
requirements and Uvicorn. The test owns its localhost server, temporary data,
reserved socket, and browser. The runner path is deliberately absent; this is
not evidence of a successful RADIUS authentication.
"""
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import secrets
import socket
import subprocess
import tempfile
import time
import unittest
from urllib.request import urlopen

try:
    from playwright.sync_api import sync_playwright, expect
except ImportError:
    sync_playwright = None

ROOT = Path(__file__).resolve().parents[2]


@unittest.skipUnless(sync_playwright and os.environ.get("EAPOLKIT_UI_BACKEND_PYTHON"),
                     "Set EAPOLKIT_UI_BACKEND_PYTHON to run the real-backend browser test")
class BackendBrowserCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.process = cls.browser = cls.playwright = cls.socket = cls.temporary = None
        try:
            cls.temporary = tempfile.TemporaryDirectory(prefix="eapolkit-browser-")
            directory = Path(cls.temporary.name)
            cls.socket = socket.socket()
            cls.socket.bind(("127.0.0.1", 0))
            cls.socket.listen()
            cls.url = f"http://127.0.0.1:{cls.socket.getsockname()[1]}"
            env = dict(os.environ, PYTHONPATH=str(ROOT / "src"), EAPOLKIT_DATA_DIR=str(directory / "data"),
                       EAPOLKIT_BINARY=str(directory / "absent-eapol-test"), EAPOLKIT_ALLOWED_HOSTS="127.0.0.1",
                       EAPOLKIT_SECURE_COOKIES="0")
            cls.process = subprocess.Popen([os.environ["EAPOLKIT_UI_BACKEND_PYTHON"], "-m", "uvicorn",
                "eapolkit.app:app", "--fd", str(cls.socket.fileno()), "--no-access-log", "--log-level", "warning"],
                cwd=ROOT, env=env, pass_fds=(cls.socket.fileno(),), stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL)
            cls.socket.close()
            cls.socket = None
            for _ in range(100):
                if cls.process.poll() is not None:
                    raise RuntimeError("The owned backend test process exited before becoming ready")
                try:
                    with urlopen(cls.url + "/api/session", timeout=.2) as response:
                        if response.status == 200:
                            break
                except OSError:
                    time.sleep(.1)
            else:
                raise RuntimeError("The owned backend test process did not become ready")
            cls.playwright = sync_playwright().start()
            cls.browser = cls.playwright.chromium.launch(headless=True,
                executable_path=os.environ.get("EAPOLKIT_UI_BROWSER") or None)
        except BaseException:
            cls.cleanup()
            raise

    @classmethod
    def cleanup(cls):
        if cls.browser:
            cls.browser.close()
        if cls.playwright:
            cls.playwright.stop()
        if cls.process:
            cls.process.terminate()
            try:
                cls.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                cls.process.kill()
                cls.process.wait(timeout=5)
        if cls.socket:
            cls.socket.close()
        if cls.temporary:
            cls.temporary.cleanup()

    @classmethod
    def tearDownClass(cls):
        cls.cleanup()


class BackendBrowserTests(BackendBrowserCase):
    def test_real_auth_profiles_certificates_and_protected_downloads(self):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.serialization.pkcs12 import load_key_and_certificates
        from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

        context = self.browser.new_context(viewport={"width": 1440, "height": 1000}, accept_downloads=True)
        self.addCleanup(context.close)
        page = context.new_page()
        errors = []
        page.on("pageerror", lambda error: errors.append(str(error)))
        password = secrets.token_urlsafe(24)
        page.goto(self.url)
        page.locator("#auth-password").fill(password)
        page.locator("#auth-confirm").fill(password)
        page.locator("#auth-submit").click()
        expect(page.locator("#app-view")).to_be_visible()
        expect(page.locator("#loading")).to_be_hidden()
        expect(page.locator("#global-error")).to_be_hidden()
        expect(page.locator("#service-status")).to_have_text("Runner unavailable")
        self.assertTrue(any(cookie["httpOnly"] and cookie["sameSite"] == "Strict" for cookie in context.cookies()))

        page.locator('[data-page="targets"]').click()
        page.locator("#new-target").click()
        page.locator("#target-name").fill("Browser test target")
        page.locator("#target-host").fill("192.0.2.42")
        shared_secret = secrets.token_urlsafe(30)
        page.locator("#target-secret").fill(shared_secret)
        page.get_by_role("button", name="Save target", exact=True).click()
        expect(page.locator("#target-dialog")).to_be_hidden()
        page.locator("#target-list").get_by_role("button", name="Edit", exact=True).click()
        expect(page.locator("#target-secret")).to_have_value("")
        page.get_by_role("button", name="Save target", exact=True).click()
        expect(page.locator("#target-dialog")).to_be_hidden()
        expect(page.locator("#target-list")).to_contain_text("Secret saved")

        page.locator('[data-page="certificates"]').click()
        for kind, name in (("ca", "Browser test issuer"), ("client", "Browser test client"), ("csr", "Browser test enrollment")):
            page.locator("#generate-certificate").click()
            page.locator("#generate-kind").select_option(kind)
            page.locator("#generate-name").fill(name)
            page.locator("#generate-cn").fill(name)
            page.locator("#generate-key-type").select_option("ec-p256")
            if kind == "client":
                page.locator("#generate-issuer").select_option(label="Browser test issuer")
            page.locator('#generate-form button[type="submit"]').click()
            expect(page.locator("#generate-dialog")).to_be_hidden()

        issuer = page.locator("#certificate-list article").filter(has=page.get_by_role("heading", name="Browser test issuer", exact=True))
        with page.expect_download() as public_ca:
            issuer.get_by_role("button", name="Download public CA").click()
        page.locator("#import-certificate").click()
        page.locator("#import-name").fill("Browser test server trust")
        page.locator("#import-cert-file").set_input_files(public_ca.value.path())
        page.get_by_role("button", name="Import certificate", exact=True).click()
        expect(page.locator("#import-dialog")).to_be_hidden()

        enrollment = page.locator("#certificate-list article").filter(has=page.get_by_role("heading", name="Browser test enrollment", exact=True))
        with page.expect_download() as csr_download:
            enrollment.get_by_role("button", name="Download public CSR").click()
        csr = x509.load_pem_x509_csr(Path(csr_download.value.path()).read_bytes())
        signing_key = ec.generate_private_key(ec.SECP256R1())
        now = datetime.now(timezone.utc)
        signed = (x509.CertificateBuilder().subject_name(csr.subject)
            .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Ephemeral browser test issuer")]))
            .public_key(csr.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
            .sign(signing_key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM))
        enrollment.get_by_role("button", name="Complete CSR").click()
        page.locator("#complete-certificate").set_input_files(dict(name="issued.pem", mimeType="application/x-pem-file", buffer=signed))
        page.locator('#complete-form button[type="submit"]').click()
        expect(page.locator("#complete-dialog")).to_be_hidden()
        expect(enrollment).to_contain_text("Client identity")

        client = page.locator("#certificate-list article").filter(has=page.get_by_role("heading", name="Browser test client", exact=True))
        client.get_by_role("button", name="Export protected PFX…").click()
        export_passphrase = secrets.token_urlsafe(24)
        page.locator("#pfx-passphrase").fill(export_passphrase)
        page.locator("#pfx-confirm-passphrase").fill(export_passphrase)
        page.locator("#pfx-confirm").check()
        with page.expect_download() as private_download:
            page.get_by_role("button", name="Export protected PFX", exact=True).click()
        key, cert, chain = load_key_and_certificates(Path(private_download.value.path()).read_bytes(), export_passphrase.encode())
        self.assertIsNotNone(key)
        self.assertEqual(cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value, "Browser test client")
        self.assertTrue(chain)
        expect(page.locator("#pfx-passphrase")).to_have_value("")

        page.locator('[data-page="profiles"]').click()
        page.locator(".preset-card").nth(2).click()
        page.locator("#profile-name").fill("Browser test TTLS")
        page.locator("#profile-identity").fill("browser@example.net")
        page.locator("#profile-password").fill(password)
        page.locator("#profile-ca").select_option(label="Browser test server trust")
        page.locator("#profile-server").fill("radius.example.net")
        page.get_by_role("button", name="Save & preview", exact=True).click()
        expect(page.locator("#preview-text")).to_contain_text("network={")
        self.assertNotIn(password, page.locator("#preview-text").inner_text())
        self.assertNotIn(shared_secret, page.locator("body").inner_text())
        page.keyboard.press("Escape")
        page.locator("#profile-list").get_by_role("button", name="Negative-test copy").click()
        page.locator("#duplicate-expectation").select_option("reject")
        page.get_by_role("button", name="Create copy & edit").click()
        expect(page.locator("#profile-password-hint")).to_contain_text("A password is saved")
        expect(page.locator("#profile-password")).to_have_value("")
        page.get_by_role("button", name="Save profile", exact=True).click()
        expect(page.locator("#profile-dialog")).to_be_hidden()
        expect(page.locator("#global-error")).to_be_hidden()
        page.locator('[data-page="workbench"]').click()
        expect(page.locator("#start-run")).to_be_disabled()
        page.locator("#logout").click()
        expect(page.locator("#auth-view")).to_be_visible()
        page.locator("#auth-password").fill(password)
        page.locator("#auth-submit").click()
        expect(page.locator("#app-view")).to_be_visible()
        self.assertFalse(errors)
        self.assertEqual(page.evaluate("localStorage.length + sessionStorage.length"), 0)



class AttributeBackendBrowserTests(BackendBrowserCase):
    def test_private_attribute_round_trip_without_radius(self):
        context = self.browser.new_context(viewport={"width": 1440, "height": 1000})
        self.addCleanup(context.close)
        page = context.new_page()
        errors = []
        page.on("pageerror", lambda _error: errors.append("page error"))
        password = secrets.token_urlsafe(24)
        private_value = "00000137" + secrets.token_hex(12)
        public_replacement = "00000137" + secrets.token_hex(12)
        page.goto(self.url)
        page.locator("#auth-password").fill(password)
        page.locator("#auth-confirm").fill(password)
        page.locator("#auth-submit").click()
        expect(page.locator("#app-view")).to_be_visible()
        expect(page.locator("#loading")).to_be_hidden()
        expect(page.locator("#service-status")).to_have_text("Runner unavailable")
        page.locator('[data-page="targets"]').click()
        page.locator("#new-target").click()
        page.locator("#target-name").fill("Attribute browser round trip")
        page.locator("#target-host").fill("192.0.2.42")
        page.locator("#target-secret").fill(secrets.token_urlsafe(30))
        page.locator("#target-form summary").click()
        for identifier, encoding, sensitivity, value in ((18, "string", "public", "Visible lab attribute"), (26, "hex", "private", private_value), (19, "string", "private", "")):
            page.locator("#add-attribute").click()
            row = page.locator(".attribute-row").last
            row.locator('[data-attribute="id"]').fill(str(identifier))
            row.locator('[data-attribute="type"]').select_option(encoding)
            row.locator('[data-attribute="sensitivity"]').select_option(sensitivity)
            if sensitivity == "private":
                row.locator('[data-attribute="replace"]').check()
            row.locator('[data-attribute="value"]').fill(value)
        page.get_by_role("button", name="Save target", exact=True).click()
        expect(page.locator("#target-dialog")).to_be_hidden()
        response = context.request.get(self.url + "/api/targets")
        self.assertEqual(response.status, 200)
        target = response.json()[0]
        original_keys = [row["key"] for row in target["extra_attributes"]]
        self.assertEqual(len(set(original_keys)), 3)
        self.assertTrue(all(row["has_value"] for row in target["extra_attributes"]))
        self.assertEqual(target["extra_attributes"][0]["value"], "Visible lab attribute")
        self.assertTrue(all("value" not in row for row in target["extra_attributes"][1:]))
        self.assertTrue(private_value not in response.text(), "The API exposed a private attribute")

        page.locator("#target-list").get_by_role("button", name="Edit", exact=True).click()
        page.locator("#target-name").fill("Renamed without replacing values")
        with page.expect_request(lambda request: request.method == "PUT" and request.url.endswith("/api/targets/" + target["id"])) as edited:
            page.get_by_role("button", name="Save target", exact=True).click()
        expect(page.locator("#target-dialog")).to_be_hidden()
        payload = edited.value.post_data_json
        self.assertNotIn("secret", payload)
        self.assertEqual([row["key"] for row in payload["extra_attributes"]], original_keys)
        self.assertTrue(all("value" not in row and "has_value" not in row for row in payload["extra_attributes"]))
        updated = context.request.get(self.url + "/api/targets").json()[0]
        self.assertEqual([row["key"] for row in updated["extra_attributes"]], original_keys)
        self.assertTrue(all(row["has_value"] for row in updated["extra_attributes"]))

        page.locator("#target-list").get_by_role("button", name="Edit", exact=True).click()
        page.locator("#target-form summary").click()
        row = page.locator(".attribute-row").nth(1)
        expect(row.locator('[data-attribute="value"]')).to_have_value("")
        expect(row).to_contain_text("Saved private value — hidden")
        row.locator('[data-attribute="sensitivity"]').select_option("public")
        row.locator('[data-attribute="replace"]').check()
        row.locator('[data-attribute="value"]').fill(public_replacement)
        row.locator('[data-attribute="confirm-public"]').check()
        page.get_by_role("button", name="Save target", exact=True).click()
        expect(page.locator("#target-dialog")).to_be_hidden()
        promoted = context.request.get(self.url + "/api/targets").json()[0]["extra_attributes"][1]
        self.assertTrue(promoted["value"] == public_replacement)
        self.assertEqual(promoted["sensitivity"], "public")
        self.assertEqual(promoted["key"], original_keys[1])

        page.locator("#target-list").get_by_role("button", name="Edit", exact=True).click()
        page.get_by_role("button", name="Save target", exact=True).click()
        expect(page.locator("#target-dialog")).to_be_hidden()
        unchanged = context.request.get(self.url + "/api/targets").json()[0]["extra_attributes"][1]
        self.assertTrue(unchanged["value"] == public_replacement)
        self.assertEqual(unchanged["sensitivity"], "public")

        page.locator("#target-list").get_by_role("button", name="Edit", exact=True).click()
        page.locator("#target-form summary").click()
        row = page.locator(".attribute-row").nth(1)
        row.locator('[data-attribute="id"]').fill("242")
        expect(row.locator('[data-attribute="sensitivity"]')).to_have_value("private")
        row.locator('[data-attribute="replace"]').check()
        row.locator('[data-attribute="value"]').fill("01020304")
        page.get_by_role("button", name="Save target", exact=True).click()
        expect(page.locator("#target-dialog")).to_be_hidden()
        reclassified = context.request.get(self.url + "/api/targets").json()[0]["extra_attributes"][1]
        self.assertEqual(reclassified["id"], 242)
        self.assertEqual(reclassified["sensitivity"], "private")
        self.assertNotIn("value", reclassified)
        self.assertTrue(reclassified["has_value"])
        self.assertFalse(errors)
        self.assertEqual(context.request.get(self.url + "/api/runs").json(), [])
        self.assertEqual(page.evaluate("localStorage.length + sessionStorage.length"), 0)

if __name__ == "__main__":
    unittest.main()
