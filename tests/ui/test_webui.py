"""Browser-only UI contract tests with an in-process static server and mock API.

Run with: python -m unittest discover -s tests/ui -v
Install Playwright and its Chromium browser in the test environment first.
Set EAPOLKIT_UI_BROWSER to use an existing Chromium executable.
Set EAPOLKIT_UI_SCREENSHOTS to a scratch directory to retain fixture screenshots.
These tests do not claim that a RADIUS authentication or certificate operation succeeded.
"""
from __future__ import annotations

import copy
from email import policy
from email.parser import BytesParser
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import secrets
import threading
import unittest
from urllib.parse import parse_qs, urlsplit

try:
    from playwright.sync_api import sync_playwright, expect
except ImportError:
    sync_playwright = None

STATIC = Path(__file__).resolve().parents[2] / "src/eapolkit/static"
METHODS = ["eap-tls", "peap-mschapv2", "ttls-pap", "ttls-mschapv2"]
XSS = '<img src=x onerror="window.uiInjection=true">'


def profile(identifier="profile-1", method="peap-mschapv2"):
    return dict(id=identifier, name="Office acceptance", method=method,
                identity="operator@example.net", anonymous_identity="anonymous@example.net",
                ca_certificate_id="trust-1", client_identity_id=None,
                server_name="radius.example.net", tls_min_version="1.2", tls_max_version="auto",
                fragment_size=1398, expected_outcome="accept",
                allow_expired_client_certificate=False, has_password=True)


def certificate(identifier="trust-1", kind="trust", name="RADIUS server CA"):
    return dict(id=identifier, name=name, kind=kind, subject="CN=" + name,
                issuer="CN=Lab issuing authority", not_before="2026-01-01T00:00:00Z",
                not_after="2030-01-01T00:00:00Z", fingerprint_sha256="ab:" * 31 + "ab",
                san_dns=["client.example.net"], san_email=["operator@example.net"],
                san_uri=["urn:eapolkit:fixture"], eku=["clientAuth"],
                has_private_key=kind != "trust", warnings=[])


class MockAPI:
    def __init__(self, authenticated=True):
        self.authenticated = authenticated
        self.setup_required = not authenticated
        self.csrf = secrets.token_urlsafe(24)
        self.password = secrets.token_urlsafe(20)
        self.writes = []
        self.bad_headers = []
        self.urls = []
        self.targets = [dict(id="target-1", name="Lab RADIUS", host="radius.example.net",
                             port=1812, timeout_seconds=30, nas_identifier="eapol-test-kit",
                             nas_ip_address=None, calling_station_id="02:00:00:00:00:01",
                             extra_attributes=[], has_secret=True)]
        self.profiles = [profile()]
        self.certificates = [certificate(), certificate("ca-1", "ca", "Kit client issuer"),
                             certificate("identity-1", "identity", "Lab client"),
                             certificate("csr-1", "csr", "Pending enrollment")]
        self.presets = []
        for method in METHODS:
            preset = profile(method=method)
            preset.pop("id")
            preset.update(name=method, identity="", anonymous_identity=None,
                          ca_certificate_id=None, client_identity_id=None, server_name="",
                          has_password=False)
            self.presets.append(preset)
        self.runs = []
        self.run_reads = 0
        self.fail_next_write = False
        self.attribute_values = {}
        self.next_attribute = 1

    def session(self):
        return dict(setup_required=self.setup_required, authenticated=self.authenticated,
                    csrf_token=self.csrf if self.authenticated else None)

    def body(self, request):
        if "multipart/form-data" not in request.headers.get("content-type", ""):
            return request.post_data_json if request.post_data else {}
        data = ("Content-Type: " + request.headers["content-type"] + "\r\n\r\n").encode()
        message = BytesParser(policy=policy.default).parsebytes(data + request.post_data_buffer)
        return {part.get_param("name", header="content-disposition"):
                part.get_payload(decode=True).decode("utf-8", errors="replace")
                for part in message.iter_parts()}

    def save_attributes(self, rows, original):
        old_rows = {row["key"]: row for row in original}
        result = []
        for row in rows:
            if set(row) - {"key", "id", "type", "sensitivity", "value"}:
                raise ValueError("Invalid fixture attribute fields")
            key = row.get("key")
            if key is None:
                key = "attribute-" + str(self.next_attribute)
                self.next_attribute += 1
            elif key not in old_rows:
                raise ValueError("Unknown fixture attribute key")
            previous = old_rows.get(key, {})
            if "value" in row:
                supplied = row["value"]
            elif key in self.attribute_values:
                supplied = self.attribute_values[key]
            else:
                supplied = previous["value"]
            self.attribute_values[key] = supplied
            sensitivity = row.get("sensitivity", previous.get("sensitivity", "private" if row["id"] == 26 or 241 <= row["id"] <= 246 else "public"))
            saved = {"key": key, "id": row["id"], "type": row["type"], "sensitivity": sensitivity, "has_value": True}
            if sensitivity == "public":
                saved["value"] = supplied
            result.append(saved)
        return result

    def handle(self, route):
        request = route.request
        url = urlsplit(request.url)
        endpoint = url.path
        method = request.method
        self.urls.append(request.url)
        body = {}
        if method != "GET":
            body = self.body(request)
            self.writes.append((method, endpoint, body))
            if request.headers.get("x-eapolkit-request") != "1":
                self.bad_headers.append("missing request marker")
            if self.authenticated and endpoint not in ("/api/login", "/api/setup"):
                if request.headers.get("x-csrf-token") != self.csrf:
                    self.bad_headers.append("missing CSRF")
            if self.fail_next_write:
                self.fail_next_write = False
                return route.fulfill(status=422, json={"detail": "Fixture validation failure " + XSS})
        if endpoint == "/api/session":
            return route.fulfill(content_type="application/json", json=self.session())
        if endpoint in ("/api/setup", "/api/login"):
            if body.get("password") != self.password:
                return route.fulfill(status=401, json={"detail": "Incorrect password"})
            self.authenticated = True
            self.setup_required = False
            return route.fulfill(content_type="application/json", json=self.session())
        if endpoint == "/api/logout":
            self.authenticated = False
            return route.fulfill(status=204)
        if not self.authenticated:
            return route.fulfill(status=401, json={"detail": "Authentication required"})
        if endpoint == "/api/status":
            active = next((run["id"] for run in self.runs if run["status"] == "running"), None)
            return route.fulfill(content_type="application/json", json=dict(version="0.1.0-fixture", eapol_test_available=True,
                                           active_run_id=active))
        if endpoint == "/api/presets":
            return route.fulfill(content_type="application/json", json=self.presets)
        if endpoint.endswith("/duplicate"):
            original = next(item for item in self.profiles if item["id"] == endpoint.split("/")[3])
            saved = copy.deepcopy(original)
            saved.update(body)
            saved["id"] = "profile-" + str(len(self.profiles) + 1)
            self.profiles.append(saved)
            return route.fulfill(content_type="application/json", json=saved)
        if endpoint.endswith("/preview"):
            return route.fulfill(content_type="application/json", json=dict(configuration='network={\n  password="[REDACTED]"\n  # ' + XSS + '\n}', warnings=["Fixture preview; server CA verification stays enabled."]))
        if endpoint.endswith("/export-pfx"):
            return route.fulfill(body=b"fixture-only-protected-pfx", content_type="application/x-pkcs12")
        if endpoint.endswith("/download"):
            return route.fulfill(body=b"fixture-only-public-material", content_type="application/x-pem-file")
        if endpoint == "/api/certificates/import" or "/generate-" in endpoint:
            kind = body.get("kind", {"generate-ca": "ca", "generate-client": "identity", "generate-csr": "csr"}.get(endpoint.split("/")[-1], "trust"))
            saved = certificate("certificate-" + str(len(self.certificates) + 1), kind, body["name"])
            self.certificates.append(saved)
            return route.fulfill(content_type="application/json", json=saved)
        if endpoint.endswith("/complete"):
            saved = next(item for item in self.certificates if item["id"] == endpoint.split("/")[3])
            saved["kind"] = "identity"
            return route.fulfill(content_type="application/json", json=saved)
        if endpoint.startswith("/api/runs/"):
            saved = next(item for item in self.runs if item["id"] == endpoint.split("/")[3])
            if endpoint.endswith("/cancel"):
                saved.update(status="cancelled", outcome="cancelled", verdict="inconclusive",
                             summary="The owned run was cancelled.", finished_at="2026-09-06T12:00:03Z",
                             duration_seconds=3, exit_code=-15)
                return route.fulfill(content_type="application/json", json=saved)
            if endpoint.endswith("/export"):
                return route.fulfill(content_type="application/json", json={**saved, "snapshot": self.snapshot(), "log_lines": []})
            if method == "DELETE":
                self.runs.remove(saved)
                return route.fulfill(status=204)
            self.run_reads += 1
            after = int(parse_qs(url.query).get("after", ["0"])[0])
            end = 900 if self.run_reads == 1 else 1700
            logs = [dict(seq=i, line=f"Sanitized fixture output {i}: " + (XSS if i == 1700 else "authentication in progress")) for i in range(after + 1, end + 1)]
            return route.fulfill(content_type="application/json", json={**saved, "snapshot": self.snapshot(), "log_lines": logs,
                                       "next_seq": end, "truncated": False})
        if endpoint == "/api/runs":
            if method == "GET":
                return route.fulfill(content_type="application/json", json=self.runs)
            saved = dict(id="run-1", target_id=body["target_id"], profile_id=body["profile_id"],
                         target_name=self.targets[0]["name"], profile_name=self.profiles[0]["name"],
                         status="running", outcome=None, verdict=None,
                         expected_outcome=body.get("expected_outcome", "accept"),
                         summary="Waiting for observed authentication evidence.",
                         created_at="2026-09-06T12:00:00Z", started_at="2026-09-06T12:00:00Z",
                         finished_at=None, duration_seconds=None, exit_code=None,
                         radius_response=None, peer_success=None, mppe_keys_match=None,
                         returned_attributes=[])
            self.runs.append(saved)
            return route.fulfill(content_type="application/json", json=saved)
        for collection in ("targets", "profiles", "certificates"):
            base = "/api/" + collection
            if endpoint == base or endpoint.startswith(base + "/"):
                items = getattr(self, collection)
                if method == "GET":
                    return route.fulfill(content_type="application/json", json=items)
                previous_attributes = []
                if method == "POST":
                    saved = {**body, "id": collection[:-1] + "-" + str(len(items) + 1)}
                    items.append(saved)
                else:
                    saved = next(item for item in items if item["id"] == endpoint.split("/")[-1])
                    if method == "DELETE":
                        items.remove(saved)
                        return route.fulfill(status=204)
                    previous_attributes = saved.get("extra_attributes", [])
                    saved.update(body)
                if collection == "targets" and "extra_attributes" in body:
                    saved["extra_attributes"] = self.save_attributes(body["extra_attributes"], previous_attributes)
                for secret, flag in (("password", "has_password"), ("secret", "has_secret")):
                    if secret in saved:
                        saved.pop(secret)
                        saved[flag] = True
                return route.fulfill(content_type="application/json", json=saved)
        route.fulfill(status=404, json={"detail": "Unimplemented fixture route"})

    def snapshot(self):
        return dict(target={key: value for key, value in self.targets[0].items() if key != "has_secret"},
                    profile={key: value for key, value in self.profiles[0].items() if key != "has_password"},
                    configuration="network={ # redacted fixture }")


class StaticHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/":
            self.path = "/index.html"
        elif self.path.startswith("/static/"):
            self.path = self.path[len("/static"):]
        super().do_GET()

    def end_headers(self):
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
        super().end_headers()

    def log_message(self, *_args):
        pass


@unittest.skipUnless(sync_playwright is not None, "Playwright is not installed; UI browser tests were not run")
class WebUITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.playwright = sync_playwright().start()
        try:
            cls.browser = cls.playwright.chromium.launch(headless=True,
                executable_path=os.environ.get("EAPOLKIT_UI_BROWSER") or None)
        except Exception as error:
            cls.playwright.stop()
            raise unittest.SkipTest("Chromium is unavailable; UI browser tests were not run: " + str(error).splitlines()[0]) from error
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), partial(StaticHandler, directory=str(STATIC)))
        cls.thread = threading.Thread(target=cls.server.serve_forever)
        cls.thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)
        cls.browser.close()
        cls.playwright.stop()

    def setUp(self):
        self.context = self.browser.new_context(viewport={"width": 1440, "height": 1000}, accept_downloads=True)
        self.page = self.context.new_page()
        self.errors = []
        self.console = []
        self.page.on("pageerror", lambda error: self.errors.append(str(error)))
        self.page.on("console", lambda message: self.console.append(message.text))
        self.mock = MockAPI()
        self.page.route("**/api/**", self.mock.handle)

    def tearDown(self):
        self.assertFalse(self.errors, "Browser JavaScript errors occurred")
        self.assertFalse(self.mock.bad_headers, "A mutation omitted required headers")
        self.assertFalse(self.page.evaluate("Boolean(window.uiInjection)"), "Untrusted content executed")
        self.assertEqual(self.page.evaluate("localStorage.length + sessionStorage.length"), 0)
        self.assertTrue(all(self.mock.password not in value for value in self.mock.urls + self.console))
        self.context.close()

    def open(self):
        self.page.goto(self.base_url)
        expect(self.page.locator("#app-view")).to_be_visible()
        expect(self.page.locator("#loading")).to_be_hidden()
        expect(self.page.locator("#global-error")).to_be_hidden()

    def nav(self, name):
        self.page.locator(f'[data-page="{name}"]').click()

    def screenshot(self, name):
        directory = os.environ.get("EAPOLKIT_UI_SCREENSHOTS")
        if directory:
            output = Path(directory)
            output.mkdir(parents=True, exist_ok=True)
            self.page.screenshot(path=str(output / name), full_page=True)

    def test_setup_login_and_password_clearing(self):
        self.mock.authenticated = False
        self.mock.setup_required = True
        self.page.goto(self.base_url)
        expect(self.page.locator("#auth-title")).to_have_text("Make this workspace yours")
        self.screenshot("setup-desktop.png")
        self.page.locator("#auth-password").fill(self.mock.password)
        self.page.locator("#auth-confirm").fill(self.mock.password)
        self.page.locator("#auth-submit").click()
        expect(self.page.locator("#app-view")).to_be_visible()
        expect(self.page.locator("#auth-password")).to_have_value("")
        expect(self.page.locator("#auth-confirm")).to_have_value("")
        self.page.locator("#logout").click()
        expect(self.page.locator("#auth-view")).to_be_visible()
        expect(self.page.locator("#auth-confirm-field")).to_be_hidden()
        self.page.locator("#auth-password").fill(secrets.token_urlsafe(20))
        self.page.locator("#auth-submit").click()
        expect(self.page.locator("#auth-form .form-error")).to_have_text("Incorrect password")
        expect(self.page.locator("#auth-password")).to_have_value("")
        self.page.locator("#auth-password").fill(self.mock.password)
        self.page.locator("#auth-submit").click()
        expect(self.page.locator("#app-view")).to_be_visible()

    def test_profiles_presets_secret_preservation_duplication_and_preview(self):
        self.open()
        self.nav("profiles")
        expect(self.page.locator(".preset-card")).to_have_count(4)
        for index, method in enumerate(METHODS):
            self.page.locator(".preset-card").nth(index).click()
            expect(self.page.locator("#profile-method")).to_have_value(method)
            self.page.keyboard.press("Escape")
        self.page.locator("#profile-list").get_by_role("button", name="Edit", exact=True).click()
        expect(self.page.locator("#profile-password")).to_have_value("")
        self.page.locator("#profile-name").fill("Renamed profile " + XSS)
        self.page.get_by_role("button", name="Save & preview", exact=True).click()
        expect(self.page.locator("#preview-text")).to_contain_text("[REDACTED]")
        expect(self.page.locator("#preview-text img")).to_have_count(0)
        update = next(body for method, endpoint, body in self.mock.writes if method == "PUT")
        self.assertNotIn("password", update)
        self.assertNotIn("id", update)
        self.assertNotIn("has_password", update)
        self.page.keyboard.press("Escape")
        self.page.locator("#profile-list").get_by_role("button", name="Negative-test copy").click()
        self.page.locator("#duplicate-expectation").select_option("certificate_error")
        self.page.get_by_role("button", name="Create copy & edit").click()
        expect(self.page.locator("#profile-dialog")).to_be_visible()
        expect(self.page.locator("#profile-expectation")).to_have_value("certificate_error")
        expect(self.page.locator("#profile-password-hint")).to_contain_text("A password is saved")
        self.assertTrue(self.mock.profiles[-1]["has_password"])
        self.page.keyboard.press("Escape")
        self.screenshot("profiles-desktop.png")

    def test_refresh_recovers_csrf_after_another_tab_logs_in(self):
        self.open()
        self.mock.csrf = secrets.token_urlsafe(24)
        self.page.locator("#refresh-all").click()
        expect(self.page.locator("#loading")).to_be_hidden()
        self.nav("targets")
        self.page.locator("#target-list").get_by_role("button", name="Edit", exact=True).click()
        self.page.get_by_role("button", name="Save target", exact=True).click()
        expect(self.page.locator("#target-dialog")).to_be_hidden()
        self.assertFalse(self.mock.bad_headers)

    def test_target_attributes_write_only_secret_and_safe_error(self):
        self.open()
        self.nav("targets")
        self.page.locator("#target-list").get_by_role("button", name="Edit", exact=True).click()
        self.page.locator("#target-name").fill("Edited target")
        self.page.locator("#target-form summary").click()
        self.page.locator("#target-nas-ip").fill("192.0.2.10")
        self.page.locator("#add-attribute").click()
        self.page.locator('[data-attribute="id"]').fill("6")
        self.page.locator('[data-attribute="type"]').select_option("integer")
        self.page.locator('[data-attribute="value"]').fill("2")
        self.page.get_by_role("button", name="Save target", exact=True).click()
        expect(self.page.locator("#target-dialog")).to_be_hidden()
        saved = self.mock.writes[-1][2]
        self.assertNotIn("secret", saved)
        self.assertNotIn("has_secret", saved)
        self.assertEqual(saved["extra_attributes"], [dict(id=6, type="integer", sensitivity="public", value="2")])
        self.page.locator("#target-list").get_by_role("button", name="Edit", exact=True).click()
        self.page.locator("#target-secret").fill(secrets.token_urlsafe(30))
        self.mock.fail_next_write = True
        self.page.get_by_role("button", name="Save target", exact=True).click()
        expect(self.page.locator("#target-form .form-error")).to_contain_text(XSS)
        expect(self.page.locator("#target-form .form-error img")).to_have_count(0)
        expect(self.page.locator("#target-secret")).to_have_value("")
        self.page.keyboard.press("Escape")

    def test_private_attribute_preservation_and_explicit_public_replacement(self):
        old_private = secrets.token_hex(12)
        new_public = secrets.token_hex(12)
        rows = [
            dict(key="public-row", id=18, type="string", sensitivity="public", has_value=True, value=XSS),
            dict(key="private-row", id=26, type="hex", sensitivity="private", has_value=True),
            dict(key="empty-row", id=19, type="string", sensitivity="public", has_value=True, value=""),
        ]
        self.mock.targets[0]["extra_attributes"] = rows
        self.mock.attribute_values.update({"public-row": XSS, "private-row": old_private, "empty-row": ""})
        self.open()
        self.nav("targets")
        self.page.locator("#target-list").get_by_role("button", name="Edit", exact=True).click()
        self.page.locator("#target-form summary").click()
        public = self.page.locator(".attribute-row").nth(0)
        private = self.page.locator(".attribute-row").nth(1)
        expect(public.locator(".attribute-saved")).to_contain_text(XSS)
        expect(public.locator(".attribute-saved img")).to_have_count(0)
        expect(private).to_contain_text("Saved private value — hidden")
        expect(private.locator('[data-attribute="value"]')).to_have_value("")
        expect(private.locator('[data-attribute="value"]')).to_be_disabled()
        expect(self.page.locator(".attribute-row").nth(2)).to_contain_text("(empty value)")
        self.assertTrue(old_private not in self.page.locator("body").inner_text(), "A stored private value appeared in the editor")
        self.page.locator("#target-dialog").evaluate("element => element.scrollTop = 0")
        self.screenshot("attributes-desktop.png")
        self.page.set_viewport_size({"width": 390, "height": 844})
        self.assertTrue(self.page.evaluate("document.documentElement.scrollWidth <= innerWidth"))
        self.assertTrue(self.page.locator("#target-dialog").evaluate("element => element.scrollWidth <= element.clientWidth"))
        self.screenshot("attributes-mobile.png")
        self.page.set_viewport_size({"width": 1440, "height": 1000})
        self.page.locator("#target-name").fill("Preserved attributes")
        self.page.get_by_role("button", name="Save target", exact=True).click()
        expect(self.page.locator("#target-dialog")).to_be_hidden()
        submitted = self.mock.writes[-1][2]["extra_attributes"]
        self.assertEqual([row["key"] for row in submitted], ["public-row", "private-row", "empty-row"])
        self.assertTrue(all("value" not in row and "has_value" not in row for row in submitted))
        self.assertTrue(self.mock.attribute_values["private-row"] == old_private)

        self.page.locator("#target-list").get_by_role("button", name="Edit", exact=True).click()
        self.page.locator("#target-form summary").click()
        private = self.page.locator(".attribute-row").nth(1)
        private.locator('[data-attribute="sensitivity"]').select_option("public")
        write_count = len(self.mock.writes)
        self.page.get_by_role("button", name="Save target", exact=True).click()
        self.assertEqual(len(self.mock.writes), write_count)
        private.locator('[data-attribute="replace"]').check()
        private.locator('[data-attribute="value"]').fill(new_public)
        self.assertEqual(private.locator('[data-attribute="value"]').get_attribute("type"), "password")
        self.page.get_by_role("button", name="Save target", exact=True).click()
        self.assertEqual(len(self.mock.writes), write_count)
        private.locator('[data-attribute="confirm-public"]').check()
        self.page.get_by_role("button", name="Save target", exact=True).click()
        expect(self.page.locator("#target-dialog")).to_be_hidden()
        promoted = self.mock.writes[-1][2]["extra_attributes"][1]
        self.assertEqual(set(promoted), {"key", "id", "type", "sensitivity", "value"})
        self.assertTrue(promoted["value"] == new_public)
        self.assertEqual(promoted["sensitivity"], "public")
        expect(private.locator('[data-attribute="value"]')).to_have_value("")

        self.page.locator("#target-list").get_by_role("button", name="Edit", exact=True).click()
        self.page.locator("#target-form summary").click()
        public_container = self.page.locator(".attribute-row").nth(1)
        expect(public_container.locator(".attribute-saved")).to_contain_text(new_public)
        expect(public_container.locator(".attribute-confirm")).to_be_hidden()
        self.page.get_by_role("button", name="Save target", exact=True).click()
        expect(self.page.locator("#target-dialog")).to_be_hidden()
        self.assertNotIn("value", self.mock.writes[-1][2]["extra_attributes"][1])
        self.assertTrue(self.mock.attribute_values["private-row"] == new_public)

        self.page.locator("#target-list").get_by_role("button", name="Edit", exact=True).click()
        self.page.locator("#target-form summary").click()
        self.page.locator(".attribute-row").nth(1).locator('[data-attribute="sensitivity"]').select_option("private")
        self.page.get_by_role("button", name="Save target", exact=True).click()
        expect(self.page.locator("#target-dialog")).to_be_hidden()
        self.assertNotIn("value", self.mock.writes[-1][2]["extra_attributes"][1])
        self.assertNotIn("value", self.mock.targets[0]["extra_attributes"][1])
        self.assertTrue(self.mock.attribute_values["private-row"] == new_public)

    def test_opaque_defaults_empty_private_values_and_failed_submission_clearing(self):
        self.open()
        self.nav("targets")
        self.page.locator("#target-list").get_by_role("button", name="Edit", exact=True).click()
        self.page.locator("#target-form summary").click()
        self.page.locator("#add-attribute").click()
        row = self.page.locator(".attribute-row").last
        row.locator('[data-attribute="id"]').fill("241")
        row.locator('[data-attribute="type"]').select_option("hex")
        expect(row.locator('[data-attribute="sensitivity"]')).to_have_value("private")
        expect(row.locator('[data-attribute="sensitivity"]')).to_be_enabled()
        row.locator('[data-attribute="replace"]').check()
        row.locator('[data-attribute="value"]').fill(secrets.token_hex(10))
        self.mock.fail_next_write = True
        self.page.get_by_role("button", name="Save target", exact=True).click()
        expect(self.page.locator("#target-form .form-error")).to_be_visible()
        expect(row.locator('[data-attribute="value"]')).to_have_value("")
        expect(row.locator('[data-attribute="replace"]')).not_to_be_checked()
        write_count = len(self.mock.writes)
        self.page.get_by_role("button", name="Save target", exact=True).click()
        self.assertEqual(len(self.mock.writes), write_count)
        row.locator('[data-attribute="id"]').fill("18")
        row.locator('[data-attribute="type"]').select_option("string")
        row.locator('[data-attribute="replace"]').check()
        self.page.get_by_role("button", name="Save target", exact=True).click()
        expect(self.page.locator("#target-dialog")).to_be_hidden()
        submitted = self.mock.writes[-1][2]["extra_attributes"][0]
        self.assertEqual(submitted, dict(id=18, type="string", sensitivity="private", value=""))
        self.assertTrue(self.mock.targets[0]["extra_attributes"][0]["has_value"])
        self.assertNotIn("value", self.mock.targets[0]["extra_attributes"][0])

    def test_attribute_payload_changes_require_replacement_and_reclassification(self):
        self.mock.targets[0]["extra_attributes"] = [dict(key="opaque-public", id=26, type="hex", sensitivity="public", has_value=True, value="000001370102")]
        self.mock.attribute_values["opaque-public"] = "000001370102"
        self.open()
        self.nav("targets")
        self.page.locator("#target-list").get_by_role("button", name="Edit", exact=True).click()
        self.page.locator("#target-form summary").click()
        row = self.page.locator(".attribute-row").first
        row.locator('[data-attribute="type"]').select_option("string")
        expect(row.locator('[data-attribute="sensitivity"]')).to_have_value("private")
        write_count = len(self.mock.writes)
        self.page.get_by_role("button", name="Save target", exact=True).click()
        self.assertEqual(len(self.mock.writes), write_count)
        row.locator('[data-attribute="replace"]').check()
        row.locator('[data-attribute="value"]').fill("Deliberately public fixture value")
        row.locator('[data-attribute="sensitivity"]').select_option("public")
        row.locator('[data-attribute="confirm-public"]').check()
        row.locator('[data-attribute="value"]').fill("Revised public fixture value")
        expect(row.locator('[data-attribute="confirm-public"]')).not_to_be_checked()
        self.page.get_by_role("button", name="Save target", exact=True).click()
        self.assertEqual(len(self.mock.writes), write_count)
        row.locator('[data-attribute="confirm-public"]').check()
        self.page.get_by_role("button", name="Save target", exact=True).click()
        expect(self.page.locator("#target-dialog")).to_be_hidden()
        self.assertEqual(self.mock.writes[-1][2]["extra_attributes"], [dict(key="opaque-public", id=26, type="string", sensitivity="public", value="Revised public fixture value")])

        self.page.locator("#target-list").get_by_role("button", name="Edit", exact=True).click()
        self.page.locator("#target-form summary").click()
        row = self.page.locator(".attribute-row").first
        row.locator('[data-attribute="id"]').fill("242")
        expect(row.locator('[data-attribute="sensitivity"]')).to_have_value("private")
        expect(row.locator('[data-attribute="value"]')).to_have_value("")
        self.page.locator("#add-attribute").click()
        credential = self.page.locator(".attribute-row").last
        credential.locator('[data-attribute="id"]').fill("2")
        expect(credential.locator('[data-attribute="sensitivity"]')).to_have_value("private")
        expect(credential.locator('[data-attribute="sensitivity"]')).to_be_disabled()
        expect(credential).to_contain_text("always stays private")
        self.page.keyboard.press("Escape")

    def test_certificate_import_generation_completion_and_private_export(self):
        self.open()
        self.nav("certificates")
        self.screenshot("certificates-desktop.png")
        self.page.locator("#import-certificate").click()
        self.page.locator("#import-name").fill("Imported client")
        self.page.locator("#import-kind").select_option("identity")
        self.page.locator("#import-format").select_option("pfx")
        self.page.locator("#import-pfx-file").set_input_files(dict(name="fixture.p12", mimeType="application/x-pkcs12", buffer=b"fixture-only"))
        self.page.locator("#import-passphrase").fill(secrets.token_urlsafe(16))
        self.page.get_by_role("button", name="Import certificate", exact=True).click()
        expect(self.page.locator("#import-dialog")).to_be_hidden()
        self.assertEqual(set(self.mock.writes[-1][2]), {"name", "kind", "pfx", "passphrase"})
        expect(self.page.locator("#import-passphrase")).to_have_value("")
        for kind in ("ca", "client", "csr"):
            self.page.locator("#generate-certificate").click()
            self.page.locator("#generate-kind").select_option(kind)
            self.page.locator("#generate-name").fill("Generated " + kind)
            self.page.locator("#generate-cn").fill("Fixture " + kind)
            if kind == "client":
                self.page.locator("#generate-issuer").select_option("ca-1")
            if kind != "ca":
                self.page.locator("#generate-dns").fill("client.example.net\nsecond.example.net")
            self.page.locator('#generate-form button[type="submit"]').click()
            expect(self.page.locator("#generate-dialog")).to_be_hidden()
            payload = self.mock.writes[-1][2]
            self.assertEqual(payload["key_type"], "rsa3072")
            self.assertEqual("days" in payload, kind != "csr")
            if kind != "ca":
                self.assertEqual(payload["san_dns"], ["client.example.net", "second.example.net"])
        csr = self.page.locator("#certificate-list article").filter(has=self.page.get_by_role("heading", name="Pending enrollment", exact=True))
        csr.get_by_role("button", name="Complete CSR").click()
        self.page.locator("#complete-certificate").set_input_files(dict(name="signed.pem", mimeType="application/x-pem-file", buffer=b"fixture-only-signed-certificate"))
        self.page.locator('#complete-form button[type="submit"]').click()
        expect(self.page.locator("#complete-dialog")).to_be_hidden()
        self.assertEqual(self.mock.writes[-1][1], "/api/certificates/csr-1/complete")
        client = self.page.locator("#certificate-list article").filter(has=self.page.get_by_role("heading", name="Lab client", exact=True))
        client.get_by_role("button", name="Inspect", exact=True).click()
        expect(self.page.locator("#certificate-facts")).to_contain_text("clientAuth")
        self.page.keyboard.press("Escape")
        with self.page.expect_download() as public_download:
            client.get_by_role("button", name="Download public PEM").click()
        self.assertTrue(public_download.value.suggested_filename.endswith(".pem"))
        client.get_by_role("button", name="Export protected PFX…").click()
        before = len(self.mock.writes)
        passphrase = secrets.token_urlsafe(20)
        self.page.locator("#pfx-passphrase").fill(passphrase)
        self.page.locator("#pfx-confirm-passphrase").fill(passphrase)
        self.page.get_by_role("button", name="Export protected PFX", exact=True).click()
        self.assertEqual(len(self.mock.writes), before, "Export occurred without explicit confirmation")
        self.page.locator("#pfx-confirm").check()
        with self.page.expect_download() as exported:
            self.page.get_by_role("button", name="Export protected PFX", exact=True).click()
        self.assertTrue(exported.value.suggested_filename.endswith(".p12"))
        expect(self.page.locator("#pfx-passphrase")).to_have_value("")
        expect(self.page.locator("#pfx-confirm-passphrase")).to_have_value("")
        self.assertEqual(self.mock.writes[-1][2], {"passphrase": passphrase})

    def test_live_run_bounded_text_logs_cancel_history_and_responsive_layout(self):
        self.open()
        self.screenshot("workbench-desktop.png")
        self.page.locator("#run-expectation").select_option("reject")
        self.page.locator("#start-run").click()
        expect(self.page.locator("#run-log")).to_contain_text("1700", timeout=8000)
        expect(self.page.locator("#run-log img")).to_have_count(0)
        self.assertLessEqual(len(self.page.locator("#run-log").inner_text().splitlines()), 600)
        self.assertLessEqual(len(self.page.locator("#run-log").inner_text()), 120000)
        expect(self.page.locator("#start-run")).to_be_disabled()
        expect(self.page.locator("#run-facts")).to_contain_text("reject")
        self.page.locator("#run-detail summary").click()
        expect(self.page.locator("#run-snapshot")).to_contain_text("redacted fixture")
        self.page.locator("#cancel-run").click()
        expect(self.page.locator("#run-badges")).to_contain_text("cancelled")
        expect(self.page.locator("#run-badges")).to_contain_text("inconclusive")
        expect(self.page.locator("#cancel-run")).to_be_hidden()
        self.screenshot("run-result-desktop.png")
        with self.page.expect_download() as downloaded:
            self.page.locator("#download-run").click()
        self.assertEqual(downloaded.value.suggested_filename, "eapolkit-run-sanitized.json")
        self.nav("history")
        expect(self.page.locator("#history-list")).to_contain_text("Office acceptance")
        self.page.locator("#history-list").get_by_role("button", name="View", exact=True).click()
        expect(self.page.locator("#run-summary")).to_contain_text("cancelled")
        self.page.set_viewport_size({"width": 390, "height": 844})
        self.screenshot("workbench-mobile.png")
        for name in ("workbench", "profiles", "targets", "certificates", "history"):
            self.nav(name)
            self.assertTrue(self.page.evaluate("document.documentElement.scrollWidth <= window.innerWidth"), name + " has horizontal page overflow")
        self.page.locator("#history-list").get_by_role("button", name="Delete", exact=True).click()
        self.page.locator("#confirm-submit").click()
        expect(self.page.locator("#history-list")).to_contain_text("No recorded runs")


if __name__ == "__main__":
    unittest.main()
