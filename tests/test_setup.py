from safe_assertions import require

from concurrent.futures import ThreadPoolExecutor
import io
import os
import secrets
import sys
import threading

import pytest
from fastapi.testclient import TestClient

from eapolkit import setup
from eapolkit.app import create_app
from eapolkit.auth import Auth
from eapolkit.settings import Settings
from eapolkit.storage import Store


class Terminal(io.StringIO):
    def isatty(self):
        return True


@pytest.fixture
def terminal(tmp_path, monkeypatch):
    os.chmod(tmp_path, 0o700)
    directory = tmp_path / "data"
    monkeypatch.setenv("EAPOLKIT_DATA_DIR", str(directory))
    monkeypatch.setenv("EAPOLKIT_BIND_ADDRESS", "192.0.2.10")
    monkeypatch.delenv("EAPOLKIT_ALLOWED_HOSTS", raising=False)
    monkeypatch.delenv("EAPOLKIT_SECURE_COOKIES", raising=False)
    monkeypatch.setattr(sys, "stdin", Terminal())
    return directory


def passwords(monkeypatch, *values):
    answers = iter(values)
    monkeypatch.setattr(setup, "read_password", lambda prompt: next(answers))


def test_terminal_setup_persists_for_lan_login_and_keeps_security(terminal, monkeypatch, capsys):
    password = "  " + secrets.token_urlsafe(32) + '\té"\\  '
    passwords(monkeypatch, password, password)
    require(setup.main([]) == 0, "Terminal setup failed")
    captured = capsys.readouterr()
    require(captured.out == "Workbench password created. You can now start the kit.\n" and not captured.err)
    require(password not in captured.out + captured.err, "Setup exposed a password")
    require(password.encode() not in (terminal / "eapolkit.sqlite3").read_bytes(), "Setup saved a plaintext password")

    settings = Settings(data_dir=terminal, binary="/nonexistent/eapol_test")
    with TestClient(create_app(settings), base_url="http://192.0.2.10:8080") as client:
        require(client.get("/api/session").json() == {"setup_required": False, "authenticated": False, "csrf_token": None})
        require(client.get("/api/targets").status_code == 401)
        marker = {"X-EapolKit-Request": "1"}
        require(client.post("/api/setup", json={"password": password}, headers=marker).status_code == 409)
        require(client.get("/api/session", headers={"Host": "foreign.invalid"}).status_code == 400)
        require(client.post("/api/login", json={"password": password}, headers={**marker, "Origin": "http://foreign.invalid"}).status_code == 403)
        require(client.post("/api/login", json={"password": password}, headers={**marker, "Origin": "https://192.0.2.10:8080"}).status_code == 403)
        require(client.post("/api/login", json={"password": password}).status_code == 403)
        require(client.post("/api/login", json={"password": password.strip()}, headers=marker).status_code == 401)
        response = client.post("/api/login", json={"password": password}, headers={**marker, "Origin": "http://192.0.2.10:8080"})
        require(response.status_code == 200, "The terminal password did not permit browser login")
        cookie = response.headers["set-cookie"].lower()
        require("httponly" in cookie and "samesite=strict" in cookie and "secure" not in cookie)
        require(client.post("/api/logout", headers=marker).status_code == 403)
        require(client.post("/api/logout", headers={**marker, "X-CSRF-Token": "wrong"}).status_code == 403)
        require(client.post("/api/logout", headers={**marker, "X-CSRF-Token": response.json()["csrf_token"]}).status_code == 200)


@pytest.mark.parametrize("case", ["mismatch", "empty", "too_long", "eof", "interrupt", "terminal_error"])
def test_terminal_input_failures_do_not_initialize_or_echo(terminal, monkeypatch, capsys, case):
    sentinel = secrets.token_urlsafe(32)
    if case == "mismatch":
        passwords(monkeypatch, sentinel, sentinel + "different")
    elif case == "empty":
        passwords(monkeypatch, "", "")
    elif case == "too_long":
        value = sentinel + "x" * 4096
        passwords(monkeypatch, value, value)
    else:
        def failed_input(prompt):
            if case == "terminal_error":
                raise OSError(sentinel)
            raise (EOFError if case == "eof" else KeyboardInterrupt)(sentinel)
        monkeypatch.setattr(setup, "read_password", failed_input)
    require(setup.main([]) == 1, "An invalid terminal input completed setup")
    captured = capsys.readouterr()
    require(not captured.out and captured.err, "An input failure lacked a safe error")
    require(sentinel not in captured.err, "An input failure exposed password content")
    store = Store(terminal)
    try:
        require(store.setting("password_hash") is None, "A failed prompt initialized the password")
    finally:
        store.close()


def test_noninteractive_setup_does_not_open_storage(terminal, monkeypatch, capsys):
    monkeypatch.setattr(sys, "stdin", io.StringIO())
    require(setup.main([]) == 1)
    require(not terminal.exists(), "Noninteractive setup accessed storage")
    captured = capsys.readouterr()
    require(not captured.out and captured.err == "Setup requires an interactive terminal with password echo disabled.\n")


def test_arguments_are_rejected_without_echo_or_storage(terminal, capsys):
    value = secrets.token_urlsafe(32)
    require(setup.main([value]) == 2)
    require(not terminal.exists(), "Rejected arguments accessed storage")
    captured = capsys.readouterr()
    require(not captured.out and captured.err == "Usage: python -m eapolkit.setup\n")
    require(value not in captured.err, "An argument was echoed")


def test_rerun_does_not_prompt_or_replace_password(terminal, monkeypatch, capsys):
    password = secrets.token_urlsafe(32)
    passwords(monkeypatch, password, password)
    require(setup.main([]) == 0)
    capsys.readouterr()
    before = (terminal / "eapolkit.sqlite3").read_bytes()
    passwords(monkeypatch)
    require(setup.main([]) == 1)
    captured = capsys.readouterr()
    require(not captured.out and captured.err == "Setup is already complete; the password was not changed.\n")
    require((terminal / "eapolkit.sqlite3").read_bytes() == before, "Rerunning setup changed the database")


def test_missing_master_key_fails_without_replacement(terminal, monkeypatch, capsys):
    Store(terminal).close()
    key = terminal / "secrets" / "master.key"
    key.unlink()
    before = (terminal / "eapolkit.sqlite3").read_bytes()
    passwords(monkeypatch)
    require(setup.main([]) == 1)
    captured = capsys.readouterr()
    require(not captured.out and captured.err == "Setup failed; check the data volume before trying again.\n")
    require(not key.exists(), "Terminal setup replaced a missing master key")
    require((terminal / "eapolkit.sqlite3").read_bytes() == before, "Failed storage initialization changed the database")


def test_storage_exception_details_are_not_printed(terminal, monkeypatch, capsys):
    sentinel = secrets.token_urlsafe(32)
    def failed_store(directory):
        raise RuntimeError(sentinel)
    monkeypatch.setattr(setup, "Store", failed_store)
    require(setup.main([]) == 1)
    captured = capsys.readouterr()
    require(not captured.out and captured.err == "Setup failed; check the data volume before trying again.\n")
    require(sentinel not in captured.err, "Setup printed storage exception details")


def test_concurrent_initializers_cannot_replace_the_winning_password(tmp_path, monkeypatch):
    directory = tmp_path / "data"
    stores = [Store(directory), Store(directory)]
    settings = Settings(data_dir=directory)
    owners = [Auth(store, settings) for store in stores]
    values = [secrets.token_urlsafe(32), secrets.token_urlsafe(32)]
    barrier = threading.Barrier(2)
    original_hash = Auth._hash

    def simultaneous_hash(password, salt):
        barrier.wait(timeout=5)
        return original_hash(password, salt)

    def initialize(index):
        try:
            owners[index].setup(values[index])
            return "created"
        except FileExistsError:
            return "exists"
        except Exception:
            return "failed"

    try:
        with monkeypatch.context() as patch:
            patch.setattr(Auth, "_hash", staticmethod(simultaneous_hash))
            with ThreadPoolExecutor(max_workers=2) as executor:
                results = list(executor.map(initialize, range(2)))
        require(sorted(results) == ["created", "exists"], "Concurrent setup did not preserve one owner")
        winner = results.index("created")
        owners[0].login(values[winner])
        with pytest.raises(PermissionError, match="Authentication failed"):
            owners[0].login(values[1 - winner])
    finally:
        for store in stores:
            store.close()


def test_localhost_first_run_web_setup_remains_available(terminal, monkeypatch):
    monkeypatch.delenv("EAPOLKIT_BIND_ADDRESS")
    settings = Settings(data_dir=terminal, binary="/nonexistent/eapol_test")
    with TestClient(create_app(settings), base_url="http://localhost:8080") as client:
        require(client.get("/api/session").json()["setup_required"])
        response = client.post("/api/setup", json={"password": secrets.token_urlsafe(32)}, headers={"X-EapolKit-Request": "1"})
        require(response.status_code == 200 and response.json()["authenticated"], "First-run web setup changed")
