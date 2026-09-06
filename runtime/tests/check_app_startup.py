#!/usr/bin/env python3
"""Verify canonical ASGI startup in an isolated final-image container."""
import http.client
import json
import os
import signal
import subprocess
import sys
import time


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def request(path):
    connection = http.client.HTTPConnection("127.0.0.1", 8080, timeout=1)
    try:
        connection.request("GET", path)
        response = connection.getresponse()
        body = response.read(256 * 1024 + 1)
        require(len(body) <= 256 * 1024, "The startup response exceeded its bound")
        return response.status, body
    finally:
        connection.close()


require(os.getuid() == 10001 and os.getgid() == 10001, "Unexpected ASGI test identity")
# Discard child diagnostics rather than persist unfiltered application output.
process = subprocess.Popen(
    [sys.executable, "-m", "uvicorn", "eapolkit.app:app", "--host", "0.0.0.0", "--port", "8080"],
    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    start_new_session=True,
)
forced_shutdown = False
try:
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        require(process.poll() is None, "The canonical ASGI process exited during startup")
        try:
            status, body = request("/api/session")
            break
        except (OSError, http.client.HTTPException):
            time.sleep(0.1)
    else:
        raise RuntimeError("The canonical ASGI process did not become ready")
    require(status == 200, "The session endpoint failed after ASGI startup")
    try:
        session = json.loads(body)
    except (ValueError, UnicodeError):
        raise RuntimeError("The session endpoint did not return JSON") from None
    require(session.get("setup_required") is True and session.get("authenticated") is False,
            "The isolated ASGI instance did not expose its initial setup state")
    status, body = request("/")
    require(status == 200 and b"<html" in body.lower(), "The ASGI instance did not serve its UI")
finally:
    if process.poll() is None:
        process.terminate()
    try:
        process.wait(timeout=8)
    except subprocess.TimeoutExpired:
        forced_shutdown = True
        process.kill()
        process.wait(timeout=5)
require(not forced_shutdown and process.returncode in (0, -signal.SIGTERM),
        "The owned ASGI process did not stop within its shutdown bound")
print(json.dumps({"asgi_startup": "passed", "session_http_status": 200, "ui_http_status": 200,
                  "uid": os.getuid(), "gid": os.getgid(), "owned_process_reaped": True,
                  "authenticated_workflow_checked": False, "full_eap_authentication": False}))
