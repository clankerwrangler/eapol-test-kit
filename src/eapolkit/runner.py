"""One bounded, cancellable eapol_test process with sanitized durable results."""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import ipaddress
import math
import hashlib
import tempfile
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import sys
import time

from .configuration import preview, radius_attribute_file, render, validate_runnable
from .attributes import decoded_rows, encode_value, public_target
from .storage import public
from .redaction import Redactor


class RunConflict(Exception):
    pass


def _stamp():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")




FOOTER = re.compile(
    r"^EAPOL_TEST_RESULT accept=([01]) reject=([01]) timeout=([01]) "
    r"mppe_ok=(0|[1-9][0-9]{0,9}) mppe_mismatch=(0|[1-9][0-9]{0,9}) "
    r"cert_error=(0|[1-9][0-9]{0,9})$"
)


class Evidence:
    def __init__(self):
        self.terminal_lines = []

    def observe(self, line):
        self.terminal_lines = (self.terminal_lines + [line])[-2:]

    def finish(self, exit_code):
        invalid = ("error", "The process did not report a verified authentication result.", None, None, None)
        if type(exit_code) is not int or not 0 <= exit_code <= 255 or len(self.terminal_lines) != 2:
            return invalid
        marker = self.terminal_lines[1]
        if not ((exit_code == 0 and marker == "SUCCESS") or (exit_code > 0 and marker == "FAILURE")):
            return invalid
        terminal = FOOTER.fullmatch(self.terminal_lines[0])
        if terminal is None:
            return invalid
        accept, reject, timeout, ok, mismatch, certificate_errors = (int(value) for value in terminal.groups())
        if ok > 2147483647 or mismatch > 2147483647 or certificate_errors > 4294967295:
            return invalid
        radius = "accept" if accept and not reject else "reject" if reject and not accept else None
        peer = marker == "SUCCESS"
        mppe = bool(ok and not mismatch) if ok or mismatch else None
        outcome = "error"
        summary = "The client completed without a verified overall authentication result."
        if peer and accept and not reject and not timeout and not certificate_errors and mppe:
            outcome = "accept"
            summary = "Authenticated Access-Accept, EAP peer success, and matching MPPE keying material were verified."
        elif not peer:
            if timeout:
                outcome = "timeout"
                summary = "eapol_test reported an authentication timeout."
            elif certificate_errors:
                outcome = "certificate_error"
                summary = "The native TLS validator reported a certificate-validation failure. This does not identify server-side policy."
            elif reject and not accept:
                outcome = "reject"
                summary = "An authenticated Access-Reject was observed. The server-side rejection reason is not known."
            elif accept:
                summary = "Access-Accept was authenticated, but overall peer or MPPE keying success was not verified."
        return outcome, summary, radius, peer, mppe


def verdict(expected, outcome):
    if outcome == expected:
        return "pass"
    if outcome in {"accept", "reject", "certificate_error"}:
        return "fail"
    return "inconclusive"


class RunManager:
    def __init__(self, store, certificates, settings):
        self.store, self.certificates, self.settings = store, certificates, settings
        self._active_run_id = None
        self._task = None
        self._process = None
        self._task_started = False
        self._cancel_requested = False
        self._shutting_down = False
        self._lock = asyncio.Lock()
        temporary_base = Path(tempfile.gettempdir()) / "eapolkit-runs"
        temporary_base.mkdir(mode=0o700, exist_ok=True)
        if temporary_base.is_symlink():
            raise RuntimeError("Run temporary base must not be a symlink")
        os.chmod(temporary_base, 0o700)
        installation = hashlib.sha256(str(Path(settings.data_dir).resolve()).encode()).hexdigest()[:24]
        self._temporary_root = temporary_base / installation
        self._temporary_root.mkdir(mode=0o700, exist_ok=True)
        if self._temporary_root.is_symlink():
            raise RuntimeError("Run temporary directory must not be a symlink")
        os.chmod(self._temporary_root, 0o700)
        for entry in self._temporary_root.iterdir():
            if re.fullmatch(r"run-[0-9a-f]{32}", entry.name):
                if entry.is_symlink():
                    entry.unlink()
                elif entry.is_dir():
                    shutil.rmtree(entry)
        for record in self.store.list("run"):
            if record.get("status") in {"queued", "running"}:
                record.update(status="interrupted", outcome="interrupted", verdict="inconclusive", summary="The service restarted before this run finished. Authentication was not replayed.", finished_at=_stamp(), duration_seconds=None)
                self.store.put("run", record)
        self._prune()

    @property
    def active_run_id(self):
        return self._active_run_id

    def _prune(self):
        records = self.store.list("run")
        for record in records[self.settings.history_limit:]:
            if record["status"] not in {"queued", "running"}:
                self.store.delete("run", record["id"])

    def list(self, limit=50):
        if not 1 <= limit <= 100:
            raise ValueError("History limit must be between 1 and 100")
        return [{key: value for key, value in public(record).items() if key not in {"log_lines", "snapshot"}} for record in self.store.list("run")[:limit]]

    def get(self, object_id, after=0):
        if after < 0:
            raise ValueError("Log sequence must be nonnegative")
        result = public(self.store.get("run", object_id))
        result["log_lines"] = [line for line in result.get("log_lines", []) if line["seq"] > after]
        return result

    def delete(self, object_id):
        record = self.store.get("run", object_id)
        if record["status"] in {"queued", "running"}:
            raise RunConflict("An active run cannot be deleted")
        self.store.delete("run", object_id)

    async def start(self, target_id, profile_id, expected_outcome=None):
        async with self._lock:
            if self._active_run_id is not None:
                raise RunConflict("Another run is already active")
            target = self.store.get("target", target_id)
            profile = self.store.get("profile", profile_id)
            start_clock = time.monotonic()
            deadline = start_clock + target["timeout_seconds"]
            validate_runnable(profile, target, self.certificates, self.store)
            rows = decoded_rows(self.store, target.get("extra_attributes", []))
            attribute_content = radius_attribute_file(target, rows)
            attribute_secrets = [value for row in rows if row["sensitivity"] == "private" for value in (row["value"], encode_value(row))]
            expected = expected_outcome or profile["expected_outcome"]
            if expected not in {"accept", "reject", "certificate_error"}:
                raise ValueError("Unsupported expected outcome")
            binary = shutil.which(self.settings.binary)
            if binary is None:
                raise ValueError("The patched eapol_test executable is not available")
            radius_secret = self.store.decrypt(target["_secret"])
            password = self.store.decrypt(profile["_password"]) if profile.get("_password") else None
            redaction_values = [radius_secret, password, *attribute_secrets]
            redactor = Redactor(redaction_values)
            run_id = secrets.token_hex(16)
            record = {
                "id": run_id, "target_id": target_id, "profile_id": profile_id,
                "target_name": redactor.text(target["name"]), "profile_name": redactor.text(profile["name"]),
                "expected_outcome": expected, "status": "queued", "outcome": None, "verdict": None, "summary": "Run queued.",
                "created_at": _stamp(), "started_at": None, "finished_at": None, "duration_seconds": None, "exit_code": None,
                "radius_response": None, "peer_success": None, "mppe_keys_match": None, "returned_attributes": [],
                "snapshot": redactor.object({"target": public_target(self.store, target), "profile": public(profile), "configuration": preview(profile, self.certificates)["configuration"]}),
                "log_lines": [], "next_seq": 0, "truncated": False,
            }
            self.store.put("run", record)
            self._active_run_id = run_id
            self._cancel_requested = False
            self._task_started = False
            self._task = asyncio.create_task(self._execute(record, target, profile, binary, attribute_content, radius_secret, password, redaction_values, start_clock, deadline))
            self._prune()
            return self.get(run_id)

    async def cancel(self, object_id):
        record = self.store.get("run", object_id)
        if object_id != self._active_run_id or record["status"] not in {"queued", "running"}:
            raise RunConflict("This run is not active")
        if not self._cancel_requested:
            self._cancel_requested = True
            if self._task_started:
                self._task.cancel()
        await asyncio.shield(self._task)
        return self.get(object_id)

    async def shutdown(self):
        self._shutting_down = True
        if self._active_run_id is not None:
            await self.cancel(self._active_run_id)
        try:
            self._temporary_root.rmdir()
        except OSError:
            pass

    async def _spawn(self, *arguments, directory):
        creation = asyncio.create_task(asyncio.create_subprocess_exec(*arguments, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT, stdin=asyncio.subprocess.DEVNULL, cwd=directory, start_new_session=True, env={"PATH": os.defpath, "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}))
        try:
            process = await asyncio.shield(creation)
        except asyncio.CancelledError:
            process = await creation
            self._process = process
            raise
        self._process = process
        return process

    async def _terminate(self):
        process = self._process
        if process is None:
            return
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            await asyncio.wait_for(process.wait(), timeout=0.5)
        except asyncio.TimeoutError:
            pass
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        await process.wait()
        self._process = None

    async def _resolve(self, host, directory):
        try:
            return str(ipaddress.ip_address(host))
        except ValueError:
            pass
        # getaddrinfo can block in platform name-service code. A private owned process makes
        # DNS preparation cancellable without leaving an unbounded executor thread behind.
        code = "import json,socket,sys; print(json.dumps(list(dict.fromkeys(a[4][0] for a in socket.getaddrinfo(sys.argv[1],None,0,socket.SOCK_DGRAM)))))"
        process = await self._spawn(sys.executable, "-c", code, host, directory=directory)
        output, _ = await process.communicate()
        self._process = None
        if process.returncode != 0 or len(output) > 65536:
            raise ValueError("Target DNS resolution failed")
        try:
            addresses = [ipaddress.ip_address(value) for value in json.loads(output)]
            addresses.sort(key=lambda address: address.version)
            return str(addresses[0])
        except (ValueError, IndexError, TypeError):
            raise ValueError("Target DNS resolution did not return an IP address") from None

    @staticmethod
    def _write(directory, name, content):
        path = directory / name
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as output:
            output.write(content)
        return str(path)

    async def _logs(self, process, record, redactor, evidence):
        pending = bytearray()
        oversized = False
        stored_bytes = 0
        async def line(raw):
            nonlocal stored_bytes
            if raw is None:
                safe = "[overlong diagnostic suppressed]"
                evidence.observe(safe)
            else:
                text = raw.decode("utf-8", errors="replace").rstrip("\r")
                evidence.observe(text)
                safe = redactor.line(text)
            encoded = safe.encode("utf-8")
            if len(encoded) > self.settings.max_line_bytes:
                safe = "[overlong sanitized diagnostic suppressed]"
                encoded = safe.encode()
            if len(record["log_lines"]) >= self.settings.max_log_lines or stored_bytes + len(encoded) > self.settings.max_log_bytes:
                if not record["truncated"]:
                    record["truncated"] = True
                    self.store.put("run", record)
                return
            record["next_seq"] += 1
            record["log_lines"].append({"seq": record["next_seq"], "line": safe})
            stored_bytes += len(encoded)
            self.store.put("run", record)
            await asyncio.sleep(0)
        while True:
            chunk = await process.stdout.read(4096)
            if not chunk:
                break
            for piece_index, piece in enumerate(chunk.split(b"\n")):
                if piece_index:
                    await line(None if oversized else bytes(pending))
                    pending.clear()
                    oversized = False
                if not oversized:
                    pending.extend(piece)
                    if len(pending) > self.settings.max_line_bytes:
                        pending.clear()
                        oversized = True
        if pending or oversized:
            await line(None if oversized else bytes(pending))

    async def _execute(self, record, target, profile, binary, attribute_content, radius_secret, password, redaction_values, start_clock, deadline):
        self._task_started = True
        directory = self._temporary_root / ("run-" + record["id"])
        outcome, summary = "error", "The run failed before a verified authentication result was available."
        evidence = Evidence()
        try:
            if self._cancel_requested:
                raise asyncio.CancelledError
            async with asyncio.timeout(max(0, deadline - time.monotonic())):
                directory.mkdir(mode=0o700)
                record.update(status="running", started_at=_stamp(), summary="Preparing and running eapol_test.")
                self.store.put("run", record)
                ca = self.certificates.material(profile["ca_certificate_id"])
                paths = {"ca_certificate": self._write(directory, "server-ca.pem", ca["certificate"])}
                if profile.get("client_identity_id"):
                    client = self.certificates.material(profile["client_identity_id"])
                    paths["client_certificate"] = self._write(directory, "client.pem", client["certificate"])
                    paths["private_key"] = self._write(directory, "client-key.pem", client["private_key"])
                configuration_path = self._write(directory, "network.conf", render(profile, paths, password).encode("utf-8"))
                secret_path = self._write(directory, "radius.secret", radius_secret)
                attribute_path = self._write(directory, "radius-attributes", attribute_content)
                redactor = Redactor([*redaction_values, client["private_key"] if profile.get("client_identity_id") else None, str(directory)])
                address = await self._resolve(target["host"], directory)
                remaining = max(1, math.ceil(deadline - time.monotonic()))
                process = await self._spawn(binary, "-c", configuration_path, "-a", address, "-p", str(target["port"]), "-F", secret_path, "-G", attribute_path, "-t", str(remaining), "-r", "0", directory=directory)
                await self._logs(process, record, redactor, evidence)
                record["exit_code"] = await process.wait()
                outcome, summary, radius, peer, mppe = evidence.finish(record["exit_code"])
                record.update(radius_response=radius, peer_success=peer, mppe_keys_match=mppe)
        except asyncio.CancelledError:
            outcome = "interrupted" if self._shutting_down else "cancelled"
            summary = "The service stopped this run without replaying authentication." if self._shutting_down else "The requested run was cancelled."
        except TimeoutError:
            outcome, summary = "timeout", "The overall run deadline expired, including preparation."
        except (ValueError, OSError):
            outcome, summary = "configuration_error", "Run preparation or process launch failed. Check saved inputs and the configured patched executable."
        except Exception:
            outcome, summary = "error", "The run failed without a verified authentication result."
        finally:
            process = self._process
            try:
                await self._terminate()
                if process is not None and record["exit_code"] is None:
                    record["exit_code"] = process.returncode
            finally:
                try:
                    if directory.exists():
                        shutil.rmtree(directory)
                except OSError:
                    outcome, summary = "error", "Owned run-file cleanup failed. Private files remain protected; cleanup must be checked."
                record.update(status="cancelled" if outcome == "cancelled" else "interrupted" if outcome == "interrupted" else "completed", outcome=outcome, verdict=verdict(record["expected_outcome"], outcome), summary=summary, finished_at=_stamp(), duration_seconds=round(time.monotonic() - start_clock, 3))
                self.store.put("run", record)
                self._active_run_id = None
                self._prune()
