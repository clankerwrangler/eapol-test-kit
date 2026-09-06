#!/usr/bin/env python3
"""Smoke-test shipped Compose startup and persistence with an ephemeral project.

Run on an authorized Docker host. This creates and removes only an unused project
named from the candidate's context label. It sends no RADIUS requests. Credentials
exist only in process memory and the ephemeral application's protected storage.
"""
import argparse
import base64
from datetime import datetime, timezone
import hashlib
import http.cookiejar
import ipaddress
import json
import os
import pty
from pathlib import Path
import re
import secrets
import shutil
import signal
import subprocess
import sys
import termios
import time
import urllib.error
import urllib.parse
import urllib.request

ENV = {"PATH": os.environ.get("PATH", os.defpath), "HOME": os.environ.get("HOME", "/tmp"),
       "EAPOLKIT_PORT": "0"}


class SmokeFailure(Exception):
    """Carry only a fixed, credential-free failure code."""


def require(condition, code):
    if not condition:
        raise SmokeFailure(code)


def command(arguments, *, timeout=30, check=True, input_bytes=None):
    result = subprocess.run(arguments, input=input_bytes, capture_output=True,
                            timeout=timeout, env=ENV)
    require(len(result.stdout) + len(result.stderr) <= 1024 * 1024, "command_output_bound")
    if check:
        require(result.returncode == 0, "command_failed")
    return result


def inspect(kind, name, *, missing_ok=False):
    if missing_ok:
        require(kind in {"container", "network", "volume"}, "unsupported_absence_query")
        arguments = ["docker", kind, "ls"]
        if kind == "container":
            arguments.append("--all")
        arguments += ["--filter", "name=^" + ("/" if kind == "container" else "") + re.escape(name) + "$",
                      "--format", "{{.Names}}" if kind == "container" else "{{.Name}}"]
        found = command(arguments).stdout.decode().splitlines()
        require(set(found) <= {name}, "unexpected_named_resource")
        if not found:
            return None
    result = command(["docker", kind, "inspect", name])
    return json.loads(result.stdout)[0]


def project_names(kind, project):
    arguments = ["docker", kind, "ls"]
    if kind == "container":
        arguments.append("--all")
    arguments += ["--filter", "label=com.docker.compose.project=" + project,
                  "--format", "{{.Names}}" if kind == "container" else "{{.Name}}"]
    return set(command(arguments).stdout.decode().splitlines())


def interrupted(signum, frame):
    raise SmokeFailure("interrupted")


def terminal_setup(arguments, verify_before_input, *, already_initialized=False):
    """Keep synthetic credentials and terminal output in this process only."""
    master, slave = pty.openpty()
    attributes = termios.tcgetattr(slave)
    attributes[3] &= ~(termios.ECHO | termios.ECHONL)
    termios.tcsetattr(slave, termios.TCSANOW, attributes)
    process = None
    output = bytearray()
    pending = bytearray()
    password = None
    stage = 0
    try:
        process = subprocess.Popen(arguments, stdin=slave, stdout=slave, stderr=slave,
                                   env=ENV, start_new_session=True)
        os.close(slave)
        slave = None
        os.set_blocking(master, False)
        deadline = time.monotonic() + 40
        while True:
            require(time.monotonic() < deadline, "setup_terminal_deadline")
            try:
                block = os.read(master, 4096)
            except BlockingIOError:
                block = None
            except OSError as error:
                if error.errno != 5:  # Linux PTYs report EIO after the slave closes.
                    raise
                block = b""
            if block:
                output.extend(block)
                require(len(output) <= 65536, "setup_terminal_output_bound")
                if b"New workbench password: " in output and stage == 0:
                    require(not already_initialized, "existing_setup_prompted_for_password")
                    verify_before_input()
                    require(not termios.tcgetattr(master)[3] & termios.ECHO, "setup_outer_terminal_echo")
                    password = "".join(chr(0x1F600 + secrets.randbelow(64)) for _ in range(4096))
                    require(len(password) == 4096 and len(password.encode()) == 16384, "maximum_password_shape")
                    pending.extend(password.encode() + b"\n")
                    stage = 1
                if b"Confirm password: " in output and stage == 1:
                    require(not termios.tcgetattr(master)[3] & termios.ECHO, "confirmation_outer_terminal_echo")
                    require(not pending, "confirmation_before_full_password_input")
                    pending.extend(password.encode() + b"\n")
                    stage = 2
                if password is not None:
                    require(all(value.encode() not in output for value in
                                (password, password[:64], password[-64:])), "password_in_setup_terminal")
            if pending:
                try:
                    written = os.write(master, pending[:4096])
                except BlockingIOError:
                    written = 0
                pending[:written] = b"\0" * written
                del pending[:written]
            if process.poll() is not None and block == b"":
                break
            time.sleep(0.02)
        if already_initialized:
            require(process.returncode == 1 and stage == 0 and
                    b"Setup is already complete; the password was not changed." in output,
                    "existing_setup_not_refused")
        else:
            require(process.returncode == 0 and stage == 2 and not pending and
                    b"Workbench password created. You can now start the kit." in output,
                    "terminal_setup_failed")
        return password
    finally:
        if slave is not None:
            os.close(slave)
        if process is not None and process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)
        os.close(master)
        output[:] = b"\0" * len(output)
        pending[:] = b"\0" * len(pending)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compose", type=Path, required=True)
    parser.add_argument("--image", required=True)
    parser.add_argument("--expected-image-id", required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--setup-mode", choices=("web", "cli"), default="web")
    parser.add_argument("--project-name")
    parser.add_argument("--bind-address", default="127.0.0.1")
    args = parser.parse_args()
    require(ipaddress.ip_address(args.bind_address).version == 4 and
            ipaddress.ip_address(args.bind_address).is_loopback, "loopback_test_bind_required")
    require(args.project_name is None or re.fullmatch(r"eapolkit-[a-z0-9-]{1,48}", args.project_name),
            "test_project_name")
    if args.setup_mode == "cli":
        ENV.pop("EAPOLKIT_PORT", None)
        signal.alarm(240)
    require(args.work_dir.is_dir() and not args.work_dir.is_symlink(), "work_directory")
    receipt_path = args.work_dir / "receipt.json"
    require(not receipt_path.exists() and not receipt_path.with_suffix(".staged").exists(), "receipt_already_exists")
    state = {"state": "prepared", "phase": "preflight", "image_tag": args.image,
             "expected_image_id": args.expected_image_id,
             "started_utc": datetime.now(timezone.utc).isoformat(),
             "no_radius_requests": True, "credential_values_persisted_in_receipt": False,
             "scope": "Shipped Compose startup and persistence, not certificate-result security or EAP authentication",
             "setup_mode": args.setup_mode, "bind_address": args.bind_address}
    with receipt_path.open("x") as output:
        json.dump(state, output)
    receipt_path.chmod(0o644)
    creation_attempted = False
    cleanup_complete = False
    expected = {}
    compose = []
    project = None
    sentinels = []
    oneoffs = set()

    def save():
        temporary = receipt_path.with_suffix(".staged")
        with temporary.open("x") as output:
            os.fchmod(output.fileno(), 0o644)
            json.dump(state, output, indent=2)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        temporary.replace(receipt_path)

    def compose_command(*arguments, timeout=150):
        return command([*compose, *arguments], timeout=timeout)

    def owned_resources():
        found = {}
        for kind, name in expected.items():
            allowed = {name} | oneoffs if kind == "container" else {name}
            present = project_names(kind, project)
            require(present <= allowed, "unexpected_project_resource")
            for current_name in sorted(allowed):
                item = inspect(kind, current_name, missing_ok=True)
                if item is None:
                    continue
                labels = item.get("Config", {}).get("Labels", {}) if kind == "container" else item.get("Labels", {})
                require(labels.get("com.docker.compose.project") == project, "resource_ownership")
                if kind == "container":
                    require(item["Image"] == args.expected_image_id and
                            labels.get("com.docker.compose.service") == "kit", "owned_container_identity")
                found.setdefault(kind, []).append({"name": current_name,
                    "id": item.get("Id", item.get("Name")), "created": item.get("CreatedAt"), "labels": labels})
        return found

    def cleanup_resources():
        snapshot = owned_resources()
        state["resources_before_teardown"] = snapshot
        save()
        for item in snapshot.get("container", []):
            current = inspect("container", item["name"], missing_ok=True)
            if current is None:
                continue
            require(current["Id"] == item["id"] and current["Image"] == args.expected_image_id,
                    "teardown_container_changed")
            if current["State"]["Running"]:
                command(["docker", "stop", "--time", "15", item["id"]], timeout=25)
            current = inspect("container", item["name"], missing_ok=True)
            if current is not None:
                require(current["Id"] == item["id"], "teardown_container_replaced")
                command(["docker", "rm", item["id"]])
        for item in snapshot.get("network", []):
            current = inspect("network", item["name"])
            require(current["Id"] == item["id"] and not current.get("Containers"), "teardown_network_consumers")
            command(["docker", "network", "rm", item["id"]])
        for item in snapshot.get("volume", []):
            current = inspect("volume", item["name"])
            require(current.get("CreatedAt") == item["created"] and current.get("Labels") == item["labels"],
                    "teardown_volume_changed")
            consumers = command(["docker", "container", "ls", "--all", "--quiet", "--no-trunc",
                                 "--filter", "volume=" + item["name"]]).stdout.strip()
            require(not consumers, "teardown_volume_consumers")
            command(["docker", "volume", "rm", item["name"]])
        for kind, name in expected.items():
            require(inspect(kind, name, missing_ok=True) is None and not project_names(kind, project), "teardown_incomplete")

    def container_state(name=None, *, setup=False):
        name = name or expected["container"]
        item = inspect("container", name)
        require(item["State"]["Running"], "container_running")
        if not setup:
            require(item["State"].get("Health", {}).get("Status") == "healthy", "container_health")
        require(item["Image"] == args.expected_image_id, "container_image_identity")
        require(item["Config"]["User"] == "10001:10001", "container_user")
        host = item["HostConfig"]
        require(host["ReadonlyRootfs"] and host.get("Init") and not host["Privileged"], "rootfs_init_privilege")
        require(set(host.get("CapDrop") or []) == {"ALL"} and not host.get("CapAdd"), "capability_configuration")
        require(any(option.split(":")[0] == "no-new-privileges" for option in host.get("SecurityOpt", [])), "no_new_privileges")
        require(host["Memory"] == 512 * 1024 * 1024 and host["NanoCpus"] == 1000000000 and host["PidsLimit"] == 64,
                "resource_limits")
        core = next((limit for limit in host.get("Ulimits", []) if limit["Name"] == "core"), None)
        require(core and core["Soft"] == 0 and core["Hard"] == 0, "core_limit")
        expected_logging = {"Type": "none", "Config": {}} if setup else {"Type": "json-file", "Config": {"max-file": "2", "max-size": "5m"}}
        require(host["LogConfig"] == expected_logging, "log_rotation")
        require(set(item["NetworkSettings"]["Networks"]) == {expected["network"]}, "isolated_compose_network")
        ports = item["NetworkSettings"]["Ports"]
        if setup:
            require(not host.get("PortBindings") and all(value is None for value in ports.values()), "setup_published_ports")
            require(item["Config"]["Cmd"] == ["python", "-m", "eapolkit.setup"] and item["Config"]["Tty"],
                    "setup_command_or_terminal")
            binding = None
        else:
            require(set(ports) == {"8080/tcp"} and len(ports["8080/tcp"]) == 1, "published_ports")
            binding = ports["8080/tcp"][0]
            require(binding["HostIp"] == args.bind_address and 0 < int(binding["HostPort"]) < 65536, "localhost_publication")
        data_mount = next((mount for mount in item["Mounts"] if mount["Destination"] == "/data"), None)
        require(data_mount and data_mount["Type"] == "volume" and data_mount["Name"] == expected["volume"] and data_mount["RW"],
                "named_data_volume")
        metadata_code = """import json, os, pathlib, stat
root = pathlib.Path('/data')
paths = [root, *root.rglob('*')]
if len(paths) > 128:
    raise RuntimeError('Owned data inventory exceeded its bound')
records = []
total_bytes = 0
for path in paths:
    value = path.lstat()
    if stat.S_ISREG(value.st_mode):
        total_bytes += value.st_size
    if total_bytes > 16 * 1024**2:
        raise RuntimeError("Owned data byte bound")
    records.append({'path': str(path), 'uid': value.st_uid, 'gid': value.st_gid,
                    'mode': value.st_mode & 0o777, 'directory': stat.S_ISDIR(value.st_mode),
                    'ordinary': stat.S_ISDIR(value.st_mode) or stat.S_ISREG(value.st_mode)})
status = pathlib.Path('/proc/self/status').read_text().splitlines()
cap = int(next(line.split()[1] for line in status if line.startswith('CapEff:')), 16)
flags = os.statvfs('/tmp').f_flag
web_processes = native_processes = 0
for proc in pathlib.Path('/proc').iterdir():
    if proc.name.isdecimal():
        try:
            argv = (proc/'cmdline').read_bytes().split(b'\\0')
            web_processes += b'uvicorn' in argv
            native_processes += (proc/'comm').read_text().strip() == 'eapol_test'
        except FileNotFoundError:
            pass
print(json.dumps({'uid': os.getuid(), 'gid': os.getgid(), 'cap_eff': cap,
                  'root_readonly': bool(os.statvfs('/').f_flag & os.ST_RDONLY),
                  'tmp_noexec': bool(flags & os.ST_NOEXEC), 'tmp_nosuid': bool(flags & os.ST_NOSUID),
                  'tmp_nodev': bool(flags & os.ST_NODEV),
                  'tmp_bytes': os.statvfs('/tmp').f_blocks * os.statvfs('/tmp').f_frsize,
                  'data': records, 'data_bytes': total_bytes,
                  'web_server_processes': web_processes, 'native_processes': native_processes}))
"""
        metadata = json.loads(command(["docker", "exec", "-i", name, "python", "-"],
                                      input_bytes=metadata_code.encode()).stdout)
        require(metadata["uid"] == 10001 and metadata["gid"] == 10001 and metadata["cap_eff"] == 0, "actual_process_identity")
        if setup:
            require(metadata["web_server_processes"] == 0 and metadata["native_processes"] == 0,
                    "setup_started_server_or_native_process")
        require(metadata["root_readonly"] and metadata["tmp_noexec"] and metadata["tmp_nosuid"] and metadata["tmp_nodev"]
                and metadata["tmp_bytes"] == 32 * 1024 * 1024, "actual_filesystem_controls")
        for entry in metadata["data"]:
            require(entry["ordinary"] and entry["uid"] == 10001 and entry["gid"] == 10001
                    and entry["mode"] == (0o700 if entry["directory"] else 0o600), "private_volume_ownership")
        return {"container_id": item["Id"], "port": int(binding["HostPort"]) if binding else None, "health": "not_started" if setup else "healthy",
                "data_volume": data_mount["Name"], "controls_verified": True, "actual_process": metadata}

    def installed_evidence(name):
        root = args.compose.parent
        inputs = {"/app/src/" + str(path.relative_to(root / "src")): path
                  for path in (root / "src").rglob("*") if path.is_file()
                  and "__pycache__" not in path.parts and path.suffix != ".pyc"}
        inputs["/app/requirements.lock"] = root / "requirements.lock"
        inputs["/usr/local/bin/eapolkit-entrypoint"] = root / "runtime/entrypoint.sh"
        for relative in ("source.env", "eapol_test.config", "SOURCE.md"):
            inputs["/usr/local/share/doc/eapol_test/" + relative] = root / "runtime" / relative
        for directory in ("patches", "licenses"):
            for path in (root / "runtime" / directory).iterdir():
                if path.is_file():
                    inputs["/usr/local/share/doc/eapol_test/" + directory + "/" + path.name] = path
        for notice in ("LICENSE", "THIRD_PARTY_NOTICES.md"):
            inputs["/usr/local/share/doc/eapol-test-kit/" + notice] = root / notice
        require(1 <= len(inputs) <= 128, "installed_input_bound")
        expected_hashes = {destination: hashlib.sha256(source.read_bytes()).hexdigest()
                           for destination, source in inputs.items()}
        locked = dict(line.split("==", 1) for line in (root / "requirements.lock").read_text().splitlines()
                      if line.strip() and not line.startswith("#"))
        proof = ("import hashlib,importlib.metadata,json; from pathlib import Path; "
                 "paths=" + repr(sorted(inputs)) + "; "
                 "packages=" + repr(sorted(locked)) + "; "
                 "print(json.dumps({'installed_input_sha256':{p:hashlib.sha256(Path(p).read_bytes()).hexdigest() for p in paths},"
                 "'eapol_test_sha256':hashlib.sha256(Path('/usr/local/bin/eapol_test').read_bytes()).hexdigest(),"
                 "'locked_dependency_versions':{p:importlib.metadata.version(p) for p in packages}}))")
        observed = json.loads(command(["docker", "exec", "-i", name, "python", "-"], input_bytes=proof.encode()).stdout)
        require(observed["installed_input_sha256"] == expected_hashes and
                observed["locked_dependency_versions"] == locked, "installed_source_or_dependency_mismatch")
        state.update(observed)
        state["native_hash_matches_previous_candidate"] = observed["eapol_test_sha256"] == \
            "6b10e7423b60c772ac7eb8165049324f4c30f24dfa53d7831d4a1ab46e7c39e1"
        packaging = command(["docker", "exec", "-i", name, "/usr/local/bin/eapolkit-entrypoint", "python", "-"],
                            input_bytes=(root / "runtime/tests/check_image.py").read_bytes())
        state["packaging"] = json.loads(packaging.stdout)
        require(state["packaging"]["packaging"] == "passed", "canonical_packaging_check_failed")

    def client(port):
        jar = http.cookiejar.CookieJar()
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPCookieProcessor(jar))

        def request(method, path, data=None, csrf=None, *, host=None, origin=None, marker=True):
            authority = args.bind_address + ":" + str(port)
            headers = {"Host": host or authority, "Origin": origin or "http://" + authority}
            if marker:
                headers["X-EapolKit-Request"] = "1"
            if csrf is not None:
                headers["X-CSRF-Token"] = csrf
            payload = None
            if data is not None:
                headers["Content-Type"] = "application/json"
                payload = json.dumps(data).encode()
            query = urllib.request.Request("http://" + args.bind_address + ":" + str(port) + path,
                                           data=payload, headers=headers, method=method)
            try:
                response = opener.open(query, timeout=5)
            except urllib.error.HTTPError as error:
                response = error
            with response:
                status = response.status
                raw = response.read(128 * 1024 + 1)
            require(len(raw) <= 128 * 1024, "http_response_bound")
            if any(cookie.name == "eapolkit_session" for cookie in jar):
                require(all(cookie.secure is False and cookie.has_nonstandard_attr("HttpOnly") and
                            cookie.get_nonstandard_attr("SameSite", "").lower() == "strict"
                            for cookie in jar if cookie.name == "eapolkit_session"), "default_session_cookie_controls")
            body = json.loads(raw)
            if isinstance(body, dict) and isinstance(body.get("csrf_token"), str):
                sentinels.append(body["csrf_token"])
            sentinels.extend(cookie.value for cookie in jar)
            return status, body
        return request

    def check_logs():
        # Docker can return stderr log records on the command's stderr pipe too.
        result = command(["docker", "logs", "--tail", "200", expected["container"]])
        output = result.stdout + result.stderr
        for sentinel in sentinels:
            raw = sentinel.encode()
            forms = (raw, raw.hex().encode(), base64.b64encode(raw), json.dumps(sentinel).encode(),
                     urllib.parse.quote(sentinel, safe="").encode())
            require(all(form not in output for form in forms), "credential_in_container_log")

    try:
        free = shutil.disk_usage(args.work_dir).free
        memory = int(next(line.split()[1] for line in Path("/proc/meminfo").read_text().splitlines()
                          if line.startswith("MemAvailable:"))) * 1024
        state["preflight"] = {"disk_available_bytes": free, "memory_available_bytes": memory}
        require(free >= 10 * 1024**3 and memory >= 3 * 1024**3, "resource_preflight")
        command(["docker", "compose", "version", "--short"])
        image = inspect("image", args.image)
        require(image["Id"] == args.expected_image_id, "candidate_image_identity")
        labels = image["Config"].get("Labels") or {}
        require(labels.get("org.eapolkit.project") == "eapol-test-kit", "candidate_project_label")
        digest = args.expected_image_id.removeprefix("sha256:")
        require(re.fullmatch(r"[0-9a-f]{64}", digest) is not None, "candidate_image_digest")
        project = args.project_name or "eapolkit-compose-smoke-" + digest[:12]
        expected = {"container": project + "-kit-1", "network": project + "_default", "volume": project + "_kit-data"}
        if args.setup_mode == "cli":
            oneoffs.update({project + "-setup-1", project + "-setup-refuse-1"})
        state.update({"project": project, "expected_resources": expected,
                      "expected_oneoff_names": sorted(oneoffs)})
        for kind, name in expected.items():
            require(not project_names(kind, project) and inspect(kind, name, missing_ok=True) is None, "smoke_resources_already_exist")
        for name in oneoffs:
            require(inspect("container", name, missing_ok=True) is None, "setup_name_already_exists")
        state["exact_names_initially_unused"] = True
        shipped_bytes = args.compose.read_bytes()
        state["shipped_compose_path"] = str(args.compose)
        state["shipped_compose_sha256"] = hashlib.sha256(shipped_bytes).hexdigest()
        shipped = args.work_dir / "shipped-compose.yaml"
        override = args.work_dir / "image-override.yaml"
        with shipped.open("xb") as output:
            output.write(shipped_bytes)
        with override.open("x") as output:
            output.write("services:\n  kit:\n    image: " + json.dumps(args.image) + "\n")
        environment_file = "/dev/null"
        if args.setup_mode == "cli":
            environment_file = str(args.work_dir / ".env")
            with open(environment_file, "x") as output:
                output.write("EAPOLKIT_BIND_ADDRESS=" + args.bind_address + "\nEAPOLKIT_PORT=0\n")
        compose = ["docker", "compose", "--env-file", environment_file, "--project-directory", str(args.compose.parent),
                   "--project-name", project, "--file", str(shipped), "--file", str(override)]
        config = json.loads(compose_command("config", "--format", "json").stdout)
        require(set(config["services"]) == {"kit"} and config["services"]["kit"]["image"] == args.image,
                "shipped_service_configuration")
        if args.setup_mode == "cli":
            require(config["services"]["kit"]["environment"]["EAPOLKIT_BIND_ADDRESS"] == args.bind_address and
                    not config["services"]["kit"]["environment"].get("EAPOLKIT_ALLOWED_HOSTS"), "bind_default_host_configuration")
            setup_override = args.work_dir / "setup-logging-override.yaml"
            with setup_override.open("x") as output:
                output.write("services:\n  kit:\n    logging: !override\n      driver: none\n")
            setup_compose = [*compose, "--file", str(setup_override)]
            setup_config = json.loads(command([*setup_compose, "config", "--format", "json"]).stdout)
            require(setup_config["services"]["kit"]["logging"] == {"driver": "none"}, "setup_logging_configuration")
            state["setup_compose_fields_overridden"] = ["services.kit.logging"]
            state["public_environment_fields"] = ["EAPOLKIT_BIND_ADDRESS", "EAPOLKIT_PORT"]
            state["phase"] = "private_terminal_setup"
            save()
            creation_attempted = True
            def verified_setup():
                state["resources"] = owned_resources()
                state["setup_container"] = container_state(project + "-setup-1", setup=True)
                state["setup_has_no_published_ports"] = True
                installed_evidence(project + "-setup-1")
                save()
            password = terminal_setup([*setup_compose, "run", "--rm", "--no-deps", "--pull", "never", "--name", project + "-setup-1",
                                       "kit", "python", "-m", "eapolkit.setup"], verified_setup)
            sentinels.extend((password, password[:64], password[-64:]))
            require(inspect("container", project + "-setup-1", missing_ok=True) is None, "setup_container_not_removed")
            state["terminal_setup_passed"] = True
            state["terminal_maximum_utf8_input"] = True
            save()
        state["phase"] = "initial_start"
        save()
        creation_attempted = True
        compose_command("up", "--detach", "--no-build", "--pull", "never", "--wait", "--wait-timeout", "120", "kit")
        state["resources"] = owned_resources()
        state["phase"] = "initial_controls"
        first = container_state()
        state["initial_container"] = first
        save()
        api = client(first["port"])
        status, session = api("GET", "/api/session")
        require(status == 200 and session["setup_required"] == (args.setup_mode == "web") and
                not session["authenticated"], "fresh_setup_state")
        if args.setup_mode == "web":
            password = secrets.token_urlsafe(48)
            shared_secret = "\r\n" + secrets.token_urlsafe(48) + "é\r\n"
            sentinels.extend((password, shared_secret))
        state["phase"] = "setup_and_record" if args.setup_mode == "web" else "initialized_http_login"
        status, session = api("POST", "/api/setup" if args.setup_mode == "web" else "/api/login", {"password": password})
        require(status == 200 and session["authenticated"] and not session["setup_required"], "setup_authentication")
        if args.setup_mode == "cli":
            state["full_original_utf8_password_login"] = True
        csrf = session["csrf_token"]
        status, health = api("GET", "/api/status")
        require(status == 200 and health["eapol_test_available"] and health["active_run_id"] is None, "application_health")
        if args.setup_mode == "web":
            record = {"name": "Compose smoke target", "host": "192.0.2.10", "secret": shared_secret}
            status, target = api("POST", "/api/targets", record, csrf)
            require(status == 200 and target.get("has_secret") is True and "secret" not in target and "_secret" not in target,
                    "private_target_record")
            saved_id = target["id"]
        else:
            require(api("GET", "/api/session", host="unexpected.invalid")[0] == 400, "unexpected_host_accepted")
            require(api("GET", "/api/session", origin="http://foreign.invalid")[0] == 403, "foreign_origin_accepted")
            require(api("POST", "/api/logout", csrf=csrf, marker=False)[0] == 403, "missing_marker_accepted")
            require(api("POST", "/api/logout")[0] == 403, "missing_csrf_accepted")
            require(api("GET", "/api/runs") == (200, []), "unexpected_authentication_record")
            state["http_authority_csrf_cookie_checks"] = True
        check_logs()
        if args.setup_mode == "cli":
            state["phase"] = "existing_setup_refusal"
            save()
            require(inspect("container", expected["container"])["Id"] == first["container_id"], "app_changed_before_stop")
            command(["docker", "stop", "--time", "15", first["container_id"]], timeout=25)
            terminal_setup([*setup_compose, "run", "--rm", "--no-deps", "--pull", "never", "--name", project + "-setup-refuse-1",
                            "kit", "python", "-m", "eapolkit.setup"],
                           lambda: require(False, "refusal_requested_input"), already_initialized=True)
            require(inspect("container", project + "-setup-refuse-1", missing_ok=True) is None, "refusal_container_not_removed")
            state["existing_setup_refused_without_input"] = True
        state["phase"] = "owned_container_recreate"
        save()
        compose_command("up", "--detach", "--no-build", "--pull", "never", "--force-recreate", "--no-deps",
                        "--wait", "--wait-timeout", "120", "kit")
        state["phase"] = "recreated_controls"
        second = container_state()
        require(second["container_id"] != first["container_id"] and second["data_volume"] == first["data_volume"], "container_recreation")
        state["recreated_container"] = second
        api = client(second["port"])
        status, session = api("GET", "/api/session")
        require(status == 200 and not session["setup_required"] and not session["authenticated"], "saved_setup_state")
        status, _ = api("GET", "/api/targets")
        require(status == 401, "saved_password_protection")
        status, session = api("POST", "/api/login", {"password": password})
        require(status == 200 and session["authenticated"], "saved_password_login")
        status, targets = api("GET", "/api/targets")
        if args.setup_mode == "web":
            require(status == 200 and len(targets) == 1 and targets[0]["id"] == saved_id
                    and targets[0]["name"] == record["name"] and targets[0]["host"] == record["host"]
                    and targets[0].get("has_secret") is True and "secret" not in targets[0] and "_secret" not in targets[0],
                    "saved_record_persistence")
        else:
            require(status == 200 and targets == [] and api("GET", "/api/runs") == (200, []), "unexpected_test_records")
            state["cli_password_persisted_without_overwrite"] = True
            state["full_original_utf8_password_persisted"] = True
        check_logs()
        state.update({"tests_passed": True, "fresh_setup_and_health": True, "saved_password_login": True,
                      "saved_record_persisted": args.setup_mode == "web", "credential_sentinels_absent_from_logs": True,
                      "compose_fields_overridden": ["services.kit.image"], "phase": "cleanup"})
    except Exception as error:
        state["failure_phase"] = state["phase"]
        state["failure_code"] = str(error) if isinstance(error, SmokeFailure) else "unexpected_smoke_failure"
    finally:
        if args.setup_mode == "cli":
            for signum in (signal.SIGHUP, signal.SIGTERM, signal.SIGINT):
                signal.signal(signum, signal.SIG_IGN)
            signal.alarm(60)
        if creation_attempted:
            try:
                cleanup_resources()
                cleanup_complete = True
            except Exception:
                state["cleanup_failure"] = "owned_project_cleanup_incomplete"
        state["cleanup_complete"] = cleanup_complete
        state["state"] = "passed" if state.get("tests_passed") and cleanup_complete else "failed"
        state["ended_utc"] = datetime.now(timezone.utc).isoformat()
        state["postflight"] = {"disk_available_bytes": shutil.disk_usage(args.work_dir).free}
        save()
        if args.setup_mode == "cli":
            signal.alarm(0)
    print(json.dumps({"state": state["state"], "project": project, "receipt": str(receipt_path),
                      "cleanup_complete": cleanup_complete,
                      "failure_phase": state.get("failure_phase"), "failure_code": state.get("failure_code")}))
    return 0 if state["state"] == "passed" else 1


if __name__ == "__main__":
    signal.signal(signal.SIGALRM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGHUP, interrupted)
    try:
        sys.exit(main())
    except Exception:
        print(json.dumps({"state": "failed", "failure_code": "smoke_preparation_failed"}))
        sys.exit(1)
