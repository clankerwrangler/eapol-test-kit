#!/usr/bin/env python3
"""Check final-image packaging under the production-style container controls."""
import importlib
import importlib.metadata
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


require(os.getuid() == 10001 and os.getgid() == 10001, "Unexpected runtime identity")
status = Path("/proc/self/status").read_text().splitlines()
cap_eff = next(line.split()[1] for line in status if line.startswith("CapEff:"))
require(int(cap_eff, 16) == 0, "The runtime has effective capabilities")
require(os.statvfs("/").f_flag & os.ST_RDONLY, "The root filesystem is writable")
for program in ("cc", "gcc", "g++", "make", "patch", "pkg-config", "docker", "freeradius", "radiusd", "hostapd"):
    require(shutil.which(program) is None, "A build, container-management, or server tool is installed")
require(Path("/app/src/eapolkit/app.py").is_file(), "Application source is missing")
spec = importlib.util.find_spec("eapolkit")
require(spec is not None and "/app/src/eapolkit" in list(spec.submodule_search_locations or []),
        "Application imports do not use the canonical source path")
for package in ("fastapi", "uvicorn", "cryptography", "multipart",
                "cryptography.x509", "cryptography.hazmat.primitives.asymmetric.rsa"):
    try:
        importlib.import_module(package)
    except Exception:
        raise RuntimeError("An application dependency cannot be imported") from None
lock_lines = Path("/app/requirements.lock").read_text().splitlines()
locked_dependencies = 0
for line in lock_lines:
    if not line.strip() or line.startswith("#"):
        continue
    package, separator, expected = line.partition("==")
    require(separator and package and expected, "The runtime dependency lock is malformed")
    try:
        actual = importlib.metadata.version(package)
    except importlib.metadata.PackageNotFoundError:
        raise RuntimeError("A locked runtime dependency is missing") from None
    require(actual == expected, "An installed dependency does not match the runtime lock")
    locked_dependencies += 1
require(locked_dependencies > 0, "The runtime dependency lock is empty")
version = subprocess.run(["/usr/local/bin/eapol_test", "-v"], check=True, capture_output=True, timeout=10)
require(version.stdout.strip() == b"eapol_test v2.11", "Unexpected client version")
linked = subprocess.run(["ldd", "/usr/local/bin/eapol_test"], check=True, capture_output=True, timeout=10)
require(b"libssl.so.3" in linked.stdout and b"libcrypto.so.3" in linked.stdout and b"not found" not in linked.stdout,
        "The final client is missing an OpenSSL runtime dependency")
legacy = subprocess.run(["openssl", "list", "-digest-algorithms", "-provider", "legacy"],
                        check=True, capture_output=True, timeout=10)
require(b"MD4" in legacy.stdout, "OpenSSL's MSCHAPv2 legacy primitives are unavailable")
for directory in ("/data", "/tmp"):
    with tempfile.TemporaryDirectory(dir=directory) as temporary:
        require(Path(temporary).stat().st_mode & 0o777 == 0o700, "A temporary directory is not private")
        path = Path(temporary) / "mode-check"
        path.write_bytes(os.urandom(32))
        require(path.stat().st_mode & 0o777 == 0o600, "The entrypoint did not apply its private umask")
for relative in ("source.env", "eapol_test.config", "SOURCE.md", "licenses/wpa_supplicant-COPYING",
                 "licenses/wpa_supplicant-README", "patches/0001-protected-secret-file.patch",
                 "patches/0002-native-certificate-result.patch",
                 "patches/0003-network-credential-line-bound.patch",
                 "patches/0004-protected-attribute-file.patch"):
    require((Path("/usr/local/share/doc/eapol_test") / relative).is_file(), "A source or license notice is missing")
print(json.dumps({"packaging": "passed", "uid": os.getuid(), "gid": os.getgid(),
                  "effective_capabilities": 0, "root_filesystem": "read-only",
                  "client_version": version.stdout.decode().strip(), "build_tools": False,
                  "authentication_server": False, "cryptography_import": "passed",
                  "locked_dependencies_verified": locked_dependencies, "full_app_import_checked": False}))
