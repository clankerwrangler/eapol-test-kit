"""Exercise terminal input through the actual CLI with private, owned PTYs."""
from safe_assertions import require

import errno
import os
from pathlib import Path
import pty
import secrets
import select
import signal
import subprocess
import sys
import termios
import time

import pytest

from eapolkit.auth import Auth
from eapolkit.settings import Settings
from eapolkit.storage import Store


# A same-session supervisor gives the CLI a non-orphan foreground process group.
# Only PID/stop metadata uses this pipe; all generated input uses the private PTY.
SUPERVISOR = r"""
import fcntl, os, resource, signal, sys, termios
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
signal.alarm(25)
fcntl.ioctl(0, termios.TIOCSCTTY, 0)
read_gate, write_gate = os.pipe()
child = os.fork()
if child == 0:
    os.close(write_gate)
    os.setpgid(0, 0)
    os.read(read_gate, 1)
    os.close(read_gate)
    os.execv(sys.executable, [sys.executable, '-m', 'eapolkit.setup'])
os.close(read_gate)
os.setpgid(child, child)
os.tcsetpgrp(0, child)
os.write(int(sys.argv[1]), ('P ' + str(child) + '\n').encode())
os.write(write_gate, b'1')
os.close(write_gate)
while True:
    _, status = os.waitpid(child, os.WUNTRACED)
    if os.WIFSTOPPED(status):
        os.write(int(sys.argv[1]), b'S\n')
        continue
    code = os.WEXITSTATUS(status) if os.WIFEXITED(status) else 128 + os.WTERMSIG(status)
    os._exit(code)
"""


def run_terminal(directory, inputs, *, controls=None, suspend=False, flow=False, ixany=False):
    master, slave = pty.openpty()
    control_read, control_write = os.pipe()
    original = termios.tcgetattr(slave)
    for index, value in (controls or {}).items():
        original[6][index] = value
    if ixany:
        original[0] |= termios.IXANY
    termios.tcsetattr(slave, termios.TCSANOW, original)
    original = termios.tcgetattr(slave)
    environment = {"PATH": os.defpath, "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
                   "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src"),
                   "PYTHONDONTWRITEBYTECODE": "1", "EAPOLKIT_DATA_DIR": str(directory)}
    process = None
    child = None
    output = bytearray()
    control_output = bytearray()
    stage = 0
    suspended = False
    resumed = False
    stopped_output_checked = False
    flow_resume_due = None
    delayed_parts = []
    delayed_due = None
    delayed_private = True
    delayed_finished_at = None
    deadline = time.monotonic() + 15

    def send(value):
        offset = 0
        while offset < len(value):
            require(time.monotonic() < deadline, "Private terminal write exceeded its deadline")
            try:
                offset += os.write(master, value[offset:])
            except BlockingIOError:
                select.select([], [master], [], 0.01)

    def start_entry(entry):
        nonlocal delayed_parts, delayed_due
        parts = entry if isinstance(entry, tuple) else (entry,)
        send(parts[0])
        delayed_parts = list(parts[1:])
        delayed_due = time.monotonic() + 0.15 if delayed_parts else None

    try:
        process = subprocess.Popen([sys.executable, "-c", SUPERVISOR, str(control_write)],
                                   stdin=slave, stdout=slave, stderr=slave, env=environment,
                                   start_new_session=True, pass_fds=(control_write,))
        os.close(control_write)
        control_write = None
        os.set_blocking(master, False)
        os.set_blocking(control_read, False)
        while True:
            require(time.monotonic() < deadline, "Private terminal child exceeded its deadline")
            try:
                block = os.read(master, 4096)
            except BlockingIOError:
                block = b""
            except OSError as error:
                require(error.errno == errno.EIO, "Private terminal read failed")
                block = b""
            output.extend(block)
            require(len(output) <= 65536, "Private terminal output exceeded its bound")
            try:
                control_output.extend(os.read(control_read, 4096))
            except BlockingIOError:
                pass
            lines = bytes(control_output).splitlines()
            if child is None:
                identifiers = [line for line in lines if line.startswith(b"P ")]
                if identifiers:
                    child = int(identifiers[0].split()[1])
            if suspend and b"S" in lines and not resumed:
                require(termios.tcgetattr(slave) == original, "Suspend did not restore terminal attributes")
                require(child is not None, "The owned terminal child is unknown")
                os.kill(child, signal.SIGCONT)
                resumed = True
            first_prompt = b"New workbench password: " in output
            if first_prompt and stage == 0:
                flags = termios.tcgetattr(slave)[3]
                if not suspended and suspend:
                    require(not flags & (termios.ECHO | termios.ICANON), "The initial prompt is not private")
                    send(original[6][termios.VSUSP])
                    suspended = True
                elif not suspend or resumed and not flags & (termios.ECHO | termios.ICANON):
                    require(not flags & (termios.ECHO | termios.ECHONL | termios.ICANON), "Input used echo or canonical buffering")
                    if flow:
                        send(original[6][termios.VSTOP])
                    start_entry(inputs[0])
                    stage = 1
                    if flow:
                        flow_resume_due = time.monotonic() + 0.15
            if flow_resume_due is not None and time.monotonic() >= flow_resume_due:
                require(b"Confirm password: " not in output, "Configured stop did not stop output")
                send(original[6][termios.VSTART])
                stopped_output_checked = True
                flow_resume_due = None
            if delayed_due is not None and time.monotonic() >= delayed_due:
                delayed_private &= not termios.tcgetattr(slave)[3] & (termios.ECHO | termios.ECHONL | termios.ICANON)
                send(delayed_parts.pop(0))
                delayed_due = time.monotonic() + 0.15 if delayed_parts else None
                if not delayed_parts:
                    delayed_finished_at = time.monotonic()
                continue
            if stage == 1 and b"Confirm password: " in output:
                require(not delayed_parts, "An incomplete terminal entry reached confirmation")
                require(len(inputs) == 2, "An input failure reached confirmation")
                require(not termios.tcgetattr(slave)[3] & (termios.ECHO | termios.ECHONL | termios.ICANON), "Confirmation is not private")
                start_entry(inputs[1])
                stage = 2
            if process.poll() is not None and not block and not delayed_parts:
                if delayed_finished_at is None or time.monotonic() - delayed_finished_at >= 0.1:
                    break
            select.select([master, control_read], [], [], 0.01)
        require(termios.tcgetattr(slave) == original, "Terminal attributes were not restored")
        if suspend:
            require(suspended and resumed, "The owned child did not suspend and resume")
        if flow:
            require(stopped_output_checked, "Flow control was not checked")
        for entry in inputs:
            for value in entry if isinstance(entry, tuple) else (entry,):
                if len(value) >= 32:
                    require(value.rstrip(b"\r\n") not in output and value[:32] not in output,
                            "Private terminal input was echoed")
        require(delayed_private, "Failed input restored terminal echo before its line ended")
        return process.returncode
    finally:
        if child is not None and process is not None:
            try:
                if os.getsid(child) == process.pid and os.getpgid(child) == child:
                    os.killpg(child, signal.SIGKILL)
            except ProcessLookupError:
                pass
        if process is not None and process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=5)
        for fd in (master, slave, control_read, control_write):
            if fd is not None:
                os.close(fd)
        output[:] = b"\0" * len(output)


def verify_owner(directory, value=None):
    store = Store(directory)
    try:
        auth = Auth(store, Settings(data_dir=directory))
        require(auth.setup_required == (value is None), "Terminal initialization state is incorrect")
        if value is not None:
            auth.login(value)
            if len(value) > 1:
                with pytest.raises(PermissionError, match="Authentication failed"):
                    auth.login(value[:-1])
            require(value.encode() not in (directory / "eapolkit.sqlite3").read_bytes() if len(value) >= 32 else True,
                    "A terminal input reached plaintext storage")
    finally:
        store.close()


@pytest.mark.parametrize("case", ["minimum", "ascii_4095", "ascii_4096", "utf8_4096_bytes", "four_byte_4096_characters"])
def test_real_terminal_preserves_exact_supported_boundaries(tmp_path, case):
    if case == "minimum":
        value = secrets.choice("ABCDEFGH")
    elif case.startswith("ascii"):
        value = secrets.token_urlsafe(3072)[:int(case.split("_")[1])]
    elif case == "utf8_4096_bytes":
        value = secrets.choice("ABCDEFGH") + "".join(secrets.choice("éΩλЖ") for _ in range(2047)) + secrets.choice("JKLMNPQR")
    else:
        value = "".join(chr(0x1F300 + secrets.randbelow(128)) for _ in range(4096))
    directory = tmp_path / "data"
    require(run_terminal(directory, [value.encode() + b"\n"] * 2) == 0, "A supported terminal value failed")
    verify_owner(directory, value)


@pytest.mark.parametrize("case", ["overlength_first", "overlength_confirmation", "overlength_multibyte", "invalid_utf8", "eof", "interrupt", "configured_interrupt", "quit", "configured_quit"])
def test_real_terminal_failures_restore_without_initialization(tmp_path, case):
    value = secrets.token_urlsafe(3072)
    first = value.encode() + b"\n"
    inputs = [first, first]
    expected = 1
    controls = None
    if case == "overlength_first":
        inputs = [(value + "x").encode() + b"\n"]
    elif case == "overlength_confirmation":
        inputs[1] = (value + "x").encode() + b"\n"
    elif case == "overlength_multibyte":
        inputs = [("".join(chr(0x1F300 + secrets.randbelow(128)) for _ in range(4097))).encode() + b"\n"]
    elif case == "invalid_utf8":
        inputs = [b"\xff\n"]
    elif case == "eof":
        inputs = [b"\x04"]
    elif case == "interrupt":
        inputs = [secrets.token_urlsafe(32).encode() + b"\x03"]
    elif case == "configured_interrupt":
        inputs = [secrets.token_urlsafe(32).encode() + b"\x02"]
        controls = {termios.VINTR: b"\x02"}
    elif case in {"quit", "configured_quit"}:
        value = b"\x1c" if case == "quit" else b"\x1e"
        inputs = [secrets.token_urlsafe(32).encode() + value]
        controls = {termios.VQUIT: value}
        expected = 128 + signal.SIGQUIT
    directory = tmp_path / "data"
    require(run_terminal(directory, inputs, controls=controls) == expected, "A terminal failure had the wrong outcome")
    verify_owner(directory)


def test_configured_editing_and_eof_preserve_full_characters(tmp_path):
    value = secrets.token_urlsafe(32)
    controls = {termios.VERASE: b"\x05", termios.VKILL: b"\x0b", termios.VWERASE: b"\x0f", termios.VEOF: b"\x06"}
    edited = (b"discard\x0b" + value.encode() + "😀".encode() + b"\x05"
              + b"x\x08y\x7f removed word  \x0f\x0f\x05\x06")
    directory = tmp_path / "data"
    require(run_terminal(directory, [edited, value.encode() + b"\r"], controls=controls) == 0,
            "Configured terminal editing failed")
    verify_owner(directory, value)


def test_literal_next_quotes_control_data_without_signals_or_flow(tmp_path):
    value = secrets.token_urlsafe(32) + "\x00\x03\x1c\x1a\x11\x13\x08\x7f\x15\x17\x04\x01\n\r\t" + "😀"
    quote = b"\x01"
    encoded = b"".join((quote if ord(char) < 32 or ord(char) == 127 else b"") + char.encode() for char in value) + b"\n"
    directory = tmp_path / "data"
    require(run_terminal(directory, [encoded, encoded], controls={termios.VLNEXT: quote}) == 0,
            "Literal-next control data failed")
    verify_owner(directory, value)


def test_suspend_restores_then_resumes_private_foreground_input(tmp_path):
    value = secrets.token_urlsafe(32)
    directory = tmp_path / "data"
    require(run_terminal(directory, [value.encode() + b"\n"] * 2, suspend=True) == 0,
            "Terminal suspension did not resume safely")
    verify_owner(directory, value)


def test_configured_flow_stop_and_start_do_not_become_input(tmp_path):
    value = secrets.token_urlsafe(32)
    directory = tmp_path / "data"
    require(run_terminal(directory, [value.encode() + b"\n"] * 2, flow=True,
                         controls={termios.VSTOP: b"\x1f", termios.VSTART: b"\x10"}) == 0,
            "Configured terminal flow control failed")
    verify_owner(directory, value)


def test_ixany_resumes_on_ordinary_input(tmp_path):
    value = secrets.token_urlsafe(32)
    directory = tmp_path / "data"
    require(run_terminal(directory, [b"\x13" + value.encode() + b"\n", value.encode() + b"\n"], ixany=True) == 0,
            "IXANY consumed ordinary input")
    verify_owner(directory, value)


@pytest.mark.parametrize("case", ["overlength", "invalid_utf8"])
def test_failed_entry_discards_delayed_suffix_without_echo(tmp_path, case):
    prefix = secrets.token_urlsafe(3072).encode() + b"x" if case == "overlength" else secrets.token_urlsafe(32).encode() + b"\xff"
    quoted_newline = b"\x16\n" + secrets.token_urlsafe(48).encode() + b"\x15"
    suffix = secrets.token_urlsafe(48).encode() + b"\n"
    directory = tmp_path / "data"
    try:
        code = run_terminal(directory, [(prefix, quoted_newline, suffix)])
    finally:
        verify_owner(directory)
    require(code == 1, "An invalid terminal entry had the wrong outcome")


@pytest.mark.parametrize("ending", [b"\n", b"\x04", b"\x03"], ids=["enter", "eof", "interrupt"])
def test_incomplete_utf8_recognizes_unquoted_line_controls(tmp_path, ending):
    value = secrets.token_urlsafe(32).encode() + b"\xf0"
    directory = tmp_path / "data"
    require(run_terminal(directory, [value + ending]) == 1, "Incomplete UTF-8 did not end safely")
    verify_owner(directory)
