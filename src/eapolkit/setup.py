"""Set the initial workbench password from an interactive terminal."""
from __future__ import annotations

import codecs
import os
import signal
import sys
import termios

from pydantic import ValidationError

from .auth import Auth
from .models import PasswordInput
from .settings import Settings
from .storage import Store


_ALREADY_COMPLETE = "Setup is already complete; the password was not changed."


class PasswordTooLong(Exception):
    """Reject an overlength entry without accepting its prefix."""


def read_password(prompt: str) -> str:
    """Read bounded UTF-8 input without the kernel's canonical line limit."""
    fd = os.open("/dev/tty", os.O_RDWR | os.O_CLOEXEC)
    try:
        original = termios.tcgetattr(fd)
        mode = original[:]
        mode[6] = original[6][:]
        mode[0] &= ~(termios.ISTRIP | termios.INLCR | termios.IGNCR | termios.ICRNL | termios.IXON | termios.PARMRK)
        mode[3] &= ~(termios.ECHO | termios.ECHONL | termios.ICANON | termios.ISIG | termios.IEXTEN)
        mode[6][termios.VMIN], mode[6][termios.VTIME] = 1, 0
        disabled = os.fpathconf(fd, "PC_VDISABLE")
        active = False

        def control(index):
            value = original[6][index]
            value = value[0] if isinstance(value, bytes) else value
            return value if value != disabled else None

        def restore():
            nonlocal active
            if active:
                # Restore immediately even when software flow control stopped output.
                termios.tcsetattr(fd, termios.TCSANOW, original)
                active = False
                termios.tcflush(fd, termios.TCIFLUSH)

        def enter():
            nonlocal active
            if os.tcgetpgrp(fd) != os.getpgrp():
                raise OSError("Password input requires the foreground terminal")
            active = True
            termios.tcsetattr(fd, termios.TCSANOW, mode)
            applied = termios.tcgetattr(fd)
            if applied[3] & (termios.ECHO | termios.ECHONL | termios.ICANON | termios.ISIG | termios.IEXTEN) or applied[0] & termios.IXON:
                raise OSError("Password input mode was not applied")

        erase = {8, 127, control(termios.VERASE)}
        extended = original[3] & termios.IEXTEN
        literal_next = control(termios.VLNEXT) if extended else None
        word_erase = control(termios.VWERASE) if extended else None
        reprint = control(termios.VREPRINT) if extended else None
        signals = {control(index): signum for index, signum in (
            (termios.VINTR, signal.SIGINT), (termios.VQUIT, signal.SIGQUIT), (termios.VSUSP, signal.SIGTSTP)
        )} if original[3] & termios.ISIG else {}
        line = []
        decoder = codecs.getincrementaldecoder("utf-8")("strict")
        quoted = False
        flow_stopped = False
        finished = False
        failure = None

        def reject(error):
            nonlocal failure
            failure = failure or error
            line.clear()
            decoder.reset()

        def complete():
            if failure is not None:
                raise failure
            return "".join(line)

        try:
            enter()
            os.write(fd, prompt.encode("ascii"))
            while True:
                value = os.read(fd, 1)
                if not value:
                    raise EOFError
                key = value[0]
                if decoder.getstate()[0] and not 0x80 <= key <= 0xBF:
                    # Recognize this control even when it ends an invalid sequence.
                    reject(UnicodeError)
                if not quoted and not decoder.getstate()[0]:
                    if key == literal_next:
                        quoted = True
                        continue
                    if original[0] & termios.IXON:
                        if key == control(termios.VSTOP):
                            termios.tcflow(fd, termios.TCOOFF)
                            flow_stopped = True
                            continue
                        if key == control(termios.VSTART) or original[0] & termios.IXANY:
                            termios.tcflow(fd, termios.TCOON)
                            flow_stopped = False
                            if finished:
                                return complete()
                        if key == control(termios.VSTART):
                            continue
                    if key in signals:
                        if flow_stopped:
                            termios.tcflow(fd, termios.TCOON)
                            flow_stopped = False
                        restore()
                        if not original[3] & termios.NOFLSH:
                            line.clear()
                            decoder.reset()
                        os.kill(os.getpid(), signals[key])
                        enter()
                        continue
                    if finished:
                        continue
                    if key in {10, 13, control(termios.VEOL), control(termios.VEOL2), control(termios.VEOF)}:
                        if key == control(termios.VEOF) and not line:
                            raise EOFError
                        if not flow_stopped:
                            return complete()
                        # Read the resume control before finishing a paused line.
                        finished = True
                        continue
                    if key in erase:
                        if line:
                            line.pop()
                        continue
                    if key == control(termios.VKILL):
                        line.clear()
                        continue
                    if key == word_erase:
                        while line and line[-1].isspace():
                            line.pop()
                        while line and not line[-1].isspace():
                            line.pop()
                        continue
                    if key == reprint:
                        continue
                quoted = False
                if finished or failure is not None:
                    continue
                try:
                    character = decoder.decode(value)
                except UnicodeError:
                    reject(UnicodeError)
                    continue
                if character:
                    if len(line) == 4096:
                        # Keep echo off until the rejected entry's line ends.
                        reject(PasswordTooLong)
                    else:
                        line.append(character)
        finally:
            try:
                if flow_stopped:
                    termios.tcflow(fd, termios.TCOON)
            finally:
                restore()
                os.write(fd, b"\n")
    finally:
        os.close(fd)


def fail(message: str) -> int:
    print(message, file=sys.stderr)
    return 1


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    if argv:
        print("Usage: python -m eapolkit.setup", file=sys.stderr)
        return 2
    try:
        if not sys.stdin.isatty():
            return fail("Setup requires an interactive terminal with password echo disabled.")
        settings = Settings()
        store = Store(settings.data_dir)
        try:
            auth = Auth(store, settings)
            if not auth.setup_required:
                return fail(_ALREADY_COMPLETE)
            try:
                password = read_password("New workbench password: ")
                confirmation = read_password("Confirm password: ")
            except PasswordTooLong:
                return fail("Password must contain 1 to 4096 characters.")
            except (OSError, termios.error, UnicodeError):
                return fail("Password input could not be read safely; setup was not completed.")
            try:
                password = PasswordInput(password=password).password
            except ValidationError:
                return fail("Password must contain 1 to 4096 characters.")
            if password != confirmation:
                return fail("Passwords do not match; setup was not completed.")
            try:
                auth.setup(password)
            except FileExistsError:
                return fail(_ALREADY_COMPLETE)
        finally:
            store.close()
    except (EOFError, KeyboardInterrupt):
        return fail("Setup cancelled. Rerun setup to check whether initialization completed.")
    except Exception:
        # Do not print exceptions that might contain password or storage details.
        return fail("Setup failed; check the data volume before trying again.")
    print("Workbench password created. You can now start the kit.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
