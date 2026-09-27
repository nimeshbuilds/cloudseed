"""Run PyInstaller with bounded retries for transient Apple timestamp failures.

PyInstaller 6.22.3's osx.sign_binary retains responsibility for the full codesign
command, including --timestamp, hardened runtime, entitlements and architectures.
Only that same signing call is repeated; a failed signature never becomes success.
This module can be imported on Python 3.9 without installing PyInstaller.
"""
from __future__ import annotations

import functools
import sys
import time


TIMESTAMP_ERRORS = (
    "A timestamp was expected but was not found.",
    "The timestamp service is not available.",
)


def timestamp_failure(error: SystemError) -> bool:
    # Match codesign's diagnostic output, not a filename/identity in the command
    # echo. Invalid/untrusted timestamps, keychain and certificate failures are
    # intentionally excluded: they require correction, not a service retry.
    message, separator, output = str(error).partition("\noutput: ")
    if not separator or not message.startswith("codesign command ("):
        return False
    return any(line.strip() == known or line.rstrip().endswith(": " + known)
               for line in output.splitlines() for known in TIMESTAMP_ERRORS)


def signing_with_retry(sign_binary):
    @functools.wraps(sign_binary)
    def sign(*args, **kwargs):
        for attempt in range(1, 4):
            try:
                return sign_binary(*args, **kwargs)
            except SystemError as error:
                if attempt == 3 or not timestamp_failure(error):
                    raise
                # Do not print the full exception (which includes signing
                # identity and local paths). Exhaustion retains its traceback.
                print(f"Apple timestamp service failed; retrying the same signing call "
                      f"in {attempt}s (attempt {attempt + 1}/3).", file=sys.stderr)
                time.sleep(attempt)
    return sign


def main(argv=None):
    # Keep optional third-party imports inside main, including macOS-only ones.
    from PyInstaller import __main__ as pyinstaller

    arguments = sys.argv[1:] if argv is None else argv
    if sys.platform != "darwin":
        return pyinstaller.run(arguments)

    # PyInstaller requires this check before importing its build utilities.
    pyinstaller.compat.check_requirements()
    from PyInstaller.utils import osx

    original = osx.sign_binary
    osx.sign_binary = signing_with_retry(original)
    try:
        return pyinstaller.run(arguments)
    finally:
        osx.sign_binary = original


if __name__ == "__main__":
    raise SystemExit(main())
