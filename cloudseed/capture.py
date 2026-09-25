"""Detached bounded command-output collector for MCP.

The collector owns the pipes and survives the MCP transport. A server shutdown
therefore does not break Terraform's stdout halfway through an apply. Each output
file contains a bounded head/tail snapshot, never an unbounded append-only log.
"""
from __future__ import annotations
import json
from pathlib import Path
import os
import selectors
import signal
import subprocess
import sys

LIMIT = 128 * 1024
MARK = b"\n...[output truncated: retained beginning and end]...\n"


class Tail:
    def __init__(self, limit=LIMIT):
        self.limit = limit
        self.head = b""
        self.tail = b""
        self.total = 0

    def add(self, data):
        self.total += len(data)
        half = (self.limit - len(MARK)) // 2
        need = max(0, half - len(self.head))
        self.head += data[:need]
        self.tail = (self.tail + data[need:])[-(self.limit - len(self.head)):]
        if self.total > self.limit:
            self.tail = self.tail[-half:]

    def value(self):
        if self.total <= self.limit:
            return self.head + self.tail
        # Cut only at complete lines. Truncating in the middle of a credential
        # would leave an unrecognisable fragment for the parent's redactor.
        head = self.head[:self.head.rfind(b"\n") + 1]
        newline = self.tail.find(b"\n")
        tail = self.tail[newline + 1:] if newline >= 0 else b""
        return head + MARK + tail


class SafeStream:
    """Redact complete lines before bounded truncation can discard their context.

    A single overlong line closes this stream's capture rather than emitting an
    unrecognisable credential fragment. The child is still drained to completion.
    """
    def __init__(self, redactor, limit=LIMIT):
        self.redactor = redactor
        self.tail = Tail(limit)
        self.pending = b""
        self.suppressed = False
        self.limit = limit

    def add(self, data):
        if self.suppressed:
            return
        self.pending += data
        while b"\n" in self.pending:
            line, self.pending = self.pending.split(b"\n", 1)
            if len(line) > self.limit or (self.redactor.in_key and self.redactor._n >= self.redactor.MAX_KEY_LINES - 1):
                self._suppress()
                return
            safe = self.redactor.feed(line.decode("utf-8", "replace") + "\n").encode()
            self.tail.add(safe)
        if len(self.pending) > self.limit:
            self._suppress()

    def _suppress(self):
        self.suppressed = True
        self.pending = b""
        self.tail.add(b"\n...[remaining output omitted: oversized or unterminated sensitive line]...\n")

    def finish(self):
        if self.pending and not self.suppressed:
            self.tail.add(self.redactor.feed(self.pending.decode("utf-8", "replace")).encode())
        self.pending = b""

    def value(self):
        return self.tail.value()


def _redaction_module():
    # Source runtimes execute this file directly. Remove its package directory
    # from sys.path so cloudseed/secrets.py cannot shadow Python's stdlib secrets.
    if not __package__:
        directory = Path(__file__).resolve().parent
        sys.path[:] = [str(directory.parent), *[p for p in sys.path if Path(p or os.getcwd()).resolve() != directory]]
        from cloudseed import secrets
    else:
        from . import secrets
    secrets.set_strict(True)
    before = dict(os.environ)
    try:
        # The broker holds literal credentials outside this collector's inherited
        # environment. Register them for redaction, then restore the boundary.
        secrets.restore_session_env()
        secrets.register_env_secrets()
    finally:
        os.environ.clear()
        os.environ.update(before)
    return secrets


def _snapshot(fd, data):
    # The parent opens an O_APPEND spool; truncate then append a full snapshot.
    # Readers can see a partial progress snapshot; the terminal snapshot is read
    # only after this process exits. The descriptor stays private and unlinked.
    os.ftruncate(fd, 0)
    os.lseek(fd, 0, os.SEEK_SET)
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        view = view[written:]


def main(args=None):
    spec = json.loads((sys.argv[1:] if args is None else args)[0])
    if not isinstance(spec.get("argv"), list) or not spec["argv"] or not all(isinstance(x, str) for x in spec["argv"]):
        return 2
    # Signals are delivered to the process group. Let the command handle its
    # signal and drain its final output; do not kill the collector prematurely.
    for sig in (signal.SIGINT, signal.SIGTERM, getattr(signal, "SIGHUP", signal.SIGTERM)):
        signal.signal(sig, lambda *_: None)
    split = bool(spec.get("split"))
    secrets = _redaction_module()
    child = subprocess.Popen(spec["argv"], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE if split else subprocess.STDOUT)
    sel = selectors.DefaultSelector()
    streams = [(child.stdout, 1)] + ([(child.stderr, 2)] if split else [])
    tails = {fd: SafeStream(secrets.StreamRedactor(auth=True)) for _, fd in streams}
    for stream, fd in streams:
        os.set_blocking(stream.fileno(), False)
        sel.register(stream, selectors.EVENT_READ, fd)
    try:
        while sel.get_map():
            ready = sel.select(0.1)
            for key, _ in ready:
                data = os.read(key.fileobj.fileno(), 65536)
                if not data:
                    sel.unregister(key.fileobj)
                    continue
                tails[key.data].add(data)
                _snapshot(key.data, tails[key.data].value())
            if child.poll() is not None and not ready:
                break  # inherited background-process descriptors cannot hold a tool call open
        rc = child.wait()
        for fd, tail in tails.items():
            tail.finish()
            _snapshot(fd, tail.value())
        return rc if rc >= 0 else 128 - rc
    finally:
        sel.close()
        for stream, _ in streams:
            stream.close()


if __name__ == "__main__":
    raise SystemExit(main())
