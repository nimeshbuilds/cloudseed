"""Terminal look & feel for cloudseed (stdlib only).

Design: a calm, branded, high-contrast UI - boxed headers, arrow-key menus, prompts that collapse into a
tidy answer line, aligned key/value panels, spinners for waits, tables for lists. Colors degrade gracefully:
truecolor -> 256 colors -> 16 colors -> plain (pipes, NO_COLOR, non-TTY). Colour is decided per stream: warnings and
errors go to stderr and stay plain when stderr is redirected, and prompts always go to the terminal.

Everything shown is also teed (plain text, no ANSI) into the per-command log once audit.begin() set a sink.
"""

from __future__ import annotations

import itertools
import os
import re
import shutil
import sys
import textwrap
import threading
import unicodedata
from typing import Callable, Sequence

# ---------------------------------------------------------------- capabilities


def _isatty(stream) -> bool:
    try:
        return bool(stream is not None and stream.isatty())
    except (AttributeError, ValueError, OSError):
        return False


# TERM=dumb (Emacs shell/compile buffers, some CI pseudo-terminals): no colour and no cursor movement either - menus
# become numbered lists, prompts are not collapsed, spinners print one static line
_DUMB = os.environ.get("TERM") == "dumb"
_NO_COLOR = bool(os.environ.get("NO_COLOR")) or _DUMB
_IS_TTY = _isatty(sys.stdout)
_COLOR = _IS_TTY and not _NO_COLOR
_TRUECOLOR = _COLOR and os.environ.get("COLORTERM", "").lower() in ("truecolor", "24bit")
_256 = _COLOR and ("256color" in os.environ.get("TERM", "") or _TRUECOLOR)
NON_INTERACTIVE = False
_SINK = None
if os.name == "nt":  # enable ANSI on Windows consoles
    os.system("")

# brand palette (truecolor) with 256/16-color fallbacks
_PALETTE = {
    "brand": ((91, 141, 239), 69, 34),   # indigo-blue
    "leaf": ((74, 222, 128), 78, 32),    # green
    "seed": ((245, 158, 11), 214, 33),   # amber
    "rose": ((248, 113, 113), 203, 31),  # red
    "sky": ((125, 211, 252), 117, 36),   # cyan
    "text": ((226, 232, 240), 254, 37),  # near-white
    "muted": ((148, 163, 184), 245, 90), # grey
    "dim": ((100, 116, 139), 240, 90),
}


def _fg(name: str) -> str:
    if not _COLOR:
        return ""
    rgb, c256, c16 = _PALETTE[name]
    if _TRUECOLOR:
        return f"\033[38;2;{rgb[0]};{rgb[1]};{rgb[2]}m"
    if _256:
        return f"\033[38;5;{c256}m"
    return f"\033[{c16}m"


RESET = "\033[0m" if _COLOR else ""
BOLD = "\033[1m" if _COLOR else ""


def _c(code: str, s: str) -> str:
    """Legacy helper: raw ANSI code (kept for older call sites)."""
    return f"\033[{code}m{s}\033[0m" if _COLOR else s


def style(s: str, *names: str) -> str:
    if not _COLOR:
        return s
    pre = "".join(BOLD if n == "bold" else _fg(n) for n in names)
    return f"{pre}{s}{RESET}"


def bold(s: str) -> str:
    return style(s, "bold")


def dim(s: str) -> str:
    return style(s, "dim")


# ---------------------------------------------------------------- measuring text

_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")


def _strip(s: str) -> str:
    return _ANSI_RE.sub("", str(s))


def _char_width(ch: str) -> int:
    if unicodedata.combining(ch):
        return 0
    return 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1


def vis_len(s: str) -> int:
    """Columns a string occupies on screen: ANSI codes count 0, east-asian wide characters 2."""
    t = _strip(s)
    if t.isascii():
        return len(t)
    return sum(_char_width(ch) for ch in t)


def cols() -> int:
    """The real terminal width (no clamping): use it for cursor and row math."""
    return max(1, shutil.get_terminal_size((100, 24)).columns)


def term_rows() -> int:
    """The real terminal height in rows (24 when it cannot be told)."""
    return max(1, shutil.get_terminal_size((100, 24)).lines)


def stdout_is_tty() -> bool:
    """Is stdout a terminal right now? (Piped output keeps values whole, so scripts can grep them.)"""
    return _isatty(sys.stdout)


def width() -> int:
    """Layout width for panels, headers and wrapping: the terminal width, kept between 40 and 110 columns."""
    return max(40, min(cols(), 110))


def rows_for(s: str) -> int:
    """How many terminal rows `s` takes once the terminal wraps it."""
    c = cols()
    return sum(max(1, -(-vis_len(part) // c)) for part in str(s).split("\n"))


def fit(s: str, n: int) -> str:
    """Plain text cut to at most `n` columns, ending with '…' when something was cut."""
    t = _strip(s)
    if vis_len(t) <= n:
        return t
    if n <= 1:
        return "…" if n == 1 else ""
    out, used = [], 0
    for ch in t:
        w = _char_width(ch)
        if used + w > n - 1:
            break
        out.append(ch)
        used += w
    return "".join(out).rstrip() + "…"


def clip(text: str, n: int) -> str:
    """Like fit(), but cuts at a word boundary when one is reasonably close (for descriptions)."""
    t = " ".join(_strip(text).split())
    if vis_len(t) <= n:
        return t
    body = fit(t, n)[:-1]
    cut = body.rfind(" ")
    if cut >= n * 0.6:
        body = body[:cut]
    return body.rstrip(" ,;:-(") + "…"


def _ljust(s: str, n: int) -> str:
    """Pad to `n` visible columns (ANSI codes do not count)."""
    return s + " " * max(0, n - vis_len(s))


# ---------------------------------------------------------------- output plumbing

def set_sink(fn) -> None:
    global _SINK
    _SINK = fn


def _tee(prefix: str, msg) -> None:
    """Copy what the user sees into the command log: plain text, no ANSI codes, no box drawing."""
    if _SINK:
        try:
            text = _strip(str(msg))
            _SINK(f"{prefix} {text}" if prefix else text)
        except Exception:
            pass


def _write(stream, text: str) -> None:
    try:
        stream.write(text)
        stream.flush()
    except (OSError, ValueError):
        pass


def _flush_stdout() -> None:
    try:
        sys.stdout.flush()
    except (OSError, ValueError):
        pass


def eprint(text: str = "", tee: bool = False) -> None:
    """Print to stderr; ANSI styling is dropped when stderr is not a terminal (e.g. `2>err.log`)."""
    _flush_stdout()
    try:
        print(text if _isatty(sys.stderr) else _strip(text), file=sys.stderr, flush=True)
    except (OSError, ValueError):
        pass
    if tee:
        _tee("", text)


def line(text: str = "") -> None:
    """print() for content lines that belong in the command log too."""
    print(text)
    _tee("", text)


def _indent_rest(msg, stream=None) -> str:
    """Continuation lines of a multi-line message line up under its first line (after the glyph). On a terminal
    (`stream` is one) a line wider than it is also wrapped there, with the same hanging indent; piped output and the
    command log keep every line whole, so scripts can grep them."""
    text = str(msg)
    if stream is not None and _isatty(stream):
        return "\n    ".join(_wrap_message_lines(text, cols() - 1 - 4))
    return text.replace("\n", "\n    ")


# A command a message tells the user to run is never split across two lines when a message is wrapped: a pasted first
# half would run on its own (`cloudseed destroy aws` without its --env). Such a span - `quoted`, a cloudseed command,
# or another tool's command where one is expected (after ': ', '(', 'run ', 'with ' ...) - stays one piece up to the end
# of its clause; a piece wider than the terminal is left to the terminal's own soft wrap.
_CMD_TAIL = (r" (?!\(|(?:is|was|are|has|had|have|not|can|cannot|could|does|did|will|would|and|or|then|the|a|an|to|in|on|"
             r"of|for|with|from|at|as|by|that|which|it|its|itself|CLI|binary|too|also|only|first|there|here|when|while|"
             r"but)\b)(?:(?!; |\. |, | {2}| \(| · |\)(?: |$)).)*[^\s.,;:)](?=[\s.,;:)]|$)")
_CMD_SPAN = re.compile(
    r"`[^`\n]+`"
    r"|(?<![\w./=-])(?<!= )(?:cloudseed|cs)" + _CMD_TAIL +
    r"|(?:^|(?<=: )|(?<=\()|(?<=\. )|(?<=run )|(?<=Run )|(?<=with )|(?<=then )|(?<=or ))"
    r"(?:terraform|kubectl|helm|ssh|sudo|export|brew|launchctl|systemctl|gcloud|az|aws|git|pip3?|npm|docker|podman|"
    r"tailscale|ansible-playbook)" + _CMD_TAIL)


def _wrap_message_lines(text: str, room: int) -> list[str]:
    """The lines of a message wrapped to `room` columns at spaces (ANSI codes count 0), never inside a command span
    (_CMD_SPAN). A continuation of a '- item' line lines up under the item's text."""
    room = max(20, room)
    out: list[str] = []
    for para in text.split("\n"):
        body = para.lstrip(" ")
        pre = para[:len(para) - len(body)]
        if not body or vis_len(para) <= room:
            out.append(para)
            continue
        hang = pre + ("  " if body[:2] in ("- ", "* ", "• ") else "")
        guarded = _CMD_SPAN.sub(lambda m: m.group(0).replace(" ", "\x00"), body)
        parts = re.split(r"( +)", guarded)           # words, and the runs of spaces between them
        cur = pre + parts[0]
        for gap, word in zip(parts[1::2], parts[2::2]):
            if vis_len(cur) + len(gap) + vis_len(word) <= room or not cur.strip():
                cur += gap + word
            else:
                out.append(cur.replace("\x00", " "))
                cur = hang + word
        out.append(cur.replace("\x00", " "))
    return out


# ---------------------------------------------------------------- messages

GLYPH = {"info": "●", "ok": "✔", "warn": "▲", "err": "✖", "step": "◆"}


def info(msg: str) -> None:
    print(f"  {style(GLYPH['info'], 'brand')} {_indent_rest(msg, sys.stdout)}")
    _tee("●", msg)


def ok(msg: str) -> None:
    print(f"  {style(GLYPH['ok'], 'leaf', 'bold')} {_indent_rest(msg, sys.stdout)}")
    _tee("✔", msg)


def warn(msg: str) -> None:
    eprint(f"  {style(GLYPH['warn'], 'seed', 'bold')} {_indent_rest(msg, sys.stderr)}")
    _tee("!", msg)


def err(msg: str) -> None:
    eprint(f"  {style(GLYPH['err'], 'rose', 'bold')} {_indent_rest(msg, sys.stderr)}")
    _tee("✖", msg)


def hints(parts: Sequence[str], indent: str = "  ") -> None:
    """A dim footer of short hints (`cs creds set KEY` · ...): one row when it fits the terminal (with tighter
    separators first), else as many rows as needed, never cutting a hint. Piped output keeps the one wide row."""
    parts = [str(p) for p in parts if p]
    if not parts:
        return
    room = cols() - 1
    for sep in ("   ·   ", "  ·  ", " · "):
        row = indent + sep.join(parts)
        if vis_len(row) <= room or not stdout_is_tty():
            print(dim(row))
            _tee("", row)
            return
    rows: list[str] = []
    cur = ""
    for p in parts:
        cand = f"{cur} · {p}" if cur else p
        if cur and vis_len(indent + cand) > room:
            rows.append(cur)
            cur = p
        else:
            cur = cand
    rows.append(cur)
    for r in rows:
        print(dim(indent + r))
    _tee("", indent + "   ·   ".join(parts))


def note(text: str, indent: str = "  ", hang: str = "") -> None:
    """A dim paragraph (a footer's explanation): wrapped at a terminal with `hang` extra indent on the continuation
    lines, never inside a command; piped output keeps it on one line."""
    lines = _wrap_message_lines(str(text), cols() - 1 - len(indent) - len(hang)) if stdout_is_tty() else [str(text)]
    for i, ln in enumerate(lines):
        print(dim(indent + ("" if i == 0 else hang) + ln))
    _tee("", indent + str(text))


def header(msg: str) -> None:
    """Section header:  ━━ Title ━━━━━━━━━━━━━━━━━━"""
    text = fit(msg, width() - 10)
    rule = "━" * max(4, width() - vis_len(text) - 6)
    print()
    print(f"  {style('━━', 'brand')} {style(text, 'bold', 'text')} {style(rule, 'dim')}")
    _tee("==", msg)


def step(n: int, total: int, title: str, hint: str = "") -> None:
    """Wizard step marker:  ◆ 2/6  Network   hint   (the hint is shortened or dropped to stay on one row)"""
    head = f"  {GLYPH['step']} {n}/{total}  {title}"
    room = cols() - 1 - vis_len(head) - 3
    shown_hint = fit(hint, room) if hint and room >= 12 else ""
    print()
    print(f"  {style(GLYPH['step'], 'brand')} {style(f'{n}/{total}', 'dim')}  {style(title, 'bold', 'text')}"
          + (f"   {style(shown_hint, 'muted')}" if shown_hint else ""))
    _tee("--", f"{n}/{total} {title}" + (f"  ({hint})" if hint else ""))


# where a word too long for any line is broken, when it has one of these: after a path's /, then a DNS name's or a
# Kubernetes resource's ., a list's comma, a flag's = ..., then - or _ inside a name (clusterrole.rbac.|authorization,
# not clusterrole.rbac.au|thorization; .../fixrun/|w5-cli-b/..., not .../fixrun/w5-|cli-b/...)
_BREAK_AFTER = ("/", ".,:;=@", "-_")


def _separator_cut(word: str, room: int, least: int) -> int:
    """The length of the longest head of `word` that fits in `room` characters and ends at a _BREAK_AFTER character
    (the strongest kind that gives one), if it is at least `least` long; else 0."""
    for kind in _BREAK_AFTER:
        cut = max(word.rfind(c, 0, max(1, room)) for c in kind) + 1
        if cut >= max(1, least):
            return cut
    return 0


def _split_by_width(word: str, n: int) -> list[str]:
    """Cut a word into pieces of at most `n` screen columns (each piece keeps at least one character), each after a
    _BREAK_AFTER character where one falls in the last three quarters of the piece."""
    out, cur, used = [], [], 0
    for ch in word:
        w = _char_width(ch)
        while cur and used + w > n:
            piece = "".join(cur)
            cut = _separator_cut(piece, len(piece), len(piece) // 4)
            if not 0 < cut < len(piece):
                cut = len(piece)
            out.append(piece[:cut])
            cur = cur[cut:]
            used = vis_len("".join(cur))
        cur.append(ch)
        used += w
    out.append("".join(cur))
    return out


class _Wrapper(textwrap.TextWrapper):
    """textwrap that breaks a word too long for any line after a _BREAK_AFTER character where it has one (a path, a
    DNS or resource name); a word without one is cut exactly as textwrap cuts it."""

    def _handle_long_word(self, reversed_chunks, cur_line, cur_len, width):
        width = max(1, width)
        room = width - cur_len
        if room <= 0:
            if cur_line:
                return              # this line is full: the word goes on
            room = 1
        chunk = reversed_chunks[-1]
        if cur_line:                # the rest of this line, when a sensible head of the word fits there
            cut = _separator_cut(chunk, room, max(4, room // 3))
            if not cut and _separator_cut(chunk, width, width // 4):
                return              # it breaks well on a line of its own: end this line here
        else:
            cut = _separator_cut(chunk, room, width // 4)
        cut = cut or room
        cur_line.append(chunk[:cut])
        reversed_chunks[-1] = chunk[cut:]


def _wrap(text: str, n: int) -> list[str]:
    """Wrap plain text to `n` screen columns, keeping explicit line breaks; never returns an empty list. East-Asian
    wide characters take two columns, so text with them is wrapped by display width (textwrap counts characters).
    A word longer than a line is broken after a separator where it has one (_BREAK_AFTER), else cut."""
    n = max(10, n)
    out: list[str] = []
    for para in _strip(text).split("\n"):
        if vis_len(para) == len(para):          # no wide characters: textwrap measures it right
            out += _Wrapper(n, break_long_words=True, break_on_hyphens=False).wrap(para) or [""]
            continue
        rows: list[str] = []
        cur = ""
        for word in para.split():
            cand = f"{cur} {word}" if cur else word
            if vis_len(cand) <= n:
                cur = cand
                continue
            if cur:
                rows.append(cur)
                cur = ""
            if vis_len(word) <= n:
                cur = word
            else:
                pieces = _split_by_width(word, n)
                rows += pieces[:-1]
                cur = pieces[-1]
        out += (rows + [cur]) if cur else (rows or [""])
    return out or [""]


def kv(key: str, value, width_: int = 22) -> None:
    """An aligned `key  value` row; long values wrap under the value column."""
    k = _ljust(str(key), width_)
    v = str(value)
    avail = max(20, width() - 4 - vis_len(k) - 1)
    if vis_len(v) <= avail and "\n" not in v:
        print(f"    {style(k, 'muted')} {v}")
    else:
        pieces = _wrap(v, avail)
        print(f"    {style(k, 'muted')} {pieces[0]}")
        for piece in pieces[1:]:
            print(" " * (4 + vis_len(k) + 1) + piece)
    _tee(" ", f"{_strip(str(key))}: {_strip(v)}")


def _box(lines: Sequence[str], accent: str = "brand", inner: int | None = None) -> None:
    """Draw a box around pre-styled lines, padding by visible width."""
    inner = inner or max(vis_len(l) for l in lines) + 2
    print("  " + style("╭" + "─" * inner + "╮", accent))
    for l in lines:
        pad = max(0, inner - vis_len(l) - 1)
        print("  " + style("│", accent) + " " + l + " " * pad + style("│", accent))
    print("  " + style("╰" + "─" * inner + "╯", accent))


def banner(version: str, tagline: str = "secure multi-cloud landing zones") -> None:
    if not _isatty(sys.stdout):
        print(f"cloudseed {version} - {tagline}")
        return
    name = style("cloud", "bold", "text") + style("seed", "bold", "leaf")
    lines = [
        f"{style(' ✦', 'sky')}     {name}  {style('v' + version, 'dim')}",
        f"{style(' ╱╲', 'leaf')}    {style(fit(tagline, max(20, width() - 20)), 'muted')}",
        f"{style('╱  ╲', 'leaf')}   {style('aws · gcp · azure · vmware', 'dim')}",
    ]
    print()
    _box(lines, inner=max(vis_len(l) for l in lines) + 4)


_TWO_COL = re.compile(r"^(\s*\S.*?\s{2,})(\S.*)$")


def _wrap_plain_row(plain: str, textw: int) -> list[str]:
    """Wrap one plain panel line. Two-column rows (`term    description`) hang their continuation lines under the
    description column; other lines keep their own indentation (+2)."""
    m = _TWO_COL.match(plain)
    if m and vis_len(m.group(1)) <= textw // 2:
        lead = m.group(1)
        pieces = _wrap(m.group(2), textw - vis_len(lead))
        return [lead + pieces[0]] + [" " * vis_len(lead) + p for p in pieces[1:]]
    indent = len(plain) - len(plain.lstrip())
    pieces = _wrap(plain.strip(), textw - 2 - indent)
    return [" " * indent + pieces[0]] + [" " * (indent + 2) + p for p in pieces[1:]]


_COLLECT = threading.local()


class collecting:
    """`with ui.collecting() as items:` - panels (and hint lines, see collect()) this thread would print are appended
    to `items` as data instead: ("panel", title, rows), ("hints", parts). Other threads print as usual. explain.lookup
    reads the platform catalog pages this way, so the console and MCP get the same content as the terminal."""

    def __enter__(self) -> list:
        self._prev = getattr(_COLLECT, "items", None)
        _COLLECT.items = []
        return _COLLECT.items

    def __exit__(self, *exc) -> None:
        _COLLECT.items = self._prev


def collect(kind: str, *data) -> bool:
    """Inside ui.collecting(): keep (kind, *data) and return True (the caller prints nothing); otherwise False."""
    items = getattr(_COLLECT, "items", None)
    if items is None:
        return False
    items.append((kind,) + data)
    return True


def panel(title: str, rows: Sequence[tuple[str, object]] | Sequence[str], accent: str = "brand") -> None:
    """A boxed panel with key/value rows (values wrap under the value column) or plain lines.

    Every line of the box is exactly width()-2 columns wide (plus the 2-column margin): widths are measured without
    ANSI codes, so styled keys and values line up like plain ones."""
    if collect("panel", title, list(rows)):
        return
    w = width() - 4           # columns between the two border characters
    textw = w - 2             # columns available for text ("│ " + text + " │")
    key_lens = [vis_len(str(r[0])) for r in rows if isinstance(r, tuple)]
    kcap = max(8, min(40, textw - 30))
    kw = min(max(key_lens + [8]), kcap) + 1
    body: list[str] = []
    for row in rows:
        if isinstance(row, tuple):
            k, v = row
            key, text = str(k), str(v)
            avail = max(10, textw - kw - 1)
            lead = style(_ljust(key, kw), "muted")
            if vis_len(key) >= kw:          # an over-long key gets its own line; the value goes underneath
                body.append(style(fit(key, textw), "muted"))
                lead = " " * kw
            if vis_len(text) <= avail and "\n" not in text:
                body.append(f"{lead} {text}")
            else:
                pieces = _wrap(text, avail)
                body.append(f"{lead} {pieces[0]}")
                body += [" " * (kw + 1) + piece for piece in pieces[1:]]
        else:
            text = str(row)
            if vis_len(text) <= textw and "\n" not in text:
                body.append(text)
            else:  # styling is dropped on wrapped lines
                for plain in _strip(text).split("\n"):
                    body += _wrap_plain_row(plain, textw) if vis_len(plain) > textw else [plain]
    shown_title = fit(title, w - 6)
    print()
    print(f"  {style('╭─ ', accent)}{style(shown_title, 'bold', 'text')}"
          f"{style(' ' + '─' * max(1, w - vis_len(shown_title) - 3) + '╮', accent)}")
    for text in body:
        if vis_len(text) > textw:           # never break the border, whatever a row holds
            text = fit(text, textw)
        pad = max(0, textw - vis_len(text))
        print(f"  {style('│', accent)} {text}{' ' * pad} {style('│', accent)}")
    print(f"  {style('╰' + '─' * w + '╯', accent)}")
    _tee("==", title)
    for row in rows:
        if isinstance(row, tuple):
            _tee(" ", f"{_strip(str(row[0])).strip()}: {_strip(str(row[1]))}" if _strip(str(row[0])).strip() else _strip(str(row[1])))
        else:
            _tee(" ", row)


def table(headers: Sequence[str], rows: Sequence[Sequence[object]]) -> None:
    """Columns sized to their content. On a terminal, wide columns shrink to fit and cut cells end with '…';
    piped output keeps every value whole so scripts can grep it."""
    n = len(headers)
    srows = [[str(c) for c in list(r)[:n]] + [""] * max(0, n - len(r)) for r in rows]
    widths = [vis_len(h) for h in headers]
    for r in srows:
        for i in range(n):
            widths[i] = max(widths[i], vis_len(r[i]))
    if _isatty(sys.stdout):
        widths = [min(x, 60) for x in widths]
        avail = cols() - 3 - 2 * (n - 1)
        while sum(widths) > avail:
            i = max(range(n), key=lambda j: widths[j])
            if widths[i] <= max(vis_len(headers[i]), 8):
                break
            widths[i] -= 1

    def cell(s: str, i: int) -> str:
        t = s if vis_len(s) <= widths[i] else fit(s, widths[i])
        return t if i == n - 1 else _ljust(t, widths[i])

    print("  " + "  ".join(style(cell(h, i), "muted", "bold") for i, h in enumerate(headers)))
    print("  " + style("  ".join("─" * x for x in widths), "dim"))
    for r in srows:
        print(("  " + "  ".join(cell(r[i], i) for i in range(n))).rstrip())
    _tee(" ", "  ".join(headers))
    for r in srows:
        _tee(" ", "  ".join(r))


# ---------------------------------------------------------------- spinner

_OUT_LOCK = threading.RLock()
_ACTIVE_SPINNER = None


class _GuardedStream:
    """Stands in for sys.stdout / sys.stderr while a spinner animates. Anything printed meanwhile - ui messages,
    an error, raw print() output from other modules - first erases the spinner frame, so it lands on a clean line
    and the spinner redraws below it instead of being glued to it."""

    def __init__(self, stream, spinner: "Spinner"):
        self._stream = stream
        self._spinner = spinner

    def write(self, s):
        with _OUT_LOCK:
            self._spinner._erase()
            n = self._stream.write(s)
            if s:
                self._spinner._line_open = not s.endswith("\n")
            return n

    def __getattr__(self, name):
        return getattr(self._stream, name)


class Spinner:
    """`with ui.Spinner("Waiting for SSH"):` - animated on a TTY, a single line otherwise."""

    FRAMES = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"

    def __init__(self, text: str, done: str | None = None):
        self.text, self.done_text = text, done
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._out = None
        self._saved: tuple = ()
        self._drawn = False       # a frame is on screen (the cursor sits at the end of it)
        self._line_open = False   # someone printed a partial line: don't draw over it

    def __enter__(self):
        global _ACTIVE_SPINNER
        if _isatty(sys.stdout) and not NON_INTERACTIVE and not _DUMB and _ACTIVE_SPINNER is None:
            self._out = sys.stdout
            self._saved = (sys.stdout, sys.stderr)
            sys.stdout = _GuardedStream(sys.stdout, self)
            if _isatty(sys.stderr):
                sys.stderr = _GuardedStream(sys.stderr, self)
            _ACTIVE_SPINNER = self
            self._thread = threading.Thread(target=self._spin, daemon=True)
            self._thread.start()
            _tee("…", self.text)
        else:
            line(f"  {GLYPH['info']} {self.text}...")
        return self

    def _draw(self, frame: str) -> None:
        text = fit(self.text, max(10, cols() - 5))   # never wider than the terminal: a wrapped frame can't be redrawn
        self._out.write(f"\r\033[2K  {style(frame, 'brand')} {text}")
        self._out.flush()
        self._drawn = True

    def _erase(self) -> None:
        if self._drawn:
            try:
                self._out.write("\r\033[2K")
                self._out.flush()
            except (OSError, ValueError):
                pass
            self._drawn = False

    def _spin(self):
        for frame in itertools.cycle(self.FRAMES):
            with _OUT_LOCK:
                if self._stop.is_set():
                    break
                if not self._line_open:
                    try:
                        self._draw(frame)
                    except (OSError, ValueError):
                        break
            if self._stop.wait(0.08):
                break

    def update(self, text: str) -> None:
        self.text = text

    def __exit__(self, exc_type, exc, tb):
        global _ACTIVE_SPINNER
        self._stop.set()
        if self._thread:
            self._thread.join()
            with _OUT_LOCK:
                self._erase()
                if isinstance(sys.stdout, _GuardedStream) and sys.stdout._spinner is self:
                    sys.stdout = self._saved[0]
                if isinstance(sys.stderr, _GuardedStream) and sys.stderr._spinner is self:
                    sys.stderr = self._saved[1]
            _ACTIVE_SPINNER = None
        if exc_type is None and self.done_text:
            ok(self.done_text)
        return False


# ---------------------------------------------------------------- prompts

class Abort(SystemExit):
    """Stop the current command. The message is not printed here: the top-level handler (cli._dispatch) shows it
    with show_abort(), and code that catches an Abort to carry on can use str(e), which is the message."""

    def __init__(self, msg: str = "", code: int = 1):
        self.msg = msg
        super().__init__(code)

    def __str__(self) -> str:
        return self.msg or f"exit code {self.code}"


def show_abort(e: Abort) -> None:
    """Print an Abort the way its exit code reads: 0 = a calm note (e.g. 'Cancelled. Nothing was changed.'),
    3 = stopped before applying and 130 = cancelled by the user (warnings), anything else = an error."""
    msg = getattr(e, "msg", "") or ""
    if not msg:
        return
    if e.code in (0, None):
        info(msg)
    elif e.code in (3, 130):
        warn(msg)
    else:
        err(msg)


def _prompt_stream():
    """Where prompts go: the terminal. stdout when it is one, else stderr (`cs setup aws > out.log`), never a file."""
    for s in (sys.stdout, sys.stderr):
        if _isatty(s):
            return s
    return None


def interactive() -> bool:
    """True when we may ask: not -y, input comes from a terminal and there is a terminal to show the question on."""
    return not NON_INTERACTIVE and _isatty(sys.stdin) and _prompt_stream() is not None


def _read_line(out) -> str:
    """input() without a prompt argument: CPython would write the prompt to stderr (or into a redirected stdout);
    the caller already wrote it to the terminal."""
    try:
        return input()
    except EOFError:
        _write(out, "\n")
        raise Abort("Input closed.", code=130)


def _answer_line(label: str, value: str) -> str:
    room = cols() - 1 - 9                                   # "  ✔ " + "  ·  "
    val = fit(value, max(10, room - min(vis_len(label), room // 2)))
    lab = fit(label, max(8, room - vis_len(val)))
    return f"  {style('✔', 'leaf')} {style(lab, 'muted')}  {style('·', 'dim')}  {style(val, 'text', 'bold')}"


def _answered(label: str, value: str, shown: str | None = None, out=None) -> None:
    """Replace the prompt (and the answer the terminal echoed, however many rows they wrapped to) with one compact
    answer line."""
    out = out or _prompt_stream() or sys.stdout
    if _isatty(out) and shown is not None and not _DUMB:
        _write(out, f"\033[{rows_for(shown)}A\r\033[J")
    _write(out, _answer_line(label, value) + "\n")
    _tee("?", f"{label}: {value}")


def _prompt_line(question: str, default: str | None) -> str:
    hint = f" {style('(' + default + ')', 'dim')}" if default not in (None, "") else ""
    return f"  {style('?', 'brand', 'bold')} {style(question, 'bold', 'text')}{hint} {style('›', 'brand')} "


def _mcp_argument(flag: str) -> str:
    """The MCP tool argument for a CLI flag: `--project-id VALUE` -> project_id (cloudseed_setup has that argument),
    `--var az_count=VALUE` -> vars {"az_count": ...}; a setup question whose flag the tool does not take (`--zone
    VALUE`, `--ssh-username VALUE`) goes into vars too, and any other option (`--host` of databricks connect) into the
    words of the tool's args."""
    words = flag.split()
    if not words:
        return flag
    if words[0] == "--var" and len(words) > 1:
        return 'vars {"' + words[1].split("=", 1)[0] + '": ...}'
    name = words[0].lstrip("-").replace("-", "_")
    try:
        from . import mcp as _mcp               # loaded by then (cli imports it); never at import time: mcp imports ui
        setup_args = tuple(getattr(_mcp, "_SETUP_OPTS", ()))
    except Exception:  # noqa: BLE001 - a hint must never fail the prompt
        setup_args = ()
    if name in setup_args:
        return name
    if len(words) > 1:                          # `--zone VALUE`: a setup question, answered through --var as well
        return 'vars {"' + name + '": ...}'
    return f'args "... {words[0]} VALUE"'


def ask(question: str, default: str | None = None, validate: Callable[[str], str | None] | None = None,
        required: bool = False, flag: str | None = None) -> str:
    """Prompt for a string. `validate` returns an error message or None. `flag` names the CLI flag in -y mode (for a
    call from an MCP client: the tool argument that carries it)."""
    if not interactive():
        mcp_call = os.environ.get("CLOUDSEED_AGENT") == "mcp"     # the caller cannot answer a prompt at all
        if default is None or (required and default == ""):
            if mcp_call:
                how = (f"pass {_mcp_argument(flag)} in the tool call's arguments" if flag
                       else "pass it in the tool call's arguments (vars for a stack variable)")
                raise Abort(f"'{question}' is required: {how}.")
            how = f"pass {flag}" if flag else "pass it as a flag or --var"
            raise Abort(f"'{question}' is required but no terminal is attached (-y / piped input): {how}, "
                        f"or run without -y to be prompted.")
        if validate and default:
            problem = validate(default)
            if problem:
                where = (f" (argument: {_mcp_argument(flag)})" if mcp_call else f" (flag: {flag})") if flag else ""
                raise Abort(problem + where)
        return default
    out = _prompt_stream()
    while True:
        prompt = _prompt_line(question, default)
        _write(out, prompt)
        typed = _read_line(out)
        raw = typed.strip()
        value = raw or (default or "")
        if required and not value:
            warn("A value is required.")
            continue
        if validate and value:
            problem = validate(value)
            if problem:
                warn(problem)
                continue
        _answered(question, value if value else "(empty)", shown=_strip(prompt) + typed, out=out)
        return value


def confirm(question: str, default: bool = False) -> bool:
    if not interactive():
        return default
    out = _prompt_stream()
    hint = "Y/n" if default else "y/N"
    while True:
        prompt = f"  {style('?', 'brand', 'bold')} {style(question, 'bold', 'text')} {style('[' + hint + ']', 'dim')} {style('›', 'brand')} "
        _write(out, prompt)
        typed = _read_line(out)
        raw = typed.strip().lower()
        shown = _strip(prompt) + typed
        if not raw:
            _answered(question, "yes" if default else "no", shown=shown, out=out)
            return default
        if raw in ("y", "yes"):
            _answered(question, "yes", shown=shown, out=out)
            return True
        if raw in ("n", "no"):
            _answered(question, "no", shown=shown, out=out)
            return False
        warn("Please answer y or n.")


def ask_bool(question: str, default: bool) -> bool:
    return confirm(question, default)


def _json_object_prefix(data: bytes) -> str | None:
    """The complete JSON object `data` starts with (after blanks), or None while it is not complete yet. Whatever
    follows the object (a newline, keys pressed after the paste) is not part of it."""
    text = data.decode("utf-8", "replace").lstrip()
    if not text.startswith("{") or "}" not in text:
        return None
    import json
    try:
        obj, end = json.JSONDecoder().raw_decode(text)
    except ValueError:
        return None
    return text[:end] if isinstance(obj, dict) else None


def read_hidden_blob(question: str, hint: str = "", limit: int = 65536, fd: int | None = None) -> str:
    """Read a pasted multi-line secret - a JSON key file - from the terminal without echoing it.

    getpass reads one line, so a pretty-printed key would be cut after '{' and the rest would reach the shell once
    the command exits; and a terminal in line mode drops everything past ~1024 bytes of one line (macOS MAX_CANON),
    which the private_key line of a service-account key exceeds. So the terminal is switched to non-canonical,
    no-echo input once (Ctrl-C still interrupts), and reading stops when the text is a complete JSON object (anything
    typed after it is dropped), at Enter when the text does not start with '{' (a one-line value), at Ctrl-D, or at
    `limit` bytes. Returns '' when nothing was entered. Whatever is still queued afterwards is discarded, never passed
    on to the shell."""
    out = _prompt_stream() or sys.stderr
    prompt = f"  {style('?', 'brand', 'bold')} {style(question, 'bold', 'text')}" + (f" {style(hint, 'dim')}" if hint else "") + \
        f" {style('›', 'brand')} "
    try:
        import select
        import termios
    except ImportError:                       # no termios (Windows): one hidden line
        import getpass
        return getpass.getpass(_strip(prompt)).strip()
    fd = sys.stdin.fileno() if fd is None else fd
    old = termios.tcgetattr(fd)
    new = termios.tcgetattr(fd)
    new[3] &= ~(termios.ECHO | termios.ICANON)
    new[6] = list(new[6])
    new[6][termios.VMIN] = 1
    new[6][termios.VTIME] = 0
    buf = bytearray()
    value = None
    try:
        termios.tcsetattr(fd, termios.TCSAFLUSH, new)   # also drops anything typed ahead of the prompt
        _write(out, prompt)
        finished = False
        while not finished:
            chunk = os.read(fd, 4096)
            if not chunk:                     # end of input
                break
            for b in chunk:
                if b == 0x04:                 # Ctrl-D: the value ends here
                    finished = True
                    break
                if b in (0x7F, 0x08):         # backspace
                    if buf:
                        del buf[-1]
                    continue
                if b == 0x0D:
                    b = 0x0A
                if b == 0x0A and not buf.lstrip().startswith(b"{"):
                    finished = True           # Enter on nothing (no value), or after a one-line value (a path ...)
                    break
                buf.append(b)
                if len(buf) > limit:
                    raise Abort(f"More than {limit} bytes pasted; that is not a key file. Nothing was changed.", code=2)
            if not finished:
                value = _json_object_prefix(bytes(buf))   # the object is complete: whatever came after it is dropped
                finished = value is not None
        # the paste's trailing newline (and anything after it) is read and dropped here, not left to the shell
        while select.select([fd], [], [], 0.1)[0]:
            if not os.read(fd, 4096):
                break
    finally:
        try:
            termios.tcsetattr(fd, termios.TCSAFLUSH, old)
        except termios.error:
            pass
        _write(out, "\n")
    if value is None:                         # ended by Ctrl-D / Enter: still only the object when there is one
        value = _json_object_prefix(bytes(buf))
    return value if value is not None else bytes(buf).decode("utf-8", "replace").strip()


_ESC_KEYS = {b"[A": "up", b"OA": "up", b"[B": "down", b"OB": "down", b"[C": "right", b"OC": "right",
             b"[D": "left", b"OD": "left", b"[H": "home", b"OH": "home", b"[F": "end", b"OF": "end",
             b"[1~": "home", b"[4~": "end", b"[5~": "pgup", b"[6~": "pgdn"}


def _read_key(fd: int | None = None) -> str:
    """Read one key press from a POSIX TTY (already in cbreak/raw mode) and decode it.

    Reads raw bytes (a buffered sys.stdin.read would swallow escape sequences and defeat select()), so a lone Esc
    returns "esc" at once, arrow keys work in both CSI (ESC [ A) and SS3 (ESC O A) form, and any other escape
    sequence (PgUp, Home, F-keys, Alt+key) returns "ignore" instead of cancelling."""
    import select
    fd = sys.stdin.fileno() if fd is None else fd
    first = os.read(fd, 1)
    if not first:
        return "ctrl-d"
    if first == b"\x1b":
        seq = b""
        while len(seq) < 16:
            ready, _, _ = select.select([fd], [], [], 0.05)
            if not ready:
                break
            ch = os.read(fd, 1)
            if not ch:
                break
            seq += ch
            if seq[:1] == b"[" and len(seq) >= 2 and 0x40 <= seq[-1] <= 0x7E:
                break
            if seq[:1] == b"O" and len(seq) >= 2:
                break
            if seq[:1] not in (b"[", b"O"):
                break
        if not seq:
            return "esc"
        return _ESC_KEYS.get(seq, "ignore")
    if first[0] >= 0x80:                                   # a multi-byte UTF-8 character is never a menu key
        lead = first[0]
        more = 1 if 0xC0 <= lead < 0xE0 else 2 if 0xE0 <= lead < 0xF0 else 3 if 0xF0 <= lead < 0xF8 else 0
        if more:
            os.read(fd, more)                              # consume the rest of it
        return "ignore"
    ch = first.decode("ascii", "replace")
    return {"\r": "enter", "\n": "enter", "\x03": "ctrl-c", "\x04": "ctrl-d", " ": "space"}.get(ch, ch)


def _fit_label(label: str, n: int) -> str:
    """Shorten a menu label to one row. Paths keep their informative tail, a trailing '(recommended)' survives."""
    t = _strip(label)
    if vis_len(t) <= n:
        return t
    m = re.search(r"\s(\([^()]*\))$", t)
    if m and vis_len(m.group(1)) < n // 2:
        return fit(t[:m.start()], n - vis_len(m.group(1)) - 1) + " " + m.group(1)
    if "/" in t and n >= 20:
        head = max(6, n // 3)
        tail = n - head - 1
        return t[:head] + "…" + t[-tail:]
    return fit(t, n)


def _answer_of(option: Sequence[str]) -> str:
    """What the answer line shows for a menu option: its explicit short answer (a third element), else the label up
    to its first ':' ('Remote: a bucket ...' -> 'Remote')."""
    if len(option) > 2 and option[2]:
        return str(option[2])
    return str(option[1]).split(":")[0]


def choose(question: str, options: Sequence[Sequence[str]], default: str | None = None) -> str:
    """Single choice. Arrow-key menu on a TTY (↑/↓ + Enter, or type a number); numbered list elsewhere.

    options are (key, label) or (key, label, answer): `answer` is what the collapsed answer line shows (default: the
    label up to its first ':'). A menu taller than the terminal scrolls inside a window, so redraws never pile up in
    the scrollback."""
    keys = [o[0] for o in options]
    if not options:
        raise Abort(f"'{question}' has nothing to choose from.")
    if not interactive():
        if default is None:
            raise Abort(f"'{question}' needs a choice in non-interactive mode.")
        return default
    idx = keys.index(default) if default in keys else 0
    out = _prompt_stream()
    fancy = os.name != "nt" and not _DUMB and _isatty(sys.stdout) and out is sys.stdout
    if fancy:
        try:
            import termios  # noqa: F401
            import tty  # noqa: F401
        except ImportError:
            fancy = False
    if not fancy:
        return _choose_numbered(question, options, default, out)

    n = len(options)
    width_ = cols()
    shown = [_fit_label(o[1], width_ - 7) for o in options]   # one row per option, so redraws stay aligned
    hint = "↑/↓ then Enter" + (f" · or 1-{n}" if n <= 9 else "")
    if vis_len(question) + vis_len(hint) + 6 > width_:
        hint = "↑/↓, Enter"                    # narrow terminal: keep the question readable
    qtext = fit(question, max(10, width_ - 6 - vis_len(hint)))
    qline = f"  {style('?', 'brand', 'bold')} {style(qtext, 'bold', 'text')} {style(hint, 'dim')}"
    q_rows = rows_for(qline)
    # The question, the menu and the row the cursor rests on must all fit on the screen: cursor-up cannot reach
    # rows that scrolled away, and every redraw would then leave a stale copy behind. A taller menu shows a window
    # of it between '↑ k more' / '↓ k more' rows; a screen too short even for that gets the numbered list.
    screen = term_rows()
    win = n
    if n + q_rows + 1 > screen:
        win = screen - q_rows - 3              # two indicator rows + the cursor row
        if win < 3:
            return _choose_numbered(question, options, default, out)
    scrolling = win < n
    height = win + (2 if scrolling else 0)    # rows the menu occupies (every redraw draws exactly this many)
    top = 0

    import termios
    import tty
    fd = sys.stdin.fileno()

    def render(first: bool) -> None:
        nonlocal top
        if idx < top:
            top = idx
        elif idx >= top + win:
            top = idx - win + 1
        buf = [] if first else [f"\033[{height}A"]
        if scrolling:
            buf.append("\r\033[2K" + (f"      {style(f'↑ {top} more', 'dim')}" if top else "") + "\n")
        for i in range(top, top + win):
            if i == idx:
                buf.append(f"\r\033[2K    {style('❯', 'brand', 'bold')} {style(shown[i], 'text', 'bold')}\n")
            else:
                buf.append(f"\r\033[2K      {style(shown[i], 'muted')}\n")
        if scrolling:
            below = n - top - win
            buf.append("\r\033[2K" + (f"      {style(f'↓ {below} more', 'dim')}" if below else "") + "\n")
        _write(out, "".join(buf))

    _write(out, qline + "\n")
    cancelled = False
    old = termios.tcgetattr(fd)
    try:
        tty.setcbreak(fd, termios.TCSANOW)   # once for the whole menu: no keys lost or echoed between redraws
        _write(out, "\033[?25l")             # hide the cursor while the menu is open
        render(True)
        while True:
            key = _read_key(fd)
            if key in ("up", "k"):
                idx = (idx - 1) % n
            elif key in ("down", "j"):
                idx = (idx + 1) % n
            elif key == "home":
                idx = 0
            elif key == "end":
                idx = n - 1
            elif key == "pgup":
                idx = max(0, idx - win)
            elif key == "pgdn":
                idx = min(n - 1, idx + win)
            elif key.isdigit() and 1 <= int(key) <= n <= 9:
                idx = int(key) - 1
                break
            elif key == "enter":
                break
            elif key in ("ctrl-c", "esc", "ctrl-d"):
                cancelled = True
                break
            else:
                continue
            render(False)
    except KeyboardInterrupt:
        cancelled = True
    finally:
        try:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)
        except termios.error:
            pass
        _write(out, "\033[?25h")
    _write(out, f"\033[{height + q_rows}A\r\033[J")      # collapse the question and the menu ...
    if cancelled:
        raise Abort("Cancelled.", code=130)
    _write(out, _answer_line(question, _answer_of(options[idx])) + "\n")   # ... into one answer line
    _tee("?", f"{question}: {options[idx][1]}")
    return keys[idx]


def _choose_numbered(question: str, options: Sequence[Sequence[str]], default: str | None, out) -> str:
    keys = [o[0] for o in options]
    how = "type a number" + (", Enter for the default" if default in keys else "")
    _write(out, f"  {style('?', 'brand', 'bold')} {style(question, 'bold', 'text')} {style(how, 'dim')}\n")
    for i, opt in enumerate(options, 1):
        mark = dim("  (default)") if opt[0] == default else ""
        _write(out, f"      {i}) {opt[1]}{mark}\n")
    while True:
        _write(out, "      choice: ")
        try:
            raw = _read_line(out).strip()
        except KeyboardInterrupt:
            _write(out, "\n")
            raise Abort("Cancelled.", code=130)
        if not raw and default in keys:
            pick = default
        elif raw.isdigit() and 1 <= int(raw) <= len(options):
            pick = keys[int(raw) - 1]
        elif raw in keys:
            pick = raw
        else:
            warn(f"Pick a number from 1 to {len(options)}.")
            continue
        opt = options[keys.index(pick)]
        _write(out, _answer_line(question, _answer_of(opt)) + "\n")
        _tee("?", f"{question}: {opt[1]}")
        return pick


def ask_list(question: str, default: Sequence[str], validate: Callable[[str], str | None] | None = None) -> list[str]:
    raw = ask(f"{question} (comma-separated)", ",".join(default), validate=validate)
    return [x.strip() for x in raw.split(",") if x.strip()]


def require_typed(expected: str, prompt: str, nothing: str = "Nothing was changed") -> None:
    """Typed confirmation for irreversible actions. Fails closed: without a terminal to type on (-y, pipes, CI,
    agents) it stops with exit code 3 instead of approving; --auto-approve is the explicit way to skip it. The line
    is read as typed (no green ✔ answer line, which would read as accepted before the check); nothing typed is a
    plain cancel (exit 0), a different text a refusal (exit 1)."""
    if not interactive():
        raise Abort(f"{nothing}: this step needs '{expected}' typed in a terminal to confirm. "
                    "Re-run with --auto-approve to go ahead without typing it.", code=3)
    out = _prompt_stream()
    _write(out, _prompt_line(prompt, None))
    typed = _read_line(out).strip()
    _tee("?", f"{prompt}: {typed}")
    if not typed:
        raise Abort(f"Cancelled. {nothing}.", code=0)
    if typed != expected:
        raise Abort(f"Confirmation did not match ('{fit(typed, 40)}' is not '{expected}'). {nothing}.")
