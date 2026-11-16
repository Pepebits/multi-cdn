"""Reads env files the way Docker Compose (env_file) does, for the cases the panel cares about.

Checked against `docker compose config` (Compose v5.6.0); tests/test_secrets_file.py keeps the
table of cases:

- a UTF-8 BOM at the start is dropped; lines end only at "\\n" (a trailing "\\r" is dropped);
  blank lines and lines starting with "#" are skipped; ``export KEY=value`` and ``KEY = value``
  are accepted.
- unquoted: surrounding whitespace is trimmed and `` #`` (a space before ``#``) starts a comment
  (``A=x#y`` keeps ``x#y``; a tab before ``#`` does not start one). ``$$`` is a ``$``;
  ``$NAME``, ``${NAME}``, ``${NAME:-default}`` and ``${NAME-default}`` are replaced by a variable
  defined earlier in the same file, else the process environment, else empty. Backslashes stay.
- 'single quotes': literal (no ``$`` replacement); only ``\\'`` becomes ``'``. Anything after the
  closing quote is ignored.
- "double quotes": ``\\n`` ``\\r`` ``\\t`` become control characters, ``\\$`` a literal ``$``, ``\\x``
  becomes ``x``; then ``$`` as unquoted. Anything after the closing quote is ignored.
- A quoted value may span lines (Compose allows it): it is read whole so the following lines are
  not misread, but a value with a line break is rejected (see below).
- The same key twice: the last one wins.

Values with any control character or Unicode line/paragraph separator are rejected: they are
reported in ``Parsed.invalid`` and left out of ``Parsed.values``. Lines that are not
``KEY=value`` are ignored.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path

_ASSIGN = re.compile(r"[ \t]*(?:export[ \t]+)?([A-Za-z_][A-Za-z0-9_.\-]*)[ \t]*=[ \t]*")
_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_BRACED = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)(?:(:?-)([^}]*))?\}")
# C0 and C1 control characters, DEL and the Unicode line/paragraph separators.
_BAD = re.compile(r"[\x00-\x1f\x7f-\x9f  ]")
_ESCAPES = {"n": "\n", "r": "\r", "t": "\t"}


def bad_chars(value: str) -> bool:
    """A control character or a line/paragraph separator: not allowed in a value."""
    return bool(_BAD.search(value))


@dataclass
class Entry:
    key: str
    value: str | None   # None: rejected (control characters, unterminated quote, bad ${...})
    first: int          # first and last line (0-based) of the assignment in the file
    last: int


@dataclass
class Parsed:
    entries: list[Entry] = field(default_factory=list)
    values: dict[str, str] = field(default_factory=dict)  # the last occurrence of each key
    invalid: set[str] = field(default_factory=set)        # keys whose last occurrence was rejected


class _Bad(Exception):
    pass


def _close(body: str, quote: str) -> int:
    """Index of the closing quote in `body` (a backslash escapes the next character), or -1."""
    i = 0
    while i < len(body):
        if body[i] == "\\":
            i += 2
            continue
        if body[i] == quote:
            return i
        i += 1
    return -1


def _interpolate(text: str, lookup, escaped_dollar: bool = False) -> str:
    out, i = [], 0
    while i < len(text):
        c = text[i]
        if c == "\0" and escaped_dollar:  # a "\$" from double quotes: a literal $ (see _double)
            out.append("$")
            i += 1
            continue
        if c != "$":
            out.append(c)
            i += 1
            continue
        nxt = text[i + 1:i + 2]
        if nxt == "$":
            out.append("$")
            i += 2
        elif nxt == "{":
            m = _BRACED.match(text, i + 1)
            if not m:
                raise _Bad("interpolation")
            name, op, default = m.group(1), m.group(2), m.group(3) or ""
            value = lookup(name)
            if op == ":-" and not value:
                value = default
            elif op == "-" and value is None:
                value = default
            out.append(value or "")
            i = m.end()
        elif m := _NAME.match(text, i + 1):
            out.append(lookup(m.group(0)) or "")
            i = m.end()
        else:
            out.append("$")
            i += 1
    return "".join(out)


def _double(body: str) -> str:
    out, i = [], 0
    while i < len(body):
        if body[i] == "\\" and i + 1 < len(body):
            nxt = body[i + 1]
            out.append("\0" if nxt == "$" else _ESCAPES.get(nxt, nxt))
            i += 2
        else:
            out.append(body[i])
            i += 1
    return "".join(out)


def parse(text: str, environ: dict[str, str] | None = None) -> Parsed:
    environ = os.environ if environ is None else environ
    text = text.removeprefix("﻿")
    lines = text.split("\n")
    out = Parsed()

    def lookup(name: str) -> str | None:
        if name in out.values:
            return out.values[name]
        return environ.get(name)

    i = 0
    while i < len(lines):
        line = lines[i].removesuffix("\r")
        stripped = line.lstrip(" \t")
        m = _ASSIGN.match(line)
        if not stripped or stripped.startswith("#") or not m:
            i += 1
            continue
        key, rest, first = m.group(1), line[m.end():], i
        value: str | None
        try:
            if rest[:1] in ("'", '"'):
                quote, body = rest[0], rest[1:]
                end = _close(body, quote)
                while end < 0 and i + 1 < len(lines):
                    i += 1
                    body += "\n" + lines[i].removesuffix("\r")
                    end = _close(body, quote)
                if end < 0:
                    raise _Bad("unterminated")
                body = body[:end]
                if bad_chars(body):
                    raise _Bad("control")
                value = body.replace("\\'", "'") if quote == "'" else _interpolate(_double(body), lookup, escaped_dollar=True)
            else:
                cut = rest.find(" #")
                value = _interpolate((rest[:cut] if cut >= 0 else rest).strip(), lookup)
            if bad_chars(value):
                raise _Bad("control")
        except _Bad:
            value = None
        out.entries.append(Entry(key, value, first, i))
        if value is None:
            out.values.pop(key, None)
            out.invalid.add(key)
        else:
            out.values[key] = value
            out.invalid.discard(key)
        i += 1
    return out


def read(path: str | Path, environ: dict[str, str] | None = None) -> Parsed:
    """Parses a file (UTF-8). Raises OSError / UnicodeDecodeError."""
    return parse(Path(path).read_bytes().decode("utf-8"), environ)


_PLAIN = re.compile(r"[A-Za-z0-9_@:/.+,=%~^-]*")
MARKER = "# Managed by the multi-cdn panel"


def quote(value: str) -> str:
    """`value` written so that Compose and parse() read it back unchanged: bare when safe, else
    in single quotes (literal: no $ replacement), else in double quotes with \\\\, \\" and $
    escaped. Raises ValueError for a value that cannot be written on one line."""
    if bad_chars(value):
        raise ValueError("control characters are not allowed")
    if _PLAIN.fullmatch(value):
        out = value
    elif "'" not in value and not value.endswith("\\"):
        out = f"'{value}'"
    else:
        out = '"' + value.replace("\\", "\\\\").replace('"', '\\"').replace("$", "$$") + '"'
    if parse(f"K={out}\n", {}).values.get("K") != value:  # never write what would read back different
        raise ValueError("this value cannot be written to an env file")
    return out


def render(content: str, key: str, value: str | None) -> str:
    """`content` with KEY set to `value` or removed (None). The last assignment of KEY (the one
    Compose uses) is rewritten in place and any earlier one removed; with none, it is appended
    under MARKER. Every other line (and a BOM) stays byte for byte."""
    bom = "\ufeff" if content.startswith("\ufeff") else ""
    content = content.removeprefix(bom)
    line = None if value is None else f"{key}={quote(value)}"
    lines = content.split("\n")
    entries = [e for e in parse(content, {}).entries if e.key == key]
    drop: set[int] = set()
    for e in entries:
        drop.update(range(e.first, e.last + 1))
    replace_at = None
    if line is not None and entries:
        last = entries[-1]
        original = lines[last.first]
        indent = original[:len(original) - len(original.lstrip(" \t"))]
        export = "export " if re.match(r"[ \t]*export[ \t]", original) else ""
        cr = "\r" if lines[last.last].endswith("\r") else ""
        replace_at, line = last.first, indent + export + line + cr
    out = [line if i == replace_at else text for i, text in enumerate(lines) if i == replace_at or i not in drop]
    text = "\n".join(out)
    if line is not None and replace_at is None:
        if text and not text.endswith("\n"):
            text += "\n"
        if MARKER not in text:
            text += ("\n" if text.strip() else "") + MARKER + "\n"
        text += line + "\n"
    return bom + text
