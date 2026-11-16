"""Reading and writing env files the way Docker Compose does (app/envparse.py)."""

import os

import pytest

from app import envparse
from app.config import load_dotenv

TOKEN = "123456789:telegram-token-for-tests-0001"
HOME = "/home/tests"


# ---------------------------------------------------------------- reading, as Docker Compose does

# (line in the file, value Compose gives, or None: the panel rejects it). Checked against
# `docker compose config` (Compose v5.6.0) with HOME=/home/tests; Compose keeps the control
# characters the panel rejects.
PARITY = [
    ("A=-100 # c", "-100"),                     # an unquoted value drops " #comment"
    ("A=x#y", "x#y"),                           # no space before #: part of the value
    ("A=x\t#y", None),                          # a tab before # is not a comment (and tabs are rejected)
    ("A=  # only comment", "# only comment"),
    ('A="x" # y', "x"),                         # quoted: ends at the closing quote
    ("A='ab' trailing", "ab"),
    ("A='x'#y", "x"),
    ("A=pa$$ss", "pa$ss"),                      # $$ is a $
    ("A=$$", "$"),
    ("A='lit $$ $HOME'", "lit $$ $HOME"),       # single quotes: literal
    ('A="dq $$ end"', "dq $ end"),
    ("A=$HOME", HOME),
    ('A="$HOME"', HOME),
    ("A=${NOPE_UNSET}x", "x"),
    ("A=$NOPE_UNSET", ""),
    ("A=a\\$b", "a\\"),                         # unquoted backslashes stay; $b is a variable
    ('A="a\\$b"', "a$b"),
    ('A="a\\"b"', 'a"b'),
    ('A="a\\\\b"', "a\\b"),
    ('A="a\\\\"', "a\\"),
    ("A=a\\b", "a\\b"),
    ("A='a\\b'", "a\\b"),
    ("A='a\\\\b'", "a\\\\b"),
    ("A='a\\'b'", "a'b"),
    ("A=\"it's\"", "it's"),
    ('A=a"b', 'a"b'),
    ("A=  spaced value   ", "spaced value"),
    ('A="  keep  "', "  keep  "),
    ("export A=exp", "exp"),
    ("A = sp", "sp"),
    ("A=", ""),
    ("A=x\r", "x"),                             # CRLF files
    ('A="new\\nline"', None),                   # Compose: a line break; the panel rejects it
    ('A="tab\\tx"', None),
]


@pytest.mark.parametrize("line,expected", PARITY)
def test_parser_matches_docker_compose(line, expected):
    parsed = envparse.parse(line + "\n", {"HOME": HOME})
    if expected is None:
        assert "A" in parsed.invalid and "A" not in parsed.values
    else:
        assert parsed.values == {"A": expected}


def test_parser_bom_lines_duplicates_and_references():
    text = "﻿BOM=1\r\nB1=1\nB2=$B1\nK=1\n# K=commented\nK=2\nnot an assignment\n"
    assert envparse.parse(text, {}).values == {"BOM": "1", "B1": "1", "B2": "1", "K": "2"}
    # only "\n" ends a line: U+2028 and friends are inside a value, and rejected
    for sep in (" ", " ", "\x85", "\x0b", "\x0c", "\x1c", "\x1d", "\x1e", "\x00"):
        parsed = envparse.parse(f"A=x{sep}y\nB=2\n", {})
        assert "A" in parsed.invalid and parsed.values == {"B": "2"}, repr(sep)
    # a quoted value over several lines is read whole (rejected), so the next lines are not misread
    parsed = envparse.parse('A="one\nB=two"\nC=3\n', {})
    assert parsed.values == {"C": "3"} and parsed.invalid == {"A"}
    # the last occurrence wins, also when it is the rejected one
    assert envparse.parse("A=1\nA=\"x\\ny\"\n", {}).values == {}


def test_load_dotenv_reads_like_compose(tmp_path, monkeypatch):
    env = tmp_path / ".env"
    env.write_bytes("﻿MULTICDN_TEST_A=-100 # comment\nMULTICDN_TEST_B=\"x\" # y\nMULTICDN_TEST_C=a$$b\n".encode())
    for k in ("MULTICDN_TEST_A", "MULTICDN_TEST_B", "MULTICDN_TEST_C"):
        monkeypatch.delenv(k, raising=False)
    load_dotenv(env)
    assert (os.environ["MULTICDN_TEST_A"], os.environ["MULTICDN_TEST_B"], os.environ["MULTICDN_TEST_C"]) == ("-100", "x", "a$b")


# ---------------------------------------------------------------- writing

@pytest.mark.parametrize("value", ["a=b=c", "with spaces", "x#y", "x #y", "it's $HOME", 'q"uote\'s $x', "plain-value_1",
                                   "pa$$word", "back\\slash", "smtps://user:p%40ss@mail.example.com:465", "ends\\"])
def test_written_values_read_back_unchanged(value):
    line = envparse.quote(value)
    assert envparse.parse(f"A={line}\n", {"HOME": HOME, "x": "X"}).values["A"] == value
    if "$" in value and "'" not in value:
        assert line.startswith("'")  # literal: Compose does not replace anything in single quotes


@pytest.mark.parametrize("bad", ["a\nb", "a\rb", "a\x00b", "a\tb", "a\u2028b", "a\x85b", "a\x0bb"])
def test_control_characters_are_never_written(bad):
    with pytest.raises(ValueError):
        envparse.quote(bad)


def test_render_rewrites_the_last_line_and_drops_duplicates():
    text = "# head\nA=1\nTELEGRAM_CHAT_ID=-1\n  export TELEGRAM_CHAT_ID=-100 # old\r\n# TELEGRAM_BOT_TOKEN=commented\nZ=2"
    out = envparse.render(text, "TELEGRAM_CHAT_ID", "-200")
    assert out == "# head\nA=1\n  export TELEGRAM_CHAT_ID=-200\r\n# TELEGRAM_BOT_TOKEN=commented\nZ=2"
    out = envparse.render(text, "TELEGRAM_BOT_TOKEN", TOKEN)  # a commented line is not the variable
    assert out == text + "\n\n" + envparse.MARKER + "\nTELEGRAM_BOT_TOKEN=" + TOKEN + "\n"
    assert envparse.render(out, "ALERT_EMAIL_TO", "ops@example.com").count(envparse.MARKER) == 1
    assert envparse.render(text, "TELEGRAM_CHAT_ID", None) == "# head\nA=1\n# TELEGRAM_BOT_TOKEN=commented\nZ=2"
    assert envparse.render("﻿SMTP_URL=x\n", "SMTP_URL", "y") == "﻿SMTP_URL=y\n"
