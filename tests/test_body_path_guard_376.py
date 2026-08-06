"""Refuse a body that is only a path to an existing file (#376).

`agentmail send -b /path/to/file` (no `@`) sends the PATH as the message. It delivers, the
sender believes they communicated, and the recipient gets a useless string. Observed on the
live bus in one evening:

    tokengate  01KZA6D3P32GBRP421TASPWDJM  body: "/tmp/opencode/reply_b.md"
    tokengate  01KZA6DBM3YSDTYV2JNK9GJGZ9  body: "/tmp/opencode/reply_c.md"
    red9       (self-corrected)             body: "@/path/to/file"

Two were answers to direct questions. Their content is unrecoverable.

The guard is deliberately narrow. The expensive failure would be refusing a legitimate
message, so the bar is: the ENTIRE body is a path, containing no whitespace, and that file
actually exists and is readable. Prose mentioning a path is untouched — a report about
/etc/postfix/main.cf must still send.
"""
from __future__ import annotations

import pytest

from agentmail.cli import _body


# -- the refusal ---------------------------------------------------------------------------

def test_bare_path_to_an_existing_file_is_refused(tmp_path):
    f = tmp_path / "reply_b.md"
    f.write_text("the real message content")
    with pytest.raises(SystemExit) as e:
        _body(str(f))
    msg = str(e.value)
    assert "refusing to send" in msg
    assert f"@{f}" in msg, "must show the correct form, not just complain"


def test_the_refusal_names_both_forms(tmp_path):
    """An agent that reads the error must be able to fix it without consulting docs."""
    f = tmp_path / "note.md"
    f.write_text("x")
    with pytest.raises(SystemExit) as e:
        _body(str(f))
    msg = str(e.value)
    assert "sends its CONTENTS" in msg
    assert "sends the path itself" in msg


# -- everything that must still work -------------------------------------------------------

def test_the_at_form_still_reads_the_file(tmp_path):
    f = tmp_path / "report.md"
    f.write_text("real content\nsecond line\n")
    assert _body(f"@{f}") == "real content\nsecond line\n"


def test_a_path_shaped_string_that_does_not_exist_is_allowed(tmp_path):
    """FR-BODY-3. Not every path-shaped body is a mistake — it may be the point."""
    ghost = str(tmp_path / "does-not-exist.md")
    assert _body(ghost) == ghost


def test_prose_mentioning_a_real_path_is_allowed(tmp_path):
    """The failure mode to avoid: refusing a genuine report because it cites a file."""
    f = tmp_path / "main.cf"
    f.write_text("x")
    body = f"The transport is misconfigured in {f} — see line 40."
    assert _body(body) == body


def test_ordinary_prose_is_untouched():
    assert _body("Reproduced. Fixing in our retry path.") == \
        "Reproduced. Fixing in our retry path."


def test_a_trailing_space_is_the_documented_escape(tmp_path):
    """The refusal tells the sender how to send a path deliberately; that must work."""
    f = tmp_path / "wanted.md"
    f.write_text("x")
    assert _body(f"{f} ") == f"{f} "


def test_a_directory_is_not_refused(tmp_path):
    """os.path.isfile, not exists — a directory as a body is odd but not this mistake."""
    assert _body(str(tmp_path)) == str(tmp_path)
