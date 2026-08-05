"""#354 — a thread tag must never produce an invalid recipient.

Reported by the folks platform with an exact reproduction, one hour after it was onboarded:

    agentmail reply <id> -b "Confirmed" -t ack
    AgentMailError: POST /api/v1/emails -> 422
    {"detail":"invalid_recipient: ['folks+<01kz7txx1he3j7qbfnr5xxyfh8@mail.rodmena.co.uk>@mail.rodmena.co.uk']"}

`Client._parse` falls back to the raw `Message-ID` when a message has no `recipient_tag` —
which is EVERY message not sent to a plus-address, including anything sent via
`POST /api/v1/emails`. A Message-ID is `<ulid@domain>`, so the tag carried angle brackets and a
second `@` straight into the local part.

The sanitiser lives in `thread_address` rather than in the fallback because `message_id` is
SENDER-CONTROLLED on inbound mail: a tag reaching an address must be cleaned whatever its
provenance.
"""
from __future__ import annotations

from agentmail.protocol import sanitise_thread_tag, thread_address

ADDR = "folks@mail.rodmena.co.uk"
# The exact string from the live 422, not a paraphrase of it (FR-AM-3).
REPORTED = "<01KZ7TXX1HE3J7QBFNR5XXYFH8@mail.rodmena.co.uk>"


def _valid(a: str) -> bool:
    local, _, domain = a.partition("@")
    return (a.count("@") == 1 and domain != "" and local != ""
            and not any(c in a for c in '<>" \t,;:\\'))


def test_the_exact_reported_value_produces_a_valid_recipient() -> None:
    """THE REGRESSION. Goes red against the unsanitised implementation."""
    got = thread_address(ADDR, REPORTED)
    assert _valid(got), f"still an invalid addr-spec: {got}"
    assert got == "folks+01kz7txx1he3j7qbfnr5xxyfh8@mail.rodmena.co.uk"


def test_a_normal_thread_id_is_left_alone() -> None:
    """The positive control. Without it, a sanitiser that mangled every tag would pass above.

    Replies must keep landing in their existing threads, so this is the half that stops the fix
    being worse than the bug.
    """
    assert thread_address(ADDR, "thr-9f13771c63f44db59edd") == \
        "folks+thr-9f13771c63f44db59edd@mail.rodmena.co.uk"


def test_hostile_tags_cannot_escape_the_local_part() -> None:
    """message_id is sender-controlled on inbound mail, so treat the tag as untrusted input."""
    for hostile in ['<a b"c>@evil.example', "x@evil.example", "a;b,c", "..--..",
                    "<>", "tag\r\nBcc: victim@example.com"]:
        got = thread_address(ADDR, hostile)
        assert _valid(got), f"{hostile!r} produced {got!r}"
        assert got.endswith("@mail.rodmena.co.uk")


def test_the_domain_of_a_message_id_is_not_part_of_the_tag() -> None:
    """Keeps the ULID, drops the domain — so the thread stays identifiable after sanitising."""
    assert sanitise_thread_tag(REPORTED) == "01kz7txx1he3j7qbfnr5xxyfh8"
