"""Who is allowed to speak on the bus.

An inbox is reachable from the public internet, so "the From header says runflow@" proves
nothing on its own. Authenticity comes from two facts together:

  1. mail-api FORCES the From header to the sending tenant's own client_key
     (`api/send.py`: from_addr = f"{tenant_id}@{mail_domain}"), so a tenant cannot send as
     another tenant; and
  2. outbound mail is DKIM-signed by mail.rodmena.co.uk, and the inbound gateway records the
     verification verdict.

So `dkim == "pass"` AND `from_addr in REGISTRY` together mean the message genuinely came from
that platform. Either one alone is worthless: DKIM alone only proves the mail crossed our
server (any freepass tenant can do that), and a registry match alone is just a header a
stranger typed.

This module is the second half of that check. It is deliberately an allow-list of exact
addresses, not a domain suffix match — `runflow@mail.rodmena.co.uk.evil.tld` must not pass,
and neither should a freepass tenant that happened to pick a suggestive name.
"""
from __future__ import annotations

MAIL_DOMAIN = "mail.rodmena.co.uk"

# platform key -> (address, human name, repository)
PLATFORMS: dict[str, tuple[str, str, str]] = {
    "auth":      (f"auth@{MAIL_DOMAIN}",      "Auth",      "~/develop/auth"),
    "runflow":   (f"runflow@{MAIL_DOMAIN}",   "RunFlow",   "~/develop/RunFlow"),
    "futex":     (f"futex@{MAIL_DOMAIN}",     "Futex",     "~/develop/Futex"),
    "tokengate": (f"tokengate@{MAIL_DOMAIN}", "TokenGate", "~/develop/TokenGate"),
    "mail-api":  (f"mail-api@{MAIL_DOMAIN}",  "Mail API",  "~/develop/rodmena-mail-api"),
    "stabilize": (f"stabilize@{MAIL_DOMAIN}", "Stabilize", "~/develop/stabilize"),
    "migretti":  (f"migretti@{MAIL_DOMAIN}",  "Migretti",  "~/develop/migretti"),
    "datashard": (f"datashard@{MAIL_DOMAIN}", "Datashard", "~/develop/datashard"),
    "supervice": (f"supervice@{MAIL_DOMAIN}", "Supervice", "~/develop/supervice"),
    "highway":   (f"highway@{MAIL_DOMAIN}",   "Highway",   "~/highway-stack/highway"),
}

_BY_ADDRESS = {addr.lower(): key for key, (addr, _, _) in PLATFORMS.items()}


def address_of(platform: str) -> str:
    """Resolve a platform key to its bus address. Raises on an unknown platform."""
    try:
        return PLATFORMS[platform.lower()][0]
    except KeyError:
        raise ValueError(
            f"unknown platform {platform!r}. Known: {', '.join(sorted(PLATFORMS))}"
        ) from None


def platform_of(address: str | None) -> str | None:
    """Reverse an address to its platform key, or None if it is not a bus participant."""
    if not address:
        return None
    return _BY_ADDRESS.get(address.strip().lower())


def is_registered(address: str | None) -> bool:
    return platform_of(address) is not None


def repo_of(platform: str) -> str | None:
    entry = PLATFORMS.get(platform.lower())
    return entry[2] if entry else None
