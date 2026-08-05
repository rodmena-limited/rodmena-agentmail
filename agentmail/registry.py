"""Who is allowed to speak on the bus, and how a checkout proves which platform it is.

AUTHENTICITY. An inbox is reachable from the public internet, so "the From header says
runflow@" proves nothing on its own. It comes from two facts together:

  1. mail-api FORCES the From header to the sending tenant's own client_key
     (`api/send.py`: from_addr = f"{tenant_id}@{mail_domain}"), so a tenant cannot send as
     another tenant; and
  2. the inbound gateway records SPF/DKIM/DMARC verdicts, and an external forgery is judged
     unaligned (measured: dmarc=fail).

So a registered From plus no failed verdict means the message genuinely came from that
platform. The registry is the first half of that check, and is deliberately an allow-list of
EXACT addresses — `runflow@mail.rodmena.co.uk.evil.tld` must not pass a suffix match.

IDENTITY OF A CHECKOUT. Which platform is *this working copy*? The first version answered
with an absolute path, which was wrong: a path is an accident of where someone cloned, and it
is the one property guaranteed not to survive a worktree, a second checkout, a container
mount or a different machine. It was also asserted rather than verified — clone anything into
`~/develop/TokenGate` and it became TokenGate.

The git remote is the project's real identity: stable across every clone, and checkable. So
resolution order is marker file, then git remote, then (last, and only as a convenience for
un-cloned working copies) the conventional path.
"""
from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

MAIL_DOMAIN = "mail.rodmena.co.uk"

#: Filename a repository can commit to declare itself, e.g. `platform: tokengate`. Works for
#: checkouts with no git remote, vendored trees, and anything the remote map does not cover.
MARKER = ".agentmail"

# platform key -> (address, human name, conventional path, canonical git repo)
PLATFORMS: dict[str, tuple[str, str, str, str]] = {
    "auth":      (f"auth@{MAIL_DOMAIN}",      "Auth",      "~/develop/auth",             "ourway/auth"),
    "runflow":   (f"runflow@{MAIL_DOMAIN}",   "RunFlow",   "~/develop/RunFlow",          "rodmena-limited/RunFlow"),
    "futex":     (f"futex@{MAIL_DOMAIN}",     "Futex",     "~/develop/Futex",            "rodmena-limited/Futex"),
    "tokengate": (f"tokengate@{MAIL_DOMAIN}", "TokenGate", "~/develop/TokenGate",        "rodmena-limited/TokenGate"),
    "mail-api":  (f"mail-api@{MAIL_DOMAIN}",  "Mail API",  "~/develop/rodmena-mail-api", "rodmena-limited/rodmena-mail-api"),
    "stabilize": (f"stabilize@{MAIL_DOMAIN}", "Stabilize", "~/develop/stabilize",        "rodmena-limited/stabilize"),
    "bulkman":   (f"bulkman@{MAIL_DOMAIN}",   "Bulkman",   "~/develop/bulkman",         "rodmena-limited/bulkman"),
    "migretti":  (f"migretti@{MAIL_DOMAIN}",  "Migretti",  "~/develop/migretti",         "rodmena-limited/migretti"),
    "datashard": (f"datashard@{MAIL_DOMAIN}", "Datashard", "~/develop/datashard",        "rodmena-limited/DataShard"),
    "supervice": (f"supervice@{MAIL_DOMAIN}", "Supervice", "~/develop/supervice",        "rodmena-limited/supervice"),
    "highway":   (f"highway@{MAIL_DOMAIN}",   "Highway",   "~/highway-stack/highway",    "rodmena-limited/highway"),
    "sponsorsignal": (f"sponsorsignal@{MAIL_DOMAIN}", "SponsorSignal", "~/develop/SponsorSignal", "rodmena-limited/SponsorSignal"),
    "identity":  (f"identity@{MAIL_DOMAIN}",  "Identity",  "~/develop/identity",         "rodmena-limited/identity"),
    # folks.solutions (#353). Bus identity is `folks`, NOT `folks.solutions`: a client
    # key must match ^[a-z0-9][a-z0-9-]{1,30}[a-z0-9]$ and dots are illegal. The local
    # directory keeps the dotted name.
    "folks":     (f"folks@{MAIL_DOMAIN}",     "Folks Solutions", "~/develop/folks.solutions", "rodmena-limited/folks.solutions"),
    # RED9 dev team. Identity is `red-dev-team`, NOT `red9`: a FREE self-service `red9`
    # tenant already exists as the RED9 app's own sending identity, and marking a customer
    # tenant `bus_participant` makes its inbox silently drop all non-bus mail.
    # Local dir is `red9`; the canonical repo slug is `red9-chat`.
    "red-dev-team": (f"red-dev-team@{MAIL_DOMAIN}", "RED9 Dev Team", "~/develop/red9", "rodmena-limited/red9-chat"),
    # Not a platform repo: the identity a human operator uses to file against the bus itself.
    # Without it, a bus-level defect can only be reported by borrowing a platform's identity.
    "operator":  (f"operator@{MAIL_DOMAIN}",  "Operator",  "",                           ""),
}

_BY_ADDRESS = {addr.lower(): key for key, (addr, _, _, _) in PLATFORMS.items()}
_BY_REPO = {repo.lower(): key for key, (_, _, _, repo) in PLATFORMS.items() if repo}


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
    return entry[2] or None if entry else None


def _normalise_remote(url: str) -> str:
    """Reduce any git remote spelling to `owner/name`.

    Handles ssh (`git@host:owner/name.git`), https, `ssh://` and trailing slashes, because the
    same repository is legitimately cloned all four ways and they must resolve identically.
    """
    u = url.strip().rstrip("/")
    u = re.sub(r"\.git$", "", u)
    m = re.search(r"[:/]([^/:]+/[^/]+)$", u)
    return (m.group(1) if m else u).lower()


def _marker_platform(start: Path) -> str | None:
    """Walk up from `start` looking for a committed `.agentmail` marker."""
    for d in [start, *start.parents]:
        f = d / MARKER
        try:
            for line in f.read_text().splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                key, _, value = line.partition(":")
                if key.strip().lower() == "platform":
                    name = value.strip().lower()
                    return name if name in PLATFORMS else None
        except (OSError, ValueError):
            continue
    return None


def _git_platform(start: Path) -> str | None:
    """Resolve via `git remote get-url origin`, the project's portable identity."""
    try:
        out = subprocess.run(
            ["git", "-C", str(start), "remote", "get-url", "origin"],
            capture_output=True, text=True, timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0 or not out.stdout.strip():
        return None
    return _BY_REPO.get(_normalise_remote(out.stdout))


def _path_platform(start: Path) -> str | None:
    """Last resort: the conventional checkout location. Longest matching root wins."""
    here = str(start)
    best: tuple[int, str] | None = None
    for key, (_, _, repo, _) in PLATFORMS.items():
        if not repo:
            continue
        root = os.path.realpath(os.path.expanduser(repo))
        if here == root or here.startswith(root + os.sep):
            if best is None or len(root) > best[0]:
                best = (len(root), key)
    return best[1] if best else None


def platform_for_path(path: str | None = None) -> str | None:
    """Which platform's working copy are we standing in?

    Marker file, then git remote, then conventional path. The first two are portable — they
    survive a worktree, a second checkout, a container mount, and a different machine — and
    the git remote additionally *verifies* the claim instead of trusting the directory name.
    The path check remains only so an un-cloned working copy in the conventional location
    keeps working; it is never consulted when either portable answer resolves.
    """
    start = Path(os.path.realpath(path or os.getcwd()))
    return _marker_platform(start) or _git_platform(start) or _path_platform(start)
