"""Identity of a working copy must be PORTABLE and VERIFIED.

The first implementation matched an absolute path, which fails for a git worktree, a second
checkout, a container mount, or any other machine — and asserted rather than verified, so
cloning anything into ~/develop/TokenGate made it TokenGate. These reproduce the operator's
reported cases.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agentmail.registry import _normalise_remote, platform_for_path  # noqa: E402


def _repo(tmp_path: Path, name: str, remote: str | None = None) -> Path:
    d = tmp_path / name
    d.mkdir(parents=True)
    subprocess.run(["git", "init", "-q", str(d)], check=True)
    if remote:
        subprocess.run(["git", "-C", str(d), "remote", "add", "origin", remote], check=True)
    return d


@pytest.mark.parametrize("remote", [
    "git@github.com:rodmena-limited/TokenGate.git",       # ssh, the usual clone
    "https://github.com/rodmena-limited/TokenGate.git",   # https
    "ssh://git@github.com/rodmena-limited/TokenGate",     # ssh:// without .git
    "git@github.com:rodmena-limited/TokenGate",           # no suffix
])
def test_any_spelling_of_the_remote_resolves(tmp_path, remote):
    """The same repository is legitimately cloned four ways; all must be TokenGate."""
    assert platform_for_path(str(_repo(tmp_path, "anywhere", remote))) == "tokengate"


def test_a_worktree_or_second_checkout_keeps_its_identity(tmp_path):
    """`git worktree add ../TokenGate-feature` used to silently drop the agent off the bus."""
    d = _repo(tmp_path, "TokenGate-feature", "git@github.com:rodmena-limited/TokenGate.git")
    assert platform_for_path(str(d)) == "tokengate"
    sub = d / "deep" / "nested"
    sub.mkdir(parents=True)
    assert platform_for_path(str(sub)) == "tokengate", "must resolve from a subdirectory too"


def test_a_marker_file_works_without_git(tmp_path):
    """Container mounts and vendored trees may have no remote at all."""
    d = tmp_path / "workspace" / "TokenGate"
    d.mkdir(parents=True)
    (d / ".agentmail").write_text("# declared identity\nplatform: tokengate\n")
    assert platform_for_path(str(d)) == "tokengate"


def test_the_marker_beats_the_remote(tmp_path):
    """A fork or mirror must be able to declare what it actually is."""
    d = _repo(tmp_path, "fork", "git@github.com:someone/unrelated.git")
    (d / ".agentmail").write_text("platform: runflow\n")
    assert platform_for_path(str(d)) == "runflow"


def test_an_unrelated_repo_is_nobody(tmp_path):
    assert platform_for_path(str(_repo(tmp_path, "other", "git@github.com:x/y.git"))) is None


def test_a_bogus_marker_does_not_grant_identity(tmp_path):
    """The marker names a platform; it cannot invent one."""
    d = tmp_path / "sneaky"
    d.mkdir()
    (d / ".agentmail").write_text("platform: not-a-real-platform\n")
    assert platform_for_path(str(d)) is None


def test_remote_normalisation():
    n = _normalise_remote
    assert n("git@github.com:rodmena-limited/TokenGate.git") == "rodmena-limited/tokengate"
    assert n("https://github.com/rodmena-limited/TokenGate/") == "rodmena-limited/tokengate"
