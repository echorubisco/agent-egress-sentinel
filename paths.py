#!/usr/bin/env python3
"""
Shared paths - SUDO_USER-safe.

The sniffer runs under `sudo` (root's HOME = /var/root), the menu-bar app runs
as you. If both used Path.home() they'd point at DIFFERENT dirs: the sniffer
would write sni.jsonl into /var/root and the app would read an empty file in
your home, forever, with no error. We resolve to the INVOKING user's home.

`pwd` is POSIX-only and is imported lazily for that reason. This module is
imported by nearly everything, so a hard dependency on it made the whole tree
unimportable off POSIX -- including the parts that are pure logic and have no
business caring (the ledger, the TLS parser, the reconciler, their tests).
Windows has no SUDO_USER equivalent: elevation does not change HOME, so both
halves already agree and the split-home problem this module exists to solve
does not arise there. See PLATFORMS.md.
"""

import os
import pathlib

try:
    import pwd                                    # POSIX only
except ImportError:                               # pragma: no cover - Windows
    pwd = None


def _real_home() -> pathlib.Path:
    # Under sudo, SUDO_USER is the human who invoked it.
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user and pwd is not None:
        try:
            return pathlib.Path(pwd.getpwnam(sudo_user).pw_dir)
        except KeyError:
            pass
    return pathlib.Path.home()


DATA_DIR = _real_home() / ".agent-egress-sentinel"
DATA_DIR.mkdir(exist_ok=True)

LOG = DATA_DIR / "sentinel.log"
SNI_FILE = DATA_DIR / "sni.jsonl"

# L1 declarations, written by the AGENT side (hook / wrapper), read by us.
# Deliberately a small append-only contract instead of parsing a vendor's
# private transcript directory: those are undocumented, change without notice,
# differ per install, and reading them means reading the user's whole
# conversation history to learn one thing (which destination was requested).
ACTIVITY_FILE = DATA_DIR / "activity.ndjson"


def chown_to_invoking_user(path):
    """
    When running under sudo, files we create are root-owned and (at 0600)
    unreadable by the user-mode menu-bar app -> its reads fail and the red
    alert path silently dies. Chown anything we write back to SUDO_USER so the
    app can read it. No-op when not under sudo, and on Windows, where an
    elevated process writes into the same profile it would have anyway.
    """
    sudo_user = os.environ.get("SUDO_USER")
    if not sudo_user or pwd is None:
        return
    try:
        pw = pwd.getpwnam(sudo_user)
        os.chown(path, pw.pw_uid, pw.pw_gid)
    except (KeyError, OSError):
        pass
