"""Documented distribution checks.

Pervius's application code is distribution-neutral: it talks to
NetworkManager, the system bus, polkit and nftables through interfaces that
are the same on Debian/Ubuntu and Fedora.  The few platform facts that *do*
differ between distributions are inspected here, and only here.  They are
reported by ``pervius-killswitch diagnose``; no application behaviour
depends on them.

Checks
------
System bus implementation
    dbus-broker (Fedora, recent Ubuntu) or dbus-daemon.  The kill-switch
    service is D-Bus activated through systemd, which works with both, and the
    packages reload the bus policy with ``busctl ... ReloadConfig``, which both
    implement.

Firewall front ends
    ufw (common on Debian/Ubuntu) and firewalld (Fedora default).  The kill
    switch adds one dedicated nftables table with an early-priority output
    chain and never modifies either front end; its drop rules win over their
    accepts.

nftables.service
    When enabled, restarting it reloads the distribution ruleset file, which
    normally starts with ``flush ruleset`` and therefore also removes the kill
    switch table.  Protection then fails open until it is armed again.

polkit rules directories
    Pervius installs only an action file; administrators can narrow it with a
    local rule in one of these directories.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from typing import Callable

Runner = Callable[[list[str]], tuple[int, str]]

UFW_CONFIG = "/etc/ufw/ufw.conf"
POLKIT_RULES_DIRS = ("/etc/polkit-1/rules.d", "/usr/share/polkit-1/rules.d")


@dataclass(frozen=True)
class Finding:
    name: str
    value: str
    note: str = ""


def run_command(argv: list[str]) -> tuple[int, str]:
    """Run a read-only query; never raises."""
    try:
        result = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
        )
    except (OSError, subprocess.SubprocessError):
        return 127, ""
    return result.returncode, (result.stdout or "").strip()


def system_bus_implementation(run: Runner = run_command) -> str:
    # dbus.service is an alias of dbus-broker.service where dbus-broker runs
    # the system bus.
    _code, unit = run(["systemctl", "show", "--property=Id", "--value", "dbus.service"])
    if unit == "dbus-broker.service":
        return "dbus-broker"
    if unit == "dbus.service":
        return "dbus-daemon"
    return "unknown"


def _ufw_enabled(read: Callable[[str], str]) -> bool:
    try:
        text = read(UFW_CONFIG)
    except OSError:
        return False
    for line in text.splitlines():
        key, _, value = line.partition("=")
        if key.strip() == "ENABLED":
            return value.strip().strip("'\"").lower() == "yes"
    return False


def _read_text(path: str) -> str:
    with open(path, encoding="utf-8") as handle:
        return handle.read()


def firewall_frontends(
    run: Runner = run_command,
    which: Callable[[str], str | None] = shutil.which,
    read: Callable[[str], str] = _read_text,
) -> list[str]:
    found = []
    if which("ufw"):
        found.append("ufw (enabled)" if _ufw_enabled(read) else "ufw (installed, disabled)")
    _code, state = run(["systemctl", "is-active", "firewalld.service"])
    if state == "active":
        found.append("firewalld (active)")
    return found


def nftables_service_enabled(run: Runner = run_command) -> bool:
    _code, state = run(["systemctl", "is-enabled", "nftables.service"])
    return state == "enabled"


def polkit_rules_dirs(isdir: Callable[[str], bool] = os.path.isdir) -> list[str]:
    return [path for path in POLKIT_RULES_DIRS if isdir(path)]


def report(
    run: Runner = run_command,
    which: Callable[[str], str | None] = shutil.which,
    read: Callable[[str], str] = _read_text,
    isdir: Callable[[str], bool] = os.path.isdir,
) -> list[Finding]:
    frontends = firewall_frontends(run, which, read)
    nft_service = nftables_service_enabled(run)
    return [
        Finding("system bus", system_bus_implementation(run)),
        Finding(
            "firewall front ends",
            ", ".join(frontends) or "none detected",
            "the kill switch uses its own nftables table and leaves them unchanged",
        ),
        Finding(
            "nftables.service",
            "enabled" if nft_service else "not enabled",
            "restarting it flushes the ruleset, including an armed kill switch"
            if nft_service
            else "",
        ),
        Finding("polkit rules directories", ", ".join(polkit_rules_dirs(isdir)) or "none"),
    ]
