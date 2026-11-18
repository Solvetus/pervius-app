# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately; do not open a public issue.

- Use GitHub private vulnerability reporting: the **Report a vulnerability**
  button on the repository's **Security** tab, or
- email **security@solvetus.com**.

Include the Pervius version, your distribution and release, and steps to
reproduce. Never include passwords, keyring contents or full VPN profiles.
We aim to acknowledge reports within 5 working days and will agree on a
disclosure date with you once a fix is ready.

## Supported versions

Only the latest release receives security fixes.

| Version | Supported |
| --- | --- |
| 1.0.x | Yes |

## Privileged component and scope

The desktop app, `pervius-killswitch`, `pervius-inspect` and `pervius-proof`
run as the logged-in user. NetworkManager performs VPN operations. The only
code Pervius runs as root is the kill-switch service and the IPv6-guard
dispatcher hook:

- **`pervius-killswitchd.service`** — started on demand by D-Bus activation
  (`com.solvetus.Pervius.KillSwitch1`), not at boot. It runs with
  `CapabilityBoundingSet=CAP_NET_ADMIN`, `NoNewPrivileges`,
  `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp` and a 0700 runtime
  directory `/run/pervius`.
- **API:** `Arm(uuid, allow_lan, interfaces)`, `Configure(allow_lan,
  interfaces)`, `UpdateEndpoints(uuid, replace)`, `SetGuardOptions(block_ipv6,
  interfaces)`, `Disarm()`, `GetStatus()`.
  Every method except `GetStatus` requires the polkit action
  `com.solvetus.pervius.killswitch.control` (active local sessions only).
  `Arm` and `UpdateEndpoints` accept only the reserved profile UUID and only
  if the caller owns that profile; `Configure`, `UpdateEndpoints` and `Disarm`
  are limited to the user who armed it, or root. Interface names are
  validated strictly. `GetStatus` reveals state and an endpoint count, not
  addresses.
- **Effect:** it adds, atomically replaces or deletes exactly one nftables
  table, `inet pervius_ks`, built from validated IP addresses it resolved
  itself from the profile. It never accepts rule text, paths, addresses or
  shell input, and never flushes the global ruleset. While the tunnel is
  down it may send A/AAAA queries for the profile's server names itself
  (dnspython) through a DNS window of at most five seconds that matches only
  its own cgroup.
- **`/usr/lib/NetworkManager/dispatcher.d/90-pervius-guard`** — a POSIX
  shell hook run by NetworkManager. It exits immediately for any connection
  other than the reserved Pervius profile, reads only NetworkManager's
  arguments and environment and the root-owned `/var/lib/pervius/guard.conf`
  (written by the service's `SetGuardOptions`; ignored unless root-owned,
  0644 and not a symlink), validates every value, and only creates or deletes
  the table `inet pervius_guard`.

Also in scope: the NetworkManager secret agent (it must release the password
only to NetworkManager, for the owned profile), profile and catalogue
validation and keyring handling.

Out of scope: vulnerabilities in NetworkManager, OpenVPN, the VPN provider's
service or servers, and the limitations documented in
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) (for example, leaks while the
kill switch is off, or fail-open after reboot).
