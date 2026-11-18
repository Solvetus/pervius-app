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
| 0.2.x | Yes |
| < 0.2 | No (private test builds) |

## Privileged component and scope

The desktop app, `pervius-killswitch`, `pervius-inspect` and `pervius-proof`
run as the logged-in user. NetworkManager performs VPN operations. The only
code Pervius runs as root is the kill-switch service:

- **`pervius-killswitchd.service`** — started on demand by D-Bus activation
  (`com.solvetus.Pervius.KillSwitch1`), not at boot. It runs with
  `CapabilityBoundingSet=CAP_NET_ADMIN`, `NoNewPrivileges`,
  `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp` and a 0700 runtime
  directory `/run/pervius`.
- **API:** `Arm(uuid, allow_lan)`, `Disarm()`, `GetStatus()`. `Arm` and
  `Disarm` require the polkit action `com.solvetus.pervius.killswitch.control`
  (active local sessions only). `Arm` accepts only the reserved profile UUID
  and only if the caller owns that profile; `Disarm` is limited to the user
  who armed it, or root. `GetStatus` reveals state and an endpoint count, not
  addresses.
- **Effect:** it adds or deletes exactly one nftables table, `inet pervius_ks`,
  built from validated IP addresses resolved from the profile. It never
  accepts rule text, paths or shell input, and never flushes the global ruleset.

Also in scope: the NetworkManager secret agent (it must release the password
only to NetworkManager, for the owned profile), profile and catalogue
validation, keyring handling and the upgrade migration.

Out of scope: vulnerabilities in NetworkManager, OpenVPN, the VPN provider's
service or servers, and the limitations documented in
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) (for example, leaks while the
kill switch is off, or fail-open after reboot).
