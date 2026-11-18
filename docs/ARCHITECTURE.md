# Architecture

This document describes how Pervius is built, how the kill switch
works, what it does and does not protect against, and the known limitations.
The user-facing overview is in [`README.md`](../README.md).

## 1. Goals and constraints

Pervius is an independent Linux desktop client for an **existing FastVPN /
OpenVPN subscription**, using only system packages and NetworkManager:

- Python 3, GTK 4, libadwaita, PyGObject and libnm.
- No custom VPN protocol, daemon or bundled VPN engine. NetworkManager and its
  OpenVPN plugin do the privileged network work.
- The GUI runs as an ordinary user, never as root.
- Provider OpenVPN profiles are imported through the NetworkManager OpenVPN
  plugin, the security-relevant fields are verified, and unsupported
  directives fail closed.
- One reusable, app-owned NetworkManager profile.
- Passwords go through a system-bus NetworkManager SecretAgent and the optional
  desktop keyring, never through argv, logs, plaintext settings or exports.
- No fake security toggles: a feature is either enforced or visibly absent.

## 2. Tested environment

Ubuntu 26.10 on aarch64 is the only tested environment, with NetworkManager
1.58, NetworkManager-openvpn 1.12, OpenVPN 2.7, Python 3.14, GTK 4.24,
libadwaita 1.10, libsoup 3.6, libsecret 0.21, nftables 1.1, polkitd and
dbus-broker as the system bus. Fedora support is planned; see
[`PACKAGING.md`](PACKAGING.md).

## 3. Components

### Desktop application

- `pervius/ui/app.py` — `Adw.Application`, single instance; relaunching
  presents the existing window; an app-level `present` action serves
  notification clicks.
- `pervius/ui/window.py` — main window, location chooser, credentials dialog,
  connection state machine, tray menu callbacks, kill-switch controls,
  connection details, notifications and quit/close prompts.
- `pervius/ui/tray.py` — native StatusNotifierItem + DBusMenu implementation
  over Gio D-Bus. No AppIndicator library dependency.

### NetworkManager integration

- `pervius/nm/client.py` — async/sync add, update, activate and deactivate
  helpers, and the profile-preparation worker.
- `pervius/nm/importer.py` — runs `nmcli connection import --temporary` with
  `NM_CERT_PATH` pointing at an app-owned directory, verifies the imported
  settings against the parsed profile field by field, builds the managed
  profile, deletes the temporary profile and keeps the CA file (mode 0600).
- `pervius/nm/profile.py` — builds the reserved managed profile. The **local
  profile owner and the VPN account name are separate**: the local login (for
  example `alice`) goes into `connection.permissions`; the VPN account (for
  example `vpnuser@example`) goes into `vpn.user-name`.
- `pervius/nm/agent.py` — system-bus NetworkManager SecretAgent. Only
  NetworkManager (uid 0) may call it. It checks the UUID, connection ID,
  OpenVPN service type and an exact single-user permission before returning a
  password. Passwords are looked up by VPN account name.
- `pervius/ownership.py` — ownership manifest and reserved UUID/ID
  validation. Exactly one `user:<local-user>:` permission is required; empty
  permissions mean "all users" and are rejected.
- `pervius/credentials.py` — memory-only by default, optional Secret Service
  persistence, no plaintext fallback.

### Catalogue and profiles

- The public server catalogue ZIP is downloaded over HTTPS from
  `vpn.ncapi.io` with strict archive limits, path safety, duplicate handling
  and size caps (`pervius/catalogue/fetcher.py`, libsoup 3).
- `pervius/catalogue/parser.py` — strict OpenVPN allowlist. It rejects
  external CA/cert/key files, inline certificates and keys, TLS-auth keys,
  scripts, plugins, compression, proxies and unknown options.
- `pervius/catalogue/validator.py` — archive validation and catalogue parsing.
- `pervius/catalogue/store.py` — last-known-good cache with atomic writes,
  mode 0600.
- `pervius/catalogue/countries.py` — ISO country names, flags, aliases and
  accent-insensitive search.

### Other modules

- `pervius/reconnect.py` — deterministic retry policy: 2, 5, 10, 20, 30, 60 s.
- `pervius/settings.py` — non-secret settings, favorites and preferences.
- `pervius/public_ip.py` — HTTPS public-IP lookup via `api64.ipify.org`.
- `pervius/killswitch_client.py` — unprivileged client for the kill-switch
  service.
- `pervius/killswitchd/` — root service and pure policy helpers.
- `pervius/tools/` — catalogue inspector, live proof CLI and kill-switch CLI.
- `pervius/migration.py` — one-time upgrade from 0.1.x (section 9).
- `pervius/distro.py` — documented, report-only distribution checks
  (section 8).

## 4. Connection model

- One app-owned NetworkManager profile with a reserved UUID and connection ID.
  Choosing a location (including a favorite) changes this profile's location;
  it never creates a second profile.
- Automatic reconnection only after an established tunnel drops: six attempts
  after 2, 5, 10, 20, 30 and 60 seconds. Manual disconnect, quit, a failed
  first connection and a rejected password never retry. Before each retry the
  managed profile, CA file and ownership are verified again.
- Closing the window with an active VPN hides it and keeps the process (and the
  secret agent) running; Quit asks whether to disconnect.
- The tray mirrors the state (red dot / green check) and offers connect,
  favorites, location, settings, notifications, kill switch, help, legal,
  forget-password and quit actions. GNOME's own VPN indicator stays visible as
  the system-level source of truth.
- Notifications are sent only while the window is unfocused or hidden.

## 5. Kill switch

### Privilege model

- The GUI and CLI are ordinary-user processes.
- A root systemd service (`pervius-killswitchd.service`) is D-Bus activated
  as `com.solvetus.Pervius.KillSwitch1` at `/com/solvetus/Pervius/KillSwitch1`. It is not
  enabled at boot.
- Unit hardening: `Type=dbus`, `CapabilityBoundingSet=CAP_NET_ADMIN`,
  `NoNewPrivileges=yes`, `ProtectSystem=strict`, `ProtectHome=yes`,
  `PrivateTmp=yes`, `RuntimeDirectory=pervius` (0700),
  `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK`.
- The service never runs a shell and never accepts rule text, paths or
  firewall expressions from callers.

### D-Bus API

Interface `com.solvetus.Pervius.KillSwitch1`:

- `Arm(s uuid, b allow_lan) -> a{sv}`
- `Disarm() -> a{sv}`
- `GetStatus() -> a{sv}`
- signal `StateChanged(a{sv})`

Status keys: `armed`, `state` (`off`/`armed`/`error`), `detail`, `uuid`,
`allow_lan`, `endpoints` (a count, not addresses), `backend`, `table`, `since`.

### Authorization

- polkit action `com.solvetus.pervius.killswitch.control`: `allow_active=yes`,
  `allow_inactive=no`, `allow_any=no`. The service calls `CheckAuthorization`
  with a `system-bus-name` subject; root bypasses polkit.
- `Arm` only accepts the reserved profile UUID and validates that the caller
  owns it through exactly one `user:<local-user>:` permission.
- `Disarm` is restricted to the UID that armed it, or root.
- `GetStatus` is readable by local users.

### nftables policy

- A dedicated table `inet pervius_ks`. The service only adds and deletes this
  table; it never flushes the global ruleset and leaves firewall front ends
  such as ufw or firewalld untouched.
- Output base chain at priority `-10`: accept loopback, `tun*`, DHCPv4/v6,
  IPv6 neighbour discovery (ICMPv6 133–136), the resolved VPN server addresses
  on their exact protocol/port, and optionally RFC 1918/ULA LAN ranges; drop
  all remaining IPv4 and IPv6.
- Forward chain policy drop.
- Server hostnames are resolved before the rules are applied. That lookup is a
  documented one-time DNS leak. Global IPv6 is blocked because the profiles are
  IPv4-only.

### State and recovery

- State lives in `/run/pervius/killswitch.json`, root-only, mode 0600.
- On service start: table + valid state → restore armed; state without table →
  rebuild the rules from the saved endpoints; table without valid state →
  report `error` and require Disarm (fail closed).
- Reboot clears `/run` and the nftables ruleset: protection fails open, with
  no automatic re-arming.
- Quitting the GUI can keep protection armed or disarm it. The CLI
  `pervius-killswitch disarm` is the recovery path.
- The GUI polls the service status every 5 seconds and never assumes local
  state.

### Verified behaviour

A live test with the VPN down armed the switch with 14 resolved endpoints.
DNS resolution, traffic bound to the physical interface and a direct TCP
connection to a public address all timed out; status stayed armed; disarm
restored IPv4 connectivity; only the dedicated table was touched.

Not yet tested live: an IPv6-literal leak (the test machine had no global IPv6
route), the GUI switch against the live service, behaviour across a real
unexpected VPN drop, Docker/containers with the forward-drop policy, and
provider IP rotation while armed.

## 6. Threat model

### Protected against (while the kill switch is armed)

- Applications sending traffic over Ethernet/Wi-Fi while the VPN is down.
- Leaks after an unexpected VPN drop, including during automatic reconnect.
- IPv6 traffic escaping an IPv4-only tunnel.
- Plain DNS queries to a local or ISP resolver outside the tunnel.
- Stale firewall state left by a crashed GUI process (fail closed).

### Not protected against

- Root, kernel or hypervisor compromise; malware that edits firewall rules.
- A malicious VPN provider or one that logs traffic.
- Side channels, traffic correlation or endpoint compromise.
- Applications in a separate network namespace the rules do not cover.
- Captive portals while strict blocking is armed.
- Anything at all while the kill switch is **off**: IPv6 and DNS can then leak
  outside the tunnel like on any NetworkManager OpenVPN connection.

## 7. Known limitations

1. **One managed NetworkManager profile only.** Favorites change its location;
   they don't create separate profiles or accounts. Location and protocol are
   locked while the kill switch is armed, because the firewall allowlist is
   built from the current profile.
2. **No auto-protect.** The kill switch never arms automatically at login or on
   a network change. Boot is fail-open.
3. **No DNS filtering.** No resolver, blocklists or DoH/DoT handling; plain DNS
   outside the tunnel is blocked only while the kill switch is armed.
4. **Static kill-switch allowlist per arm.** Provider DNS/IP rotation while
   disconnected can break reconnection until you disarm and re-arm.
5. **The privileged component ships in the main package** for convenience; it
   is idle until armed.
6. **The public-IP display uses a third-party HTTPS endpoint**
   (`api64.ipify.org`), which sees your public IP. If the app starts while
   connected, the ISP IP is "Not captured" because learning it would leak.
7. **Traffic totals are interface totals** since the first sample, not
   provider billing or history.
8. **Switch IP is a reconnect**, not a server-selection API; it can return the
   same exit IP.
9. **The GUI kill-switch path is not formally live-tested**; the service and
   CLI path are.
10. **No localization, help pages or start-at-login.**
11. **`diagnose` reports the service as inactive until D-Bus activation**,
    because it checks `NameHasOwner` without activating the service.
12. **GNOME's VPN indicator cannot be hidden**; a shell extension would be
    fragile and is deliberately not attempted.
13. **No multiple simultaneous VPNs or accounts; no split tunnelling.**
14. **No signed packages or reproducible builds.** Releases publish a
    `SHA256SUMS` file next to the `.deb`.
15. **Upgrades from 0.1.x with `apt` bypass the armed-kill-switch guard**,
    because apt removes the old package (whose removal script deletes its
    table) before unpacking Pervius. `dpkg -i` is guarded. See section 9.

## 8. Platform differences

Application code under `pervius/` is distribution-neutral. The only module
that knows about distribution differences is `pervius/distro.py`, and it only
*reports* them (`pervius-killswitch diagnose`):

- **System bus:** dbus-broker or dbus-daemon. D-Bus activation goes through
  systemd and the packages reload the bus policy with `busctl ... ReloadConfig`;
  both implementations support this.
- **Firewall front ends:** ufw or firewalld. The kill switch uses its own table
  and never modifies them; its early-priority drop wins over their accepts.
- **nftables.service:** when enabled, restarting it reloads a ruleset file that
  normally begins with `flush ruleset`, which also removes an armed kill-switch
  table (fail-open until armed again). `diagnose` warns about it.
- **polkit:** Pervius ships only an action file in
  `/usr/share/polkit-1/actions`; local rules can narrow it.

Install paths are listed once in `packaging/layout.tsv`; see
[`PACKAGING.md`](PACKAGING.md).

## 9. Upgrade migration from 0.1.x

Releases up to 0.1.19 used different identifiers. `pervius/migration.py` is
the only module that knows them. Each step runs once, is recorded in
`~/.local/share/pervius/migration.json`, and runs only if the old data
directory exists:

1. **Files** (before settings load): settings and favorites, the ownership
   manifest, the cached catalogue and the CA file are copied into the new data
   directory (directories 0700, files 0600, regular files only, never
   overwriting). The old directory is left in place.
2. **Keyring:** saved passwords are copied from the old Secret Service schema
   to `com.solvetus.Pervius`, read back to verify, then the old entries are
   deleted. A locked or unavailable keyring postpones the step to the next
   start. Secrets and account names are never logged.
3. **Profile** (before the secret agent registers): the profile with the
   reserved UUID must pass the usual ownership checks, using its old
   connection ID, and the copied CA must match the manifest hash. It is then
   renamed to **Pervius (managed)**, pointed at the copied CA, and the manifest
   is updated. Anything that does not validate is left untouched, and the
   strict ownership check then blocks with an explanation. If the VPN is up
   during the upgrade, the stored profile is still renamed; a
   reauthentication during that one session may fail, after which automatic
   reconnect uses the renamed profile.

The Debian `preinst` refuses to install while the old kill-switch table
exists, and never deletes it. apt removes the conflicting old package first,
and the old package's removal script deletes its own table, so the guard
protects `dpkg -i` upgrades only.

## 10. Future work

- **Auto-protect** needs a background component that is not tied to the
  window, a trusted-network model, an auto-connect and credential policy,
  captive-portal handling, and a documented escape hatch. It must not be a
  toggle that arms without being able to reconnect.
- **DNS filtering** needs a local filtering resolver with maintained
  blocklists, integration with systemd-resolved, and an explicit DoH/DoT
  policy. It filters names, not IP-literal traffic, and must not be labelled
  "DNS leak protection" unless the fallback paths are addressed.
- **Kill-switch test plan** still to automate in a disposable VM or network
  namespace: arm with the VPN down (no internet, DNS or IPv6), drop the tunnel
  during reconnect, restart the service (rules rebuilt or error reported),
  reboot (fail-open), uninstall (table and service removed), and bypass
  attempts (bound sockets, IPv6 literals, plain DNS, DoH), with the host
  firewall front end active throughout.

## 11. Test status

- Unit tests cover the parser, validator, store, settings, ownership, profile
  building, import verification, agent authorization, fetcher, country search,
  reconnect policy, tray properties, public-IP parsing, kill-switch rules and
  profile validation, every upgrade-migration path, the Debian preinst guard,
  the distribution checks, and version and identifier consistency.
- UI harnesses in [`tests/manual/`](../tests/manual/README.md) exercise the
  window on a private Broadway display.
- Verified live: first VPN import/activation and browsing; keyring store,
  lookup and clear with a temporary entry; public-IP lookup; the kill-switch
  arm/leak/disarm test above; tray red/green icons; connected IPs, traffic
  totals, protocol display and Switch IP.
- Not yet verified live: a real unexpected drop with auto-reconnect,
  long hidden-window residency and reauthentication, a saved password across a
  full restart, the GUI kill-switch switch, dual-stack IPv6.
