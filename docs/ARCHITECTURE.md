# Architecture

This document describes how Solvetus VPN Manager is built, how the kill switch
works, what it does and does not protect against, and the known limitations.
The user-facing overview is in [`README.md`](../README.md).

## 1. Goals and constraints

An independent Linux desktop front end for an **existing FastVPN / OpenVPN
subscription**, using only system packages and NetworkManager:

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
libadwaita 1.10, libsoup 3.6, libsecret 0.21, nftables 1.1, polkitd, dbus-broker
as the system bus, and UFW active on the nftables backend.

## 3. Components

### Desktop application

- `solvetus/ui/app.py` — `Adw.Application`, single instance; relaunching
  presents the existing window; an app-level `present` action serves
  notification clicks.
- `solvetus/ui/window.py` — main window, location chooser, credentials dialog,
  connection state machine, tray menu callbacks, kill-switch controls,
  connection details, notifications and quit/close prompts.
- `solvetus/ui/tray.py` — native StatusNotifierItem + DBusMenu implementation
  over Gio D-Bus. No AppIndicator library dependency.

### NetworkManager integration

- `solvetus/nm/client.py` — async/sync add, update, activate and deactivate
  helpers, and the profile-preparation worker.
- `solvetus/nm/importer.py` — runs `nmcli connection import --temporary` with
  `NM_CERT_PATH` pointing at an app-owned directory, verifies the imported
  settings against the parsed profile field by field, builds the managed
  profile, deletes the temporary profile and keeps the CA file (mode 0600).
- `solvetus/nm/profile.py` — builds the reserved managed profile. The **local
  profile owner and the VPN account name are separate**: the local login (for
  example `alice`) goes into `connection.permissions`; the VPN account (for
  example `vpnuser@example`) goes into `vpn.user-name`.
- `solvetus/nm/agent.py` — system-bus NetworkManager SecretAgent. Only
  NetworkManager (uid 0) may call it. It checks the UUID, connection ID,
  OpenVPN service type and an exact single-user permission before returning a
  password. Passwords are looked up by VPN account name.
- `solvetus/ownership.py` — ownership manifest and reserved UUID/ID
  validation. Exactly one `user:<local-user>:` permission is required; empty
  permissions mean "all users" and are rejected.
- `solvetus/credentials.py` — memory-only by default, optional Secret Service
  persistence, no plaintext fallback.

### Catalogue and profiles

- The public server catalogue ZIP is downloaded over HTTPS from
  `vpn.ncapi.io` with strict archive limits, path safety, duplicate handling
  and size caps (`solvetus/catalogue/fetcher.py`, libsoup 3).
- `solvetus/catalogue/parser.py` — strict OpenVPN allowlist. It rejects
  external CA/cert/key files, inline certificates and keys, TLS-auth keys,
  scripts, plugins, compression, proxies and unknown options.
- `solvetus/catalogue/validator.py` — archive validation and catalogue parsing.
- `solvetus/catalogue/store.py` — last-known-good cache with atomic writes,
  mode 0600.
- `solvetus/catalogue/countries.py` — ISO country names, flags, aliases and
  accent-insensitive search.

### Other modules

- `solvetus/reconnect.py` — deterministic retry policy: 2, 5, 10, 20, 30, 60 s.
- `solvetus/settings.py` — non-secret settings, favorites and preferences.
- `solvetus/public_ip.py` — HTTPS public-IP lookup via `api64.ipify.org`.
- `solvetus/killswitch_client.py` — unprivileged client for the kill-switch
  service.
- `solvetus/killswitchd/` — root service and pure policy helpers.
- `solvetus/tools/` — catalogue inspector, live proof CLI and kill-switch CLI.

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
- A root systemd service (`solvetus-killswitchd.service`) is D-Bus activated
  as `org.solvetus.KillSwitch1` at `/org/solvetus/KillSwitch1`. It is not
  enabled at boot.
- Unit hardening: `Type=dbus`, `CapabilityBoundingSet=CAP_NET_ADMIN`,
  `NoNewPrivileges=yes`, `ProtectSystem=strict`, `ProtectHome=yes`,
  `PrivateTmp=yes`, `RuntimeDirectory=solvetus` (0700),
  `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK`.
- The service never runs a shell and never accepts rule text, paths or
  firewall expressions from callers.

### D-Bus API

Interface `org.solvetus.KillSwitch1`:

- `Arm(s uuid, b allow_lan) -> a{sv}`
- `Disarm() -> a{sv}`
- `GetStatus() -> a{sv}`
- signal `StateChanged(a{sv})`

Status keys: `armed`, `state` (`off`/`armed`/`error`), `detail`, `uuid`,
`allow_lan`, `endpoints` (a count, not addresses), `backend`, `table`, `since`.

### Authorization

- polkit action `org.solvetus.killswitch.control`: `allow_active=yes`,
  `allow_inactive=no`, `allow_any=no`. The service calls `CheckAuthorization`
  with a `system-bus-name` subject; root bypasses polkit.
- `Arm` only accepts the reserved profile UUID and validates that the caller
  owns it through exactly one `user:<local-user>:` permission.
- `Disarm` is restricted to the UID that armed it, or root.
- `GetStatus` is readable by local users.

### nftables policy

- A dedicated table `inet solvetus_ks`. The service only adds and deletes this
  table; it never flushes the global ruleset and coexists with UFW.
- Output base chain at priority `-10`: accept loopback, `tun*`, DHCPv4/v6,
  IPv6 neighbour discovery (ICMPv6 133–136), the resolved VPN server addresses
  on their exact protocol/port, and optionally RFC 1918/ULA LAN ranges; drop
  all remaining IPv4 and IPv6.
- Forward chain policy drop.
- Server hostnames are resolved before the rules are applied. That lookup is a
  documented one-time DNS leak. Global IPv6 is blocked because the profiles are
  IPv4-only.

### State and recovery

- State lives in `/run/solvetus/killswitch.json`, root-only, mode 0600.
- On service start: table + valid state → restore armed; state without table →
  rebuild the rules from the saved endpoints; table without valid state →
  report `error` and require Disarm (fail closed).
- Reboot clears `/run` and the nftables ruleset: protection fails open, with
  no automatic re-arming.
- Quitting the GUI can keep protection armed or disarm it. The CLI
  `solvetus-killswitch disarm` is the recovery path.
- The GUI polls the service status every 5 seconds and never assumes local
  state.

### Verified behaviour

A live test with the VPN down armed the switch with 14 resolved endpoints.
DNS resolution, traffic bound to the physical interface and a direct TCP
connection to a public address all timed out; status stayed armed; disarm
restored IPv4 connectivity; UFW stayed active and only the dedicated table was
touched.

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
14. **No signed packages or reproducible builds.**

## 8. Test status

- Unit tests cover the parser, validator, store, settings, ownership, profile
  building, import verification, agent authorization, fetcher, country search,
  reconnect policy, tray properties, public-IP parsing, kill-switch rules and
  profile validation.
- UI harnesses in [`tests/manual/`](../tests/manual/README.md) exercise the
  window on a private Broadway display.
- Verified live: first VPN import/activation and browsing; keyring store,
  lookup and clear with a temporary entry; public-IP lookup; the kill-switch
  arm/leak/disarm test above; tray red/green icons; connected IPs, traffic
  totals, protocol display and Switch IP.
- Not yet verified live: a real unexpected drop with auto-reconnect,
  long hidden-window residency and reauthentication, a saved password across a
  full restart, the GUI kill-switch switch, dual-stack IPv6.
