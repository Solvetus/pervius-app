# Architecture

This document describes how Pervius is built, how the kill switch and the
leak guards work, what they do and do not protect against, and the known
limitations.
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
  notification clicks. `pervius --hidden` (start at login) stays in the tray.
  The language override is applied before GTK initialises.
- `pervius/ui/window.py` — main window, location chooser, connection state
  machine, tray menu callbacks, kill-switch controls, endpoint pinning,
  connection details, settings, help, about, notifications and quit/close
  prompts.
- `pervius/ui/account.py` — the Account dialog. It never reads a stored
  password (section 4).
- `pervius/ui/tray.py` — native StatusNotifierItem + DBusMenu implementation
  over Gio D-Bus. No AppIndicator library dependency.
- `pervius/i18n.py` — gettext setup (domain `pervius`) and country names
  through iso-codes (section 11).
- `pervius/autostart.py` — the XDG autostart entry for start at login.

### NetworkManager integration

- `pervius/nm/client.py` — async/sync add, update, activate and deactivate
  helpers, and the profile-preparation worker.
- `pervius/nm/importer.py` — runs `nmcli connection import --temporary` with
  `NM_CERT_PATH` pointing at an app-owned directory, verifies the imported
  settings against the parsed profile field by field (and rejects any
  `vpn.data` key outside a reviewed allowlist), builds the managed profile,
  deletes the temporary profile and keeps the CA file (mode 0600).
- `pervius/nm/profile.py` — builds the reserved managed profile. The **local
  profile owner and the VPN account name are separate**: the local login (for
  example `alice`) goes into `connection.permissions`; the VPN account (for
  example `vpnuser@example`) goes into `vpn.user-name`. It also pins the
  tunnel device to `pervius0`, makes VPN DNS exclusive and pins the remote
  list to resolved IP addresses (section 5). It keeps nothing in connection
  user-data: NetworkManager 1.58 drops it when it reads the profile back.
  Every change starts from NetworkManager's current settings (`GetSettings`),
  never from libnm's cached copy, which can lag behind our own last write.
- `pervius/nm/agent.py` — system-bus NetworkManager SecretAgent. Only
  NetworkManager may call it: a uid-0 connection that currently owns the
  `org.freedesktop.NetworkManager` bus name (uid 0 alone is not enough). It checks the UUID, connection ID,
  OpenVPN service type and an exact single-user permission before returning a
  password. It is the only reader of a stored password, by VPN account name.
- `pervius/ownership.py` — ownership manifest and reserved UUID/ID
  validation. Exactly one `user:<local-user>:` permission is required; empty
  permissions mean "all users" and are rejected.
- `pervius/credentials.py` — memory-only by default, optional Secret Service
  persistence, no plaintext fallback. `password_state()` tells the UI whether
  a password is kept without loading it.

### Catalogue and profiles

- The public server catalogue ZIP is downloaded over HTTPS from
  `vpn.ncapi.io` with strict archive limits, path safety, duplicate handling
  and size caps (`pervius/catalogue/fetcher.py`, libsoup 3).
- `pervius/catalogue/parser.py` — strict OpenVPN allowlist. It rejects
  external CA/cert/key files, inline certificates and keys, TLS-auth keys,
  scripts, plugins, compression, proxies and unknown options.
- `pervius/catalogue/validator.py` — archive validation and catalogue parsing.
  A profile that fails validation is left out and reported; it never fails
  the whole catalogue (an unsafe archive still does).
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
- `pervius/killswitchd/` — root service (`daemon.py`), pure rule generation
  (`rules.py`), profile validation (`profile.py`) and the service's own DNS
  lookups for the DNS window (`dnsquery.py`, dnspython).
- `data/networkmanager/90-pervius-guard` — the IPv6 leak guard, a
  NetworkManager dispatcher hook (section 6).
- `pervius/tools/` — catalogue inspector, live proof CLI and kill-switch CLI.
- `pervius/distro.py` — documented, report-only distribution checks
  (section 9).

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
- The tray mirrors the state (white glyph; green badge connected, amber badge
  reconnecting). Its menu: a status line with the connected time, Connect /
  Disconnect / Stop Retrying, Favorites, Choose Location, Kill switch (a
  checkmark from the service's real state), Show Pervius and Quit. GNOME's own
  VPN indicator stays visible as the system-level source of truth.
- Notifications are sent only while the window is unfocused or hidden.
- **The window never blocks.** The secret agent answers `GetSecrets`
  asynchronously (the keyring may have to be unlocked first); every
  NetworkManager call is bounded by a timeout and kill-switch calls run in
  worker threads (15 s). Connecting and reconnecting can always be
  cancelled, and Quit works at once even mid-connect.
- Tray "Show Pervius" presents the window with the XDG activation token the
  tray host provides (`ProvideXdgActivationToken`), so GNOME raises it.
- **DNS goes only through the tunnel.** The managed profile sets
  `ipv4.dns-priority=-1` and `ipv6.dns-priority=-1` (a negative priority
  excludes the DNS servers of every connection with a higher value) and the
  routing domain `~.`, so systemd-resolved sends every query not claimed by a
  more specific routing domain to the VPN's servers. Tools that configure
  resolved themselves for their own domains (for example NetBird's
  `netbird.cloud`) keep those domains.
- **Passwords never reach the UI.** The Account dialog asks the credential
  store only whether a password is kept (a Secret Service search that does
  not load the secret) and shows "Saved in the keyring" with Replace and
  Forget. The password entry, and its reveal toggle, exists only for a password
  being typed. The secret agent reads the stored password only inside
  `GetSecrets`, after authorizing NetworkManager and the connection.

## 5. Kill switch

### Privilege model

- The GUI and CLI are ordinary-user processes.
- A root systemd service (`pervius-killswitchd.service`) is D-Bus activated
  as `com.solvetus.Pervius.KillSwitch1` at `/com/solvetus/Pervius/KillSwitch1`. It is not
  enabled at boot.
- Unit hardening: `Type=dbus`, `python3 -I` (isolated: no `PYTHON*`
  variables, user site or working directory on the path),
  `CapabilityBoundingSet=CAP_NET_ADMIN`, `NoNewPrivileges=yes`,
  `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`,
  `PrivateDevices=yes`, `ProtectKernelTunables/Modules/Logs=yes`,
  `ProtectControlGroups=yes`, `ProtectClock=yes`, `ProtectHostname=yes`,
  `ProtectProc=invisible`, `ProcSubset=pid`, `RestrictNamespaces=yes`,
  `RestrictRealtime=yes`, `RestrictSUIDSGID=yes`, `LockPersonality=yes`,
  `SystemCallArchitectures=native`, `SystemCallFilter=@system-service`,
  `UMask=0077`, `RuntimeDirectory=pervius` (0700),
  `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK`
  (`systemd-analyze security`: 2.1, "OK").
- The service never runs a shell and never accepts rule text, paths or
  firewall expressions from callers.

### D-Bus API (version 2)

Interface `com.solvetus.Pervius.KillSwitch1`:

- `Arm(s uuid, b allow_lan, as interfaces) -> a{sv}`
- `Configure(b allow_lan, as interfaces) -> a{sv}` — change LAN access and the
  always-allowed interfaces while armed, in one atomic rebuild.
- `UpdateEndpoints(s uuid, b replace) -> a{sv}` — resolve the profile's server
  names again and swap the endpoint sets in one transaction (`replace=false`
  keeps the current endpoints as well, so a live tunnel is never cut).
- `SetGuardOptions(b block_ipv6, as interfaces) -> a{sv}` — options of the
  leak guard (section 6), written to the root-owned
  `/var/lib/pervius/guard.conf`; the caller must own the managed profile.
- `Disarm() -> a{sv}`
- `GetStatus() -> a{sv}`
- signal `StateChanged(a{sv})`

Status keys: `armed`, `state` (`off`/`armed`/`error`), `detail`, `uuid`,
`allow_lan`, `interfaces`, `endpoints` (a count, not addresses),
`resolved_at`, `guard` (whether the leak-guard table exists), `backend`,
`table`, `since`. Replies to `Arm` and `UpdateEndpoints` also carry
`resolved` (the endpoints, for the caller to pin its profile); `GetStatus`
and `StateChanged` never do. Errors: `PermissionDenied`, `NotAvailable`,
`NotArmed`, `ResolveFailed`, `Failed`; the GUI maps them to translated
messages.

### Authorization

- polkit action `com.solvetus.pervius.killswitch.control`: `allow_active=yes`,
  `allow_inactive=no`, `allow_any=no`, for every method except `GetStatus`.
  The service calls `CheckAuthorization` with a `system-bus-name` subject;
  root bypasses polkit.
- `Arm` and `UpdateEndpoints` only accept the reserved profile UUID and
  validate that the caller owns it through exactly one `user:<local-user>:`
  permission.
- `Configure`, `UpdateEndpoints` and `Disarm` are restricted to the UID that
  armed the switch, or root. The owner is saved with the state and kept
  through a failed recovery; when it is unknown (a table without saved
  state), only root may change or disarm the switch.
- `GetStatus` is readable by local users. It never starts a process per
  call: the leak-guard check is cached for two seconds.
- Callers never pass rule text, paths or addresses. Interface names are
  validated strictly (1–15 characters from `[A-Za-z0-9_.-]`, starting with a
  letter or digit, never `.` or `..`, at most 16).

### nftables policy

- A dedicated table `inet pervius_ks`. The service only adds, replaces and
  deletes this table; it never flushes the global ruleset and leaves firewall
  front ends such as ufw or firewalld untouched. Every change is one `nft -f`
  transaction: a full rebuild is "create if missing, delete, define again",
  so there is never a moment without rules; an endpoint update flushes and
  refills the named sets and closes the DNS window in the same transaction.
- Named sets: `allowed_ifaces` (`ifname`), `endpoints_v4` / `endpoints_v6`
  (`addr . inet_proto . inet_service`), `dns_window_v4` / `dns_window_v6`
  (addresses with `flags timeout`).
- Output base chain at priority `-10`: accept loopback; the tunnel, matched
  by name **and** device kind (`oifname "pervius0" oifkind { "tun", "ovpn",
  "ovpn-dco" }`: OpenVPN's tun device or its in-kernel data channel offload
  device, so a VLAN, macvlan or dummy that takes the name is not trusted);
  `oifname @allowed_ifaces` (the interfaces the user always allows, for
  example NetBird's `wt0`); DHCPv4 only to broadcast or local addresses
  (RFC 1918, `100.64.0.0/10`, link-local) and DHCPv6 only to `ff02::1:2` or
  `fe80::/10`; IPv6 neighbour discovery (ICMPv6 133–136); the endpoint sets
  on their exact protocol and port; while a DNS window is open, plain DNS
  (port 53) **from the service's own cgroup** (`socket cgroupv2 level 2
  "system.slice/pervius-killswitchd.service"`) to the window's resolvers; then
  DNS (53) and DNS over TLS/QUIC (853), TCP and UDP, are dropped; optionally
  RFC 1918/ULA LAN ranges; drop all remaining IPv4 and IPv6.
- Forward chain policy drop.
- There is no `tun*` wildcard: another VPN's tunnel is blocked unless you
  allow it.

### Endpoints, pinning and the DNS window

Every catalogue remote is a host name, and while the kill switch is armed
and the tunnel is down, DNS is blocked. Pervius therefore:

1. **The profile is always pinned.** Before every activation the remote list
   is set to resolved IP addresses, so OpenVPN never needs DNS to (re)connect
   while the leak guard or the kill switch blocks it. Without the kill switch
   the app resolves the names (asynchronously, before the tunnel exists);
   with it armed the app writes the provider's names (from the catalogue)
   into the profile and the service resolves and allows them, then the app
   pins the answer. Verification accepts IP literals on the catalogue
   profile's ports; which catalogue profile the stored one is comes from the
   ownership manifest's source hash. The CA and `verify-x509-name` checks
   still decide whether a server is genuine.
2. **Arming keeps the live tunnel.** Because the profile is pinned, arming
   allows exactly the addresses the tunnel uses; the service also adds the
   live VPN server (NetworkManager's host route to it). Arming never cuts an
   active tunnel.
3. **Refreshes through the tunnel.** After every connection while armed the
   GUI calls `UpdateEndpoints(replace=false)`, which resolves through the
   tunnel's DNS, so provider IP rotation is tracked without any DNS outside
   the tunnel. If that fails, the profile is pinned back to its previous
   addresses; it never stays on bare names.
4. **Switches location without a gap.** A connected tunnel switching location
   imports the new profile, calls `UpdateEndpoints(replace=false)` while the
   old tunnel still carries DNS (the old server stays allowed, so the old
   OpenVPN can close cleanly and release `pervius0`), pins the new addresses,
   disconnects, waits until `pervius0` is gone, and connects. Once the new
   tunnel is up, `UpdateEndpoints(replace=true)` drops the old location's
   servers; the service always keeps the live tunnel's server allowed.
   Protection never lapses.
5. **Uses a DNS window only when unavoidable.** When the tunnel is down (a new
   location while disconnected, or the first retry after a drop), the
   service adds the physical links' resolvers (from NetworkManager) to the
   window set with a 5-second kernel timeout, at most once per 30 seconds,
   and resolves the names itself with dnspython: A and AAAA only, a random
   query ID and source port, a 2-second per-server and 5-second overall
   timeout, a 1232-byte reply cap, and truncated, malformed or mismatched
   replies rejected. At most four **public** addresses per name and address
   family are taken (private, shared, loopback, link-local and documentation
   space is refused), and every new address learned through the window is
   **provisional**: unless the tunnel is up 90 seconds later, the service
   removes it again (the deadline survives a service restart). Only packets
   from the service's cgroup match the window rule; other processes' DNS
   stays blocked. The window closes in the same
   transaction that swaps the endpoints, or expires in the kernel even if the
   service dies. If the cgroup cannot be determined, no window rule is built
   and such a lookup fails closed. A failed resolution never changes the
   endpoint set.

### State and recovery

- State lives in `/run/pervius/killswitch.json` (version 2: adds the allowed
  interfaces and the last resolution time), root-only, mode 0600.
- On service start: valid state → rebuild the table atomically from the saved
  endpoints and interfaces, whether or not the table survived (the DNS window
  rule names the service's cgroup, which a restart replaces); table without valid state → report
  `error` and require Disarm by root (`sudo pervius-killswitch disarm`;
  fail closed). A rebuild failure keeps the old table and the saved owner.
- Reboot clears `/run` and the nftables ruleset: protection fails open, with
  no automatic re-arming.
- Quitting the GUI can keep protection armed or disarm it; the rules survive
  the GUI exiting or crashing. The CLI `pervius-killswitch disarm` is the
  recovery path.
- The GUI polls the service status every 5 seconds and never assumes local
  state.

### Verified behaviour

A live test with the VPN down armed the switch with 14 resolved endpoints.
DNS resolution, traffic bound to the physical interface and a direct TCP
connection to a public address all timed out; status stayed armed; disarm
restored IPv4 connectivity; only the dedicated table was touched.

The rules are tested in CI inside a throwaway network namespace with
dummy interfaces (`tests/integration/`), using the kernel as the oracle
(`EPERM` from the output hook): endpoints on their exact protocol and port,
the pinned tunnel versus other tunnels, always-allowed interfaces, LAN
access, atomic endpoint swaps, a rejected transaction keeping the old set,
the DNS window admitting only its cgroup and expiring, and the leak guard.

Verified live (Ubuntu 26.10, home LAN): no DNS on the physical
link while connected (tcpdump, including a catalogue refresh and with
NetBird installed), the leak guard present on the first connection after
install, arming while connected without dropping the tunnel, traffic
through `pervius0` while armed, a location switch while armed, connecting
while armed from disconnected, Cancel/Quit while connecting, and the tray.
Not yet tested live: reaching a NetBird peer through an always-allowed `wt0`.

## 6. Leak guard (DNS and IPv6)

The FastVPN profiles are IPv4-only. Without a guard, IPv6 traffic would leave
over the physical link while the VPN is "connected", and DNS could still
reach the physical link's resolver: a tool such as NetBird can put its search
domain on that link, and failed lookups are then retried with the suffix
against the router (observed on the test machine).

### Design: a NetworkManager dispatcher hook

`/usr/lib/NetworkManager/dispatcher.d/90-pervius-guard` (POSIX sh, 0755,
root-owned) with a link in `pre-up.d/`. It was chosen over the kill-switch
service because:

- NetworkManager runs it for **every** activation path (the app, `nmcli`, the
  desktop's VPN menu, NetworkManager's own reactivation), with no Pervius
  process running. The service is started only on demand and would miss
  activations it did not see.
- In `vpn-pre-up`, NetworkManager **waits** for the hook, so the guard is in
  place before the VPN is reported as activated. A service watching
  NetworkManager's signals could only react afterwards.
- The kill-switch service stays D-Bus-activated and idle until armed; no
  permanently running root daemon is needed.

### Behaviour

- First statement: exit unless `CONNECTION_UUID` is the reserved Pervius
  UUID. Its inputs are NetworkManager's arguments and environment and one
  root-owned options file (below); every value is validated.
- `vpn-pre-up` / `vpn-up`: atomically (re)install the table
  `inet pervius_guard` (output and forward chains at priority -10):
  - **DNS** (UDP/TCP 53, and DNS over TLS/QUIC on TCP/UDP 853) may use only
    loopback, the tunnel and the always-allowed interfaces; queries to any
    other interface, such as the router's resolver, are dropped. The same
    applies in the forward chain, so containers and VMs that route through
    this host cannot query the router either. The tunnel is matched by name
    and device kind, as in the kill switch. NetBird's own domain keeps working
    through NetBird's local resolver or its interface (if allowed); public
    names never reach the physical resolver.
  - **IPv6** (unless turned off): outside the tunnel only loopback,
    link-local (`fe80::/10`, `ff02::/16`), ICMPv6 neighbour discovery,
    unique local addresses (`fc00::/7`, not routable on the internet) and
    the always-allowed interfaces pass; all other IPv6 is dropped.
  - Other IPv4 is untouched.
- `vpn-down`: delete the table.
- A VPN that was already up when Pervius was installed never saw
  `vpn-up`: the package's `postinst` and the kill-switch service (at start
  and whenever the options change) run the same hook for it. A guard left behind by a NetworkManager crash
  fails closed for IPv6 only; it is cleared by the next managed VPN event, by
  the kill-switch service when it starts (if the managed VPN is not active),
  by a reboot, or with `sudo nft delete table inet pervius_guard`.
- Options: `/var/lib/pervius/guard.conf`, written by the kill-switch service
  (`SetGuardOptions`, from Settings → Block IPv6 while connected, default on,
  and Always allow these interfaces). The hook reads it only if it is
  root-owned, mode 0644 and not a symlink; otherwise it uses the defaults
  (block IPv6, no extra interfaces). Changes apply from the next
  connection. (NetworkManager user-data would have been the natural
  channel, but NetworkManager 1.58 does not keep it.)
- The app's own lookups while connected also stay in the tunnel: the exit-IP
  lookup resolves through `pervius0`'s DNS only (systemd-resolved, search
  domains off) and fails rather than fall back.
- It works whether or not the kill switch is armed; with both active, both
  tables must accept a packet.

## 7. Threat model

### Protected against while the VPN is connected (kill switch on or off)

- DNS queries outside the tunnel: NetworkManager makes the VPN's DNS
  exclusive (section 4).
- IPv6 traffic escaping the IPv4-only tunnel, and DNS reaching the physical
  link's resolver: the leak guard (section 6).

### Protected against while the kill switch is armed

- Applications sending traffic over Ethernet/Wi-Fi while the VPN is down.
- Leaks after an unexpected VPN drop, including during automatic reconnect.
- Traffic through another VPN's tunnel or any interface you did not allow.
- Plain DNS queries to a local or ISP resolver outside the tunnel. The one
  exception is the DNS window: while the tunnel is down, only the
  kill-switch service's own lookups of the VPN server names may reach the
  link's resolvers, for at most 5 seconds. These lookups skip DNSSEC and the
  local cache. A hostile or spoofing resolver can add at most four public
  addresses per server name and address family to the allowlist, only on
  the VPN's port and protocol, and only provisionally: they are removed
  again unless the tunnel is up within 90 seconds. Server identity is still
  enforced by the CA and `verify-x509-name`.
- Stale firewall state left by a crashed GUI process (fail closed).

### Not protected against

- Root, kernel or hypervisor compromise; malware that edits firewall rules.
- A malicious VPN provider or one that logs traffic.
- Side channels, traffic correlation or endpoint compromise.
- Applications in a separate network namespace the rules do not cover.
- Captive portals while strict blocking is armed.
- IPv4 traffic outside the tunnel while the kill switch is **off** (for
  example during a drop or before connecting).
- Applications that ignore the system resolver (their own DoH/DoT or
  hard-coded resolvers) while the kill switch is off; while it is armed their
  traffic is blocked like any other.
- Arming while disconnected resolves the server names before any rule exists
  (a one-time lookup outside the tunnel).

## 8. Known limitations

1. **One managed NetworkManager profile only.** Favorites change its location;
   they don't create separate profiles or accounts.
2. **No auto-protect.** The kill switch never arms automatically at login or on
   a network change. Boot is fail-open.
3. **No DNS filtering.** No resolver, blocklists or DoH/DoT handling. While
   connected, all DNS goes through the tunnel's resolvers; plain DNS outside
   the tunnel while disconnected is blocked only while the kill switch is
   armed.
4. **IP rotation is tracked while connected.** The allowed endpoints are
   refreshed after every connection and before the first reconnect attempt;
   if the provider moves servers while you are disconnected for a long time
   and the DNS window cannot be used, reconnecting can fail until you
   disarm and arm again.
5. **The privileged component ships in the main package** for convenience; it
   is idle until armed.
6. **The public-IP display uses a third-party HTTPS endpoint**
   (`api64.ipify.org`), which sees your public IP. If the app starts while
   connected, the ISP IP is "Not captured" because learning it would leak.
7. **Traffic totals are interface totals** since the first sample, not
   provider billing or history.
8. **Switch IP is a reconnect**, not a server-selection API; it can return the
   same exit IP.
9. **The kill-switch and guard paths are verified live only through the
   release checklist**; the rules themselves are tested in CI in a network
   namespace.
10. **City names are not translated**; they come from the provider's
    catalogue. Country names are translated through iso-codes.
11. **`diagnose` reports the service as inactive until D-Bus activation**,
    because it checks `NameHasOwner` without activating the service.
12. **GNOME's VPN indicator cannot be hidden**; a shell extension would be
    fragile and is deliberately not attempted.
13. **No multiple simultaneous VPNs or accounts; no split tunnelling.**
14. **No signed packages or reproducible builds.** Releases publish a
    `SHA256SUMS` file next to the `.deb`.
15. **The leak guard and the kill switch protect this machine's traffic**;
    the guard also drops forwarded IPv6, but containers or VMs in their own
    network namespaces are outside both.
16. **Forwarded DNS is guarded too.** While the VPN is connected, DNS that
    containers or VMs route through this host may leave only through the
    tunnel or an always-allowed interface. A DNS server running in a
    container on a local bridge (for example a Pi-hole container serving
    other containers) needs that bridge (`docker0`, `br-…`) in the
    always-allowed interfaces.
17. **DHCP renewals to a public DHCP server are blocked while armed.** DHCP
    is allowed only to broadcast and local addresses; a client whose DHCP
    server has a public address renews by broadcast (rebinding) instead.
18. **The DNS window needs cgroup v2** (standard on current distributions).
    Without it, resolving new server names while armed and disconnected fails
    closed.

## 9. Platform differences

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
- **NetworkManager dispatcher:** the leak guard lives in
  `/usr/lib/NetworkManager/dispatcher.d`, the same path on Debian/Ubuntu and
  Fedora.

Install paths are listed once in `packaging/layout.tsv`; see
[`PACKAGING.md`](PACKAGING.md).

## 10. Future work

### Roadmap (security)

- **CA change warning.** The catalogue supplies both the server names and
  the CA, so trust in a new CA rests on HTTPS to the catalogue host alone.
  Pervius should remember the CA hash it last accepted and ask before using
  a profile whose CA differs.
- **Re-authentication for weakening operations.** The polkit action allows
  every kill-switch operation in an active session without a prompt. Disarm,
  allowing the LAN and adding always-allowed interfaces weaken protection and
  should use a separate action with `auth_self_keep`.
- **Always-on VPN.** An opt-in boot-time ruleset (a systemd unit ordered
  before the network comes up) that blocks traffic outside the tunnel from
  boot until the user connects or disarms, closing the fail-open window
  after a reboot.

### Other

- **Auto-protect** needs a background component that is not tied to the
  window, a trusted-network model, an auto-connect and credential policy,
  captive-portal handling, and a documented escape hatch. It must not be a
  toggle that arms without being able to reconnect.
- **DNS filtering** needs a local filtering resolver with maintained
  blocklists, integration with systemd-resolved, and an explicit DoH/DoT
  policy. It filters names, not IP-literal traffic, and must not be labelled
  "DNS leak protection" unless the fallback paths are addressed.
- **End-to-end tests** still to automate in a disposable VM: a real VPN drop
  during reconnect, a service restart (rules rebuilt), reboot (fail-open),
  uninstall (tables and service removed), and bypass attempts with a host
  firewall front end active. The rules themselves are already tested in a
  network namespace.

## 11. Translations

- gettext domain `pervius`; English source strings, catalogues for European
  Portuguese, French, Spanish and Italian in `po/`, compiled at build time by
  `packaging/build-i18n.sh` (never committed). The desktop file and AppStream
  metadata are translated from `data/*.in` templates with `msgfmt --desktop`
  and `msgfmt --xml`. `scripts/update-pot.sh` regenerates the template.
- Strings use positional placeholders (`{0}`), `ngettext` for plurals and
  translator comments.
- Settings → Language overrides the system language through `LANGUAGE`,
  applied at startup before GTK and gettext initialise; changing it asks for
  a restart.
- The command-line tools and manual pages stay in English.

## 12. Test status

- Unit tests cover the parser, validator, store, settings, ownership, profile
  building, import verification, agent authorization, the password-never-in-UI
  guarantees, fetcher, country search, reconnect policy, tray properties,
  public-IP parsing, kill-switch rules and service (authorization, atomic
  updates, DNS window, provisional endpoints, owner recovery, status cost),
  the dnspython lookups against malformed, spoofed and oversized answers, the leak-guard hook, translation completeness and coverage,
  the language override, start at login, the distribution checks, and
  version consistency.
- Integration tests (`tests/integration/`) enforce the kill-switch and IPv6
  guard rules in a network namespace with a real tun device; CI runs them
  with `sudo unshare --net`. They include an impostor device named like the
  tunnel, DHCP destinations, DNS over QUIC and DNS forwarded from a client
  namespace.
- UI harnesses in [`tests/manual/`](../tests/manual/README.md) exercise the
  window on a private Broadway display.
- Verified live: first VPN import/activation and browsing; keyring store,
  lookup and clear with a temporary entry; public-IP lookup; the kill-switch
  arm/leak/disarm test; connected IPs, traffic totals, protocol display and
  Switch IP.
- Not yet verified live: a real unexpected drop with auto-reconnect, long
  hidden-window residency and reauthentication, a saved password across a
  full restart.
