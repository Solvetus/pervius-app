# Security features — design proposal

Status: **implemented for the test VM in 0.1.13.** The kill-switch service,
CLI, and GUI control are present and the service passed a live arm/leak/disarm
test. Auto-protect and DNS filtering remain design-only.

## 0. Approved baseline (2026-11-17)

- Optional privileged package `solvetus-vpn-killswitch`; the current test build
  ships it inside one combined `.deb` for convenience.
- nftables only; dedicated table; coexist with UFW.
- Strict LAN policy: LAN blocked by default; an explicit Allow LAN option is
  required for printers/NAS.
- Arm before connecting, with the documented DNS bootstrap limitation.
- On GUI quit: ask; default is to keep protection armed.
- On boot: fail open with a visible warning.
- Auto-protect and DNS filtering remain deferred.
- Implementation status: service, CLI, and GUI control complete; live test with
  the VPN off blocked DNS, physical-interface traffic, and direct TCP; disarm
  restored IPv4 connectivity; UFW stayed active. A dual-stack IPv6 test is
  still pending because the VM has no global IPv6 route.

## 1. Goals

- Prevent accidental traffic leaks when the VPN is down, drops, reconnects, or
  is bypassed by an application.
- Make DNS behaviour explicit: no silent fallback to an untrusted resolver.
- Keep the graphical application an ordinary-user process.
- Never present a security toggle that is not enforced.
- Keep every feature removable and testable, with a clear “off” state.

## 2. Non-goals

- Protecting against a compromised kernel, root account, or VPN provider.
- Hiding traffic patterns from the local network or ISP beyond what the tunnel
  itself provides.
- Circumventing captive portals, firewalls that block VPN traffic, or local
  policy.
- A guarantee that every application respects the tunnel; only kernel-level
  filtering can approach that.
- DNS filtering in the first implementation. It is a separate resolver feature,
  not a firewall checkbox.

## 3. Current architecture

- GUI runs as the desktop user and talks to NetworkManager over D-Bus.
- One app-owned OpenVPN profile is imported through the OpenVPN plugin, with an
  agent-owned password and an app-owned CA file.
- Automatic reconnect retries after an established tunnel drops.
- The app does **not** run as root and has no privileged helper.
- GNOME’s own VPN indicator remains the system-level tunnel signal.

This architecture is suitable for managing connections, but it cannot install
kernel firewall rules. A real system-wide kill switch therefore requires a
privileged component. That is a scope decision, not an implementation detail.

### Verified environment constraints

The test VM has:

- nftables 1.1.6 and the nft variant of iptables.
- **UFW active**, using the nftables backend.
- polkitd and `pkexec` installed.
- NetworkManager 1.58.1 and the OpenVPN plugin.

The kill switch must use its own table (for example `inet solvetus_ks`) with a
base chain at an early priority, add only its own rules, and **never** run
`nft flush ruleset`, replace UFW rules, or disable UFW. A drop in our own base
chain still wins over UFW accepts. Integration tests must run with UFW enabled.

## 4. Threat model

### Protected against

- An application sending traffic over Ethernet/Wi-Fi while the VPN is down.
- Leaks after an unexpected VPN drop, including during automatic reconnect.
- IPv6 traffic escaping when the tunnel is IPv4-only.
- Plain DNS queries going to a local or ISP resolver outside the tunnel.
- A stale firewall state left by a crashed GUI process (within the chosen
  fail-closed or fail-open policy).

### Not protected against

- Root, kernel, or hypervisor compromise.
- A malicious VPN provider or a provider that logs traffic.
- Malware that can modify firewall rules directly.
- Side channels, traffic correlation, or endpoint compromise.
- Applications that use a separate network namespace or interface the rules do
  not cover, unless explicitly blocked.
- Captive portals while strict blocking is armed.

## 5. Privilege model options

### A. No privileged component

Only routes and DNS settings can be changed. Routes are not a firewall:
applications can bind to the physical interface, IPv6 can leak, and DNS can
fall back. This option can be described as “route guard”, never as a kill
switch. **Rejected as a kill-switch implementation.**

### B. NetworkManager dispatcher script

A root script in `/etc/NetworkManager/dispatcher.d/` reacts to VPN up/down and
installs rules. Simple, but policy is static and the GUI cannot reliably arm or
disarm it without writing a privileged configuration file. Cleanup and error
reporting are weak. Suitable only for an always-on policy, not a user toggle.

### C. Optional system service with a narrow D-Bus API — recommended

Ship a separate, optional package, for example `solvetus-vpn-killswitch`:

- `solvetus-killswitchd.service`, running as root under systemd.
- D-Bus name `org.solvetus.KillSwitch1`, one object, a few methods:
  - `Arm(profile_uuid, policy)` → status
  - `Disarm()` → status
  - `GetStatus()` → state, backend, ruleset version, last error
- Polkit action `org.solvetus.killswitch.control`, limited to the active local
  user. No setuid binary.
- nftables backend only for the first version (Ubuntu 24.04+ target). Detect a
  missing backend and report “not available”; do not silently fall back to
  weaker rules.
- The service never accepts arbitrary rule text, shell commands, paths, or
  firewall expressions. It reads the reserved NetworkManager profile by UUID
  and extracts only validated remote hosts/ports/protocols.
- All state lives in root-owned `/run/solvetus/` (tmpfs). The GUI cannot write
  it directly.
- The base application remains unprivileged. If the optional package is not
  installed, the GUI shows an explanation and no switch.

### D. One-shot `pkexec` helper

Rejected. Cleanup after a crash is unreliable, and every change becomes a new
privileged process invocation.

## 6. Kill-switch policy

### States

- `off` — no Solvetus firewall table.
- `arming` — rules installed, VPN server endpoints allowed, tunnel not yet up.
- `active` — rules installed and tunnel up.
- `disarming` — rules being removed.
- `error` — rules may be partially applied; status must be visible.

The GUI must display the actual service state, not an optimistic local flag.

### Initial rule set (strict, IPv4 tunnel)

nftables table `inet solvetus`, dedicated chains, named comments for audit:

- Allow loopback.
- Allow traffic on `tun*` interfaces.
- Allow DHCP client traffic (UDP 68 → 67) so the physical link keeps a lease.
- Allow IPv6 neighbour discovery and link-local control traffic.
- Allow the resolved VPN server addresses on their exact protocol/port
  (UDP/1194, TCP/443, etc., from the validated profile).
- Block all other IPv4 forwarding/output on physical interfaces.
- Block all global IPv6 output. The current catalogue profiles are IPv4-only;
  if an IPv6 tunnel is added later, this rule must be revised.
- Block DNS to non-tunnel destinations by the general physical-interface drop.
  DNS inside the tunnel remains allowed.

Open decision: allow RFC1918 LAN traffic (printers, NAS) or block it. Strict
means block; convenience means allow. This must be an explicit, labelled
policy, not a silent default.

### Arming order

1. Read and validate the reserved profile via NetworkManager.
2. Resolve all remote hostnames before DNS is blocked.
3. Install the allow rules, then the drop rules.
4. Verify the ruleset with `nft list ruleset`/netlink.
5. Ask NetworkManager to activate the VPN.
6. Mark `active` only when NetworkManager reports the tunnel activated.

If any step fails, keep the last known-safe state and report the failure. Do
not claim “protected” from a partially installed ruleset.

### DNS bootstrap limitation

Resolving the VPN server hostname before arming may itself use the local
resolver. That query is a small, one-time leak and must be documented. After
arming, DNS is only possible through the tunnel. If the provider rotates server
IPs, reconnection may fail until the user disarms/re-arms; that is an honest
fail-closed behaviour, not a silent leak.

### Lifecycle decisions

- GUI quit while kill switch is armed: ask whether to disarm. Leaving it armed
  without the secret agent can leave the user offline after a drop.
- App crash: the system service keeps the rules; fail-closed.
- Service crash: systemd restarts it; if rules cannot be reconstructed, they
  remain until explicitly cleared.
- Reboot: `/run` state disappears. Default is fail-open (normal network) with a
  visible warning on next start, unless a future auto-protect feature changes
  that policy.
- Uninstall: package removal must flush the table and stop the service.

## 7. Automatic reconnection interaction

- Rules stay installed for the entire reconnect cycle.
- Server endpoints remain allowed while the tunnel is down.
- A successful reconnect does not reinstall or relax rules.
- Giving up reconnection leaves the rules installed (fail-closed) and the GUI
  shows “protection active, VPN down”.
- Disarming is always a deliberate user action with confirmation.

## 8. Auto-protect

Proposed definition: when the app starts or a network change is detected,
enable the kill switch and require a VPN connection before allowing traffic.

This requires:

- a background service that is not tied to the window,
- trusted-network configuration (SSID/Ethernet identity),
- auto-connect policy and credential availability,
- captive-portal handling (otherwise hotel/airport Wi-Fi becomes unusable),
- clear recovery instructions and a documented escape hatch.

It is a separate design and implementation phase after the kill switch. Do not
add an auto-protect switch before the daemon exists.

## 9. DNS filtering

DNS filtering is not a VPN firewall rule. It needs:

- a local filtering resolver with maintained blocklists,
- a way to make systemd-resolved/apps use it (networkd/resolved configuration),
- blocking or accepting DoH/DoT bypasses (a policy decision with privacy
  trade-offs),
- update and failure handling for blocklists,
- a clear statement that it filters names, not IP-literal traffic.

Options considered:

1. **Hosts-file blocklist** — simple, but weak, bypassable, and requires root
   edits. Not a real filtering service.
2. **Local forwarding resolver + nftables redirect** — meaningful, but needs a
   packaged daemon, blocklist updates, and DoH/DoT policy. This is the credible
   option.
3. **Provider-side filtering** — outside this app’s control.

Recommendation: defer until after the kill switch is stable. If implemented,
ship it as another optional package and never label it “DNS leak protection”
unless DoH/DoT and fallback paths are addressed.

## 10. Testing plan

### Unit tests

- Rule generation from a validated profile: remotes, ports, protocol, IPv4
  only, duplicate remotes, invalid ports, no shell interpolation.
- Input rejection: arbitrary paths, rule text, UUID not reserved, non-OpenVPN
  profile, malformed remote strings.
- State machine transitions and idempotent Arm/Disarm.
- Status reporting when nftables is unavailable.

### Integration tests

Use a disposable VM/network namespace, never the user’s live network without
approval:

- Arm with VPN down → verify no internet, no DNS, no IPv6.
- Arm, connect → verify traffic uses `tun0`.
- Drop `tun0` → verify no leak during reconnect.
- Reconnect succeeds → verify tunnel traffic resumes.
- Disarm → verify normal network returns and no Solvetus table remains.
- GUI crash → service state remains fail-closed.
- Service restart → rules reconstruct or report error.
- Reboot → verify documented fail-open/fail-closed policy.
- Package uninstall → table and service removed.
- Attempted bypass: bind to physical interface, IPv6 literal, plain DNS,
  direct IP, DoH endpoint.
- Existing UFW rules remain intact and functional after arm and disarm.

### Leak checks

- `curl --interface enp0s1` while armed must fail.
- Plain DNS query to a public resolver must fail while armed.
- IPv6 ping/HTTP must fail.
- Route table must not contain a non-VPN default when armed.
- No traffic counters on physical interface except allowed control/VPN
  endpoints.

## 11. UX requirements

- A real **Kill switch** row with states: Off, Arming, Active, Error,
  Unavailable (package/backend missing).
- A one-time explanation of what is and is not blocked.
- An explicit **Allow local network** option if we support LAN access.
- A prominent “VPN down, protection active” state after a drop or failed
  reconnect.
- No “Auto-protect” or “DNS filtering” controls until those features exist.
- Logs avoid passwords, keys, and full connection contents.

## 12. Open decisions

1. ~~Approve an optional privileged system service?~~ Approved and implemented.
2. ~~Default LAN policy~~ Strict; Allow LAN is opt-in and locked while armed.
3. ~~GUI quit behaviour~~ Prompts; can disarm or keep protection.
4. ~~Boot behaviour~~ Fail open with a visible warning; no auto-protect yet.
5. ~~First implementation scope~~ Pre-connect arm; DNS bootstrap documented.
6. DNS filtering: still deferred; needs a separate resolver design.

## 13. Recommended sequence

1. Approve decisions 1–5.
2. Build a read-only diagnostic (`nftables` availability, existing tables,
   routes, DNS, IPv6) with no system changes.
3. Build the optional kill-switch service and CLI, test it with network
   namespaces first.
4. Integrate the GUI state, reconnect, quit, and notification paths.
5. Only then design auto-protect and DNS filtering.
