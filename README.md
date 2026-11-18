# Solvetus VPN Manager (test build)

An independent GTK4/libadwaita desktop front end for an existing
FastVPN/OpenVPN subscription. It does not provide a VPN service and is not
affiliated with the VPN provider.

This is an early **0.1.19 test build**. No license has been chosen; all rights
are reserved. Do not redistribute the package without permission. The product
name, application ID, and licensing remain provisional.

## What it does

- Downloads the provider's public catalogue over HTTPS and validates it
  strictly before use.
- Rejects unexpected, insecure, or unsupported OpenVPN directives instead of
  silently ignoring them.
- Shows country flags and full country names, and searches by city, country,
  country code, or common aliases such as UK, USA, and Holland.
- Includes a TCP/UDP guide; UDP is the default and TCP is for restrictive
  networks.
- Imports the selected profile through NetworkManager's OpenVPN editor plugin,
  verifies the security-relevant fields, and builds one reusable app-owned
  NetworkManager profile.
- Keeps the VPN password out of the NetworkManager profile. The app registers a
  system-bus NetworkManager secret agent and supplies the password only when
  NetworkManager asks for it.
- Retries an unexpected drop of an established tunnel with bounded backoff,
  visible countdown, and a Stop button.
- Sends desktop notifications for connection loss, automatic recovery, and
  reconnection giving up while the window is hidden; clicking one brings the
  window back.
- Adds a Solvetus tray icon via StatusNotifierItem with connection, location,
  settings, notification, help, legal, and quit actions. Ubuntu's own VPN
  indicator remains visible and authoritative for tunnel state.
- Supports favorite locations: star them in the location list, filter to
  favorites, and connect from the tray's Favorites submenu.
- Provides a real, service-backed kill switch with a dedicated nftables table,
  live status, strict default policy, optional LAN access, and safe quit/close
  prompts. The GUI stays unprivileged; polkit authorizes the root service.
- Shows the ISP public IP captured while disconnected and the VPN exit IP
  measured through the tunnel, with a **Switch IP** reconnect action.
- Shows session download/upload totals from the active tunnel interface and the
  transport actually in use: **OpenVPN · UDP** or **OpenVPN · TCP**.
- Includes **Forget Saved Password** to remove the keyring entry and the
  in-memory copy after confirmation.
- Runs entirely as an ordinary user. NetworkManager performs privileged network
  operations.

## What it does not do

- No auto-protect or DNS filtering yet. DNS filtering needs its own resolver
  and DoH/DoT policy; see [`docs/security-design.md`](docs/security-design.md).
- The kill switch does not arm itself at login or on a network change. You
  enable it explicitly. It blocks traffic outside the VPN, but it is not a
  defense against root/kernel compromise or a malicious VPN provider.
- Location and protocol changes are locked while the kill switch is armed,
  because the firewall allowlist is built from the current profile. Disarm
  first to switch.
- No unbounded or credential-retry loop. Automatic reconnection is limited to
  six attempts after an established tunnel drops. It never retries a failed
  first connection, a rejected password, a manual disconnect, or a quit, and it
  does not prompt for credentials again.
- No support for client certificates, static TLS keys, proxies, external
  scripts, plugins, compression, or TAP devices.
- Cannot hide or replace GNOME's own VPN indicator. That emblem belongs to the
  shell and stays visible as a system-level tunnel signal.
- No multiple simultaneous NetworkManager profiles or VPN accounts. One
  profile is active at a time; favorites only change its selected location.
- No guarantee of background residency. Closing the window with an active or
  reconnecting VPN hides it and is designed to keep the process running, but
  long hidden sessions and reauthentication remain unverified.
- No start-at-login option yet.
- No guarantee of Ubuntu 24.04 compatibility. The only verified environment is
  the test VM described below.

## Install

```sh
sudo apt install ./solvetus-vpn_0.1.19_all.deb
```

Then start **Solvetus VPN Manager** from the application menu, or run:

```sh
solvetus-vpn
```

Do not run the application with `sudo`. NetworkManager handles privileges.

## First use

1. Open the main menu and choose **Credentials**.
2. Enter the VPN username and password provided by your VPN service.
3. Choose a location and UDP or TCP.
4. Press **Connect**.

The VPN username is the account name sent to the VPN server. It is separate
from your local Ubuntu login, which owns the NetworkManager profile; shared
computers cannot use or modify that profile from another account.

## Reconnection

**Reconnect automatically** is on by default. If an established tunnel drops,
the app retries after 2, 5, 10, 20, 30, and 60 seconds, showing a countdown and
a **Stop Retrying** button. Before each attempt it re-verifies the managed
profile, ownership, and CA file; if any of them is wrong it stops and asks you
to rebuild the profile with **Try Again** instead of looping.

Manual **Disconnect**, **Quit**, a failed first connection, and a rejected
password never start the retry loop. Turning the switch off cancels a retry in
progress. Closing the window during reconnection hides it and keeps retrying;
quitting cancels the retry.

## Tray icon

While the app runs, a Solvetus icon is exported through StatusNotifierItem and
shown by Ubuntu's AppIndicator support. The icon carries a **red dot when no
managed tunnel is active** and a **green check when it is connected**; the
tooltip repeats the current location, protocol, and state. Its menu provides:

- Connect / Disconnect / Stop Retrying, following the current state
- Favorites: starred locations, with direct connect and Manage Favorites
- Choose Location
- Show Solvetus VPN Manager
- Settings
- Notifications (checkable)
- Help: Protocol Guide and About
- Legal Information: license status and third-party components
- Forget Saved Password
- Quit

Ubuntu's NetworkManager VPN indicator remains in place and reports the real
tunnel state even if the app is hidden or closed. The tray is a second control
surface, not a replacement.

GNOME does not expose a supported setting to hide only its VPN emblem. Doing so
would require a GNOME Shell extension that patches shell internals, which could
break on GNOME updates and would hide the system-level signal that traffic is
tunnelled. This app deliberately does not attempt that. Keeping the system
indicator also means you can still see that the tunnel is up if the app crashes
or is closed.

The macOS FastVPN **Favorite** entry is now covered by the Favorites submenu.
**Best available** remains deferred: this app has no latency ranking or
measurement model yet, and showing a fake “best” choice would be misleading.

## Connection details and privacy

The status card always shows the details panel. When disconnected it shows the
**ISP IP** and protocol, with `—` for VPN exit IP, traffic, and a disabled
**Switch IP**. When connected it adds:

- **ISP IP** — captured while disconnected from `https://api64.ipify.org`
  over HTTPS. No identifiers are sent beyond the request itself; the service
  sees your public address, as any HTTPS site does.
- **VPN exit IP** — measured after the tunnel is up, so it reflects the address
  websites see while connected.
- **Switch IP** — disconnects and reconnects the same profile. The VPN exit IP
  field updates silently; a different exit address is not guaranteed.
- **Download / Upload** — totals since this connection, read from the tun
  interface counters. They are local interface totals, not provider billing.
- **Protocol** — the real transport in use: `OpenVPN · UDP` or `OpenVPN · TCP`.

If the app starts while already connected, it cannot honestly learn the ISP
address without leaking traffic outside the tunnel, so it shows **Not captured**.
The ISP lookup is skipped while the kill switch is armed and disconnected.
The public-IP endpoint can be unavailable; the app then shows `Unavailable`
rather than inventing an address.

## Kill switch

The combined package installs a small root-owned system service and its assets.
The GUI and CLI remain ordinary-user processes; polkit authorizes arm/disarm
requests. The service uses one dedicated nftables table, never flushes the
global ruleset, and coexists with UFW.

- **Strict by default:** only the VPN server, the tunnel, DHCP, and link control
  are allowed. DNS outside the tunnel and global IPv6 are blocked.
- **Allow local network** is off by default and can only be changed while the
  kill switch is disarmed.
- **Location and protocol are locked while armed**, because the allowlist is
  built from the current profile. Disarm before switching.
- **Quit/close prompts** explain whether protection will stay armed. Quitting
  can disarm first or leave protection active for later CLI recovery.
- The service is idle until you enable the switch. If it is unavailable, the
  GUI shows that state instead of pretending protection is on.

CLI:

```sh
solvetus-killswitch status
solvetus-killswitch arm [--allow-lan]
solvetus-killswitch disarm
solvetus-killswitch diagnose
```

## Favorites and profiles

The app still keeps exactly **one reusable NetworkManager profile and CA**.
Favorites store location keys and change which location that profile connects
to; they do not duplicate profiles, ownership entries, or certificates. This
keeps the ownership and verification rules small and auditable.

Switching to a favorite from the tray while connected asks for confirmation,
then disconnects and connects to the new location. Saving several VPN accounts
or running multiple managed profiles at once is not implemented.

The password is stored in the desktop keyring only if **Save password in the
desktop keyring** is enabled and the keyring is available. Otherwise it is kept
in memory for the current process only. If the keyring rejects a write, the app
reports the error and does not fall back to a plaintext file.

## Live proof tool

`solvetus-vpn-proof` is a diagnostic command for an agreed test window. It
creates or updates the app-owned NetworkManager profile and activates a real
VPN connection. It prompts for the username and password locally and never
accepts a password through arguments, environment variables, or files.

```sh
solvetus-vpn-proof --location "Andorra la Vella" --proto udp
```

Add `--refresh` to download a fresh catalogue. `--delete-profile` offers to
delete the app-owned managed profile after the test. Do not run this tool unless
you intend to change NetworkManager settings and bring up a real VPN tunnel.
Close the graphical app before running the proof tool: only one secret agent
with this application's identifier can be registered per user.

## Catalogue inspection

This tool only reads and validates a catalogue ZIP; it does not touch
NetworkManager:

```sh
solvetus-vpn-inspect --zip /path/to/groupedServerList.zip
solvetus-vpn-inspect --url https://vpn.ncapi.io/groupedServerList.zip
```

## Files and uninstall

The app stores non-secret state under `~/.local/share/solvetus-vpn`:

- `catalogue/` — last-known-good archive and metadata
- `certificates/nm-openvpn/` — imported CA files (mode 0600)
- `ownership.json` — manifest proving which NetworkManager profile the app owns
- `settings.json` — username, selected location/protocol, and preferences

A saved password lives in the desktop keyring under the schema
`org.solvetus.vpn`, not in these files. The app does not write a plaintext
password file.

Uninstall the package with:

```sh
sudo apt remove solvetus-vpn
```

The NetworkManager profile it created is not automatically removed by package
uninstall. Remove **Solvetus VPN (managed)** in NetworkManager's connection
editor if you no longer want it. The app's data directory and keyring entry can
be removed separately if desired.

## Verified environment

The package was built and tested on:

- Ubuntu 26.10, aarch64
- NetworkManager 1.58.1
- NetworkManager OpenVPN plugin 1.12.5
- OpenVPN 2.7.7
- Python 3.14
- GTK 4.24, libadwaita 1.10, libsecret 0.21, libsoup 3.6

Unit tests cover the strict parser, ZIP safety, caching, settings, ownership
checks, profile construction, import preservation checks, country names and
search, the secret agent's authorization rules, and fetcher error handling. The
GTK window has been exercised on a private Broadway display with the real
NetworkManager client and the real 302-profile catalogue.

## Verification status

- The first live profile import and VPN activation succeeded on 2026-11-17
  through the graphical app (build 0.1.2). The provider accepted the generated
  profile, and the CA file was written with mode 0600 and the expected hash.
- A later check showed no active VPN, so the tunnel was down; explicit
  disconnect, reconnect, and reauthentication behavior have not been formally
  exercised.
- The reconnection state machine (countdown, success, retry failure, give-up,
  manual cancellation, and the off switch) was exercised in an isolated UI
  harness with simulated drops. It has not yet been tested against a real
  unexpected tunnel drop.
- Desktop-notification triggers were exercised in a hidden-window harness.
  Their visual appearance and click behavior depend on the desktop notification
  service and have not been inspected manually.
- The tray's D-Bus protocol was verified against Ubuntu's StatusNotifierWatcher:
  registration, SNI properties, nested DBusMenu layout, click dispatch, the
  Notifications toggle, and switching the red/green status icon. Its visual
  placement and icon rendering in the top bar still need a human check.
- Favorites were exercised in a UI harness: persisted settings, star state,
  favorites-only filtering, and tray Favorites menu entries. The connected
  switch flow has not yet been exercised against a live tunnel.
- The kill switch was live-tested on 2026-11-17 with the VPN off. It armed with
  14 resolved endpoints. DNS resolution, physical-interface traffic, and a
  direct TCP connection were blocked; status remained armed; disarm restored
  IPv4 connectivity. UFW stayed active and only the dedicated
  `inet solvetus_ks` table was managed.
- The VM has no global IPv6 route, so an IPv6-literal leak test was not
  meaningful. The rules include a global IPv6 drop; this still needs a
  dual-stack test environment.
- The GUI's armed-state rendering, control locking, tray toggle state, and
  confirmation path were exercised with a fake service status. The real
  arm/disarm path was tested through the service and CLI; clicking the GUI
  switch has not yet been exercised against the live service.
- Public-IP lookup succeeded from this VM over HTTPS. The connected-details
  panel was exercised with a fake IP response and synthetic tunnel counters;
  live exit-IP and traffic totals while connected still need a live VPN run.
- Switch IP's reconnect transition was exercised with a stubbed disconnect;
  the full reconnect-and-new-exit-IP flow has not yet been tested live.
- Keyring store, lookup, and clear were verified on 2026-11-17 with a temporary
  self-test entry that was removed immediately. The app-specific saved-password
  path across a full app restart has not yet been observed.
- Keeping the window hidden, the window-close and Quit prompts, and cleanup
  after a live session still need a dedicated test.

Use the proof tool only with an approved test window and credentials entered
locally.
