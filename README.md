# Pervius

**Unofficial Linux client for FastVPN.** Published by Solvetus Labs.

Pervius is a GTK 4/libadwaita desktop app for an existing FastVPN (OpenVPN)
subscription. It validates the provider's public server list, imports the
profile you choose through NetworkManager and its OpenVPN plugin, and keeps
your password out of the profile. It does not provide a VPN service; you need
your own FastVPN account.

> Pervius is an independent open-source project by Solvetus Labs. It is not
> affiliated with, endorsed by, or sponsored by Namecheap, Inc. FastVPN is a
> trademark of Namecheap, Inc.

## Screenshots

_Screenshots will be added here._

## Features

- **Strict profile validation.** The public catalogue is downloaded over
  HTTPS and checked before use; unsupported or unsafe OpenVPN directives are
  rejected instead of ignored.
- **NetworkManager does the privileged work.** The app runs as your user,
  never as root. One app-owned NetworkManager profile is reused for every
  location.
- **Passwords stay out of the profile and out of sight.** A NetworkManager
  secret agent supplies the password on request. Saving it in the desktop
  keyring is optional; there is never a plaintext fallback. A saved password
  is never shown again: the Account dialog says "Saved in the keyring" and
  offers Replace and Forget.
- **No DNS or IPv6 leaks while connected.** All DNS goes through the tunnel,
  and IPv6 outside the (IPv4-only) tunnel is blocked by a NetworkManager hook,
  whether or not the kill switch is on and whether or not the app is running.
- **Locations:** country flags and names, search by city, country, code or
  alias (UK, USA, Holland…), favorites, and a UDP/TCP switch with a guide.
- **Bounded automatic reconnect** after an established tunnel drops (2, 5, 10,
  20, 30, 60 s), with a countdown and Stop button. It never retries a failed
  first connection, a rejected password or a manual disconnect.
- **Tray icon** (StatusNotifierItem) with a status line and connected time,
  connect, favorites, location and kill-switch actions; a green badge when
  connected, amber while reconnecting.
- **Desktop notifications** for drops and recovery while the window is hidden.
- **Connection details:** ISP IP and VPN exit IP (hidden until you reveal
  them), **Switch IP** (reconnect), traffic totals, connected time and the
  transport in use.
- **Optional kill switch** that blocks traffic outside the tunnel while armed,
  and still lets you change location or protocol. See
  [Kill switch](#kill-switch).
- **Languages:** English, European Portuguese, French, Spanish and Italian,
  following the system language or chosen in Settings.
- **Start at login**, hidden in the tray (optional).

## Supported distributions

| Distribution | Status |
| --- | --- |
| Ubuntu | `.deb` package. **Tested only on Ubuntu 26.10, aarch64.** Other releases may work but are untested. |
| Debian | Same `.deb`; untested. |
| Fedora | Planned (RPM). See [`packaging/rpm/README.md`](packaging/rpm/README.md). |

The package depends on NetworkManager, `network-manager-openvpn`, OpenVPN,
nftables, polkit, systemd and the GTK 4/libadwaita GObject bindings.

## Install

Packages are published on [GitHub Releases](https://github.com/Solvetus/pervius-app/releases).
Download the `.deb` and `SHA256SUMS` from the same release, verify the
checksum, then install:

```sh
sha256sum --check --ignore-missing SHA256SUMS
sudo apt install ./pervius_0.3.2_all.deb
```

`sha256sum` must print `pervius_0.3.2_all.deb: OK`. Do not install a package
whose checksum does not match. The packages are not signed yet.

Start **Pervius** from the application menu or run `pervius`. Do not run it
with `sudo`.

### Upgrading from 0.2.0

Disarm the kill switch, disconnect and quit Pervius before upgrading. 0.3.0
pins the tunnel to the interface `pervius0`; an armed 0.2.0 kill switch that
is restored by the new service blocks the old tunnel until you reconnect. The
managed profile is re-imported automatically on the next connection (new
tunnel name, DNS through the tunnel).

### Upgrading from the 0.1.x test builds

**Turn the kill switch off in the old app before upgrading.** `apt` removes
the old package first, and the old package's removal script deletes its own
firewall table, so an armed kill switch would be turned off without asking.
`sudo dpkg -i pervius_0.3.2_all.deb` instead refuses to install while the old
kill switch is armed and prints the command to disarm it.

On the first start, Pervius moves your settings, favorites and cached server
list to `~/.local/share/pervius`, moves a saved password to its own keyring
entry (deleting the old one), and renames the existing NetworkManager profile
to **Pervius (managed)**. The old data directory is left in place and can be
deleted once Pervius works.

## First use

1. In the **Account** row choose **Edit**.
2. Enter your FastVPN username and password.
3. Choose a location and UDP or TCP.
4. Press **Connect**.

The VPN username is sent to the VPN server. It is separate from your local
login, which owns the NetworkManager profile, so other accounts on the same
computer cannot use or change it.

## Kill switch

The package installs a small root service, `pervius-killswitchd`, that is idle
until you arm the kill switch. Arming asks polkit for permission. While armed,
a dedicated nftables table (`inet pervius_ks`) allows only loopback, the
Pervius tunnel (`pervius0`), the interfaces you always allow, DHCP, IPv6
neighbour discovery and the VPN server addresses, and drops all other IPv4
and IPv6 traffic, including plain DNS. Another VPN's tunnel is blocked unless
you allow its interface.

While armed you can still change location or protocol: the service resolves
the new servers and swaps the allowed addresses in one atomic update, and the
profile is pinned to those addresses so OpenVPN needs no DNS outside the
tunnel. A connected tunnel resolves the new location through itself before it
is dropped. When the tunnel is down, the service may resolve the server names
through a DNS window of at most five seconds that admits only its own
lookups.

Options, editable while armed:

- **Allow local network** permits RFC 1918/ULA ranges.
- **Always allow these interfaces** (Settings) — for example `wt0` for NetBird.
  The interfaces are also allowed by the leak guard.

The kill switch never arms itself, and a reboot turns it off (fail-open).
Quitting or a crash of the app leaves it armed.

**Recovery:** if you are offline because the kill switch is still armed, run:

```sh
pervius-killswitch disarm
```

As a last resort (for example if the service is broken), remove the table as
root: `sudo nft delete table inet pervius_ks`. Other commands:
`pervius-killswitch status`, `pervius-killswitch arm [--allow-lan]
[--allow-interface IFACE]`, `pervius-killswitch configure …`,
`pervius-killswitch update-endpoints`, `pervius-killswitch diagnose`.

## Leak guard

While the Pervius-managed VPN is up, a NetworkManager dispatcher hook
(`/usr/lib/NetworkManager/dispatcher.d/90-pervius-guard`) installs the
nftables table `inet pervius_guard`:

- **DNS** may only go through the tunnel, loopback and the interfaces you
  always allow; nothing reaches your router's resolver, whatever another tool
  (for example NetBird's search domain) configured.
- **IPv6** outside the tunnel is blocked except loopback, link-local,
  neighbour discovery, unique local addresses and the interfaces you always
  allow. Turn this part off with **Settings → Block IPv6 while connected**
  (applies from the next connection).

It is removed when the VPN goes down and needs neither the app nor the kill
switch. The VPN profile is always pinned to resolved server addresses, so
reconnecting never needs DNS outside the tunnel. If a NetworkManager crash
ever leaves the table behind, `sudo nft delete table inet pervius_guard`
removes it.

## Settings

- **Language:** system default, English, Português, Français, Español or
  Italiano; takes effect after a restart.
- **Start at login:** starts Pervius hidden in the tray through
  `~/.config/autostart/com.solvetus.Pervius.desktop`.
- **Desktop notifications** and **Reconnect automatically**.
- **Block IPv6 while connected** (on by default) and **Always allow these
  interfaces**.

## Privacy

- **Server list:** downloaded over HTTPS from `vpn.ncapi.io`, the provider's
  public catalogue, and cached locally.
- **Public IP:** the ISP and exit IPs come from `https://api64.ipify.org`,
  which sees your public address. If Pervius starts while already connected,
  the ISP IP is shown as "Not captured": learning it would mean sending
  traffic outside the tunnel.
- **IP addresses** in the connection details are hidden until you press the
  eye button; the choice is remembered.
- Pervius has no servers of its own and sends nothing to Solvetus Labs.

## Known limitations

- **No auto-protect.** The kill switch never arms automatically at login or on
  a network change, and a reboot turns it off.
- **No DNS filtering** (no resolver, blocklists or DoH/DoT handling).
- **Resolving the VPN server names before arming** while disconnected is a
  small, one-time DNS lookup outside the tunnel; while armed and
  disconnected, only the kill-switch service's own lookups of the server names
  can leave, for at most five seconds.
- **One managed profile and one account.** Favorites change its location; no
  simultaneous VPNs, multiple accounts or split tunnelling.
- **Switch IP is a reconnect** and can return the same exit IP. Traffic totals
  are interface counters since connecting, not provider data.
- **Not yet verified live:** a real unexpected drop with automatic reconnect
  and long hidden-window sessions with reauthentication.
- **GNOME's own VPN indicator stays visible**; it is the system's source of
  truth and is deliberately not hidden.
- City names come from the provider and are not translated; the command-line
  tools and manual pages are English only. Packages are not signed.

## Files

- `~/.local/share/pervius/` — settings, favorites, cached catalogue, CA file,
  ownership manifest. No passwords.
- Desktop keyring (Secret Service schema `com.solvetus.Pervius`) — the saved
  password, only if you chose to save it.
- `~/.config/autostart/com.solvetus.Pervius.desktop` — only while Start at
  login is on.

`sudo apt remove pervius` removes the app, the kill-switch service, the IPv6
guard hook and both firewall tables. The
NetworkManager profile **Pervius (managed)**, the data directory and the
keyring entry stay until you remove them.

## Command-line tools

- `pervius` — the desktop app.
- `pervius-killswitch` — kill-switch status, arm, disarm and diagnostics.
- `pervius-inspect --zip FILE | --url URL` — validate a catalogue ZIP without
  touching NetworkManager.
- `pervius-proof --location CITY [--proto udp|tcp]` — live connection test
  that changes NetworkManager settings; it prompts for credentials locally and
  never accepts a password as an argument.

## Documentation

- [Architecture, kill-switch design and threat model](docs/ARCHITECTURE.md)
- [Packaging and adding a distribution](docs/PACKAGING.md)
- [Contributing](CONTRIBUTING.md) · [Security policy](SECURITY.md) · [Changelog](CHANGELOG.md)

## License

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).
