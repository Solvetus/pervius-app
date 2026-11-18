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
- **Passwords stay out of the profile.** A NetworkManager secret agent supplies
  the password on request. Saving it in the desktop keyring is optional; there
  is never a plaintext fallback.
- **Locations:** country flags and names, search by city, country, code or
  alias (UK, USA, Holland…), favorites, and a UDP/TCP switch with a guide.
- **Bounded automatic reconnect** after an established tunnel drops (2, 5, 10,
  20, 30, 60 s), with a countdown and Stop button. It never retries a failed
  first connection, a rejected password or a manual disconnect.
- **Tray icon** (StatusNotifierItem) with connect, favorites, settings and
  kill-switch actions; red when disconnected, green when connected.
- **Desktop notifications** for drops and recovery while the window is hidden.
- **Connection details:** ISP IP, VPN exit IP, **Switch IP** (reconnect),
  traffic totals and the transport in use.
- **Optional kill switch** that blocks traffic outside the tunnel while armed.
  See [Kill switch](#kill-switch).

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
sudo apt install ./pervius_0.2.0_all.deb
```

`sha256sum` must print `pervius_0.2.0_all.deb: OK`. Do not install a package
whose checksum does not match. The packages are not signed yet.

Start **Pervius** from the application menu or run `pervius`. Do not run it
with `sudo`.

### Upgrading from the 0.1.x test builds

**Turn the kill switch off in the old app before upgrading.** `apt` removes
the old package first, and the old package's removal script deletes its own
firewall table, so an armed kill switch would be turned off without asking.
`sudo dpkg -i pervius_0.2.0_all.deb` instead refuses to install while the old
kill switch is armed and prints the command to disarm it.

On the first start, Pervius moves your settings, favorites and cached server
list to `~/.local/share/pervius`, moves a saved password to its own keyring
entry (deleting the old one), and renames the existing NetworkManager profile
to **Pervius (managed)**. The old data directory is left in place and can be
deleted once Pervius works.

## First use

1. Open the main menu and choose **Credentials**.
2. Enter your FastVPN username and password.
3. Choose a location and UDP or TCP.
4. Press **Connect**.

The VPN username is sent to the VPN server. It is separate from your local
login, which owns the NetworkManager profile, so other accounts on the same
computer cannot use or change it.

## Kill switch

The package installs a small root service, `pervius-killswitchd`, that is idle
until you arm the kill switch. Arming asks polkit for permission. While armed,
a dedicated nftables table (`inet pervius_ks`) allows only loopback, the tunnel
interface, DHCP, IPv6 neighbour discovery and the VPN server addresses, and
drops all other IPv4 and IPv6 traffic, including plain DNS. **Allow local
network** optionally permits RFC 1918/ULA ranges. Location and protocol are
locked while armed, because the allowlist is built from the current profile.

The kill switch never arms itself, and a reboot turns it off (fail-open).
Quitting the app can leave it armed.

**Recovery:** if you are offline because the kill switch is still armed, run:

```sh
pervius-killswitch disarm
```

As a last resort (for example if the service is broken), remove the table as
root: `sudo nft delete table inet pervius_ks`. Other commands:
`pervius-killswitch status`, `pervius-killswitch arm [--allow-lan]`,
`pervius-killswitch diagnose`.

## Privacy

- **Server list:** downloaded over HTTPS from `vpn.ncapi.io`, the provider's
  public catalogue, and cached locally.
- **Public IP:** the ISP and exit IPs come from `https://api64.ipify.org`,
  which sees your public address. If Pervius starts while already connected,
  the ISP IP is shown as "Not captured": learning it would mean sending
  traffic outside the tunnel.
- Pervius has no servers of its own and sends nothing to Solvetus Labs.

## Known limitations

- **IPv6 and DNS can leak when the kill switch is off.** Without it you get
  ordinary NetworkManager OpenVPN behaviour: the current profiles are
  IPv4-only, so IPv6 traffic and DNS queries can bypass the tunnel. Arm the
  kill switch if that matters to you.
- **No auto-protect.** The kill switch never arms automatically at login or on
  a network change, and a reboot turns it off.
- **No DNS filtering** (no resolver, blocklists or DoH/DoT handling).
- **Resolving the VPN server names before arming** is a small, one-time DNS
  lookup outside the tunnel.
- **The kill-switch allowlist is fixed when armed.** If the provider changes
  server addresses while you are disconnected, reconnecting can fail until you
  disarm and arm again.
- **One managed profile and one account.** Favorites change its location; no
  simultaneous VPNs, multiple accounts or split tunnelling.
- **Switch IP is a reconnect** and can return the same exit IP. Traffic totals
  are interface counters since connecting, not provider data.
- **Not yet verified live:** a real unexpected drop with automatic reconnect,
  long hidden-window sessions with reauthentication, the GUI kill-switch switch
  against the live service, and dual-stack IPv6 leak tests. The service and CLI
  kill-switch path has been tested live.
- **GNOME's own VPN indicator stays visible**; it is the system's source of
  truth and is deliberately not hidden.
- No localization, help pages or start-at-login yet. Packages are not signed.

## Files

- `~/.local/share/pervius/` — settings, favorites, cached catalogue, CA file,
  ownership manifest. No passwords.
- Desktop keyring (Secret Service schema `com.solvetus.Pervius`) — the saved
  password, only if you chose to save it.

`sudo apt remove pervius` removes the app and the kill-switch service. The
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
