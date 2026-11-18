# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.1] - 2026-11-19

Security fixes from an independent review of the privileged code.

### Security

- Kill switch: addresses learned through the DNS window are capped at four
  public addresses per server name and address family, and are provisional:
  unless the tunnel is up 90 seconds later they are removed again. A hostile
  resolver on the local network could otherwise open many allowlist holes on
  the VPN's port while the switch showed "armed". Private, shared, loopback,
  link-local and documentation addresses are never allowed from a lookup.
- Endpoint addresses with an IPv6 scope id (`fe80::1%…`) or in IPv4-mapped
  form are rejected, and only the canonical address reaches the nftables
  input; before, arbitrary text after `%` was copied into it.
- The tunnel is matched by name and device kind (tun or OpenVPN data channel
  offload) in the kill switch and the leak guard, so another device named
  `pervius0` is not trusted.
- DHCP is allowed only to broadcast or local addresses (DHCPv6 only to
  `ff02::1:2` and `fe80::/10`); the DHCP ports were an open path to any host.
- DNS over QUIC (UDP 853) is dropped like DNS over TLS, and the leak guard
  now also drops DNS forwarded for containers and VMs outside the tunnel.
- After a failed recovery the kill switch keeps its saved owner; with no
  saved owner only root may disarm it (before, any active-session user
  could).
- The secret agent answers only the connection that owns NetworkManager's
  bus name, not any root process.
- The importer rejects any NetworkManager OpenVPN setting outside a reviewed
  allowlist, and the parser rejects `verify-x509-name` values starting with
  `-`.
- The catalogue download never follows redirects and stops reading as soon
  as the response exceeds the size cap.
- The live VPN server is taken only from the active Pervius connection's
  device and only if the profile or the allowlist already names it, not from
  any host route.

### Changed

- `GetStatus` no longer runs `nft` on every call (the leak-guard state is
  cached for two seconds), and oversized interface lists are refused before
  any work.
- The service unit is sandboxed further (`python3 -I`, `PrivateDevices`,
  `ProtectKernel*`, `ProtectControlGroups`, `ProtectProc`,
  `RestrictNamespaces`, `SystemCallFilter=@system-service`, `UMask=0077` and
  more).
- Roadmap: a CA change warning, re-authentication for operations that weaken
  protection, and an opt-in boot-time ruleset ("Always-on VPN") are
  documented in `docs/ARCHITECTURE.md`.

## [1.0.0] - 2026-11-19

1.0.0 — first public release.

### Added

- GTK 4/libadwaita desktop client for an existing FastVPN (OpenVPN)
  subscription. The provider's public server catalogue is downloaded over
  HTTPS and strictly validated; one app-owned NetworkManager profile is
  imported through the OpenVPN plugin and reused for every location.
- Passwords never enter the profile and are never shown: a NetworkManager
  secret agent supplies them on request, saving in the desktop keyring is
  optional, and the Account dialog only offers Replace and Forget.
- Leak protection while connected, with or without the kill switch and with
  or without the app running: all DNS goes through the tunnel and IPv6
  outside the IPv4-only tunnel is blocked, by a NetworkManager dispatcher
  hook. The profile is pinned to resolved server addresses.
- Optional kill switch (root service, nftables, polkit) that allows only the
  Pervius tunnel, the VPN servers and interfaces you choose, and still lets
  you change location or protocol while armed.
- Locations with flags, search by city, country, code or alias, favorites,
  and UDP/TCP.
- Bounded automatic reconnect after an established tunnel drops, with a
  countdown and Stop.
- Tray icon with status, connected time, connect, favorites, location and
  kill-switch actions; desktop notifications while the window is hidden.
- Connection details: ISP and exit IP (hidden until revealed), Switch IP,
  traffic totals, connected time and protocol.
- English, European Portuguese, French, Spanish and Italian; start at login
  hidden in the tray; the window remembers its size.
- Debian package with lintian-clean CI builds and published SHA-256 checksums.

[Unreleased]: https://github.com/Solvetus/pervius-app/compare/v1.0.1...HEAD
[1.0.1]: https://github.com/Solvetus/pervius-app/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/Solvetus/pervius-app/releases/tag/v1.0.0
