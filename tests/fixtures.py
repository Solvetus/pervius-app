"""Synthetic fixtures shared by the unit tests."""

from __future__ import annotations

import io
import stat
import zipfile

CA_PEM = """-----BEGIN CERTIFICATE-----
AAAA
-----END CERTIFICATE-----
"""


def profile_text(*, protocol: str = "udp", host: str = "vpn.example.com") -> str:
    port = 443 if protocol == "tcp" else 1194
    return f"""client
dev tun
proto {protocol}
remote {host} {port}
remote-random
resolv-retry infinite
nobind
persist-key
persist-tun
persist-remote-ip
<ca>
{CA_PEM}</ca>
verify-x509-name example name-prefix
remote-cert-tls server
auth-user-pass
verb 3
auth SHA256
data-ciphers AES-256-GCM:AES-256-CBC
data-ciphers-fallback AES-256-CBC
tls-cipher TLS-DHE-RSA-WITH-AES-256-CBC-SHA
"""


def zip_with(entries: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in entries.items():
            archive.writestr(name, data)
    return buffer.getvalue()


def catalogue_zip() -> bytes:
    entries = {}
    for index, (city, country) in enumerate(
        [("Test City", "TS"), ("Other Town", "OT"), ("Third Place", "TP")]
    ):
        for protocol in ("tcp", "udp"):
            entries[
                f"{protocol}/NCVPN-{country}-{city} - Virtual-{protocol.upper()}.ovpn"
            ] = profile_text(protocol=protocol, host=f"vpn{index}.example.com").encode()
    return zip_with(entries)


def malicious_symlink_zip() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        info = zipfile.ZipInfo("udp/NCVPN-TS-Link-UDP.ovpn")
        info.create_system = 3
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive.writestr(info, "/etc/passwd")
    return buffer.getvalue()
