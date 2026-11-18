"""Strict OpenVPN profile parser.

The NetworkManager OpenVPN importer silently ignores directives it does not
understand.  For a security tool that is not acceptable: this parser accepts
exactly the directive set that this application understands and rejects
everything else with a filename and line number.  The parser never modifies
security-relevant values; it only normalizes them for comparison.
"""

from __future__ import annotations

import hashlib
import re
import ssl
from dataclasses import dataclass
from typing import Iterable

from ..config import MAX_CA_BYTES, MAX_PROFILE_BYTES, MAX_REMOTES
from .models import ParsedProfile

MAX_LINE_LENGTH = 4096
MAX_LINES = 2000

ALLOWED_DATA_CIPHERS = {
    "AES-256-GCM",
    "AES-128-GCM",
    "CHACHA20-POLY1305",
    "AES-256-CBC",
    "AES-128-CBC",
}
AEAD_DATA_CIPHERS = {"AES-256-GCM", "AES-128-GCM", "CHACHA20-POLY1305"}

# Directives that are understood and safe in this context.
_ALLOWED = {
    "client",
    "dev",
    "proto",
    "remote",
    "remote-random",
    "resolv-retry",
    "nobind",
    "persist-key",
    "persist-tun",
    "persist-remote-ip",
    "verify-x509-name",
    "remote-cert-tls",
    "auth-user-pass",
    "auth",
    "data-ciphers",
    "data-ciphers-fallback",
    "tls-cipher",
    "verb",
    "<ca>",
}

# Explicitly named rejections give better diagnostics than "unknown".
_DENIED = {
    "up": "external command hooks are not supported",
    "down": "external command hooks are not supported",
    "plugin": "plugins are not supported",
    "script-security": "external scripts are not supported",
    "setenv": "environment manipulation is not supported",
    "management": "a management interface is not supported in imported profiles",
    "http-proxy": "proxy directives are not supported",
    "socks-proxy": "proxy directives are not supported",
    "tls-auth": "static TLS keys are not part of this catalogue",
    "tls-crypt": "static TLS keys are not part of this catalogue",
    "tls-crypt-v2": "static TLS keys are not part of this catalogue",
    "pkcs12": "PKCS#12 material is not part of this catalogue",
    "cert": "client certificates are not part of this catalogue",
    "key": "private keys are not part of this catalogue",
    "ca": "external CA files are not accepted; the CA must be inline",
    "crl-verify": "external CRL files are not accepted",
    "route": "routes are managed by NetworkManager, not imported profiles",
    "route-nopull": "routes are managed by NetworkManager",
    "dhcp-option": "DHCP options are managed by NetworkManager",
    "pull-filter": "pull filters are not part of this catalogue",
    "askpass": "interactive external password input is not supported",
    "auth-user-pass-verify": "external authentication hooks are not supported",
    "client-cert-not-required": "this catalogue requires server certificate verification",
    "username-as-common-name": "username identity overrides are not supported",
    "verify-client-cert": "client certificates are not part of this catalogue",
    "remote-random-hostname": "remote hostname randomization is not part of this catalogue",
    "connection": "connection blocks are not supported",
    "fragment": "fragmentation directives are not part of this catalogue",
    "mssfix": "MSS clamping is managed by NetworkManager",
    "tun-mtu": "MTU is managed by NetworkManager",
    "tun-mtu-extra": "MTU is managed by NetworkManager",
    "link-mtu": "MTU is managed by NetworkManager",
    "comp-lzo": "compression is not supported",
    "compress": "compression is not supported",
    "allow-compression": "compression is not supported",
    "cipher": "legacy cipher selection is not supported; data-ciphers is required",
    "ncp-disable": "cipher negotiation may not be disabled",
    "tls-version-min": "TLS version policy is not part of this catalogue",
    "tls-version-max": "TLS version policy is not part of this catalogue",
    "reneg-sec": "renegotiation policy is not part of this catalogue",
    "auth-retry": "authentication retry policy is managed by NetworkManager",
    "ping": "keepalive policy is managed by NetworkManager",
    "ping-restart": "keepalive policy is managed by NetworkManager",
    "ping-exit": "keepalive policy is managed by NetworkManager",
    "keepalive": "keepalive policy is managed by NetworkManager",
    "float": "server address changes are not supported",
    "duplicate-cn": "duplicate certificate common names are not supported",
    "ns-cert-type": "legacy Netscape certificate type checks are not supported",
    "tls-remote": "legacy subject matching is not supported",
    "static-key": "static key mode is not supported",
    "secret": "static key mode is not supported",
    "dev-type": "device type is fixed to tun",
    "tap-dev": "TAP devices are not supported",
    "ifconfig": "interface configuration is managed by NetworkManager",
    "route-delay": "routes are managed by NetworkManager",
    "redirect-gateway": "routing is managed by NetworkManager",
    "block-outside-dns": "DNS handling is managed by NetworkManager",
    "register-dns": "DNS handling is managed by NetworkManager",
    "ip-win32": "platform-specific directives are not supported",
    "windows-driver": "platform-specific directives are not supported",
    "dhcp-renew": "platform-specific directives are not supported",
    "dhcp-release": "platform-specific directives are not supported",
}

VERIFY_X509_TYPES = {"subject", "name", "name-prefix"}

_REQUIRED_ARG_COUNTS = {
    "dev": 1,
    "proto": 1,
    "auth": 1,
    "data-ciphers": 1,
    "data-ciphers-fallback": 1,
    "tls-cipher": 1,
    "resolv-retry": 1,
    "verb": 1,
    "verify-x509-name": 1,  # value, optionally followed by a type (see below)
    "remote-cert-tls": 1,
    "remote": None,
}

_LOW_RISK = {
    "remote-random",
    "resolv-retry",
    "nobind",
    "persist-key",
    "persist-tun",
    "persist-remote-ip",
    "verb",
}

_HOST_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_TLS_CIPHER_RE = re.compile(r"^TLS-[A-Za-z0-9-]+(?:@SECLEVEL=[2-5])?$")
_BAD_TLS_CIPHER_PARTS = ("NULL", "anon", "EXPORT", "RC4", "3DES", "DES-CBC", "MD5")


class ProfileError(ValueError):
    """Raised when a profile cannot be accepted without weakening security."""

    def __init__(self, message: str, profile: str = "<profile>", line: int | None = None):
        self.profile_name = profile
        self.line = line
        if line is None:
            full = f"{profile}: {message}"
        else:
            full = f"{profile}:{line}: {message}"
        super().__init__(full)


@dataclass(frozen=True)
class _Directive:
    name: str
    args: tuple[str, ...]
    line: int


def _tokenize(line: str, profile: str, lineno: int) -> tuple[str, ...]:
    tokens: list[str] = []
    current: list[str] = []
    quote: str | None = None
    escaped = False

    for char in line.strip():
        if char == "\x00" or (ord(char) < 0x20 and char != "\t"):
            raise ProfileError("control character in configuration line", profile, lineno)
        if escaped:
            current.append(char)
            escaped = False
            continue
        if quote == '"' and char == "\\":
            escaped = True
            continue
        if quote is not None:
            if char == quote:
                quote = None
            else:
                current.append(char)
            continue
        if char in ('"', "'"):
            quote = char
            continue
        if char.isspace():
            if current:
                tokens.append("".join(current))
                current = []
            continue
        current.append(char)

    if escaped:
        raise ProfileError("trailing backslash in quoted argument", profile, lineno)
    if quote is not None:
        raise ProfileError("unterminated quoted argument", profile, lineno)
    if current:
        tokens.append("".join(current))
    if not tokens:
        return ()
    if "#" in line.strip() or ";" in line.strip():
        raise ProfileError("inline comments are not accepted", profile, lineno)
    return tuple(tokens)


def _check_count(directive: _Directive, profile: str, minimum: int, maximum: int | None = None) -> None:
    count = len(directive.args)
    maximum = minimum if maximum is None else maximum
    if count < minimum or count > maximum:
        if minimum == maximum:
            expected = f"exactly {minimum}"
        else:
            expected = f"between {minimum} and {maximum}"
        raise ProfileError(
            f"'{directive.name}' expects {expected} argument(s), got {count}",
            profile,
            directive.line,
        )


def _valid_host(host: str) -> bool:
    if not host or len(host) > 253 or host.startswith("-") or host.endswith("-"):
        return False
    labels = host.rstrip(".").split(".")
    if not labels or any(not label for label in labels):
        return False
    return all(_HOST_LABEL_RE.match(label) is not None for label in labels)


def _parse_port(raw: str, profile: str, lineno: int) -> int:
    try:
        port = int(raw, 10)
    except ValueError:
        raise ProfileError(f"invalid remote port '{raw}'", profile, lineno) from None
    if not 1 <= port <= 65535:
        raise ProfileError(f"remote port out of range: {port}", profile, lineno)
    return port


def _parse_cipher_list(raw: str, profile: str, lineno: int, *, tls: bool) -> str:
    if not raw or len(raw) > 512:
        raise ProfileError("cipher list is empty or too long", profile, lineno)
    parts = raw.split(":")
    if not parts or any(not part for part in parts):
        raise ProfileError("cipher list contains an empty entry", profile, lineno)
    if len(parts) > 32:
        raise ProfileError("cipher list has too many entries", profile, lineno)
    for part in parts:
        if tls:
            if _TLS_CIPHER_RE.match(part) is None:
                raise ProfileError(f"unsupported TLS cipher name '{part}'", profile, lineno)
            upper = part.upper()
            if any(bad.upper() in upper for bad in _BAD_TLS_CIPHER_PARTS):
                raise ProfileError(f"insecure TLS cipher '{part}'", profile, lineno)
        else:
            if part not in ALLOWED_DATA_CIPHERS:
                raise ProfileError(f"unsupported data cipher '{part}'", profile, lineno)
    return raw


def _validate_directive(directive: _Directive, profile: str) -> None:
    name = directive.name
    args = directive.args

    if name in _REQUIRED_ARG_COUNTS:
        minimum = _REQUIRED_ARG_COUNTS[name]
        if name == "remote":
            _check_count(directive, profile, 2, 2)
        elif name == "verify-x509-name":
            _check_count(directive, profile, 1, 2)
        else:
            _check_count(directive, profile, minimum, minimum)

    if name in {"client", "remote-random", "nobind", "persist-key", "persist-tun", "persist-remote-ip", "auth-user-pass"}:
        _check_count(directive, profile, 0, 0)
        return

    if name == "dev":
        if args[0] != "tun":
            raise ProfileError(f"only 'dev tun' is accepted, got 'dev {args[0]}'", profile, directive.line)
        return

    if name == "proto":
        if args[0] not in {"tcp", "udp"}:
            raise ProfileError(f"unsupported protocol '{args[0]}'", profile, directive.line)
        return

    if name == "remote":
        host, port_raw = args
        if not _valid_host(host):
            raise ProfileError(f"invalid remote host '{host}'", profile, directive.line)
        _parse_port(port_raw, profile, directive.line)
        return

    if name == "resolv-retry":
        value = args[0]
        if value != "infinite":
            try:
                number = int(value, 10)
            except ValueError:
                raise ProfileError("resolv-retry must be 'infinite' or an integer", profile, directive.line) from None
            if not 0 <= number <= 86400:
                raise ProfileError("resolv-retry out of range", profile, directive.line)
        return

    if name == "verb":
        try:
            level = int(args[0], 10)
        except ValueError:
            raise ProfileError("verb must be an integer", profile, directive.line) from None
        if not 0 <= level <= 9:
            raise ProfileError("verb out of range", profile, directive.line)
        return

    if name == "auth":
        if args[0] != "SHA256":
            raise ProfileError(f"only 'auth SHA256' is accepted, got 'auth {args[0]}'", profile, directive.line)
        return

    if name == "data-ciphers":
        raw = _parse_cipher_list(args[0], profile, directive.line, tls=False)
        if not any(cipher in AEAD_DATA_CIPHERS for cipher in raw.split(":")):
            raise ProfileError("data-ciphers must include an AEAD cipher", profile, directive.line)
        return

    if name == "data-ciphers-fallback":
        _parse_cipher_list(args[0], profile, directive.line, tls=False)
        return

    if name == "tls-cipher":
        _parse_cipher_list(args[0], profile, directive.line, tls=True)
        return

    if name == "verify-x509-name":
        value = args[0]
        # OpenVPN: "verify-x509-name name [type]"; without a type the value
        # is matched against the whole certificate subject ("subject").
        verify_type = args[1] if len(args) == 2 else "subject"
        if verify_type not in VERIFY_X509_TYPES:
            raise ProfileError(f"unsupported verify-x509-name type '{verify_type}'", profile, directive.line)
        if (
            not value
            or value.startswith("-")  # would be read as an OpenVPN option
            or len(value) > 255
            or any(ord(char) < 0x20 or ord(char) == 0x7F for char in value)
            or (verify_type != "subject" and any(char.isspace() for char in value))
        ):
            raise ProfileError("invalid verify-x509-name value", profile, directive.line)
        return

    if name == "remote-cert-tls":
        if args[0] != "server":
            raise ProfileError("only 'remote-cert-tls server' is accepted", profile, directive.line)
        return

    raise ProfileError(f"unsupported directive '{name}'", profile, directive.line)


def _normalize_ca(lines: Iterable[str]) -> str:
    cleaned = [line.rstrip() for line in lines]
    while cleaned and not cleaned[0]:
        cleaned.pop(0)
    while cleaned and not cleaned[-1]:
        cleaned.pop()
    text = "\n".join(cleaned)
    if not text:
        raise ValueError("inline CA block is empty")
    if "PRIVATE KEY" in text:
        raise ValueError("inline CA block contains private key material")
    if "-----BEGIN CERTIFICATE-----" not in text or "-----END CERTIFICATE-----" not in text:
        raise ValueError("inline CA block does not contain a PEM certificate")
    # Validate each certificate's base64/DER envelope without trusting it.
    blocks = re.findall(
        r"-----BEGIN CERTIFICATE-----\s*(.*?)\s*-----END CERTIFICATE-----",
        text,
        flags=re.DOTALL,
    )
    if not blocks:
        raise ValueError("inline CA block has no complete certificate")
    for block in blocks:
        try:
            der = ssl.PEM_cert_to_DER_cert(
                "-----BEGIN CERTIFICATE-----\n" + block.strip() + "\n-----END CERTIFICATE-----\n"
            )
        except (ValueError, ssl.SSLError) as exc:
            raise ValueError(f"invalid PEM certificate: {exc}") from exc
        if not der:
            raise ValueError("empty certificate")
    return text + "\n"


def parse_profile(data: bytes, profile_name: str = "<profile>") -> ParsedProfile:
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("profile data must be bytes")
    data = bytes(data)
    if not data:
        raise ProfileError("profile is empty", profile_name)
    if len(data) > MAX_PROFILE_BYTES:
        raise ProfileError(f"profile exceeds {MAX_PROFILE_BYTES} bytes", profile_name)
    if b"\x00" in data:
        raise ProfileError("profile contains a NUL byte", profile_name)
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ProfileError(f"profile is not valid UTF-8: {exc}", profile_name) from None
    if text.startswith("\ufeff"):
        text = text[1:]

    lines = text.splitlines()
    if len(lines) > MAX_LINES:
        raise ProfileError("profile has too many lines", profile_name)

    directives: list[_Directive] = []
    ca_lines: list[str] = []
    ca_started = False
    ca_finished = False

    for number, raw_line in enumerate(lines, start=1):
        if len(raw_line) > MAX_LINE_LENGTH:
            raise ProfileError("configuration line is too long", profile_name, number)
        stripped = raw_line.strip()
        if ca_started:
            if stripped == "</ca>":
                ca_started = False
                ca_finished = True
                continue
            if "<ca>" in stripped or "</ca>" in stripped:
                raise ProfileError("nested or malformed inline CA block", profile_name, number)
            ca_lines.append(raw_line)
            continue

        if not stripped or stripped.startswith("#") or stripped.startswith(";"):
            continue
        if stripped.startswith("<"):
            if stripped == "<ca>":
                if ca_finished:
                    raise ProfileError("duplicate inline CA block", profile_name, number)
                ca_started = True
                continue
            if stripped == "</ca>":
                raise ProfileError("unexpected </ca>", profile_name, number)
            raise ProfileError(f"unsupported inline block '{stripped[:32]}'", profile_name, number)

        tokens = _tokenize(raw_line, profile_name, number)
        if not tokens:
            continue
        name, args = tokens[0], tuple(tokens[1:])
        if name in _DENIED:
            raise ProfileError(f"'{name}' rejected: {_DENIED[name]}", profile_name, number)
        if name not in _ALLOWED:
            raise ProfileError(f"unsupported directive '{name}'", profile_name, number)
        directive = _Directive(name=name, args=args, line=number)
        _validate_directive(directive, profile_name)
        directives.append(directive)

    if ca_started:
        raise ProfileError("unterminated inline CA block", profile_name)
    if not ca_finished:
        raise ProfileError("missing inline CA block", profile_name)
    if len("\n".join(ca_lines)) > MAX_CA_BYTES:
        raise ProfileError("inline CA block is too large", profile_name)

    names = {directive.name for directive in directives}
    required = {
        "client",
        "dev",
        "proto",
        "remote",
        "verify-x509-name",
        "remote-cert-tls",
        "auth-user-pass",
        "auth",
        "data-ciphers",
        "data-ciphers-fallback",
        "tls-cipher",
    }
    missing = sorted(required - names)
    if missing:
        raise ProfileError(f"missing required directive(s): {', '.join(missing)}", profile_name)

    critical = {
        "client",
        "dev",
        "proto",
        "verify-x509-name",
        "remote-cert-tls",
        "auth-user-pass",
        "auth",
        "data-ciphers",
        "data-ciphers-fallback",
        "tls-cipher",
    }
    seen: set[str] = set()
    for directive in directives:
        if directive.name in critical:
            if directive.name in seen:
                raise ProfileError(f"duplicate '{directive.name}' directive", profile_name, directive.line)
            seen.add(directive.name)

    proto_values = {directive.args[0] for directive in directives if directive.name == "proto"}
    if len(proto_values) != 1:
        raise ProfileError("contradictory proto directives", profile_name)
    protocol = next(iter(proto_values))

    remotes: list[tuple[str, int]] = []
    for directive in directives:
        if directive.name == "remote":
            host, port_raw = directive.args
            remotes.append((host, _parse_port(port_raw, profile_name, directive.line)))
    if not remotes:
        raise ProfileError("profile has no remote servers", profile_name)
    if len(remotes) > MAX_REMOTES:
        raise ProfileError(f"profile has more than {MAX_REMOTES} remotes", profile_name)

    try:
        ca_pem = _normalize_ca(ca_lines)
    except ValueError as exc:
        raise ProfileError(str(exc), profile_name) from None

    verify_values = [directive for directive in directives if directive.name == "verify-x509-name"]
    verify = verify_values[0]
    verify_type = verify.args[1] if len(verify.args) == 2 else "subject"
    verify_name = f"{verify_type}:{verify.args[0]}"

    auth = next(d.args[0] for d in directives if d.name == "auth")
    data_ciphers = next(d.args[0] for d in directives if d.name == "data-ciphers")
    fallback = next(d.args[0] for d in directives if d.name == "data-ciphers-fallback")
    tls_cipher = next(d.args[0] for d in directives if d.name == "tls-cipher")

    low_risk = tuple(
        sorted({d.name for d in directives if d.name in _LOW_RISK})
    )

    return ParsedProfile(
        archive_name=profile_name,
        protocol=protocol,
        remotes=tuple(remotes),
        ca_pem=ca_pem,
        ca_sha256=hashlib.sha256(ca_pem.encode("utf-8")).hexdigest(),
        verify_x509_name=verify_name,
        auth=auth,
        data_ciphers=data_ciphers,
        data_ciphers_fallback=fallback,
        tls_cipher=tls_cipher,
        source_sha256=hashlib.sha256(data).hexdigest(),
        size=len(data),
        low_risk_directives=low_risk,
        raw=data,
    )
