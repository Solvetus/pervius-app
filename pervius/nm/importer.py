"""Import an OpenVPN profile through NetworkManager's OpenVPN editor plugin.

There is no D-Bus Import method on the VPN plugin in NetworkManager 1.58.
nmcli loads the libnm editor plugin in-process, so that is the front end used
here.  The imported profile is temporary (in-memory), is verified field by
field against the source profile, and is deleted immediately after the
managed profile is built.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import secrets
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path

import gi

gi.require_version("NM", "1.0")
from gi.repository import GLib, NM  # noqa: E402

from ..config import (  # noqa: E402
    OPENVPN_SERVICE_TYPE,
    certificate_dir,
    ensure_private_dir,
    runtime_dir,
)
from ..catalogue.models import ParsedProfile  # noqa: E402
from .profile import (  # noqa: E402
    PreparedProfile,
    ProfileBuildError,
    build_managed_connection,
    build_variant,
    low_risk_warnings,
)

log = logging.getLogger(__name__)

_CA_PEM_RE = re.compile(
    r"-----BEGIN CERTIFICATE-----\s*(.*?)\s*-----END CERTIFICATE-----",
    re.DOTALL,
)


class ImportError(RuntimeError):
    pass


class ImportVerificationError(ImportError):
    pass


@dataclass(frozen=True)
class ImportedProfile:
    """Temporary profile plus the preserved non-secret values."""

    connection: NM.Connection
    ca_path: Path
    warnings: tuple[str, ...]


def _normalize_pem(text: str) -> str:
    lines = [line.rstrip() for line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n")]
    while lines and not lines[0]:
        lines.pop(0)
    while lines and not lines[-1]:
        lines.pop()
    return "\n".join(lines) + "\n"


def _cert_files(directory: Path) -> set[Path]:
    try:
        return {path for path in directory.iterdir() if path.is_file()}
    except FileNotFoundError:
        return set()


def _cleanup_new_cert_files(directory: Path, before: set[Path]) -> None:
    for path in _cert_files(directory) - before:
        try:
            path.unlink()
        except OSError:
            log.warning("could not remove leftover certificate file")


def _read_ca_hash(path: Path) -> str:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise ImportVerificationError(f"could not read imported CA file: {exc}") from exc
    if "PRIVATE KEY" in text:
        raise ImportVerificationError("imported CA file unexpectedly contains private key material")
    return hashlib.sha256(_normalize_pem(text).encode("utf-8")).hexdigest()


def _check_ca_path(path_value: str | None, cert_dir: Path, expected_hash: str) -> Path:
    if not path_value:
        raise ImportVerificationError("imported profile has no CA path")
    path = Path(path_value)
    try:
        real = path.resolve(strict=True)
        root = cert_dir.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ImportVerificationError(f"imported CA path is not accessible: {exc}") from exc
    if root not in real.parents:
        raise ImportVerificationError("imported CA path is outside the app-owned certificate directory")
    if path.is_symlink():
        raise ImportVerificationError("imported CA path is a symlink")
    try:
        info = path.stat()
    except OSError as exc:
        raise ImportVerificationError(f"could not stat imported CA file: {exc}") from exc
    if not stat.S_ISREG(info.st_mode):
        raise ImportVerificationError("imported CA path is not a regular file")
    if stat.S_IMODE(info.st_mode) != 0o600:
        raise ImportVerificationError(
            f"imported CA file has mode {stat.S_IMODE(info.st_mode):04o}, expected 0600"
        )
    actual_hash = _read_ca_hash(path)
    if actual_hash != expected_hash:
        raise ImportVerificationError("imported CA does not match the source CA")
    return path


def check_ca_file(path_value: str | None, cert_dir: Path, expected_hash: str) -> Path:
    """Verify an app-owned CA file: location, type, mode 0600 and hash."""
    return _check_ca_path(path_value, cert_dir, expected_hash)


def _verify_vpn_fields(
    connection: NM.Connection,
    parsed: ParsedProfile,
    cert_dir: Path,
) -> tuple[Path, tuple[str, ...]]:
    s_con = connection.get_setting_connection()
    s_vpn = connection.get_setting_vpn()
    if not isinstance(s_con, NM.SettingConnection) or not isinstance(s_vpn, NM.SettingVpn):
        raise ImportVerificationError("profile is missing required settings")
    if connection.get_connection_type() != "vpn":
        raise ImportVerificationError("profile is not a VPN connection")
    if s_vpn.get_service_type() != OPENVPN_SERVICE_TYPE:
        raise ImportVerificationError("profile uses an unexpected VPN service")

    data = s_vpn.props.data

    def require(key: str, expected: str | None) -> None:
        actual = data.get(key)
        if actual != expected:
            raise ImportVerificationError(
                f"preservation check failed for '{key}': expected {expected!r}, got {actual!r}"
            )

    expected_remote = ", ".join(f"{host}:{port}" for host, port in parsed.remotes)
    require("remote", expected_remote)
    if parsed.protocol == "tcp":
        require("proto-tcp", "yes")
    else:
        require("proto-tcp", None)
    require("remote-cert-tls", "server")
    require("verify-x509-name", parsed.verify_x509_name)
    require("auth", parsed.auth)
    require("data-ciphers", parsed.data_ciphers)
    require("data-ciphers-fallback", parsed.data_ciphers_fallback)
    require("tls-cipher", parsed.tls_cipher)
    require("connection-type", "password")

    if data.get("password") is not None:
        raise ImportVerificationError("password was written into non-secret profile data")
    if s_vpn.get_secret("password") is not None:
        raise ImportVerificationError("password secret was unexpectedly present in the profile")
    if data.get("password-flags") != str(int(NM.SettingSecretFlags.AGENT_OWNED)):
        raise ImportVerificationError("password is not marked agent-owned in the profile")
    for forbidden in (
        "cert",
        "key",
        "pkcs12",
        "tls-auth",
        "tls-crypt",
        "tls-crypt-v2",
        "http-proxy-password",
        "proxy-password",
    ):
        if data.get(forbidden):
            raise ImportVerificationError(f"unexpected sensitive field '{forbidden}' in profile")

    ca_path = _check_ca_path(data.get("ca"), cert_dir, parsed.ca_sha256)
    warnings = low_risk_warnings(parsed, connection)
    return ca_path, warnings


def verify_imported_profile(
    connection: NM.Connection,
    parsed: ParsedProfile,
    cert_dir: Path,
) -> ImportedProfile:
    ca_path, warnings = _verify_vpn_fields(connection, parsed, cert_dir)
    return ImportedProfile(connection=connection, ca_path=ca_path, warnings=warnings)


def verify_managed_profile(
    connection: NM.Connection,
    parsed: ParsedProfile,
    cert_dir: Path,
) -> tuple[str, ...]:
    """Verify an already-managed profile before reusing it."""
    _ca_path, warnings = _verify_vpn_fields(connection, parsed, cert_dir)
    return warnings


def _nmcli_import(staged: Path, cert_root: Path, timeout: int = 60) -> None:
    env = os.environ.copy()
    env["NM_CERT_PATH"] = str(cert_root)
    env["LC_ALL"] = "C"
    command = [
        "nmcli",
        "connection",
        "import",
        "--temporary",
        "type",
        "openvpn",
        "file",
        str(staged),
    ]
    try:
        result = subprocess.run(
            command,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError as exc:
        raise ImportError("nmcli is not installed") from exc
    except subprocess.TimeoutExpired as exc:
        raise ImportError("nmcli import timed out") from exc
    except OSError as exc:
        raise ImportError(f"could not run nmcli: {exc}") from exc

    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        if len(detail) > 800:
            detail = detail[:800] + "…"
        raise ImportError(f"nmcli import failed (exit {result.returncode}): {detail}")


def _new_temp_connection(
    client: NM.Client,
    before_uuids: set[str],
) -> NM.Connection:
    candidates: list[NM.Connection] = []
    for connection in client.get_connections():
        if connection.get_uuid() in before_uuids:
            continue
        if connection.get_connection_type() != "vpn":
            continue
        s_vpn = connection.get_setting_vpn()
        if isinstance(s_vpn, NM.SettingVpn) and s_vpn.get_service_type() == OPENVPN_SERVICE_TYPE:
            candidates.append(connection)
    if len(candidates) != 1:
        names = ", ".join(
            f"{c.get_uuid()} ({c.get_setting_connection().get_id()})" for c in candidates
        )
        raise ImportError(
            "could not identify exactly one newly imported OpenVPN profile"
            + (f"; candidates: {names}" if names else "")
        )
    return candidates[0]


def import_and_prepare(
    client: NM.Client,
    profile_bytes: bytes,
    parsed: ParsedProfile,
    *,
    vpn_username: str,
    local_username: str,
    cert_dir: Path | None = None,
) -> PreparedProfile:
    if hashlib.sha256(profile_bytes).hexdigest() != parsed.source_sha256:
        raise ImportError("source profile bytes do not match the validated profile hash")
    if not local_username:
        raise ImportError("a local username is required")
    if not vpn_username:
        raise ImportError("a VPN username is required")

    cert_dir = cert_dir or certificate_dir()
    cert_root = cert_dir.parent
    ensure_private_dir(cert_root)
    ensure_private_dir(cert_dir)
    stage_dir = ensure_private_dir(runtime_dir())
    before_certs = _cert_files(cert_dir)
    staged = stage_dir / f"import-{secrets.token_hex(12)}.ovpn"
    before_uuids = {connection.get_uuid() for connection in client.get_connections()}

    fd = os.open(staged, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(profile_bytes)
            handle.flush()
            os.fsync(handle.fileno())
        _nmcli_import(staged, cert_root)
    except Exception:
        staged.unlink(missing_ok=True)
        _cleanup_new_cert_files(cert_dir, before_certs)
        raise
    else:
        staged.unlink(missing_ok=True)

    # A fresh client avoids racing libnm's signal cache after nmcli exits.
    fresh = NM.Client.new(None)
    try:
        temp = _new_temp_connection(fresh, before_uuids)
    except Exception:
        _cleanup_new_cert_files(cert_dir, before_certs)
        raise

    try:
        imported = verify_imported_profile(temp, parsed, cert_dir)
        managed = build_managed_connection(
            imported.connection,
            local_username=local_username,
            vpn_username=vpn_username,
        )
        variant = build_variant(managed)
    except Exception:
        try:
            temp.delete(None)
        except GLib.Error as exc:
            log.warning("could not delete failed temporary import: %s", exc.message)
        _cleanup_new_cert_files(cert_dir, before_certs)
        raise

    try:
        if not temp.delete(None):
            raise ImportError("NetworkManager did not delete the temporary imported profile")
    except GLib.Error as exc:
        raise ImportError(f"could not delete the temporary imported profile: {exc.message}") from exc

    return PreparedProfile(
        variant=variant,
        source_sha256=parsed.source_sha256,
        ca_path=str(imported.ca_path),
        ca_sha256=parsed.ca_sha256,
        warnings=imported.warnings,
    )
