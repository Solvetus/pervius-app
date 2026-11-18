#!/usr/bin/env python3
"""Approval-gated live proof for the NetworkManager OpenVPN backend.

This tool prompts for credentials locally.  It never accepts a password as a
command-line argument, environment variable, or file.  Nothing secret is
logged or printed.  It performs real NetworkManager changes, so run it only in
an agreed test window.
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys
import time
from pathlib import Path

if __package__ in (None, ""):  # direct execution: python3 pervius/tools/proof_connect.py
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import gi

gi.require_version("NM", "1.0")
from gi.repository import GLib  # noqa: E402

from pervius.catalogue import CatalogueStore  # noqa: E402
from pervius.catalogue.fetcher import fetch_catalogue  # noqa: E402
from pervius.catalogue.validator import parse_catalogue  # noqa: E402
from pervius.config import CATALOGUE_URL, certificate_dir, local_username  # noqa: E402
from pervius.credentials import CredentialStore  # noqa: E402
from pervius.nm.agent import AgentError, NetworkManagerSecretAgent  # noqa: E402
from pervius.nm.client import (  # noqa: E402
    NetworkManagerError,
    active_vpn_for_uuid,
    add_connection_sync,
    deactivate_sync,
    delete_sync,
    new_client,
    prepare_managed_profile,
    update_connection_sync,
    vpn_state_name,
    vpn_state_reason,
)
from pervius.nm.importer import verify_managed_profile  # noqa: E402
from pervius.ownership import (  # noqa: E402
    OwnershipEntry,
    OwnershipError,
    OwnershipStore,
    check_create_collision,
    find_managed_connection,
)
from pervius.migration import REFUSED, migrate_profile, migrate_user_data  # noqa: E402
from pervius.settings import SettingsStore  # noqa: E402


def _pick_location(catalogue, query: str, protocol: str):
    query = query.strip()
    matches = []
    for location in catalogue.locations:
        if query and not location.matches(query):
            continue
        if protocol in location.profiles:
            matches.append(location)
    if len(matches) == 1:
        return matches[0]
    if not matches:
        raise SystemExit(f"No location matches {query!r} with protocol {protocol}.")
    print("Multiple matches; use a more specific query:")
    for location in matches[:30]:
        print(
            f"  {location.key}  "
            f"({location.city}, {location.display_country}, {location.flag})"
        )
    if len(matches) > 30:
        print(f"  … and {len(matches) - 30} more")
    raise SystemExit(2)


def main(argv: list[str] | None = None) -> int:
    if os.geteuid() == 0:
        print(
            "Refusing to run as root. Run this test as your desktop user; "
            "NetworkManager performs privileged network operations.",
            file=sys.stderr,
        )
        return 1
    parser = argparse.ArgumentParser(
        description="Live NetworkManager/OpenVPN proof (prompts locally for credentials)"
    )
    parser.add_argument("--location", required=True, help="city or country/city, e.g. DE/Frankfurt")
    parser.add_argument("--proto", choices=("udp", "tcp"), default="udp")
    parser.add_argument("--refresh", action="store_true", help="refresh the catalogue before running")
    parser.add_argument("--timeout", type=int, default=90, help="connection timeout in seconds")
    parser.add_argument(
        "--delete-profile",
        action="store_true",
        help="delete the app-owned managed profile after the proof",
    )
    args = parser.parse_args(argv)

    migrate_user_data()
    store = CatalogueStore()
    try:
        catalogue = None if args.refresh else store.load()
    except Exception as exc:
        print(f"Cached catalogue is unusable: {exc}", file=sys.stderr)
        catalogue = None
    if catalogue is None:
        print("Downloading and validating the public catalogue…")
        blob = fetch_catalogue()
        catalogue = parse_catalogue(blob, source_url=CATALOGUE_URL)
        try:
            store.save(blob, catalogue)
        except Exception as exc:
            print(f"Warning: could not save catalogue cache: {exc}", file=sys.stderr)

    location = _pick_location(catalogue, args.location, args.proto)
    ref = location.profiles[args.proto]
    print(f"Selected: {location.key} · {args.proto.upper()}")
    print(f"Remotes: {', '.join(host + ':' + str(port) for host, port in ref.profile.remotes)}")

    settings = SettingsStore().load()
    default_user = settings.username.strip()
    prompt = f"Username [{default_user}]: " if default_user else "Username: "
    username = input(prompt).strip() or default_user
    if not username:
        print("A username is required.", file=sys.stderr)
        return 2
    password = getpass.getpass("Password (not echoed): ")
    if not password:
        print("A password is required.", file=sys.stderr)
        return 2
    credentials = CredentialStore()
    credentials.remember(username, password)
    local_user = local_username()
    print(f"Local profile owner: {local_user}")

    try:
        client = new_client()
    except NetworkManagerError as exc:
        print(f"NetworkManager unavailable: {exc}", file=sys.stderr)
        return 1

    migrated = migrate_profile(client.get_connections(), local_user)
    if migrated.status == REFUSED:
        print(f"Could not adopt the previous release's profile: {migrated.detail}", file=sys.stderr)

    agent = None
    managed = None
    try:
        ownership = OwnershipStore.load()
        try:
            lookup = find_managed_connection(
                client.get_connections(), ownership, local_user
            )
        except OwnershipError as exc:
            print(f"Ownership check failed: {exc}", file=sys.stderr)
            return 1
        managed = lookup.connection
        prepare_needed = managed is None
        if managed is not None:
            try:
                verify_managed_profile(managed, ref.profile, certificate_dir())
            except Exception as exc:
                print(f"Existing managed profile must be re-imported: {exc}")
                prepare_needed = True

        if prepare_needed:
            print("Importing and verifying the profile through nmcli/NetworkManager…")
            prepared = prepare_managed_profile(
                ref, vpn_username=username, local_username=local_user
            )
            for warning in prepared.warnings:
                print(f"note: {warning}")
            if managed is not None:
                managed = update_connection_sync(managed, prepared.variant)
                action = "updated"
            else:
                try:
                    check_create_collision(client.get_connections(), local_user)
                except OwnershipError as exc:
                    print(f"Ownership check failed: {exc}", file=sys.stderr)
                    return 1
                managed = add_connection_sync(client, prepared.variant)
                action = "created"
            entry = OwnershipEntry(
                created_at=lookup.entry.created_at if lookup.entry else "",
                source_sha256=prepared.source_sha256,
                ca_sha256=prepared.ca_sha256,
                ca_path=prepared.ca_path,
            )
            ownership.record(entry)
            print(f"Managed profile {action}: {managed.get_uuid()}")
        else:
            entry = lookup.entry
            if entry is None:
                print("Managed profile exists without an ownership manifest; refusing.", file=sys.stderr)
                return 1
            print(f"Reusing verified managed profile: {managed.get_uuid()}")

        # Register the agent only after the manifest exists; the agent refuses
        # any UUID that is not manifest-owned.
        agent = NetworkManagerSecretAgent(
            lambda _local_user: credentials.lookup(username),
            username=local_user,
            store_provider=OwnershipStore.load,
        )
        try:
            agent.register()
        except AgentError as exc:
            print(f"Secret agent registration failed: {exc}", file=sys.stderr)
            return 1
        print("Secret agent registered on the system bus.")

        print("Activating the VPN through NetworkManager…")
        # Use async activation and a monitored main loop so state transitions
        # are observed rather than assumed.
        from ..nm.client import activate_async

        loop = GLib.MainLoop()
        result: dict = {}

        def activated(active, error):
            if error is not None:
                result["error"] = str(error)
                loop.quit()
                return
            print("Activation request accepted; waiting for the tunnel…")

        activate_async(client, managed, activated)
        deadline = time.monotonic() + max(10, args.timeout)
        last_state = None

        def poll():
            nonlocal last_state
            active = active_vpn_for_uuid(client)
            if active is None:
                if "error" in result:
                    loop.quit()
                    return False
                if time.monotonic() > deadline:
                    result["error"] = "timed out waiting for an active VPN"
                    loop.quit()
                    return False
                return True
            state = vpn_state_name(active)
            if state != last_state:
                print(f"state: {state}" + (f" ({vpn_state_reason(active)})" if state == "failed" else ""))
                last_state = state
            if state == "failed":
                result["error"] = f"VPN failed: {vpn_state_reason(active)}"
                loop.quit()
                return False
            if state == "activated":
                result["active"] = active
                print("activated: tunnel is up")
                loop.quit()
                return False
            if state == "disconnected":
                result["error"] = "VPN disconnected before activation completed"
                loop.quit()
                return False
            if time.monotonic() > deadline:
                result["error"] = "timed out waiting for the tunnel"
                loop.quit()
                return False
            return True

        GLib.timeout_add_seconds(1, poll)
        loop.run()

        if "error" in result:
            print(f"PROOF FAILED: {result['error']}", file=sys.stderr)
            return 1

        print("Tunnel is active. Press Enter to disconnect.")
        try:
            input()
        except EOFError:
            pass
        active = active_vpn_for_uuid(client)
        if active is not None:
            deactivate_sync(client, active)
            print("Disconnect requested.")
            for _ in range(30):
                if active_vpn_for_uuid(client) is None:
                    print("state: disconnected")
                    break
                time.sleep(1)
            else:
                print("warning: VPN still appears active after 30 seconds", file=sys.stderr)

        print("PROOF COMPLETE: credentials were prompted locally and were not printed.")
        return 0
    finally:
        if agent is not None:
            try:
                agent.unregister()
            except Exception:
                pass
        if args.delete_profile and managed is not None:
            answer = input("Delete the app-owned managed profile? [y/N]: ").strip().lower()
            if answer == "y":
                try:
                    delete_sync(managed)
                    try:
                        OwnershipStore.load().remove(managed.get_uuid())
                    except Exception:
                        pass
                    print("Managed profile deleted.")
                except Exception as exc:
                    print(f"Could not delete managed profile: {exc}", file=sys.stderr)


if __name__ == "__main__":
    raise SystemExit(main())
