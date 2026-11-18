"""NetworkManager integration package."""

from .agent import AgentError, NetworkManagerSecretAgent
from .client import (
    NetworkManagerError,
    activate_async,
    active_vpn_for_uuid,
    add_connection_async,
    deactivate_async,
    get_connection_by_uuid,
    new_client,
    prepare_managed_profile,
    prepare_managed_profile_async,
    update_connection_async,
)
from .importer import ImportError, ImportVerificationError, import_and_prepare, verify_managed_profile
from .profile import PreparedProfile, ProfileBuildError, build_managed_connection

__all__ = [
    "AgentError",
    "ImportError",
    "ImportVerificationError",
    "NetworkManagerError",
    "NetworkManagerSecretAgent",
    "PreparedProfile",
    "ProfileBuildError",
    "activate_async",
    "active_vpn_for_uuid",
    "add_connection_async",
    "build_managed_connection",
    "deactivate_async",
    "get_connection_by_uuid",
    "import_and_prepare",
    "new_client",
    "prepare_managed_profile",
    "prepare_managed_profile_async",
    "update_connection_async",
    "verify_managed_profile",
]
