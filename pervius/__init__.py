"""Solvetus VPN Manager.

An independent desktop front end for managing an existing OpenVPN
subscription through NetworkManager.  This is an early test build.
"""

from .config import APP_NAME, APP_ID, VERSION

__version__ = VERSION
__all__ = ["APP_NAME", "APP_ID", "VERSION"]
