"""Account dialog: VPN username and password.

A stored password is never read into this dialog.  The dialog asks the
credential store only *whether* a password is kept (``password_state``),
shows that fact, and offers Replace and Forget.  The password entry, and the
reveal toggle that comes with it, exists only for a password the user is
typing now.  The secret agent (``pervius.nm.agent``) is the only reader of a
stored password, and only when NetworkManager asks for it.
"""

from __future__ import annotations

from dataclasses import dataclass

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gtk  # noqa: E402

from ..credentials import (  # noqa: E402
    SAVED_IN_KEYRING,
    SESSION_ONLY,
    CredentialError,
    CredentialStore,
)
from ..settings import Settings, SettingsStore  # noqa: E402


@dataclass(frozen=True)
class AccountView:
    """What the dialog shows for a username; derived without any secret."""

    kept: str | None  # SAVED_IN_KEYRING, SESSION_ONLY or None
    show_entry: bool
    can_forget: bool


def account_view(store: CredentialStore, saved_username: str, typed_username: str) -> AccountView:
    """Decide the dialog layout.

    A kept password belongs to the saved username.  Typing a different
    username therefore requires a new password.
    """
    saved = saved_username.strip()
    typed = typed_username.strip()
    kept = store.password_state(saved) if saved else None
    if kept is None or typed != saved:
        return AccountView(kept=None, show_entry=True, can_forget=kept is not None)
    return AccountView(kept=kept, show_entry=False, can_forget=True)


class CredentialsWindow(Adw.Window):
    def __init__(self, parent, store: CredentialStore, settings: Settings, on_saved):
        super().__init__()
        self._store = store
        self._settings = settings
        self._on_saved = on_saved
        self._replacing = False
        self.set_title("Account")
        self.set_transient_for(parent)
        self.set_modal(True)
        self.set_default_size(460, 460)

        toolbar = Adw.ToolbarView()
        header = Adw.HeaderBar()
        cancel = Gtk.Button(label="Cancel")
        cancel.connect("clicked", lambda *_: self.close())
        save = Gtk.Button(label="Save")
        save.add_css_class("suggested-action")
        save.connect("clicked", self._save)
        header.pack_start(cancel)
        header.pack_end(save)
        toolbar.add_top_bar(header)

        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        box.set_margin_top(18)
        box.set_margin_bottom(18)
        box.set_margin_start(18)
        box.set_margin_end(18)

        page = Adw.PreferencesPage()
        group = Adw.PreferencesGroup()
        group.set_title("FastVPN account")
        group.set_description(
            "The password is sent to NetworkManager only when the VPN is activated. "
            "It is never written to the NetworkManager profile."
        )
        self.username_row = Adw.EntryRow()
        self.username_row.set_title("Username")
        self.username_row.set_text(settings.username)
        self.username_row.connect("changed", lambda *_: self._refresh())

        # Shown instead of an entry when a password is already kept.  It holds
        # no secret: only the fact that one exists.
        self.kept_row = Adw.ActionRow()
        self.kept_row.set_title("Password")
        replace = Gtk.Button(label="Replace")
        replace.set_valign(Gtk.Align.CENTER)
        replace.connect("clicked", self._on_replace)
        self.kept_row.add_suffix(replace)

        # Always starts empty; the reveal toggle applies only to typed text.
        self.password_row = Adw.PasswordEntryRow()
        self.password_row.set_title("Password")

        self.save_row = Adw.SwitchRow()
        self.save_row.set_title("Save password in the desktop keyring")
        self.save_row.set_active(bool(settings.save_password and store.persistence_available))
        group.add(self.username_row)
        group.add(self.kept_row)
        group.add(self.password_row)
        group.add(self.save_row)
        page.add(group)

        self.forget_group = Adw.PreferencesGroup()
        forget = Gtk.Button(label="Forget Saved Password…")
        forget.add_css_class("destructive-action")
        forget.set_halign(Gtk.Align.START)
        forget.connect("clicked", self._confirm_forget)
        self.forget_group.add(forget)
        page.add(self.forget_group)
        box.append(page)

        self.error_label = Gtk.Label()
        self.error_label.set_wrap(True)
        self.error_label.set_xalign(0.0)
        self.error_label.add_css_class("error")
        self.error_label.set_visible(False)
        box.append(self.error_label)

        note = Gtk.Label()
        note.set_wrap(True)
        note.set_xalign(0.0)
        note.add_css_class("dim-label")
        note.set_label(
            "Credentials are not verified until a connection succeeds. "
            "Nothing is sent to Solvetus Labs; Pervius has no servers of its own."
        )
        box.append(note)

        clamp = Adw.Clamp()
        clamp.set_maximum_size(560)
        clamp.set_child(box)
        scroller = Gtk.ScrolledWindow()
        scroller.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        scroller.set_child(clamp)
        toolbar.set_content(scroller)
        self.set_content(toolbar)

        self._refresh()
        self.username_row.grab_focus()

    # ------------------------------------------------------------------ view

    def _view(self) -> AccountView:
        view = account_view(self._store, self._settings.username, self.username_row.get_text())
        if self._replacing and not view.show_entry:
            return AccountView(kept=None, show_entry=True, can_forget=view.can_forget)
        return view

    def _refresh(self) -> None:
        view = self._view()
        if view.kept == SAVED_IN_KEYRING:
            self.kept_row.set_subtitle("Saved in the keyring")
        elif view.kept == SESSION_ONLY:
            self.kept_row.set_subtitle("Kept for this session only")
        self.kept_row.set_visible(not view.show_entry)
        self.password_row.set_visible(view.show_entry)
        self.forget_group.set_visible(view.can_forget)
        available = self._store.persistence_available
        if not available:
            self.save_row.set_subtitle(
                "The desktop keyring is unavailable; the password will be session-only."
            )
        elif view.show_entry:
            self.save_row.set_subtitle(
                "If unavailable, the password is kept only for this session."
            )
        else:
            self.save_row.set_subtitle("Replace the password to change where it is kept.")
        self.save_row.set_sensitive(available and view.show_entry)
        if not view.show_entry:
            self.save_row.set_active(view.kept == SAVED_IN_KEYRING)

    def _on_replace(self, *_args) -> None:
        self._replacing = True
        self.password_row.set_text("")
        self._refresh()
        self.password_row.grab_focus()

    def _show_error(self, message: str) -> None:
        self.error_label.set_label(message)
        self.error_label.set_visible(True)

    # ---------------------------------------------------------------- forget

    def _confirm_forget(self, *_args) -> None:
        username = self._settings.username.strip()
        if not username:
            return
        dialog = Adw.AlertDialog.new(
            "Forget saved password?",
            "This removes the desktop-keyring entry and the in-memory copy for "
            f"{username}. An already-connected VPN stays up, but reauthentication "
            "may fail until you enter the password again.",
        )
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("forget", "Forget Password")
        dialog.set_close_response("cancel")
        dialog.set_default_response("cancel")
        dialog.set_response_appearance("forget", Adw.ResponseAppearance.DESTRUCTIVE)

        def response(_dialog, response_id):
            if response_id == "forget":
                self._forget(username)

        dialog.connect("response", response)
        dialog.present(self)

    def _forget(self, username: str) -> None:
        try:
            self._store.forget(username)
        except CredentialError as exc:
            self._show_error(f"Could not remove the saved password: {exc}")
            return
        self._replacing = False
        self.password_row.set_text("")
        self.error_label.set_visible(False)
        self._refresh()
        self._on_saved()

    # ------------------------------------------------------------------ save

    def _save(self, *_args) -> None:
        username = self.username_row.get_text().strip()
        if not username:
            self._show_error("Enter your VPN username.")
            return
        view = self._view()
        if not view.show_entry:
            # The kept password is unchanged; nothing secret is touched.
            self._finish(username, self._settings.save_password)
            return
        password = self.password_row.get_text()
        if not password:
            self._show_error("Enter your VPN password.")
            return
        persist = bool(self.save_row.get_active()) and self._store.persistence_available
        try:
            self._store.store(username, password, persist=persist)
        except CredentialError as exc:
            self._show_error(
                f"The password is in memory for this session, but could not be saved: {exc}"
            )
            self.save_row.set_active(False)
            return
        finally:
            self.password_row.set_text("")
        self._finish(username, persist)

    def _finish(self, username: str, persist: bool) -> None:
        self._settings.username = username
        self._settings.save_password = persist
        SettingsStore().save(self._settings)
        self._on_saved()
        self.close()
