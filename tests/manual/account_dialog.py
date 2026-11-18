"""Account dialog: a saved password is shown as a status, never as text."""

from gi.repository import GLib

from harness import run_window_harness

SECRET = "harness-secret-value"


def scenario(window, checks, done):
    from pervius.credentials import SAVED_IN_KEYRING
    from pervius.ui.account import CredentialsWindow

    class Store:
        persistence_available = True
        lookups = 0
        forgotten = []

        def password_state(self, _username):
            return None if self.forgotten else SAVED_IN_KEYRING

        def lookup(self, _username):
            Store.lookups += 1
            return SECRET

        def forget(self, username):
            self.forgotten.append(username)
            return True

    window.settings.username = "user@example.com"
    store = Store()
    dialog = CredentialsWindow(window, store, window.settings, lambda: None)
    dialog.present()

    def check():
        checks.equal("status row shown", dialog.kept_row.get_visible(), True)
        checks.equal("status text", dialog.kept_row.get_subtitle(), "Saved in the keyring")
        checks.equal("no password entry", dialog.password_row.get_visible(), False)
        checks.equal("entry empty", dialog.password_row.get_text(), "")
        checks.equal("forget offered", dialog.forget_group.get_visible(), True)
        dialog._on_replace()
        checks.equal("replace shows entry", dialog.password_row.get_visible(), True)
        checks.equal("replace entry empty", dialog.password_row.get_text(), "")
        dialog._replacing = False
        dialog.username_row.set_text("other@example.com")
        checks.equal("new username needs password", dialog.password_row.get_visible(), True)
        dialog.username_row.set_text("user@example.com")
        dialog._forget("user@example.com")
        checks.equal("forget removed", store.forgotten, ["user@example.com"])
        checks.equal("entry after forget", dialog.password_row.get_visible(), True)
        checks.equal("never looked up", Store.lookups, 0)
        dialog.close()
        done()
        return False

    GLib.timeout_add(800, check)


raise SystemExit(run_window_harness("account_dialog", scenario))
