from __future__ import annotations

from typing import Optional

from PyQt5 import QtWidgets

from electroncash.wallet import Deterministic_Wallet

from ..password_dialog import PasswordDialog


def get_privkey_suggestion(
    wallet: Deterministic_Wallet,
    key_index: int = 0,
    pwd: Optional[str] = None,
) -> str:
    """Get a deterministic private key derived from a BIP44 path that is not used
    by the wallet to generate addresses.

    Return it in WIF format, or return an empty string on failure (pwd dialog
    cancelled).
    """
    # Use BIP44 change_index 2, which is not used by any application.
    privkey_index = (2, key_index)

    if wallet.has_password() and pwd is None:
        raise RuntimeError("Wallet password required")
    return wallet.export_private_key_for_index(privkey_index, pwd)


class CachedWalletPasswordWidget(QtWidgets.QWidget):
    """A base class for widgets that may prompt the user for a wallet password and
    remember that password for later reuse.
    The password can also be specified in the constructor. In this case, there is no
    need to prompt the user for it.
    """

    def __init__(
        self,
        wallet: Deterministic_Wallet,
        pwd: Optional[str] = None,
        parent: QtWidgets.QWidget = None,
    ):
        super().__init__(parent)
        self._pwd = pwd
        self.wallet = wallet

    @property
    def pwd(self) -> Optional[str]:
        """Return wallet password.

        Open a dialog to ask for the wallet password if necessary, and cache it.
        Keep asking until the user provides the correct pwd or clicks cancel.
        If the password dialog is cancelled, return None.
        """
        if self._pwd is not None:
            return self._pwd

        while self.wallet.has_password():
            password = PasswordDialog(parent=self).run()
            if password is None:
                # dialog cancelled
                return
            try:
                self.wallet.check_password(password)
                self._pwd = password
                # success
                return self._pwd
            except Exception as e:
                QtWidgets.QMessageBox.critical(self, "Invalid password", str(e))
