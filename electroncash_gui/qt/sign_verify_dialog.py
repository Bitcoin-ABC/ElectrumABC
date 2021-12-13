from __future__ import annotations

import base64
from functools import partial
from typing import TYPE_CHECKING, Optional

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (
    QDialog,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QTextEdit,
)

from electroncash import bitcoin
from electroncash.address import Address
from electroncash.constants import CURRENCY, PROJECT_NAME
from electroncash.i18n import _

from .password_dialog import PasswordDialog
from .util import MessageBoxMixin

if TYPE_CHECKING:
    from electroncash.wallet import Abstract_Wallet


class SignVerifyDialog(QDialog, MessageBoxMixin):
    def __init__(
        self, wallet: Abstract_Wallet, address: Optional[Address] = None, parent=None
    ):
        super().__init__(parent)
        self.setWindowModality(Qt.WindowModal)
        self.setWindowTitle(_("Sign/verify Message"))
        self.setMinimumSize(610, 290)

        self.wallet = wallet

        layout = QGridLayout(self)
        self.setLayout(layout)

        self.message_e = QTextEdit()
        self.message_e.setAcceptRichText(False)
        layout.addWidget(QLabel(_("Message")), 1, 0)
        layout.addWidget(self.message_e, 1, 1)
        layout.setRowStretch(2, 3)

        self.address_e = QLineEdit()
        self.address_e.setText(address.to_ui_string() if address else "")
        layout.addWidget(QLabel(_("Address")), 2, 0)
        layout.addWidget(self.address_e, 2, 1)

        self.signature_e = QTextEdit()
        self.signature_e.setAcceptRichText(False)
        layout.addWidget(QLabel(_("Signature")), 3, 0)
        layout.addWidget(self.signature_e, 3, 1)
        layout.setRowStretch(3, 1)

        hbox = QHBoxLayout()

        b = QPushButton(_("Sign"))
        b.clicked.connect(lambda: self.do_sign())
        hbox.addWidget(b)

        b = QPushButton(_("Verify"))
        b.clicked.connect(lambda: self.do_verify())
        hbox.addWidget(b)

        b = QPushButton(_("Close"))
        b.clicked.connect(self.accept)
        hbox.addWidget(b)
        layout.addLayout(hbox, 4, 1)

    def _get_password(self) -> Optional[str]:
        password = None
        while self.wallet.has_keystore_encryption():
            password = PasswordDialog(self).run()
            if password is None:
                return
            try:
                self.wallet.check_password(password)
                break
            except Exception as e:
                self.show_error(str(e))
                continue
        return password

    def do_sign(self):
        password = self._get_password()
        address = self.address_e.text().strip()
        message = self.message_e.toPlainText().strip()
        try:
            addr = Address.from_string(address)
        except Exception:
            self.show_message(_(f"Invalid {CURRENCY} address."))
            return
        if addr.kind != addr.ADDR_P2PKH:
            msg_sign = (
                _(
                    "Signing with an address actually means signing with the corresponding "
                    "private key, and verifying with the corresponding public key. The "
                    "address you have entered does not have a unique public key, so these "
                    "operations cannot be performed."
                )
                + "\n\n"
                + _(
                    f"The operation is undefined. Not just in "
                    f"{PROJECT_NAME}, but in general."
                )
            )
            self.show_message(
                _("Cannot sign messages with this type of address.") + "\n\n" + msg_sign
            )
            return
        if self.wallet.is_watching_only():
            self.show_message(_("This is a watching-only wallet."))
            return
        if not self.wallet.is_mine(addr):
            self.show_message(_("Address not in wallet."))
            return
        task = partial(self.wallet.sign_message, addr, message, password)

        def show_signed_message(sig):
            self.signature_e.setText(base64.b64encode(sig).decode("ascii"))

        self.wallet.thread.add(task, on_success=show_signed_message)

    def do_verify(self):
        try:
            address = Address.from_string(self.address_e.text().strip())
        except Exception:
            self.show_message(_(f"Invalid {CURRENCY} address."))
            return
        message = self.message_e.toPlainText().strip().encode("utf-8")
        try:
            # This can throw on invalid base64
            sig = base64.b64decode(self.signature_e.toPlainText())
            verified = bitcoin.verify_message(address, sig, message)
        except Exception:
            verified = False

        if verified:
            self.show_message(_("Signature verified"))
        else:
            self.show_error(_("Wrong signature"))
