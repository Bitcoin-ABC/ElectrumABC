from __future__ import annotations

from typing import TYPE_CHECKING, List, Optional

from PyQt5 import QtCore, QtGui, QtWidgets

from electroncash.address import Address, AddressError
from electroncash.avalanche.delegation import (
    Delegation,
    DelegationBuilder,
    WrongDelegatorKeyError,
)
from electroncash.avalanche.primitives import Key, PublicKey
from electroncash.avalanche.proof import LimitedProofId, Proof, ProofBuilder
from electroncash.avalanche.serialize import DeserializationError
from electroncash.bitcoin import is_private_key
from electroncash.constants import PROOF_DUST_THRESHOLD
from electroncash.i18n import _
from electroncash.uint256 import UInt256

from .password_dialog import PasswordDialog

if TYPE_CHECKING:
    from electroncash.wallet import Deterministic_Wallet


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


class Link(QtWidgets.QPushButton):
    def __init__(self, text="", parent=None):
        super().__init__(text, parent)
        stylesheet = """
            QPushButton {
                color: blue;
                border: none;
                font-weight: bold;
                font-size: 14px;
                text-align: center;
            }
            QPushButton:disabled {
                color: gray;
            }
            """
        self.setStyleSheet(stylesheet)
        size_policy = QtWidgets.QSizePolicy()
        size_policy.setHorizontalPolicy(QtWidgets.QSizePolicy.Fixed)
        self.setSizePolicy(size_policy)


class AvaProofWidget(CachedWalletPasswordWidget):
    def __init__(
        self,
        utxos: List[dict],
        wallet: Deterministic_Wallet,
        receive_address: Optional[Address] = None,
        parent: QtWidgets.QWidget = None,
    ):
        """

        :param utxos:  List of UTXOs to be used as stakes
        :param parent:
        """
        CachedWalletPasswordWidget.__init__(self, wallet, parent=parent)
        # This is enough width to show a whole compressed pubkey.
        self.setMinimumWidth(750)
        # Enough height to show the entire proof without scrolling.
        self.setMinimumHeight(680)

        self.utxos = utxos
        self.excluded_utxos: List[dict] = []
        self.wallet = wallet

        layout = QtWidgets.QVBoxLayout()
        self.setLayout(layout)

        layout.addWidget(QtWidgets.QLabel("Proof sequence"))
        self.sequence_sb = QtWidgets.QSpinBox()
        self.sequence_sb.setMinimum(0)
        layout.addWidget(self.sequence_sb)
        layout.addSpacing(10)

        expiration_layout = QtWidgets.QHBoxLayout()
        layout.addLayout(expiration_layout)

        expiration_left_sublayout = QtWidgets.QVBoxLayout()
        expiration_layout.addLayout(expiration_left_sublayout)
        expiration_left_sublayout.addWidget(QtWidgets.QLabel("Expiration date"))
        self.calendar = QtWidgets.QDateTimeEdit()
        self.calendar.setToolTip("Date and time at which the proof will expire")
        expiration_left_sublayout.addWidget(self.calendar)

        expiration_right_sublayout = QtWidgets.QVBoxLayout()
        expiration_layout.addLayout(expiration_right_sublayout)
        expiration_right_sublayout.addWidget(
            QtWidgets.QLabel("Expiration POSIX timestamp")
        )
        # Use a QDoubleSpinbox with precision set to 0 decimals, because
        # QSpinBox is limited to the int32 range (January 19, 2038)
        self.timestamp_widget = QtWidgets.QDoubleSpinBox()
        self.timestamp_widget.setDecimals(0)
        # date range: genesis block to Wed Jun 09 3554 16:53:20 GMT
        self.timestamp_widget.setRange(1231006505, 50**10)
        self.timestamp_widget.setSingleStep(86400)
        self.timestamp_widget.setToolTip(
            "POSIX time, seconds since 1970-01-01T00:00:00"
        )
        expiration_right_sublayout.addWidget(self.timestamp_widget)
        layout.addSpacing(10)

        layout.addWidget(QtWidgets.QLabel("Master private key (WIF)"))
        self.master_key_edit = QtWidgets.QLineEdit()
        self.master_key_edit.setToolTip(
            "Private key that controls the proof. This is the key that signs the "
            "delegation or signs the avalanche votes."
        )
        # Suggest a private key to the user. He can change it if he wants.
        self.master_key_edit.setText(self._get_privkey_suggestion())
        layout.addWidget(self.master_key_edit)
        layout.addSpacing(10)

        layout.addWidget(
            QtWidgets.QLabel("Master public key (computed from master private key)")
        )
        self.master_pubkey_view = QtWidgets.QLineEdit()
        self.master_pubkey_view.setReadOnly(True)
        layout.addWidget(self.master_pubkey_view)
        layout.addSpacing(10)

        layout.addWidget(QtWidgets.QLabel("Payout address"))
        self.payout_addr_edit = QtWidgets.QLineEdit()
        self.payout_addr_edit.setToolTip(
            "Address to which staking rewards could be sent, in the future"
        )
        if receive_address is not None:
            self.payout_addr_edit.setText(receive_address.to_ui_string())
        layout.addWidget(self.payout_addr_edit)
        layout.addSpacing(10)

        self.utxos_wigdet = QtWidgets.QTableWidget(len(utxos), 4)
        self.utxos_wigdet.setHorizontalHeaderLabels(
            ["txid", "vout", "amount (sats)", "block height"]
        )
        self.utxos_wigdet.verticalHeader().setVisible(False)
        self.utxos_wigdet.setSelectionMode(QtWidgets.QTableWidget.NoSelection)
        self.utxos_wigdet.horizontalHeader().setSectionResizeMode(
            0, QtWidgets.QHeaderView.Stretch
        )
        layout.addWidget(self.utxos_wigdet)
        for i, utxo in enumerate(utxos):
            txid_item = QtWidgets.QTableWidgetItem(utxo["prevout_hash"])
            self.utxos_wigdet.setItem(i, 0, txid_item)

            vout_item = QtWidgets.QTableWidgetItem(str(utxo["prevout_n"]))
            self.utxos_wigdet.setItem(i, 1, vout_item)

            amount_item = QtWidgets.QTableWidgetItem(str(utxo["value"]))
            if utxo["value"] < PROOF_DUST_THRESHOLD:
                amount_item.setForeground(QtGui.QColor("red"))
                amount_item.setToolTip(
                    _(
                        "The minimum threshold for a coin in an avalanche proof is "
                        "1,000,000 XEC."
                    )
                )
            self.utxos_wigdet.setItem(i, 2, amount_item)

            height_item = QtWidgets.QTableWidgetItem(str(utxo["height"]))
            if utxo["height"] <= 0:
                # TODO: make the height cell editable, for users to fill the block
                #       height manually.
                height_item.setForeground(QtGui.QColor("red"))
                height_item.setToolTip(
                    _(
                        "Unconfirmed coins will not be included because the height of the"
                        "block for each coin is required to generate the proof."
                    )
                )
            self.utxos_wigdet.setItem(i, 3, height_item)

        self.generate_button = QtWidgets.QPushButton("Generate proof")
        layout.addWidget(self.generate_button)
        self.generate_button.clicked.connect(self._on_generate_clicked)

        self.proof_display = QtWidgets.QTextEdit()
        self.proof_display.setReadOnly(True)
        layout.addWidget(self.proof_display)

        self.generate_dg_button = Link("Generate a delegation for this proof")
        self.generate_dg_button.setEnabled(False)
        layout.addWidget(self.generate_dg_button)

        # Connect signals
        self.calendar.dateTimeChanged.connect(self.on_datetime_changed)
        self.timestamp_widget.valueChanged.connect(self.on_timestamp_changed)
        self.master_key_edit.textChanged.connect(self.update_master_pubkey)
        self.generate_dg_button.clicked.connect(self.open_dg_dialog)

        # Init widgets
        now = QtCore.QDateTime.currentDateTime()
        self.calendar.setDateTime(now.addYears(1))
        self.dg_dialog = None
        self.update_master_pubkey(self.master_key_edit.text())

    def _get_privkey_suggestion(self) -> str:
        """Get a private key to pre-fill the master key field.
        Return it in WIF format, or return an empty string on failure (pwd dialog
        cancelled).
        """
        wif_pk = ""
        if not self.wallet.has_password() or self.pwd is not None:
            wif_pk = get_privkey_suggestion(self.wallet, key_index=0, pwd=self.pwd)
        return wif_pk

    def on_datetime_changed(self, dt: QtCore.QDateTime):
        """Set the timestamp from a QDateTime"""
        was_blocked = self.blockSignals(True)
        self.timestamp_widget.setValue(dt.toSecsSinceEpoch())
        self.blockSignals(was_blocked)

    def on_timestamp_changed(self, timestamp: float):
        """Set the calendar date from POSIX timestamp"""
        timestamp = int(timestamp)
        was_blocked = self.blockSignals(True)
        self.calendar.setDateTime(QtCore.QDateTime.fromSecsSinceEpoch(timestamp))
        self.blockSignals(was_blocked)

    def update_master_pubkey(self, master_wif: str):
        if is_private_key(master_wif):
            master_pub = Key.from_wif(master_wif).get_pubkey()
            pubkey_str = master_pub.to_hex()
            self.master_pubkey_view.setText(pubkey_str)

    def _on_generate_clicked(self):
        proof = self._build()
        if proof is not None:
            self.proof_display.setText(f'<p style="color:black;"><b>{proof}</b></p>')
            reply = QtWidgets.QMessageBox.question(
                self,
                "Freeze coins",
                "Spending coins that are used as stakes in a proof will invalidate "
                "the proof. Do you want to freeze the corresponding coins to avoid "
                "accidentally spending them?",
                defaultButton=QtWidgets.QMessageBox.Yes,
            )
            utxos_to_freeze = [u for u in self.utxos if u not in self.excluded_utxos]
            if reply == QtWidgets.QMessageBox.Yes:
                self.wallet.set_frozen_coin_state(utxos_to_freeze, freeze=True)
        self.generate_dg_button.setEnabled(proof is not None)

    def _build(self) -> Optional[str]:
        if self.wallet.has_password() and self.pwd is None:
            self.proof_display.setText(
                '<p style="color:red;">Password dialog cancelled!</p>'
            )
            return

        master_wif = self.master_key_edit.text()
        if not is_private_key(master_wif):
            QtWidgets.QMessageBox.critical(
                self, "Invalid private key", "Could not parse private key."
            )
            return
        master = Key.from_wif(master_wif)

        try:
            payout_address = Address.from_string(self.payout_addr_edit.text())
        except AddressError as e:
            QtWidgets.QMessageBox.critical(self, "Invalid payout address", str(e))
            return
        payout_script = payout_address.to_script()

        proofbuilder = ProofBuilder(
            sequence=self.sequence_sb.value(),
            expiration_time=self.calendar.dateTime().toSecsSinceEpoch(),
            master=master,
            payout_script_pubkey=payout_script,
        )

        self.excluded_utxos = []
        for utxo in self.utxos:
            if utxo["height"] <= 0:
                # ignore unconfirmed coins
                self.excluded_utxos.append(utxo)
                continue
            address = utxo["address"]
            if not isinstance(utxo["address"], Address):
                # utxo loaded from JSON file (serialized)
                address = Address.from_string(address)
            priv_key = self.wallet.export_private_key(address, self.pwd)
            proofbuilder.add_utxo(
                txid=UInt256.from_hex(utxo["prevout_hash"]),
                vout=utxo["prevout_n"],
                amount=utxo["value"],
                height=utxo["height"],
                wif_privkey=priv_key,
                is_coinbase=utxo["coinbase"],
            )

        num_utxos_in_proof = len(self.utxos) - len(self.excluded_utxos)
        if num_utxos_in_proof <= 0:
            QtWidgets.QMessageBox.critical(
                self,
                _("No valid stake"),
                _("No valid stake left after excluding unconfirmed coins."),
            )
            return
        if len(self.excluded_utxos) > 0:
            QtWidgets.QMessageBox.warning(
                self,
                _("Excluded stakes"),
                f"{len(self.excluded_utxos)}"
                + " "
                + _(
                    "coins have been excluded from the proof because they are "
                    "unconfirmed or do not have a block height specified."
                ),
            )

        return proofbuilder.build().to_hex()

    def open_dg_dialog(self):
        if self.dg_dialog is None:
            self.dg_dialog = AvaDelegationDialog(self)
        self.dg_dialog.set_proof(self.proof_display.toPlainText())
        self.dg_dialog.set_master(self.master_key_edit.text())
        self.dg_dialog.show()


class AvaProofDialog(QtWidgets.QDialog):
    def __init__(
        self,
        utxos: List[dict],
        wallet: Deterministic_Wallet,
        receive_address: Optional[Address] = None,
        parent: Optional[QtWidgets.QWidget] = None,
    ):
        super().__init__(parent)
        self.setWindowTitle("Build avalanche proof")

        layout = QtWidgets.QVBoxLayout()
        self.setLayout(layout)
        self.proof_widget = AvaProofWidget(utxos, wallet, receive_address, self)
        layout.addWidget(self.proof_widget)

        buttons_layout = QtWidgets.QHBoxLayout()
        layout.addLayout(buttons_layout)
        self.ok_button = QtWidgets.QPushButton("OK")
        buttons_layout.addWidget(self.ok_button)
        self.dismiss_button = QtWidgets.QPushButton("Dismiss")
        buttons_layout.addWidget(self.dismiss_button)

        self.ok_button.clicked.connect(self.accept)
        self.dismiss_button.clicked.connect(self.reject)


class AvaDelegationWidget(QtWidgets.QWidget):
    def __init__(self, parent: QtWidgets.QWidget = None):
        super().__init__(parent)
        self.setMinimumWidth(600)
        self.setMinimumHeight(580)

        self._pwd = None

        layout = QtWidgets.QVBoxLayout()
        self.setLayout(layout)

        self.tab_widget = QtWidgets.QTabWidget()
        layout.addWidget(self.tab_widget)
        layout.addSpacing(10)

        self.proof_edit = QtWidgets.QTextEdit()
        self.proof_edit.setAcceptRichText(False)
        self.proof_edit.setToolTip(
            "Enter a proof in hexadecimal format. A delegation will be generated for "
            "this proof. Specify the proof master key as the delegator key below."
        )
        self.tab_widget.addTab(self.proof_edit, "From a proof")

        self.ltd_id_edit = QtWidgets.QLineEdit()
        self.ltd_id_edit.setToolTip(
            "Enter the proof ID of the proof to be delegated. A delegation will be "
            "generated for the proof corresponding to this ID. "
            "You need to provide this proof's master key as the delegator key (below)."
        )
        self.tab_widget.addTab(self.ltd_id_edit, "From a Limited Proof ID")

        self.dg_edit = QtWidgets.QTextEdit()
        self.dg_edit.setAcceptRichText(False)
        self.dg_edit.setToolTip(
            "Enter an existing delegation to which you want to add another level. "
            "Enter the private key corresponding to this existing delegation's "
            "delegated key as the new delegator key, and specify a new delegated key."
        )
        self.tab_widget.addTab(self.dg_edit, "From an existing delegation")

        layout.addWidget(QtWidgets.QLabel("Delegator key (WIF)"))
        self.delegator_key_edit = QtWidgets.QLineEdit()
        self.delegator_key_edit.setToolTip(
            "Master key of the proof, or private key for the last level of an "
            "existing delegation."
        )
        layout.addWidget(self.delegator_key_edit)
        layout.addSpacing(10)

        layout.addWidget(QtWidgets.QLabel("Delegated public key"))
        self.pubkey_edit = QtWidgets.QLineEdit()
        self.pubkey_edit.setToolTip("The public key to delegate the proof to.")
        layout.addWidget(self.pubkey_edit)
        layout.addSpacing(10)

        self.generate_button = QtWidgets.QPushButton("Generate delegation")
        layout.addWidget(self.generate_button)

        self.dg_display = QtWidgets.QTextEdit()
        self.dg_display.setReadOnly(True)
        layout.addWidget(self.dg_display)

        # Signals
        self.generate_button.clicked.connect(self.on_generate_clicked)

    def set_proof(self, proof_hex: str):
        self.proof_edit.setText(proof_hex)

    def set_master(self, master_wif: str):
        self.delegator_key_edit.setText(master_wif)

    def compute_ltd_id_from_proof(self):
        proof_hex = self.proof_edit.toPlainText()
        try:
            proof = Proof.from_hex(proof_hex)
        except DeserializationError:
            self.ltd_id_edit.setText("")
            self.proof_title_label.setText("Proof ❌")
        else:
            self.ltd_id_edit.setText(proof.limitedid.get_hex())
            self.proof_title_label.setText("Proof ✔")

    def on_generate_clicked(self):
        dg_hex = self._build()
        if dg_hex is not None:
            self.dg_display.setText(f'<p style="color:black;"><b>{dg_hex}</b></p>')

    def _build(self) -> Optional[str]:
        delegator_wif = self.delegator_key_edit.text()
        if not is_private_key(delegator_wif):
            QtWidgets.QMessageBox.critical(
                self, "Invalid private key", "Could not parse private key."
            )
            return
        delegator = Key.from_wif(delegator_wif)

        try:
            delegated_pubkey = PublicKey.from_hex(self.pubkey_edit.text())
        except DeserializationError:
            QtWidgets.QMessageBox.critical(
                self,
                "Invalid delegated pubkey",
                "Could not parse delegated public key.",
            )
            return

        active_tab_widget = self.tab_widget.currentWidget()
        if active_tab_widget is self.ltd_id_edit:
            try:
                ltd_id = LimitedProofId.from_hex(self.ltd_id_edit.text())
            except DeserializationError:
                QtWidgets.QMessageBox.critical(
                    self,
                    "Invalid limited ID",
                    "Could not parse limited ID (not a 32 bytes hex string).",
                )
                return
            dgb = DelegationBuilder(ltd_id, delegator.get_pubkey())
        elif active_tab_widget is self.proof_edit:
            try:
                proof = Proof.from_hex(self.proof_edit.toPlainText())
            except DeserializationError:
                QtWidgets.QMessageBox.critical(
                    self,
                    "Invalid proof",
                    "Could not parse proof. Check the format.",
                )
                return
            dgb = DelegationBuilder.from_proof(proof)
        elif active_tab_widget is self.dg_edit:
            try:
                dg = Delegation.from_hex(self.dg_edit.toPlainText())
            except DeserializationError:
                QtWidgets.QMessageBox.critical(
                    self,
                    "Invalid delegation",
                    "Could not parse delegation. Check the format.",
                )
                return
            dgb = DelegationBuilder.from_delegation(dg)
        else:
            # This should never happen, so we want to hear about it. Catch fire.
            raise RuntimeError("Indeterminate active tab.")

        try:
            dgb.add_level(delegator, delegated_pubkey)
        except WrongDelegatorKeyError:
            QtWidgets.QMessageBox.critical(
                self,
                "Wrong delegator key",
                "The provided delegator key does not match the proof master key or "
                "the previous delegated public key (if adding a level to an existing "
                "delegation).",
            )
            return

        return dgb.build().to_hex()

    def get_delegation(self) -> str:
        """Return delegation, as a hexadecimal string.

        An empty string means the delegation building failed.
        """
        return self.dg_display.toPlainText()


class AvaDelegationDialog(QtWidgets.QDialog):
    def __init__(self, parent: Optional[QtWidgets.QWidget] = None):
        super().__init__(parent)
        self.setWindowTitle("Build avalanche delegation")

        layout = QtWidgets.QVBoxLayout()
        self.setLayout(layout)
        self.dg_widget = AvaDelegationWidget(self)
        layout.addWidget(self.dg_widget)

        buttons_layout = QtWidgets.QHBoxLayout()
        layout.addLayout(buttons_layout)
        self.ok_button = QtWidgets.QPushButton("OK")
        buttons_layout.addWidget(self.ok_button)
        self.dismiss_button = QtWidgets.QPushButton("Dismiss")
        buttons_layout.addWidget(self.dismiss_button)

        self.ok_button.clicked.connect(self.accept)
        self.dismiss_button.clicked.connect(self.reject)

    def set_proof(self, proof_hex: str):
        self.dg_widget.set_proof(proof_hex)

    def set_master(self, master_wif: str):
        self.dg_widget.set_master(master_wif)
