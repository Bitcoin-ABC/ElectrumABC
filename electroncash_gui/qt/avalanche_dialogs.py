from __future__ import annotations

import json
from dataclasses import dataclass
from typing import TYPE_CHECKING, List, Optional, Union

from PyQt5 import QtCore, QtGui, QtWidgets

from electroncash import address
from electroncash.address import Address, AddressError
from electroncash.avalanche.delegation import (
    Delegation,
    DelegationBuilder,
    WrongDelegatorKeyError,
)
from electroncash.avalanche.primitives import COutPoint, Key, PublicKey
from electroncash.avalanche.proof import (
    LimitedProofId,
    Proof,
    ProofBuilder,
    SignedStake,
    Stake,
)
from electroncash.avalanche.serialize import DeserializationError
from electroncash.bitcoin import is_private_key
from electroncash.constants import PROOF_DUST_THRESHOLD, STAKE_UTXO_CONFIRMATIONS
from electroncash.i18n import _
from electroncash.uint256 import UInt256
from electroncash.util import format_satoshis
from electroncash.wallet import AddressNotFoundError

from .password_dialog import PasswordDialog

if TYPE_CHECKING:
    from electroncash.wallet import Deterministic_Wallet


@dataclass
class StakeAndKey:
    """Class storing a stake waiting to be signed (waiting for the stake commitment)"""

    stake: stake
    key: Key


# We generate a few deterministic private keys to pre-fill some widgets, so the user
# does not need to use an external tool or a dummy wallet to generate keys.
# TODO: don't always use the same keys, increment the index as needed (requires saving
#       the index or the generated keys to the wallet file)
_PROOF_MASTER_KEY_INDEX = 0
_DELEGATED_KEY_INDEX = 1


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


class AvaProofEditor(CachedWalletPasswordWidget):
    def __init__(
        self,
        wallet: Deterministic_Wallet,
        receive_address: Optional[Address] = None,
        parent: QtWidgets.QWidget = None,
    ):
        CachedWalletPasswordWidget.__init__(self, wallet, parent=parent)
        # This is enough width to show a whole compressed pubkey.
        self.setMinimumWidth(750)
        # Enough height to show the entire proof without scrolling.
        self.setMinimumHeight(680)

        self.stakes: List[Union[SignedStake, StakeAndKey]] = []
        self.receive_address = receive_address

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

        self.expiration_checkbox = QtWidgets.QCheckBox("Enable proof expiration")
        self.expiration_checkbox.setChecked(True)
        expiration_layout.addWidget(self.expiration_checkbox)

        expiration_date_sublayout = QtWidgets.QVBoxLayout()
        expiration_layout.addLayout(expiration_date_sublayout)
        expiration_date_sublayout.addWidget(QtWidgets.QLabel("Expiration date"))
        self.calendar = QtWidgets.QDateTimeEdit()
        self.calendar.setToolTip("Date and time at which the proof will expire")
        expiration_date_sublayout.addWidget(self.calendar)

        expiration_timestamp_sublayout = QtWidgets.QVBoxLayout()
        expiration_layout.addLayout(expiration_timestamp_sublayout)
        expiration_timestamp_sublayout.addWidget(
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
        expiration_timestamp_sublayout.addWidget(self.timestamp_widget)
        layout.addSpacing(10)

        layout.addWidget(QtWidgets.QLabel("Master private key (WIF)"))
        self.master_key_edit = QtWidgets.QLineEdit()
        self.master_key_edit.setToolTip(
            "Private key that controls the proof. This is the key that signs the "
            "delegation or signs the avalanche votes."
        )
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
        layout.addWidget(self.payout_addr_edit)
        layout.addSpacing(10)

        self.utxos_wigdet = QtWidgets.QTableWidget()
        self.utxos_wigdet.setColumnCount(4)
        self.utxos_wigdet.setHorizontalHeaderLabels(
            ["txid", "vout", "amount (sats)", "block height"]
        )
        self.utxos_wigdet.verticalHeader().setVisible(False)
        self.utxos_wigdet.setSelectionMode(QtWidgets.QTableWidget.NoSelection)
        self.utxos_wigdet.horizontalHeader().setSectionResizeMode(
            0, QtWidgets.QHeaderView.Stretch
        )
        layout.addWidget(self.utxos_wigdet)

        self.add_coins_button = QtWidgets.QPushButton("Add coins from file")
        layout.addWidget(self.add_coins_button, alignment=QtCore.Qt.AlignLeft)

        self.generate_button = QtWidgets.QPushButton("Generate proof")
        layout.addWidget(self.generate_button)
        self.generate_button.clicked.connect(self._on_generate_clicked)

        self.proof_display = QtWidgets.QTextEdit()
        self.proof_display.setReadOnly(True)
        layout.addWidget(self.proof_display)

        proof_buttons_layout = QtWidgets.QHBoxLayout()
        layout.addLayout(proof_buttons_layout)

        self.load_proof_button = QtWidgets.QPushButton("Load proof")
        self.load_proof_button.setToolTip("Load a proof from a .proof file.")
        proof_buttons_layout.addWidget(self.load_proof_button)

        self.save_proof_button = QtWidgets.QPushButton("Save proof")
        self.save_proof_button.setToolTip("Save this proof to a .proof file.")
        self.save_proof_button.setEnabled(False)
        proof_buttons_layout.addWidget(self.save_proof_button)

        self.generate_dg_button = QtWidgets.QPushButton("Generate a delegation")
        self.generate_dg_button.setEnabled(False)
        proof_buttons_layout.addWidget(self.generate_dg_button)

        # Connect signals
        self.expiration_checkbox.toggled.connect(self.on_expiration_cb_toggled)
        self.calendar.dateTimeChanged.connect(self.on_datetime_changed)
        self.timestamp_widget.valueChanged.connect(self.on_timestamp_changed)
        self.master_key_edit.textChanged.connect(self.update_master_pubkey)
        self.add_coins_button.clicked.connect(self.on_add_coins_clicked)
        self.generate_dg_button.clicked.connect(self.open_dg_dialog)
        self.load_proof_button.clicked.connect(self.on_load_proof_clicked)
        self.save_proof_button.clicked.connect(self.on_save_proof_clicked)

        # Init widgets
        self.dg_dialog = None
        self.init_data()

    def init_data(self):
        # Clear internal state
        self.stakes.clear()

        self.sequence_sb.setValue(0)

        # Set a default expiration date
        self.expiration_checkbox.setChecked(True)
        now = QtCore.QDateTime.currentDateTime()
        self.calendar.setDateTime(now.addYears(3))

        self.master_pubkey_view.setText("")
        # Suggest a private key to the user. He can change it if he wants.
        self.master_key_edit.setText(self._get_privkey_suggestion())

        if self.receive_address is not None:
            self.payout_addr_edit.setText(self.receive_address.to_ui_string())

        self.utxos_wigdet.clearContents()
        self.proof_display.setText("")

    def add_utxos(self, utxos: List[dict]):
        """Add UTXOs from a list of dict objects, such as stored internally by
        the wallet or loaded from a JSON file. These UTXOs must belong to the current
        wallet, as they are not yet signed.
        They must also be confirmed (i.e. have a block height number).
        """
        unconfirmed_count = 0
        stakes = []
        for utxo in utxos:
            height = utxo["height"]
            if height <= 0:
                unconfirmed_count += 1
                continue

            address = utxo["address"]
            if not isinstance(utxo["address"], Address):
                # utxo loaded from JSON file (serialized)
                address = Address.from_string(address)
            txid = UInt256.from_hex(utxo["prevout_hash"])

            try:
                wif_key = self.wallet.export_private_key(address, self.pwd)
                key = Key.from_wif(wif_key)
            except AddressNotFoundError:
                QtWidgets.QMessageBox.critical(
                    self,
                    _("Missing key or signature"),
                    f'UTXO {utxo["prevout_hash"]}:{utxo["prevout_n"]} with address '
                    f"{address.to_ui_string()} does not belong to this wallet.",
                )
                return

            stakes.append(
                StakeAndKey(
                    Stake(
                        COutPoint(txid, utxo["prevout_n"]),
                        amount=utxo["value"],
                        height=utxo["height"],
                        pubkey=key.get_pubkey(),
                        is_coinbase=utxo["coinbase"],
                    ),
                    key,
                )
            )

        if unconfirmed_count:
            QtWidgets.QMessageBox.warning(
                self,
                _("Excluded coins"),
                f"{unconfirmed_count} coins have been ignored because they are "
                f"unconfirmed or do not have a block height specified.",
            )

        self.add_stakes(stakes)

    def add_stakes(self, stakes: List[Union[SignedStake, StakeAndKey]]):
        previous_utxo_count = len(self.stakes)
        self.stakes += stakes
        self.utxos_wigdet.setRowCount(len(self.stakes))

        tip = self.wallet.get_local_height()
        for i, ss in enumerate(stakes):
            stake = ss.stake
            height = stake.height

            row_index = previous_utxo_count + i
            txid_item = QtWidgets.QTableWidgetItem(stake.utxo.txid.get_hex())
            self.utxos_wigdet.setItem(row_index, 0, txid_item)

            vout_item = QtWidgets.QTableWidgetItem(str(stake.utxo.n))
            self.utxos_wigdet.setItem(row_index, 1, vout_item)

            amount_item = QtWidgets.QTableWidgetItem(str(stake.amount))
            if stake.amount < PROOF_DUST_THRESHOLD:
                amount_item.setForeground(QtGui.QColor("red"))
                amount_item.setToolTip(
                    _(
                        f"The minimum threshold for a coin in an avalanche proof is "
                        f"{format_satoshis(PROOF_DUST_THRESHOLD)} XEC."
                    )
                )
            self.utxos_wigdet.setItem(row_index, 2, amount_item)

            height_item = QtWidgets.QTableWidgetItem(str(height))
            utxo_validity_height = height + STAKE_UTXO_CONFIRMATIONS
            if utxo_validity_height > tip:
                height_item.setForeground(QtGui.QColor("orange"))
                height_item.setToolTip(
                    _(
                        f"UTXOs with less than {STAKE_UTXO_CONFIRMATIONS} "
                        "confirmations cannot be used as stake proofs."
                    )
                    + f"\nCurrent known block height is {tip}.\nYour proof will be "
                    f"valid after block {utxo_validity_height}."
                )
            self.utxos_wigdet.setItem(row_index, 3, height_item)

    def _get_privkey_suggestion(self) -> str:
        """Get a private key to pre-fill the master key field.
        Return it in WIF format, or return an empty string on failure (pwd dialog
        cancelled).
        """
        if not self.wallet.is_deterministic() or not self.wallet.can_export():
            return ""
        wif_pk = ""
        if not self.wallet.has_password() or self.pwd is not None:
            wif_pk = get_privkey_suggestion(
                self.wallet, key_index=_PROOF_MASTER_KEY_INDEX, pwd=self.pwd
            )
        return wif_pk

    def on_expiration_cb_toggled(self, is_checked: bool):
        self.timestamp_widget.setEnabled(is_checked)
        self.calendar.setEnabled(is_checked)

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

    def on_add_coins_clicked(self):
        fileName, __ = QtWidgets.QFileDialog.getOpenFileName(
            self,
            "Select the file containing the data for coins to be used as stakes",
            filter="JSON (*.json);;All files (*)",
        )

        if not fileName:
            return
        with open(fileName, "r", encoding="utf-8") as f:
            utxos = json.load(f)
        if utxos is None:
            return
        self.add_utxos(utxos)

    def on_load_proof_clicked(self):
        reply = QtWidgets.QMessageBox.question(
            self,
            "Overwrite current proof data",
            "Loading a proof will overwrite all data. Do you confirm?",
            defaultButton=QtWidgets.QMessageBox.Yes,
        )
        if reply != QtWidgets.QMessageBox.Yes:
            return
        fileName, __ = QtWidgets.QFileDialog.getOpenFileName(
            self,
            "Select the proof file",
            filter="Avalanche proof (*.proof);;All files (*)",
        )
        if not fileName:
            return
        with open(fileName, "r") as f:
            proof_hex = f.read().strip()
        # TODO: catch all possible proof & hex format errors
        self.load_proof(Proof.from_hex(proof_hex))

        self.generate_dg_button.setEnabled(True)
        self.save_proof_button.setEnabled(True)

    def load_proof(self, proof: Proof):
        known_keys = []
        if self._get_privkey_suggestion():
            known_keys.append(self._get_privkey_suggestion())
        if is_private_key(self.master_key_edit.text()):
            known_keys.append(self.master_key_edit.text())
        self.init_data()

        self.sequence_sb.setValue(proof.sequence)
        if proof.expiration_time <= 0:
            self.expiration_checkbox.setChecked(False)
        else:
            self.timestamp_widget.setValue(proof.expiration_time)

        self.master_key_edit.setText("")
        for wif_key in known_keys:
            if Key.from_wif(wif_key).get_pubkey() == proof.master_pub:
                self.master_key_edit.setText(wif_key)
                break
        else:
            QtWidgets.QMessageBox.warning(
                self,
                "Missing private key",
                "Unable to guess private key associated with this proof's public key. "
                "Please fill it manually.",
            )
        self.master_pubkey_view.setText(proof.master_pub.to_hex())
        self.add_stakes(proof.signed_stakes)

        self.proof_display.setText(
            f'<p style="color:black;"><b>{proof.to_hex()}</b></p>'
        )

    def on_save_proof_clicked(self):
        if not self.proof_display.toPlainText():
            raise AssertionError(
                "No proof to be saved. The save button should not be enabled."
            )
        proof = Proof.from_hex(self.proof_display.toPlainText())
        fileName, __ = QtWidgets.QFileDialog.getSaveFileName(
            self,
            "Save proof to file",
            f"{proof.proofid.get_hex()[:8]}.proof",
            filter="Avalanche proof (*.proof);;All files (*)",
        )
        if not fileName:
            return
        with open(fileName, "w") as f:
            f.write(proof.to_hex())

    def update_master_pubkey(self, master_wif: str):
        if is_private_key(master_wif):
            master_pub = Key.from_wif(master_wif).get_pubkey()
            pubkey_str = master_pub.to_hex()
            self.master_pubkey_view.setText(pubkey_str)

    def _on_generate_clicked(self):
        proof = self._build()
        if proof is not None:
            self.proof_display.setText(f'<p style="color:black;"><b>{proof}</b></p>')
        self.generate_dg_button.setEnabled(proof is not None)
        self.save_proof_button.setEnabled(proof is not None)

    def _build(self) -> Optional[str]:
        master_wif = self.master_key_edit.text()
        if not is_private_key(master_wif):
            reply = QtWidgets.QMessageBox.question(
                self,
                "Invalid private key",
                "Could not parse private key. Do you want to generate a proof with an "
                "invalid signature anyway?",
            )
            if reply != QtWidgets.QMessageBox.Yes:
                return
            master = None
            master_pub = PublicKey.from_hex(self.master_pubkey_view.text())
        else:
            master = Key.from_wif(master_wif)
            master_pub = None

        try:
            payout_address = Address.from_string(self.payout_addr_edit.text())
        except AddressError as e:
            QtWidgets.QMessageBox.critical(self, "Invalid payout address", str(e))
            return

        if self.wallet.has_password() and self.pwd is None:
            self.proof_display.setText(
                '<p style="color:red;">Password dialog cancelled!</p>'
            )
            return
        expiration_time = (
            0
            if not self.expiration_checkbox.isChecked()
            else self.calendar.dateTime().toSecsSinceEpoch()
        )
        proofbuilder = ProofBuilder(
            sequence=self.sequence_sb.value(),
            expiration_time=expiration_time,
            payout_address=payout_address,
            master=master,
            master_pub=master_pub,
        )

        for ss in self.stakes:
            if isinstance(ss, StakeAndKey):
                proofbuilder.sign_and_add_stake(ss.stake, ss.key)
            else:
                proofbuilder.add_signed_stake(ss)

        return proofbuilder.build().to_hex()

    def open_dg_dialog(self):
        if self.dg_dialog is None:
            self.dg_dialog = AvaDelegationDialog(self.wallet, self.pwd, self)
        self.dg_dialog.set_proof(self.proof_display.toPlainText())
        self.dg_dialog.set_master(self.master_key_edit.text())
        self.dg_dialog.show()


class AvaProofDialog(QtWidgets.QDialog):
    def __init__(
        self,
        wallet: Deterministic_Wallet,
        receive_address: Optional[Address] = None,
        parent: Optional[QtWidgets.QWidget] = None,
    ):
        super().__init__(parent)
        self.setWindowTitle("Avalanche proof editor")

        layout = QtWidgets.QVBoxLayout()
        self.setLayout(layout)
        self.proof_widget = AvaProofEditor(wallet, receive_address, self)
        layout.addWidget(self.proof_widget)

        buttons_layout = QtWidgets.QHBoxLayout()
        layout.addLayout(buttons_layout)
        self.ok_button = QtWidgets.QPushButton("OK")
        buttons_layout.addWidget(self.ok_button)
        self.dismiss_button = QtWidgets.QPushButton("Dismiss")
        buttons_layout.addWidget(self.dismiss_button)

        self.ok_button.clicked.connect(self.accept)
        self.dismiss_button.clicked.connect(self.reject)

    def add_utxos(self, utxos: List[dict]) -> bool:
        if not self.check_utxos(utxos):
            return False
        self.proof_widget.add_utxos(utxos)
        return True

    def check_utxos(self, utxos: List[dict]) -> bool:
        """Check utxos are usable for avalanche proofs.
        If they aren't, and the user has not acknowledged that he wants to build the
        proof anyway, return False.
        """
        if any(u["value"] < PROOF_DUST_THRESHOLD for u in utxos):
            warning_dialog = StakeDustThresholdMessageBox(self)
            warning_dialog.exec_()
            if warning_dialog.has_cancelled():
                return False
        return True


class AvaDelegationWidget(CachedWalletPasswordWidget):
    def __init__(
        self,
        wallet: Deterministic_Wallet,
        pwd: Optional[str] = None,
        parent: Optional[QtWidgets.QWidget] = None,
    ):
        super().__init__(wallet, pwd, parent)
        self.setMinimumWidth(750)
        self.setMinimumHeight(580)

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
        delegated_key_layout = QtWidgets.QHBoxLayout()
        self.pubkey_edit = QtWidgets.QLineEdit()
        self.pubkey_edit.setToolTip("The public key to delegate the proof to.")
        delegated_key_layout.addWidget(self.pubkey_edit)
        generate_key_button = QtWidgets.QPushButton("Generate key")
        delegated_key_layout.addWidget(generate_key_button)
        layout.addLayout(delegated_key_layout)
        layout.addSpacing(10)

        self.generate_button = QtWidgets.QPushButton("Generate delegation")
        layout.addWidget(self.generate_button)

        self.dg_display = QtWidgets.QTextEdit()
        self.dg_display.setReadOnly(True)
        layout.addWidget(self.dg_display)

        # Signals
        self.dg_edit.textChanged.connect(self.on_delegation_pasted)
        generate_key_button.clicked.connect(self.on_generate_key_clicked)
        self.generate_button.clicked.connect(self.on_generate_clicked)

    def set_proof(self, proof_hex: str):
        self.proof_edit.setText(proof_hex)

    def set_master(self, master_wif: str):
        self.delegator_key_edit.setText(master_wif)

    def on_delegation_pasted(self):
        """Deserialize the delegation to be used as a base delegation to which a level
        is to be added. Find the delegated pubkey and check whether this is an auxiliary
        key from this wallet. If it is, prefill the Delegator key field with the private
        key.
        """
        try:
            dg = Delegation.from_hex(self.dg_edit.toPlainText())
        except DeserializationError:
            return
        dg_pubkey = dg.get_delegated_public_key()
        # Mind the type difference between PublicKey returned by
        # Delegation.get_delegated_public_key and PublicKey used by Wallet.
        idx = self.wallet.get_auxiliary_pubkey_index(
            address.PublicKey.from_pubkey(dg_pubkey.keydata),
            self.pwd,
        )
        if idx is not None:
            self.delegator_key_edit.setText(
                self.wallet.export_private_key_for_index((2, idx), self.pwd)
            )

    def on_generate_key_clicked(self):
        """Open a dialog to show a private/public key pair to be used as delegated key.
        Fill the delegated public key widget with the resulting public key.
        """
        if not self.wallet.is_deterministic() or not self.wallet.can_export():
            return
        wif_pk = ""
        if not self.wallet.has_password() or self.pwd is not None:
            wif_pk = get_privkey_suggestion(
                self.wallet,
                key_index=_DELEGATED_KEY_INDEX,
                pwd=self.pwd,
            )
        if not wif_pk:
            # This should only happen if the pwd dialog was cancelled
            self.pubkey_edit.setText("")
            return
        QtWidgets.QMessageBox.information(
            self,
            "Delegated key",
            f"Please save the following private key:<br><b>{wif_pk}</b><br><br>"
            f"You will need it to use your delegation with a Bitcoin ABC node.",
        )
        self.pubkey_edit.setText(Key.from_wif(wif_pk).get_pubkey().to_hex())

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
    def __init__(
        self,
        wallet: Deterministic_Wallet,
        pwd: Optional[str] = None,
        parent: Optional[QtWidgets.QWidget] = None,
    ):
        super().__init__(parent)
        self.setWindowTitle("Build avalanche delegation")

        layout = QtWidgets.QVBoxLayout()
        self.setLayout(layout)
        self.dg_widget = AvaDelegationWidget(wallet, pwd, parent)
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


class StakeDustThresholdMessageBox(QtWidgets.QMessageBox):
    """QMessageBox question dialog with custom buttons."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setIcon(QtWidgets.QMessageBox.Warning)
        self.setWindowTitle(_("Coins below the stake dust threshold"))
        self.setText(
            _(
                f"The value of one or more coins is below the {format_satoshis(PROOF_DUST_THRESHOLD)} XEC stake "
                f"minimum threshold. The generated proof will be invalid."
            )
        )

        self.setStandardButtons(QtWidgets.QMessageBox.Ok | QtWidgets.QMessageBox.Cancel)
        ok_button = self.button(QtWidgets.QMessageBox.Ok)
        ok_button.setText(_("Continue, I'm just testing"))

        self.cancel_button = self.button(QtWidgets.QMessageBox.Cancel)
        self.setEscapeButton(self.cancel_button)

    def has_cancelled(self) -> bool:
        return self.clickedButton() == self.cancel_button
