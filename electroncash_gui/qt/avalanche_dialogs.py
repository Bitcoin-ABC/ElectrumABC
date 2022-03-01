from typing import List, Optional

from PyQt5 import QtCore, QtWidgets

from electroncash.address import Address, AddressError
from electroncash.avalanche.delegation import Delegation, DelegationBuilder
from electroncash.avalanche.primitives import Key, PublicKey
from electroncash.avalanche.proof import LimitedProofId, Proof, ProofBuilder
from electroncash.avalanche.serialize import DeserializationError
from electroncash.bitcoin import is_private_key
from electroncash.uint256 import UInt256

from .password_dialog import PasswordDialog


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


class AvaProofWidget(QtWidgets.QWidget):
    def __init__(self, utxos: List[dict], wallet, parent: QtWidgets.QWidget = None):
        """

        :param utxos:  List of UTXOs to be used as stakes
        :param parent:
        """
        super().__init__(parent)
        # This is enough width to show a whole compressed pubkey.
        self.setMinimumWidth(600)
        # Enough height to show the entire proof without scrolling.
        self.setMinimumHeight(580)

        self.utxos = utxos
        self.wallet = wallet
        self._pwd = None

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
        self.timestamp_widget.setRange(1231006505, 50 ** 10)
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
        layout.addWidget(self.master_key_edit)
        layout.addSpacing(10)

        layout.addWidget(QtWidgets.QLabel("Payout address"))
        self.payout_addr_edit = QtWidgets.QLineEdit()
        self.payout_addr_edit.setToolTip(
            "Address to which staking rewards could be sent, in the future"
        )
        layout.addWidget(self.payout_addr_edit)
        layout.addSpacing(10)

        self.utxos_wigdet = QtWidgets.QTableWidget(len(utxos), 3)
        self.utxos_wigdet.setHorizontalHeaderLabels(["txid", "vout", "amount"])
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
            self.utxos_wigdet.setItem(i, 2, amount_item)

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
        self.generate_dg_button.clicked.connect(self.open_dg_dialog)

        # Init widgets
        now = QtCore.QDateTime.currentDateTime()
        self.calendar.setDateTime(now.addYears(1))
        self.dg_dialog = None

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

    def _on_generate_clicked(self):
        proof = self._build()
        if proof is not None:
            self.proof_display.setText(f'<p style="color:black;"><b>{proof}</b></p>')
        self.generate_dg_button.setEnabled(proof is not None)

    def _build(self) -> Optional[str]:
        if self._pwd is None and self.wallet.has_password():
            while self.wallet.has_password():
                password = PasswordDialog(parent=self).run()

                if password is None:
                    # User cancelled password input
                    self._pwd = None
                    self.proof_display.setText(
                        '<p style="color:red;">Password dialog cancelled!</p>'
                    )
                    return
                try:
                    self.wallet.check_password(password)
                    break
                except Exception as e:
                    QtWidgets.QMessageBox.critical(self, "Invalid password", str(e))
                    continue
            self._pwd = password

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
        for utxo in self.utxos:
            address = utxo["address"]
            if not isinstance(utxo["address"], Address):
                # utxo loaded from JSON file (serialized)
                address = Address.from_string(address)
            priv_key = self.wallet.export_private_key(address, self._pwd)
            proofbuilder.add_utxo(
                txid=UInt256.from_hex(utxo["prevout_hash"]),
                vout=utxo["prevout_n"],
                # we need the value in "bitcoins"
                amount=utxo["value"],
                height=utxo["height"],
                wif_privkey=priv_key,
                is_coinbase=utxo["coinbase"],
            )
        return proofbuilder.build().to_hex()

    def open_dg_dialog(self):
        if self.dg_dialog is None:
            self.dg_dialog = AvaDelegationDialog()
        self.dg_dialog.set_proof(self.proof_display.toPlainText())
        self.dg_dialog.set_master(self.master_key_edit.text())
        self.dg_dialog.show()


class AvaProofDialog(QtWidgets.QDialog):
    def __init__(
        self, utxos: List[dict], wallet, parent: Optional[QtWidgets.QWidget] = None
    ):
        super().__init__(parent)
        self.setWindowTitle("Build avalanche proof")

        layout = QtWidgets.QVBoxLayout()
        self.setLayout(layout)
        self.proof_widget = AvaProofWidget(utxos, wallet, self)
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
        master_wif = self.delegator_key_edit.text()
        if not is_private_key(master_wif):
            QtWidgets.QMessageBox.critical(
                self, "Invalid private key", "Could not parse private key."
            )
            return
        master = Key.from_wif(master_wif)

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
            dgb = DelegationBuilder(ltd_id, master.get_pubkey())
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

        dgb.add_level(master, delegated_pubkey)
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
