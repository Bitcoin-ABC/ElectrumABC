
from typing import List, Optional

import ecdsa

from PyQt5 import QtWidgets
from PyQt5 import QtCore

from electroncash.avaproof import ProofBuilder
from electroncash.bitcoin import (
    is_private_key,
    deserialize_privkey,
    public_key_from_private_key,
    ser_to_point
)

from .password_dialog import PasswordDialog


class AvaProofWidget(QtWidgets.QWidget):
    def __init__(self, utxos: List[dict], wallet, parent: QtWidgets.QWidget = None):
        """

        :param utxos:  List of UTXOs to be used as stakes
        :param parent:
        """
        super().__init__(parent)
        self.setWindowTitle("Build avalanche proof")
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

        layout.addWidget(QtWidgets.QLabel("Expiration date"))
        expiration_layout = QtWidgets.QHBoxLayout()
        layout.addLayout(expiration_layout)
        self.calendar = QtWidgets.QDateTimeEdit()
        self.calendar.setToolTip("Date and time at which the proof will expire")
        expiration_layout.addWidget(self.calendar)
        # Use a QDoubleSpinbox with precision set to 0 decimals, because
        # QSpinBox is limited to the int32 range (January 19, 2038)
        self.timestamp_widget = QtWidgets.QDoubleSpinBox()
        self.timestamp_widget.setDecimals(0)
        # date range: genesis block to Wed Jun 09 3554 16:53:20 GMT
        self.timestamp_widget.setRange(1231006505, 50**10)
        self.timestamp_widget.setSingleStep(86400)
        self.timestamp_widget.setToolTip(
            "POSIX time, seconds since 1970-01-01T00:00:00")
        expiration_layout.addWidget(self.timestamp_widget)
        layout.addSpacing(10)

        layout.addWidget(
            QtWidgets.QLabel("Master public key (hex) or private key (WIF)"))
        self.master_pubkey_edit = QtWidgets.QLineEdit()
        self.master_pubkey_edit.setToolTip(
            "Public key corresponding to the private key specified for the "
            "node's -avasessionkey parameter."
        )
        layout.addWidget(self.master_pubkey_edit)
        layout.addSpacing(10)

        self.generate_button = QtWidgets.QPushButton("Generate proof")
        layout.addWidget(self.generate_button)
        self.generate_button.clicked.connect(self._on_generate_clicked)

        self.proof_display = QtWidgets.QTextEdit()
        self.proof_display.setReadOnly(True)
        layout.addWidget(self.proof_display)

        # Connect signals
        self.calendar.dateTimeChanged.connect(self.on_datetime_changed)
        self.timestamp_widget.valueChanged.connect(self.on_timestamp_changed)

        # Init widgets
        now = QtCore.QDateTime.currentDateTime()
        self.calendar.setDateTime(now.addYears(1))

    def on_datetime_changed(self, dt: QtCore.QDateTime):
        """Set the timestamp from a QDateTime"""
        was_blocked = self.blockSignals(True)
        self.timestamp_widget.setValue(dt.toSecsSinceEpoch())
        self.blockSignals(was_blocked)

    def on_timestamp_changed(self, timestamp: float):
        """Set the calendar date from POSIX timestamp"""
        timestamp = int(timestamp)
        was_blocked = self.blockSignals(True)
        self.calendar.setDateTime(
            QtCore.QDateTime.fromSecsSinceEpoch(timestamp))
        self.blockSignals(was_blocked)

    def _on_generate_clicked(self):
        proof = self._build()
        if proof is not None:
            self.proof_display.setText(
                f'<p style="color:black;"><b>{proof}</b></p>'
            )

    def _build(self) -> Optional[str]:
        if self._pwd is None and self.wallet.has_password():
            while self.wallet.has_password():
                password = PasswordDialog(parent=self).run()

                if password is None:
                    # User cancelled password input
                    self._pwd = None
                    self.proof_display.setText(
                        f'<p style="color:red;">Password dialog cancelled!</p>')
                    return
                try:
                    self.wallet.check_password(password)
                    break
                except Exception as e:
                    QtWidgets.QMessageBox.critical(
                        self, "Invalid password",
                        str(e)
                    )
                    continue
            self._pwd = password

        master = self.master_pubkey_edit.text()
        if is_private_key(master):
            txin_type, privkey, compressed = deserialize_privkey(master)
            master = public_key_from_private_key(privkey, compressed)
        if not self._validate_pubkey(master):
            return

        proofbuilder = ProofBuilder(
            sequence=self.sequence_sb.value(),
            expiration_time=self.calendar.dateTime().toSecsSinceEpoch(),
            master=master)
        for utxo in self.utxos:
            priv_key = self.wallet.export_private_key(utxo['address'], self._pwd)
            proofbuilder.add_utxo(
                txid=utxo['prevout_hash'],
                vout=utxo['prevout_n'],
                # we need the value in "bitcoins"
                value=utxo['value'] * 10**-8,
                height=utxo['height'],
                wif_privkey=priv_key)
        proof = proofbuilder.build()
        return proof.serialize().hex()

    def _validate_pubkey(self, master: str):
        """A valid public key must be a valid hexadecimal string
        defining a valid point on the SECP256k1 elliptic curve."""
        try:
            key_bytes = bytes.fromhex(master)
        except ValueError:
            self.proof_display.setText(
                f'<p style="color:red;">Master key: invalid hexadecimal</p>')
            return False
        try:
            point = ser_to_point(key_bytes)
            ecdsa.keys.VerifyingKey.from_public_point(
                point, ecdsa.curves.SECP256k1)
        except Exception:
            self.proof_display.setText(
                f'<p style="color:red;">Master key is not a valid public key</p>')
            return False
        return True

    def getProof(self) -> str:
        """Return proof, as a hexadecimal string.

        An empty string means the proof building failed.
        """
        return self.proof_display.toPlainText()


class AvaProofDialog(QtWidgets.QDialog):
    def __init__(self, utxos: List[dict], wallet, parent: Optional[QtWidgets.QWidget] = None):
        super().__init__(parent)

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
