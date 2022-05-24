#!/usr/bin/env python3
#
# Electrum ABC - lightweight eCash client
# Copyright (C) 2022 The Electrum ABC developers
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
from __future__ import annotations

from typing import Optional

from PyQt5 import QtCore, QtWidgets


class InvoiceDialog(QtWidgets.QDialog):
    def __init__(self, parent: Optional[QtWidgets.QWidget] = None):
        super().__init__(parent)

        layout = QtWidgets.QVBoxLayout()
        self.setLayout(layout)

        layout.addWidget(QtWidgets.QLabel("Payment address"))
        self.address_edit = QtWidgets.QLineEdit()
        layout.addWidget(self.address_edit)
        layout.addSpacing(10)

        self.amount_currency_edit = AmountCurrencyEdit()
        layout.addWidget(self.amount_currency_edit)
        layout.addSpacing(10)

        self.exchange_rate_widget = ExchangeRateWidget()
        layout.addWidget(self.exchange_rate_widget)
        layout.addSpacing(10)

        # Trigger callback to init widgets
        self._on_currency_changed(self.amount_currency_edit.get_currency())

        # signals
        self.amount_currency_edit.currencyChanged.connect(self._on_currency_changed)

    def _on_currency_changed(self, currency: str):
        self.exchange_rate_widget.setVisible(currency.lower() != "xec")
        self.exchange_rate_widget.setCurrency(currency)


class AmountCurrencyEdit(QtWidgets.QWidget):
    currencyChanged = QtCore.pyqtSignal(str)

    def __init__(self, parent: Optional[QtWidgets.QWidget] = None):
        super().__init__(parent)
        layout = QtWidgets.QVBoxLayout()
        self.setLayout(layout)

        layout.addWidget(QtWidgets.QLabel("Amount"))
        amount_layout = QtWidgets.QHBoxLayout()
        self.amount_edit = QtWidgets.QDoubleSpinBox()
        self.amount_edit.setStepType(QtWidgets.QAbstractSpinBox.AdaptiveDecimalStepType)
        self.amount_edit.setDecimals(2)
        self.amount_edit.setRange(0, 10**100)
        amount_layout.addWidget(self.amount_edit)

        self.currency_edit = QtWidgets.QComboBox()
        self.currency_edit.addItems(["XEC", "USD", "EUR"])
        self.currency_edit.setCurrentText("XEC")
        self.currency_edit.setEditable(True)
        amount_layout.addWidget(self.currency_edit)
        layout.addLayout(amount_layout)

        self.currency_edit.currentTextChanged.connect(self.currencyChanged.emit)

    def get_currency(self) -> str:
        return self.currency_edit.currentText()


class ExchangeRateWidget(QtWidgets.QWidget):
    def __init__(self, parent: Optional[QtWidgets.QWidget] = None):
        super().__init__(parent)
        layout = QtWidgets.QVBoxLayout()
        self.setLayout(layout)

        fixed_rate_layout = QtWidgets.QHBoxLayout()
        layout.addLayout(fixed_rate_layout)
        self.fixed_rate_rb = QtWidgets.QRadioButton("Fixed rate")
        fixed_rate_layout.addWidget(self.fixed_rate_rb)
        self.rate_edit = QtWidgets.QDoubleSpinBox()
        self.rate_edit.setDecimals(8)
        self.rate_edit.setRange(10**-8, 10**100)
        self.rate_edit.setStepType(QtWidgets.QAbstractSpinBox.AdaptiveDecimalStepType)
        self.rate_edit.setValue(1.0)
        fixed_rate_layout.addWidget(self.rate_edit)

    def setCurrency(self, currency: str):
        self.fixed_rate_rb.setText(f"Fixed rate ({currency}/XEC)")


if __name__ == "__main__":
    app = QtWidgets.QApplication([])
    w = InvoiceDialog()
    w.show()
    app.exec_()
