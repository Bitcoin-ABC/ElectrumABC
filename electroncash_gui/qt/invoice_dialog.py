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

import json
from typing import List, Optional, Type

from PyQt5 import QtCore, QtWidgets

from electroncash.address import Address, AddressError


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

        layout.addStretch(1)
        buttons_layout = QtWidgets.QHBoxLayout()
        layout.addLayout(buttons_layout)

        self.save_button = QtWidgets.QPushButton("Save invoice")
        buttons_layout.addWidget(self.save_button)
        self.load_button = QtWidgets.QPushButton("Load invoice")
        buttons_layout.addWidget(self.load_button)

        # Trigger callback to init widgets
        self._on_currency_changed(self.amount_currency_edit.get_currency())

        # signals
        self.amount_currency_edit.currencyChanged.connect(self._on_currency_changed)
        self.save_button.clicked.connect(self._on_save_clicked)
        self.load_button.clicked.connect(self._on_load_clicked)

    def _on_currency_changed(self, currency: str):
        self.exchange_rate_widget.setVisible(currency.lower() != "xec")
        self.exchange_rate_widget.set_currency(currency)

    def _on_save_clicked(self):
        filename, _selected_filter = QtWidgets.QFileDialog.getSaveFileName(
            self,
            "Save invoice to file",
            filter="JSON file (*.json);;All files (*)",
        )

        if not filename:
            return

        params_dict = self.get_params_dict()
        if not params_dict:
            return

        with open(filename, "w") as f:
            json.dump(self.get_params_dict(), f, indent=4)

    def get_payment_address(self) -> str:
        address_string = self.address_edit.text().strip()
        try:
            Address.from_string(address_string)
        except AddressError:
            QtWidgets.QMessageBox.critical(
                self, "Invalid payment address", "Unable to decode payement address"
            )
            return ""
        return address_string

    def get_params_dict(self) -> dict:
        payment_address = self.get_payment_address()
        if not payment_address:
            return {}

        currency = self.amount_currency_edit.get_currency()

        out = {
            "invoice": {
                "address": payment_address,
                "amount": self.amount_currency_edit.get_amount_as_string(),
                "currency": currency,
            }
        }
        if currency.lower() == "xec":
            return out

        if self.exchange_rate_widget.is_fixed_rate():
            out["invoice"][
                "exchangeRate"
            ] = self.exchange_rate_widget.get_exchange_rate()
            return out

        out["invoice"]["exchangeRateAPI"] = {
            "url": self.exchange_rate_widget.api_widget.get_url(),
            "keys": self.exchange_rate_widget.api_widget.get_keys(),
        }
        return out

    def _on_load_clicked(self):
        pass


class AmountCurrencyEdit(QtWidgets.QWidget):
    currencyChanged = QtCore.pyqtSignal(str)

    def __init__(self, parent: Optional[QtWidgets.QWidget] = None):
        super().__init__(parent)
        layout = QtWidgets.QVBoxLayout()
        self.setLayout(layout)
        layout.setContentsMargins(0, 0, 0, 0)

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

    def get_amount_as_string(self) -> str:
        return f"{self.amount_edit.value():.2f}"


class ExchangeRateWidget(QtWidgets.QWidget):
    def __init__(self, parent: Optional[QtWidgets.QWidget] = None):
        super().__init__(parent)
        layout = QtWidgets.QVBoxLayout()
        self.setLayout(layout)
        layout.setContentsMargins(0, 0, 0, 0)

        layout.addWidget(QtWidgets.QLabel("Exchange rate"))
        fixed_rate_layout = QtWidgets.QHBoxLayout()
        layout.addLayout(fixed_rate_layout)
        self.fixed_rate_rb = QtWidgets.QRadioButton("Fixed rate")
        fixed_rate_layout.addWidget(self.fixed_rate_rb)
        self.rate_edit = QtWidgets.QDoubleSpinBox()
        self.rate_edit.setDecimals(8)
        self.rate_edit.setRange(10**-8, 10**100)
        self.rate_edit.setStepType(QtWidgets.QAbstractSpinBox.AdaptiveDecimalStepType)
        fixed_rate_layout.addWidget(self.rate_edit)

        api_rate_layout = QtWidgets.QVBoxLayout()
        layout.addLayout(api_rate_layout)
        self.api_rate_rb = QtWidgets.QRadioButton("Fetch the rate at payment time")
        api_rate_layout.addWidget(self.api_rate_rb)

        self.api_widget = ExchangeRateAPIWidget()
        margins = self.api_widget.contentsMargins()
        margins.setLeft(margins.left() + 10)
        self.api_widget.setContentsMargins(margins)

        api_rate_layout.addWidget(self.api_widget)

        # Signals
        self.api_rate_rb.toggled.connect(self._on_api_rate_clicked)

        # Default state
        # Use an exclusive button group to disallow unckecking the check radio button
        self._button_group = QtWidgets.QButtonGroup()
        self._button_group.setExclusive(True)
        self._button_group.addButton(self.fixed_rate_rb)
        self._button_group.addButton(self.api_rate_rb)

        self.api_widget.setVisible(False)
        self.fixed_rate_rb.setChecked(True)
        self.rate_edit.setValue(1.0)

    def set_currency(self, currency: str):
        self.fixed_rate_rb.setText(f"Fixed rate ({currency}/XEC)")
        self.api_widget.set_currency(currency)

    def _on_api_rate_clicked(self, is_checked: bool):
        self.api_widget.setVisible(is_checked)

    def is_fixed_rate(self) -> bool:
        return self.fixed_rate_rb.isChecked()

    def get_exchange_rate(self) -> str:
        return f"{self.rate_edit.value():.8f}"


class ExchangeRateAPI:
    def __init__(self, currency: str):
        self._currency = currency
        self.url: str = ""
        self.keys: List[str] = []


class CoingeckoAPI1(ExchangeRateAPI):
    def __init__(self, currency: str):
        super().__init__(currency)
        self.url = f"https://api.coingecko.com/api/v3/simple/price?ids=ecash&vs_currencies={currency.lower()}"
        self.keys = ["ecash", f"{currency.lower()}"]


class CoingeckoAPI2(ExchangeRateAPI):
    def __init__(self, currency: str):
        super().__init__(currency)
        self.url = "https://api.coingecko.com/api/v3/coins/ecash?localization=False&sparkline=false"
        self.keys = ["market_data", "current_price", f"{currency.lower()}"]


class BinanceUSDT(ExchangeRateAPI):
    def __init__(self, currency: str):
        super().__init__(currency)
        self.url = "https://api.binance.com/api/v3/avgPrice?symbol=XECUSDT"
        self.keys = ["price"]


class BinanceBUSD(ExchangeRateAPI):
    def __init__(self, currency: str):
        super().__init__(currency)
        self.url = "https://api.binance.com/api/v3/avgPrice?symbol=XECBUSD"
        self.keys = ["price"]


APIS: List[Type[ExchangeRateAPI]] = [
    CoingeckoAPI1,
    CoingeckoAPI2,
    BinanceUSDT,
    BinanceBUSD,
]


class ExchangeRateAPIWidget(QtWidgets.QWidget):
    def __init__(self, parent: Optional[QtWidgets.QWidget] = None):
        super().__init__(parent)

        layout = QtWidgets.QVBoxLayout()
        self.setLayout(layout)

        layout.addWidget(QtWidgets.QLabel("Request URL"))
        self.request_url_edit = QtWidgets.QComboBox()
        self.request_url_edit.setEditable(True)
        layout.addWidget(self.request_url_edit)

        layout.addWidget(QtWidgets.QLabel("Keys"))
        self.keys_edit = QtWidgets.QLineEdit()
        layout.addWidget(self.keys_edit)

        # Default state
        self._currency: str = ""
        self.set_currency("USD")

        # signals
        self.request_url_edit.currentIndexChanged.connect(self._on_api_url_selected)

    def set_currency(self, currency: str):
        self._currency = currency
        # Update currency part of preset URLs while remembering selection
        index = self.request_url_edit.currentIndex()
        self.request_url_edit.clear()
        apis: List[ExchangeRateAPI] = []
        for api_class in APIS:
            api = api_class(currency)
            self.request_url_edit.addItem(api.url)
            apis.append(api)
        self.request_url_edit.setCurrentIndex(index)

    def _on_api_url_selected(self, index: int):
        if index < 0:
            self.keys_edit.clear()
            return
        api = APIS[index](self._currency)
        self.keys_edit.setText(", ".join(api.keys))

    def get_url(self) -> str:
        return self.request_url_edit.currentText()

    def get_keys(self) -> List[str]:
        return [k.strip() for k in self.keys_edit.text().split(",")]


if __name__ == "__main__":
    app = QtWidgets.QApplication([])
    w = InvoiceDialog()
    w.show()
    app.exec_()
