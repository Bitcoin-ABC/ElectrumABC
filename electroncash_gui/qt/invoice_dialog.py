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
from dataclasses import dataclass
from typing import List, Optional, Sequence, Tuple

import requests
from PyQt5 import QtCore, QtWidgets

from electroncash.address import Address, AddressError
from electroncash.i18n import _


class InvoiceDialog(QtWidgets.QDialog):
    def __init__(self, parent: Optional[QtWidgets.QWidget] = None):
        super().__init__(parent)
        self.setMinimumWidth(650)
        self.setMinimumHeight(520)

        layout = QtWidgets.QVBoxLayout()
        self.setLayout(layout)

        layout.addWidget(QtWidgets.QLabel(_("Payment address")))
        self.address_edit = QtWidgets.QLineEdit()
        layout.addWidget(self.address_edit)
        layout.addSpacing(10)

        layout.addWidget(QtWidgets.QLabel(_("Label")))
        self.label_edit = QtWidgets.QLineEdit()
        layout.addWidget(self.label_edit)
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

        self.save_button = QtWidgets.QPushButton(_("Save invoice"))
        buttons_layout.addWidget(self.save_button)
        self.load_button = QtWidgets.QPushButton(_("Load invoice"))
        buttons_layout.addWidget(self.load_button)

        # Trigger callback to init widgets
        self._on_currency_changed(self.amount_currency_edit.get_currency())

        # signals
        self.amount_currency_edit.currencyChanged.connect(self._on_currency_changed)
        self.save_button.clicked.connect(self._on_save_clicked)
        self.load_button.clicked.connect(self.open_file_and_load_invoice)

    def _on_currency_changed(self, currency: str):
        self.exchange_rate_widget.setVisible(currency.lower() != "xec")
        self.exchange_rate_widget.set_currency(currency)

    def _on_save_clicked(self):
        filename, _selected_filter = QtWidgets.QFileDialog.getSaveFileName(
            self,
            _("Save invoice to file"),
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
                self,
                _("Invalid payment address"),
                _("Unable to decode payement address"),
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
                "label": self.label_edit.text(),
                "amount": self.amount_currency_edit.get_amount_as_string(),
                "currency": currency,
            }
        }
        if currency.lower() == "xec":
            return out

        if self.exchange_rate_widget.is_fixed_rate():
            out["invoice"][
                "exchangeRate"
            ] = f"{self.exchange_rate_widget.get_fixed_rate():.10f}"
            return out

        url, keys = self.exchange_rate_widget.get_api_rate_params()
        out["invoice"]["exchangeRateAPI"] = {"url": url, "keys": keys}
        return out

    def open_file_and_load_invoice(self):
        filename, _selected_filter = QtWidgets.QFileDialog.getOpenFileName(
            self,
            _("Load invoice from file"),
            filter="JSON file (*.json);;All files (*)",
        )

        if not filename:
            return

        self.load_from_file(filename)

    def load_from_file(self, filename: str):
        failed_decoding = False
        with open(filename, "r") as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError:
                failed_decoding = True

        if failed_decoding or "invoice" not in data:
            QtWidgets.QMessageBox.critical(
                self,
                _("Failed to load invoice"),
                _("Unable to decode JSON data for invoice") + f" {filename}",
            )
            return
        invoice = data["invoice"]
        self.address_edit.setText(invoice.get("address") or "")
        self.label_edit.setText(invoice.get("label") or "")
        self.amount_currency_edit.set_amount(invoice.get("amount") or "0")
        self.amount_currency_edit.set_currency(invoice.get("currency") or "XEC")
        if "exchangeRate" in invoice:
            rate = float(invoice["exchangeRate"])
            self.exchange_rate_widget.set_fixed_rate(rate)
            if "exchangeRateAPI" in invoice:
                QtWidgets.QMessageBox.warning(
                    self,
                    _("Ambiguous exchange rate specifications"),
                    _(
                        "This invoice specifies both a fixed exchange rate and an "
                        "exchange rate API. Ignoring the API and using the fixed rate."
                    ),
                )
        elif "exchangeRateAPI" in invoice:
            url = invoice["exchangeRateAPI"].get("url") or ""
            keys = invoice["exchangeRateAPI"].get("keys") or []
            self.exchange_rate_widget.set_api_rate_params(url, keys)

    def set_address(self, address: Address):
        self.address_edit.setText(address.to_ui_string())


class AmountCurrencyEdit(QtWidgets.QWidget):
    currencyChanged = QtCore.pyqtSignal(str)

    def __init__(self, parent: Optional[QtWidgets.QWidget] = None):
        super().__init__(parent)
        layout = QtWidgets.QVBoxLayout()
        self.setLayout(layout)
        layout.setContentsMargins(0, 0, 0, 0)

        layout.addWidget(QtWidgets.QLabel(_("Amount")))
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

    def set_currency(self, currency: str):
        return self.currency_edit.setCurrentText(currency)

    def get_amount_as_string(self) -> str:
        return f"{self.amount_edit.value():.2f}"

    def set_amount(self, amount: str):
        return self.amount_edit.setValue(float(amount))


class ExchangeRateWidget(QtWidgets.QWidget):
    def __init__(self, parent: Optional[QtWidgets.QWidget] = None):
        super().__init__(parent)
        layout = QtWidgets.QVBoxLayout()
        self.setLayout(layout)
        layout.setContentsMargins(0, 0, 0, 0)

        layout.addWidget(QtWidgets.QLabel(_("Exchange rate")))
        fixed_rate_layout = QtWidgets.QHBoxLayout()
        layout.addLayout(fixed_rate_layout)
        self.fixed_rate_rb = QtWidgets.QRadioButton(_("Fixed rate"))
        fixed_rate_layout.addWidget(self.fixed_rate_rb)
        self.rate_edit = QtWidgets.QDoubleSpinBox()
        self.rate_edit.setDecimals(10)
        self.rate_edit.setRange(10**-8, 10**100)
        self.rate_edit.setStepType(QtWidgets.QAbstractSpinBox.AdaptiveDecimalStepType)
        fixed_rate_layout.addWidget(self.rate_edit)

        api_rate_layout = QtWidgets.QVBoxLayout()
        layout.addLayout(api_rate_layout)
        self.api_rate_rb = QtWidgets.QRadioButton(_("Fetch rate at payment time"))
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
        self.fixed_rate_rb.setText(_("Fixed rate ") + f"({currency}/XEC)")
        self.api_widget.set_currency(currency)

    def _on_api_rate_clicked(self, is_checked: bool):
        self.api_widget.setVisible(is_checked)

    def is_fixed_rate(self) -> bool:
        return self.fixed_rate_rb.isChecked()

    def set_fixed_rate(self, rate: float):
        self.fixed_rate_rb.setChecked(True)
        self.rate_edit.setValue(rate)

    def get_fixed_rate(self) -> float:
        return self.rate_edit.value()

    def get_api_rate_params(self) -> Tuple[str, List[str]]:
        return self.api_widget.get_url(), self.api_widget.get_keys()

    def set_api_rate_params(self, url: str, keys: List[str]):
        self.api_rate_rb.setChecked(True)
        self.api_widget.set_url(url)
        self.api_widget.set_keys(keys)


@dataclass
class ExchangeRateAPI:
    url: str
    keys: Sequence[str]

    def get_url(self, currency: str) -> str:
        """Get request url with occurrences of ${cur} and %CUR% replaced with
        respectively lower case or upper case currency symbol.
        """
        url = self.url.replace("%cur%", currency.lower())
        return url.replace("%CUR%", currency.upper())

    def get_keys(self, currency: str) -> List[str]:
        """Get keys with occurrences of %cur% and %CUR% replaced with
        respectively lower case or upper case currency symbol.
        """
        return [
            k.replace("%cur%", currency.lower()).replace("%CUR%", currency.upper())
            for k in self.keys
        ]

    def get_exchange_rate(self, currency: str) -> float:
        url = self.get_url(currency)
        keys = self.get_keys(currency)

        json_data = requests.get(url).json()

        next_node = json_data
        for k in keys:
            next_node = next_node[k]
        return float(next_node)


APIS: List[ExchangeRateAPI] = [
    ExchangeRateAPI(
        "https://api.coingecko.com/api/v3/simple/price?ids=ecash&vs_currencies=%cur%",
        ["ecash", "%cur%"],
    ),
    ExchangeRateAPI(
        "https://api.coingecko.com/api/v3/coins/ecash?localization=False&sparkline=false",
        ["market_data", "current_price", "%cur%"],
    ),
    ExchangeRateAPI(
        "https://api.binance.com/api/v3/avgPrice?symbol=XECUSDT",
        ["price"],
    ),
    ExchangeRateAPI(
        "https://api.binance.com/api/v3/avgPrice?symbol=XECBUSD",
        ["price"],
    ),
]


class ExchangeRateAPIWidget(QtWidgets.QWidget):
    def __init__(self, parent: Optional[QtWidgets.QWidget] = None):
        super().__init__(parent)

        layout = QtWidgets.QVBoxLayout()
        self.setLayout(layout)

        layout.addWidget(QtWidgets.QLabel(_("Request URL")))
        self.request_url_edit = QtWidgets.QComboBox()
        self.request_url_edit.setEditable(True)
        layout.addWidget(self.request_url_edit)

        layout.addWidget(QtWidgets.QLabel(_("Keys")))
        self.keys_edit = QtWidgets.QLineEdit()
        self.keys_edit.setToolTip(
            _(
                "Comma separated list of JSON keys used to find the exchange rate in the "
                "data sent by the API."
            )
        )
        layout.addWidget(self.keys_edit)

        self.test_api_button = QtWidgets.QPushButton(_("Test API"))
        layout.addWidget(self.test_api_button, alignment=QtCore.Qt.AlignLeft)

        # signals
        self.request_url_edit.currentIndexChanged.connect(self._on_api_url_selected)
        self.test_api_button.clicked.connect(self._on_test_api_clicked)

        # Default state
        self._currency: str = ""
        self.set_currency("USD")
        self.request_url_edit.setCurrentIndex(0)

    def set_currency(self, currency: str):
        self._currency = currency
        # Update currency part of preset URLs while remembering selection
        index = self.request_url_edit.currentIndex()
        self.request_url_edit.clear()
        for api in APIS:
            self.request_url_edit.addItem(api.get_url(currency))
        self.request_url_edit.setCurrentIndex(index)

    def _on_api_url_selected(self, index: int):
        if index < 0:
            self.keys_edit.clear()
            return
        self.keys_edit.setText(", ".join(APIS[index].get_keys(self._currency)))

    def get_url(self) -> str:
        return self.request_url_edit.currentText()

    def set_url(self, url: str):
        return self.request_url_edit.setCurrentText(url)

    def get_keys(self) -> List[str]:
        return [k.strip() for k in self.keys_edit.text().split(",")]

    def set_keys(self, keys: List[str]):
        return self.keys_edit.setText(", ".join(keys))

    def _on_test_api_clicked(self):
        api = ExchangeRateAPI(self.get_url(), self.get_keys())
        try:
            rate = api.get_exchange_rate(self._currency)
        except (KeyError, requests.exceptions.RequestException) as e:
            QtWidgets.QMessageBox.critical(
                self,
                "Error fetching exchange rate",
                f"Unable to fetch the XEC/{self._currency} exchange rate using the "
                f"specified API parameters.\n\nThe error message was:\n\n{e}",
            )
            return

        QtWidgets.QMessageBox.information(
            self,
            "Exchange rate",
            f"The XEC/{self._currency} exchange rate is {rate:.10f}",
        )
