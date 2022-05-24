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

import enum
from typing import List, Optional, Type

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

        layout.addStretch(1)

        # Trigger callback to init widgets
        self._on_currency_changed(self.amount_currency_edit.get_currency())

        # signals
        self.amount_currency_edit.currencyChanged.connect(self._on_currency_changed)

    def _on_currency_changed(self, currency: str):
        self.exchange_rate_widget.setVisible(currency.lower() != "xec")
        self.exchange_rate_widget.set_currency(currency)


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


class APIDataFormat(enum.Enum):
    JSON = 1
    YAML = 2


class ExchangeRateAPI:
    def __init__(self, currency: str):
        self._currency = currency
        self.url: str = ""
        self.format: APIDataFormat = APIDataFormat.JSON
        self.keys: List[str] = []


class CoingeckoAPI1(ExchangeRateAPI):
    def __init__(self, currency: str):
        super().__init__(currency)
        self.url = f"https://api.coingecko.com/api/v3/simple/price?ids=ecash&vs_currencies={currency.lower()}"
        self.format = APIDataFormat.JSON
        self.keys = ["ecash", f"{currency.lower()}"]


class CoingeckoAPI2(ExchangeRateAPI):
    def __init__(self, currency: str):
        super().__init__(currency)
        self.url = "https://api.coingecko.com/api/v3/coins/ecash?localization=False&sparkline=false"
        self.format = APIDataFormat.JSON
        self.keys = ["market_data", "current_price", f"{currency.lower()}"]


class BinanceUSDT(ExchangeRateAPI):
    def __init__(self, currency: str):
        super().__init__(currency)
        self.url = "https://api.binance.com/api/v3/avgPrice?symbol=XECUSDT"
        self.format = APIDataFormat.JSON
        self.keys = ["price"]


class BinanceBUSD(ExchangeRateAPI):
    def __init__(self, currency: str):
        super().__init__(currency)
        self.url = "https://api.binance.com/api/v3/avgPrice?symbol=XECBUSD"
        self.format = APIDataFormat.JSON
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

        layout.addWidget(QtWidgets.QLabel("Data format"))
        data_format_layout = QtWidgets.QHBoxLayout()
        layout.addLayout(data_format_layout)

        self.json_rb = QtWidgets.QRadioButton("JSON")
        data_format_layout.addWidget(self.json_rb)
        self.yaml_rb = QtWidgets.QRadioButton("YAML")
        data_format_layout.addWidget(self.yaml_rb)

        layout.addWidget(QtWidgets.QLabel("Keys"))
        self.keys_edit = QtWidgets.QLineEdit()
        layout.addWidget(self.keys_edit)

        # Default state
        self._currency: str = ""
        self.set_currency("USD")
        self.json_rb.setChecked(True)

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
        if api.format == APIDataFormat.JSON:
            self.json_rb.setChecked(True)
        else:
            self.yaml_rb.setChecked(True)


if __name__ == "__main__":
    app = QtWidgets.QApplication([])
    w = InvoiceDialog()
    w.show()
    app.exec_()
