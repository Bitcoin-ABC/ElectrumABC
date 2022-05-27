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
from decimal import Decimal
from typing import Dict, List, Optional, Sequence, Union
from urllib.request import urlopen

from .address import Address, AddressError


class InvoiceDataError(Exception):
    pass


class Invoice:
    def __init__(
        self,
        address: Address,
        amount: Decimal,
        label: str = "",
        currency: str = "XEC",
        exchange_rate: Optional[Union[FixedExchangeRate, APIExchangeRate]] = None,
    ):
        self.address = address
        self.amount = amount
        self.currency = currency
        self.label = label
        if currency.lower() != "xec":
            assert exchange_rate is not None
        self.exchange_rate = exchange_rate

    def to_dict(self) -> dict:
        out = {
            "invoice": {
                "address": self.address.to_ui_string(),
                "label": self.label,
                "amount": str(self.amount),
                "currency": self.currency,
            }
        }

        if self.exchange_rate is None:
            return out

        if isinstance(self.exchange_rate, FixedExchangeRate):
            out["exchangeRate"] = self.exchange_rate.to_string()
            return out

        out["exchangeRateAPI"] = self.exchange_rate.to_dict()
        return out

    @classmethod
    def from_dict(cls, data: dict) -> Invoice:
        """Build an invoice from a dict."""
        if "invoice" not in data:
            raise InvoiceDataError("Missing top-level invoice node.")
        invoice = data["invoice"]
        currency = invoice.get("currency") or "XEC"
        try:
            address = Address.from_string(invoice["address"])
        except (KeyError, AddressError):
            raise InvoiceDataError("Missing or invalid payment address.")

        if "exchangeRate" in invoice and "exchangeRateAPI" in invoice:
            raise InvoiceDataError(
                "Ambiguous exchange rate data (both fixed and API rates are present)"
            )
        if currency.lower() == "xec" and (
            "exchangeRate" in invoice or "exchangeRateAPI" in invoice
        ):
            raise InvoiceDataError(
                "Exchange rate must not be specified for XEC amounts"
            )

        rate = None
        if "exchangeRate" in invoice:
            rate = FixedExchangeRate(Decimal(invoice["exchangeRate"]))
        elif "exchangeRateAPI" in invoice:
            rate = APIExchangeRate(
                url=invoice["exchangeRateAPI"].get("url") or "",
                keys=invoice["exchangeRateAPI"].get("keys") or [],
            )

        return Invoice(
            address=address,
            amount=Decimal(invoice.get("amount", "0.")),
            label=invoice.get("label", ""),
            currency=currency,
            exchange_rate=rate,
        )


@dataclass
class FixedExchangeRate:
    rate: Decimal

    def to_string(self) -> str:
        return str(self.rate)


@dataclass
class APIExchangeRate:
    url: str
    keys: List[str]

    def to_dict(self) -> Dict[str, Union[str, List[str]]]:
        return {"url": self.url, "keys": self.keys}


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

        with urlopen(url) as response:
            body = response.read()
            json_data = json.loads(body)

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
