#!/usr/bin/env python3
#
# Electron Cash - a lightweight Bitcoin Cash client
# CashFusion - an advanced coin anonymizer
#
# Copyright (C) 2020 Mark B. Lundeberg
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

from contextlib import suppress
from typing import TYPE_CHECKING, List, NamedTuple, Optional

from electroncash.plugins import daemon_command
from electroncash.util import InvalidPassword

from .plugin import FusionPlugin

if TYPE_CHECKING:
    from electroncash.daemon import Daemon
    from electroncash.simple_config import SimpleConfig
    from electroncash.wallet import Abstract_Wallet


class WalletToFuse(NamedTuple):
    name: str
    wallet: Abstract_Wallet
    password: Optional[str]


def is_password_valid(wallet: Abstract_Wallet, pwd: str) -> bool:
    try:
        wallet.storage.check_password(pwd)
    except InvalidPassword:
        return False
    return True


def find_password_in_list(
    wallet: Abstract_Wallet, passwords: List[str]
) -> Optional[str]:
    for pwd in passwords:
        if is_password_valid(wallet, pwd):
            return pwd
    return None


class Plugin(FusionPlugin):
    @daemon_command
    def enable_autofuse(self, daemon: Daemon, config: SimpleConfig):
        """Usage:

            ./electrum-abc daemon start
            ./electrum-abc -w  /path/to/wallet daemon load_wallet
            ./electrum-abc daemon enable_autofuse

        For encrypted wallets, the password must be supplied on the command line:

            ./electrum-abc daemon start
            ./electrum-abc -w  /path/to/encrypted_wallet daemon load_wallet
            ./electrum-abc daemon enable_autofuse 'password1'
        """
        passwords = config.get("subargs")

        wallets_to_fuse: List[WalletToFuse] = []
        for name, wallet in daemon.wallets.items():
            if wallet.is_hardware():
                print(f"Error: Cannot add hardware wallet {name} to Cash Fusion.")
                continue

            password = None
            if wallet.storage.is_encrypted():
                password = find_password_in_list(wallet, passwords)
                if password is None:
                    print(
                        f"Error: No valid password provided for wallet {name}. Skipping."
                    )
                    continue
            wallets_to_fuse.append(WalletToFuse(name, wallet, password))

        for w in wallets_to_fuse:
            print(f"adding wallet {w.name} to Cash Fusion")
            super().add_wallet(w.wallet, w.password)
            super().enable_autofusing(w.wallet, w.password)

        if self.tor_port_good is None:
            print("Enabling tor for Cash Fusion")
            self._enable_tor(daemon)

    def _enable_tor(self, daemon: Daemon):
        if self.active and self.tor_port_good is None:
            network = daemon.network
            if (
                network
                and network.tor_controller.is_available()
                and not network.tor_controller.is_enabled()
            ):

                def on_status(controller):
                    with suppress(ValueError):
                        # remove the callback immediately
                        network.tor_controller.status_changed.remove(on_status)
                    if controller.status != controller.Status.STARTED:
                        print("There was an error starting the Tor client")

                network.tor_controller.status_changed.append(on_status)
                network.tor_controller.set_enabled(True)

    @daemon_command
    def fusion_status(self, daemon: Daemon, config: SimpleConfig):
        """Print a table showing the status for all fusions."""
        print("Wallet                    Status          Status Extra")
        for fusion in reversed(self.get_all_fusions()):
            wname = fusion.target_wallet.diagnostic_name()
            status, status_ext = fusion.status
            print(f"{wname:<25.25} {status:<15.15} {status_ext}")
