import os
import shutil
import tempfile
import unittest

from electrumabc.migrate_data import migrate_data_from_ec


def create_blank_file(filename: str):
    with open(filename, "w"):
        pass
    assert os.path.exists(filename)


def create_mock_user_data(data_dir: str):
    os.mkdir(data_dir)

    create_blank_file(os.path.join(data_dir, "blockchain_headers"))
    create_blank_file(os.path.join(data_dir, "daemon"))
    create_blank_file(os.path.join(data_dir, "recent-servers"))
    os.mkdir(os.path.join(data_dir, "cache"))
    create_blank_file(os.path.join(data_dir, "cache", "CoinGecko_USD"))
    os.mkdir(os.path.join(data_dir, "certs"))
    os.mkdir(os.path.join(data_dir, "external_plugins"))
    create_blank_file(os.path.join(data_dir, "external_plugins", "flipstarter-1.3.zip"))
    os.mkdir(os.path.join(data_dir, "forks"))
    os.mkdir(os.path.join(data_dir, "testnet"))
    create_blank_file(os.path.join(data_dir, "testnet", "recent-servers"))
    os.mkdir(os.path.join(data_dir, "tor"))
    os.mkdir(os.path.join(data_dir, "wallet"))

    with open(os.path.join(data_dir, "config"), "w") as f:
        f.write(
            f"""
            {{
                "addr_format": 1,
                "address_format": "CashAddr",
                "allow_legacy_p2sh": false,
                "auto_connect": false,
                "block_explorer": "Blockchair",
                "config_version": 2,
                "confirmed_only": false,
                "console-history": [],
                "currency": "USD",
                "decimal_point": 2,
                "enable_opreturn": true,
                "fee_per_kb": 1000,
                "fiat_address": true,
                "gui_last_wallet": "{data_dir}/wallets/test_wallet",
                "hide_cashaddr_button": false,
                "history_rates": true,
                "io_dir": "/a/b/c/ElectrumABC",
                "is_maximized": false,
                "latest_version_used": [
                    5,
                    0,
                    1
                ],
                "network_unanswered_requests_throttle": [
                    2000,
                    100
                ],
                "proxy": "socks5:127.0.0.1:33539::",
                "qt_enable_highdpi": true,
                "recently_open": [
                    "{data_dir}/wallets/test_wallet",
                    "{data_dir}/wallets/wallet_8"
                ],
                "rpcpassword": "very pwd",
                "rpcuser": "much user",
                "server": "electrum.bitcoin-abc.org:50002:s",
                "server_whitelist_added": [],
                "server_whitelist_removed": [],
                "show_addresses_tab": true,
                "show_cashaddr": true,
                "show_fee": false,
                "tor_enabled": true,
                "tor_socks_port": 0,
                "tor_use": true,
                "use_cosigner_pool": true,
                "use_email_requests": true,
                "use_exchange": "CoinGecko",
                "use_exchange_rate": true,
                "use_external_flipstarter": true,
                "use_fusion": true,
                "use_labels": true,
                "use_satochip_2FA": false,
                "use_shuffle_deprecated": true,
                "use_virtualkeyboard": true,
                "video_device": "/dev/video0",
                "whitelist_servers_only": true
            }}
            """
        )


class TestImportECData(unittest.TestCase):
    def setUp(self):
        # Create a temporary directory
        self.test_dir = tempfile.mkdtemp()
        self.ec_data_dir = os.path.join(self.test_dir, ".electroncash")
        self.data_dir = os.path.join(self.test_dir, ".electrum-abc")

    def tearDown(self):
        if os.path.isdir(self.test_dir):
            shutil.rmtree(self.test_dir)

    def test_no_data(self):
        """No Electron Cash nor Electrum ABC data"""
        self.assertFalse(migrate_data_from_ec(self.ec_data_dir, self.data_dir))

    def test_no_ec_data(self):
        """No Electron Cash data, nothing to import."""
        os.mkdir(self.data_dir)
        self.assertFalse(migrate_data_from_ec(self.ec_data_dir, self.data_dir))

    def test_already_have_data(self):
        """If the Electrum ABC data dir already exists, nothing is done"""
        os.mkdir(self.ec_data_dir)
        os.mkdir(self.data_dir)
        self.assertFalse(migrate_data_from_ec(self.ec_data_dir, self.data_dir))

    def test_migrate(self):
        """Test the function does something when Electron Cash
        data is found, but not Electrum ABC data (typical situation when
        someone run Electrum ABC for the first time)"""
        create_mock_user_data(self.ec_data_dir)
        self.assertTrue(migrate_data_from_ec(self.ec_data_dir, self.data_dir))

        def path_was_deleted(*args) -> bool:
            return not os.path.exists(os.path.join(self.data_dir, *args))

        self.assertTrue(path_was_deleted("daemon"), "Lock file was not deleted")
        self.assertTrue(
            path_was_deleted("cache", "CoinGecko_USD"),
            "Exchange rate data was not deleted",
        )
        self.assertTrue(
            path_was_deleted("external_plugins", "flipstarter-1.3.zip"),
            "External plugin was not deleted",
        )
        self.assertTrue(
            path_was_deleted("recent-servers"), "Recent servers list was not deleted"
        )
        self.assertTrue(
            path_was_deleted("testnet", "recent-servers"),
            "Tesnet recent servers list was not deleted",
        )

        self.assertTrue(os.path.isfile(os.path.join(self.data_dir, "config")))

        with open(os.path.join(self.data_dir, "config"), "r") as f:
            config_text = f.read()
            # Check that ec_data_dir was replaced with data_dir
            self.assertNotIn(
                f'"gui_last_wallet": "{self.ec_data_dir}/wallets/test_wallet"',
                config_text,
            )
            self.assertIn(
                f'"gui_last_wallet": "{self.data_dir}/wallets/test_wallet"', config_text
            )

            # Check server config
            self.assertNotIn("server_whitelist_added", config_text)
            self.assertNotIn("server_whitelist_removed", config_text)
            self.assertNotIn("server_whitelist_blacklist", config_text)
            self.assertNotIn("rpcuser", config_text)
            self.assertNotIn("rpcpassword", config_text)

            self.assertIn('"whitelist_servers_only": true', config_text)
            self.assertNotIn("server_whitelist_blacklist", config_text)
            self.assertNotIn("rpcuser", config_text)
            self.assertNotIn("rpcpassword", config_text)

            # Fee hardcoded to notice accidental changes in the default fee
            self.assertIn('"fee_per_kb": 2000', config_text)


if __name__ == "__main__":
    unittest.main()
