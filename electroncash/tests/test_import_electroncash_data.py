
import os
import shutil
import unittest
import tempfile

from electroncash.migrate_data import migrate_data_from_ec


def create_mock_user_data(data_dir: str):
    os.mkdir(data_dir)
    os.mkdir(os.path.join(data_dir, "cache"))
    os.mkdir(os.path.join(data_dir, "certs"))
    os.mkdir(os.path.join(data_dir, "external_plugins"))
    os.mkdir(os.path.join(data_dir, "forks"))
    os.mkdir(os.path.join(data_dir, "testnet"))
    os.mkdir(os.path.join(data_dir, "tor"))
    os.mkdir(os.path.join(data_dir, "wallet"))


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

    def test_basic(self):
        """Test the the function tries to do something when Electron Cash
        data is found, but not Electrum ABC data (typical situation when
        someone run Electrum ABC for the first time)"""
        create_mock_user_data(self.ec_data_dir)
        self.assertTrue(migrate_data_from_ec(self.ec_data_dir, self.data_dir))


if __name__ == '__main__':
    unittest.main()
