from typing import Mapping
from collections import OrderedDict

PROJECT_NAME: str = "Electrum ABC"
PROJECT_NAME_NO_SPACES = "ElectrumABC"
SCRIPT_NAME: str = "electrum-abc"
REPOSITORY_OWNER: str = "Bitcoin-ABC"
REPOSITORY_NAME: str = "ElectrumABC"
REPOSITORY_URL: str = f"https://github.com/{REPOSITORY_OWNER}/{REPOSITORY_NAME}"
RELEASES_JSON_URL: str = f"https://raw.github.com/{REPOSITORY_OWNER}/" \
                         f"{REPOSITORY_NAME}/master/contrib/update_checker" \
                         f"/releases.json"

POSIX_DATA_DIR: str = ".electrum-abc"
"""This is the name of the directory where the wallets, recent server lists
and some other things are saved.
"""

PORTABLE_DATA_DIR: str = 'electrum_abc_data'
"""This is the name of the dir where the wallets, recent server lists and some
other things are saved when running the portable .exe file.
This directory is saved in the local directory containing the exe.
"""

BASE_UNITS: Mapping[str, int] = OrderedDict(
    (('BCHA', 8), ('mBCHA', 5), ('bits', 2)))
"""Ordered dict providing the location of the decimal place for all units."""
"""Ordered dict providing the location of the decimal place for all
conventional units."""

INV_BASE_UNITS: Mapping[int, str] = {v: k for k, v in BASE_UNITS.items()}
"""Dict providing the unit string for a given decimal place."""

BASE_UNIT_8 = INV_BASE_UNITS[8]
"""Previous base unit ("bitcoin"), by convention 10^8 satoshis"""
