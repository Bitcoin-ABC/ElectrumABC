"""This module handles copying the Electron Cash data dir
to the Electrum ABC data path if it does not already exists.

The first time a user runs this program, if he already uses Electron Cash,
he should be able to see all his BCH wallets and have some of the
settings imported.
"""
import glob
import logging
import os
import shutil
from typing import Optional

from .network import DEFAULT_WHITELIST_SERVERS_ONLY, DEFAULT_AUTO_CONNECT
from .simple_config import read_user_config, save_user_config, SimpleConfig
from .util import get_user_dir
from .version import VERSION_TUPLE, PACKAGE_VERSION

from electrumabc_plugins.fusion.conf import DEFAULT_SERVERS

_logger = logging.getLogger(__name__)


INVALID_FUSION_HOSTS = [
    # Electron Cash server
    'cashfusion.electroncash.dk',
    # Test server
    "161.97.82.60"]

# The default fee set to 80000 in 4.3.0 was lowered to 10000 in 4.3.2,
# and then again to 5000 in 4.3.3, and then again to 2000 in 5.0.2
OLD_DEFAULT_FEES = [80000, 10000, 5000]


# function copied from https://github.com/Electron-Cash/Electron-Cash/blob/master/electroncash/util.py
def get_ec_user_dir() -> Optional[str]:
    """Get the Electron Cash data directory.
    """
    if os.name == 'posix' and "HOME" in os.environ:
        return os.path.join(os.environ["HOME"], ".electron-cash")
    elif "APPDATA" in os.environ or "LOCALAPPDATA" in os.environ:
        app_dir = os.environ.get("APPDATA")
        localapp_dir = os.environ.get("LOCALAPPDATA")
        if app_dir is None:
            app_dir = localapp_dir
        return os.path.join(app_dir, "ElectronCash")
    else:
        return


def does_dir_exist(user_dir: Optional[str]) -> bool:
    return user_dir is not None and os.path.isdir(user_dir)


def safe_rm(path: str):
    """Delete a file or a directory.
    In case an exception occurs, log the error message.
    """
    try:
        if os.path.isfile(path):
            os.remove(path)
        elif os.path.isdir(path):
            shutil.rmtree(path)
    except (OSError, shutil.Error) as e:
        _logger.warning(
            f"Unable to delete path {path}.\n{str(e)}")


def replace_src_dest_in_config(src: str, dest: str, config: dict):
    """Replace all occurrences of the string src by the str dest in the
    relevant values of the config dictionary.
    """
    norm_src = os.path.normcase(src)
    norm_dest = os.path.normcase(dest)
    # adjust all paths to point to the new user dir
    for k, v in config.items():
        if isinstance(v, str):
            norm_path = os.path.normcase(v)
            if norm_path.startswith(norm_src):
                config[k] = norm_path.replace(norm_src, norm_dest)
    # adjust paths in list of recently open wallets
    if "recently_open" in config:
        for idx, wallet in enumerate(config["recently_open"]):
            norm_wallet = os.path.normcase(wallet)
            config["recently_open"][idx] = norm_wallet.replace(norm_src,
                                                               norm_dest)


def reset_server_config(config: dict):
    # Reset server selection policy to make sure we don't start on the
    # wrong chain.
    config["whitelist_servers_only"] = DEFAULT_WHITELIST_SERVERS_ONLY
    config["auto_connect"] = DEFAULT_AUTO_CONNECT
    config["server"] = ""
    config.pop("server_whitelist_added", None)
    config.pop("server_whitelist_removed", None)
    config.pop("server_blacklist", None)

    # Delete rpcuser and password. These will be generated on
    # the first connection with jsonrpclib.Server
    config.pop("rpcuser", None)
    config.pop("rpcpassword", None)


def migrate_data_from_ec(ec_user_dir: str = get_ec_user_dir(),
                         user_dir: str = get_user_dir()) -> bool:
    """Copy the EC data dir the first time Electrum ABC is executed.
    This makes all the wallets and settings available to users.
    """
    if not does_dir_exist(ec_user_dir) or does_dir_exist(user_dir):
        return False
    _logger.info("Importing Electron Cash user settings")

    shutil.copytree(ec_user_dir, user_dir)

    # Delete the server lock file if it exists.
    # This file exists if electron cash is currently running.
    lock_file = os.path.join(user_dir, "daemon")
    if os.path.isfile(lock_file):
        safe_rm(lock_file)

    # Delete cache files containing BCH exchange rates
    cache_dir = os.path.join(user_dir, "cache")
    for filename in os.listdir(cache_dir):
        _logger.info(f"Deleting exchange rates cache  {filename}")
        safe_rm(os.path.join(cache_dir, filename))

    # Delete external plugins. They will most likely not be compatible.
    # (see https://github.com/Bitcoin-ABC/ElectrumABC/issues/132)
    plugins_dir = os.path.join(user_dir, "external_plugins")
    for filename in os.listdir(plugins_dir):
        _logger.info(f"Deleting external plugin {filename}")
        safe_rm(os.path.join(plugins_dir, filename))

    # Delete recent servers list
    recent_servers_file = os.path.join(user_dir, "recent-servers")
    safe_rm(recent_servers_file)

    # update some parameters in mainnet config file
    config = read_user_config(user_dir)
    if config:
        reset_server_config(config)

        if "fee_per_kb" in config:
            config["fee_per_kb"] = SimpleConfig.default_fee_rate()

        # Disable plugins that cannot be selected in the Electrum ABC menu.
        config["use_labels"] = False
        config["use_cosigner_pool"] = False

        # Disable by default other plugins that depend on servers that
        # do not exist yet for BCHA.
        config["use_fusion"] = False

        # adjust all paths to point to the new user dir
        replace_src_dest_in_config(ec_user_dir, user_dir, config)
        save_user_config(config, user_dir)

    # Testnet configuration
    testnet_dir_path = os.path.join(user_dir, "testnet")
    recent_tservers_file = os.path.join(testnet_dir_path, "recent-servers")
    safe_rm(recent_tservers_file)

    testnet_config = read_user_config(testnet_dir_path)
    if testnet_config:
        reset_server_config(testnet_config)
        replace_src_dest_in_config(ec_user_dir, user_dir, testnet_config)
        save_user_config(testnet_config, testnet_dir_path)

    return True


def _version_tuple_to_str(version_tuple):
    return ".".join(map(str, version_tuple))


def update_config():
    """Update configuration parameters for old default parameters
    that changed in newer releases. This function should only be
    called if a data directory already exists."""
    config = read_user_config(get_user_dir())
    if not config:
        return

    # update config only when first running a new version
    config_version = config.get("latest_version_used", (4, 3, 1))
    if tuple(config_version) >= VERSION_TUPLE:
        return

    version_transition_msg = _version_tuple_to_str(config_version)
    version_transition_msg += " 🠚 " + PACKAGE_VERSION
    _logger.info("Updating configuration file " + version_transition_msg)

    if config.get("fee_per_kb") in OLD_DEFAULT_FEES:
        _logger.info("Updating default transaction fee")
        config["fee_per_kb"] = SimpleConfig.default_fee_rate()

    # Help users find the new default server if they tried the Electron Cash
    # host or if they manually specified the test server.
    if "cashfusion_server" in config:
        previous_host = config["cashfusion_server"][0]
        if previous_host in INVALID_FUSION_HOSTS:
            _logger.info("Updating default CashFusion server")
            config["cashfusion_server"] = DEFAULT_SERVERS[0]

    # Migrate all users to the XEC unit
    if "decimal_point" in config and tuple(config_version) <= (4, 9, 9):
        config["decimal_point"] = 2

    # Remove exchange cache data after upgrading to 5.0.1 because the old
    # "CoinGecko" exchange was renamed and the name reused for the new
    # XEC API.
    if tuple(config_version) <= (5, 0, 0):
        for fname in glob.glob(os.path.join(get_user_dir(), "cache", "CoinGecko_*")):
            _logger.info(f"Deleting exchange cache data {fname}")
            safe_rm(fname)

    # update version number, to avoid doing this again for this version
    config["latest_version_used"] = VERSION_TUPLE
    save_user_config(config, get_user_dir())
