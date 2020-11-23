"""This module handles copying the Electron Cash data dir
to the Electrum ABC data path if it does not already exists.

The first time a user runs this program, if he already uses Electron Cash,
he should be able to see all his BCH wallets.
"""
import os
import shutil
from typing import Optional

from .network import DEFAULT_WHITELIST_SERVERS_ONLY, DEFAULT_AUTO_CONNECT
from .simple_config import read_user_config, save_user_config
from .util import get_user_dir


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


def does_user_dir_exist() -> bool:
    """Return True if an Electrum ABC directory exists.
    It will be False the first time a user runs the application.
    """
    user_dir = get_user_dir()
    if user_dir is None or not os.path.isdir(user_dir):
        return False
    return True


def does_ec_user_dir_exist() -> bool:
    """Return True if an Electron Cash user directory exists.
    It will return False if Electron Cash is not installed.
    """
    user_dir = get_ec_user_dir()
    if user_dir is None or not os.path.isdir(user_dir):
        return False
    return True


def migrate_data_from_ec():
    """Copy the EC data dir the first time Electrum ABC is executed.
    This makes all the wallets and settings available to users.
    """
    if does_ec_user_dir_exist() and not does_user_dir_exist():
        src = get_ec_user_dir()
        dest = get_user_dir()
        shutil.copytree(src, dest)

        # Delete the server lock file if it exists.
        # This file exists if electron cash is currently running.
        lock_file = os.path.join(dest, "daemon")
        if os.path.isfile(lock_file):
            os.remove(lock_file)

        # update some parameters in config file
        config = read_user_config(dest)
        if config:
            # Reset server selection policy to make sure we don't start on the
            # wrong chain.
            config["whitelist_servers_only"] = DEFAULT_WHITELIST_SERVERS_ONLY
            config["auto_connect"] = DEFAULT_AUTO_CONNECT
            config["server"] = ""

            # Delete rpcuser and password. These will be generated on
            # the first connection with jsonrpclib.Server
            if "rpcuser" in config:
                del config["rpcuser"]
            if "rpcpassword" in config:
                del config["rpcpassword"]

            # Make sure the fiat columns are hidden, because the menu to change
            # this setting is hidden for now.
            config["fiat_address"] = False
            config["history_rates"] = False

            # Disable plugins that can not be selected in the Electrum ABC menu.
            config["use_labels"] = False
            config["use_cosigner_pool"] = False

            # Disable by default other plugins that depend on servers that
            # do not exist yet for BCHA.
            config["use_fusion"] = False
            config["use_shuffle_deprecated"] = False

            # adjust all paths to point to the new user dir
            for k, v in config.items():
                if isinstance(v, str) and v.startswith(src):
                    config[k] = v.replace(src, dest)
            # adjust paths in list of recently open wallets
            if "recently_open" in config:
                for idx, wallet in enumerate(config["recently_open"]):
                    config["recently_open"][idx] = wallet.replace(src, dest)

            save_user_config(config, dest)
