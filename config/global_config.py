# blackline/config/global_config.py

import os
from config.config_loader import load_config

_GLOBAL_CONFIG = None

def _load_global_config():
    global _GLOBAL_CONFIG
    if _GLOBAL_CONFIG is None:
        config_path = os.path.join("global.json")
        _GLOBAL_CONFIG = load_config(config_path)
    return _GLOBAL_CONFIG


def get_global_config():
    """Return the full global configuration dict."""
    return _load_global_config()


def get(key_path, default=None):
    """Retrieve a nested config value using dot-notation."""
    config = _load_global_config()
    keys = key_path.split(".")
    value = config
    for key in keys:
        if isinstance(value, dict) and key in value:
            value = value[key]
        else:
            return default
    return value


def reload_global_config():
    """Force reload of the global config file."""
    global _GLOBAL_CONFIG
    _GLOBAL_CONFIG = None
    return _load_global_config()
