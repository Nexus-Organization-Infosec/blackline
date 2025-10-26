# blackline/config/config_loader.py

import json
import os
from utils.display import print_error


def load_config(config_path: str):
    base_dir = os.path.dirname(os.path.abspath(__file__))

    abs_path = os.path.join(base_dir, config_path) if not os.path.isabs(config_path) else config_path

    if not abs_path.endswith(".json"):
        abs_path += ".json"

    if not os.path.exists(abs_path):
        print_error(f"Config file not found: {abs_path}")
        return {}

    try:
        with open(abs_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data
    except json.JSONDecodeError as e:
        print_error(f"JSON decode error in {abs_path}: {e}")
    except Exception as e:
        print_error(f"Failed to load config {abs_path}: {e}")

    return {}
