# blackline/frontend/commands/utils/version_cmd.py

from config.global_config import get 
from utils.display import print_info, print_success
import platform
import os

def handle_version():
    """
    Display current Blackline version and environment info 
    Loaded from config/global.json
    """

    version = get("version", "unknown")
    env = get("environment", "unknown")
    author = get("author", "Unknown")
    system = platform.system()           
    release = platform.release()         
    machine = platform.machine()         
    python_version = platform.python_version()
    user = os.getenv("USER") or os.getenv("USERNAME")

    print_info("Blackline Configuration:")
    print_success(f"Version: {version}")
    print_success(f"Environment: {env}")
    print_success(f"Author: {author}\n")
    print_info("System Info:")
    print_success(f"System: {system}")
    print_success(f"Release {release}")
    print_success(f"Machine: {machine}")
    print_success(f"Python version: {python_version}")
    print_success(f"User: {user}")