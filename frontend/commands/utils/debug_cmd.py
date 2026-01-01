from utils.display import print_info


def handle_debug(shell, arg: str):
    arg = (arg or "").strip().lower()

    if arg in ("on", "true", "1"):
        shell.debug = True
        print_info("Debug mode enabled.")
    elif arg in ("off", "false", "0"):
        shell.debug = False
        print_info("Debug mode disabled.")
    else:
        print_info(f"Debug mode is {'ON' if shell.debug else 'OFF'}.")
