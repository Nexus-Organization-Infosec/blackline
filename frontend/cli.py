# frontend/cli.py

import sys 
import traceback 

from frontend.core_shell import BLShell 
from frontend.ui_elements import show_banner, show_hacker_consent, show_welcome_message
from utils.display import print_error, print_step, print_info

def main() -> int:
    try:
        show_hacker_consent()
        show_banner()
        show_welcome_message()

        shell = BLShell()
        try:
            shell.cmdloop()
        except KeyboardInterrupt:
            print_info("\n[!] Keyboard interrupt received. Exiting shell.")
            return 0
        except SystemExit as se:
            raise se
        except Exception as e:
            print_error(f"Unexpected error in shell loop: {e}")
            traceback.print_exc()
            return 2

        return 0

    except SystemExit as se:
        return int(se.code or 1)
    except Exception as e:
        print_error(f"Fatal error starting Blackline: {e}")
        traceback.print_exc()
        return 3


if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)