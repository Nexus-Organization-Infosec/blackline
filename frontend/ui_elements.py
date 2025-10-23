import sys
from pathlib import Path 
from datetime import datetime

from utils.colors import color 
from utils.display import get_terminal_width
from utils.display import (
    print_warning,
    print_success,
    print_info,
    print_error,
    print_step,
)
from frontend.commands.utils.clear_cmd import handle_clear
from frontend.commands.utils.update_cmd import handle_update 

CONSENT_FILE = Path(__file__).resolve().parent.parent / ".blackline_consent"

BIG_BANNER = r"""

@@@@@@@   @@@        @@@@@@    @@@@@@@  @@@  @@@  @@@       @@@  @@@  @@@  @@@@@@@@
@@@@@@@@  @@@       @@@@@@@@  @@@@@@@@  @@@  @@@  @@@       @@@  @@@@ @@@  @@@@@@@@
@@!  @@@  @@!       @@!  @@@  !@@       @@!  !@@  @@!       @@!  @@!@!@@@  @@!
!@   @!@  !@!       !@!  @!@  !@!       !@!  @!!  !@!       !@!  !@!!@!@!  !@!
@!@!@!@   @!!       @!@!@!@!  !@!       @!@@!@!   @!!       !!@  @!@ !!@!  @!!!:!  
!!!@!!!!  !!!       !!!@!!!!  !!!       !!@!!!    !!!       !!!  !@!  !!!  !!!!!:  
!!:  !!!  !!:       !!:  !!!  :!!       !!: :!!   !!:       !!:  !!:  !!!  !!:     
:!:  !:!   :!:      :!:  !:!  :!:       :!:  !:!   :!:      :!:  :!:  !:!  :!:     
 :: ::::   :: ::::  ::   :::   ::: :::   ::  :::   :: ::::   ::   ::   ::   :: ::::
:: : ::   : :: : :   :   : :   :: :: :   :   :::  : :: : :  :    ::    :   : :: :: 

"""

SMALL_BANNER = r"""
______ _            _    _ _            
| ___ \ |          | |  | (_)           
| |_/ / | __ _  ___| | _| |_ _ __   ___ 
| ___ \ |/ _` |/ __| |/ / | | '_ \ / _ \
| |_/ / | (_| | (__|   <| | | | | |  __/
\____/|_|\__,_|\___|_|\_\_|_|_| |_|\___|
"""

CONSENT_ART = color(r"""
╔═════════════════════════════════════════════════════════════════╗
║                         BLACKLINE TOOLCHAIN                     ║
║                   ETHICAL SECURITY AUTOMATION                   ║
╠═════════════════════════════════════════════════════════════════╣
║ WARNING: This software is intended solely for educational,      ║
║ research, or authorized red team and security assessment use.   ║
║                                                                 ║
║ ▸ You must have explicit, written permission before engaging    ║
║   in any testing or exploitation activity on target systems.    ║
║ ▸ Unauthorized use may violate laws and organizational policies.║
║ ▸ The authors assume no liability for misuse or resulting harm. ║
║                                                                 ║
║ By continuing, you acknowledge that:                            ║
║ [1] You understand and accept the above risks.                  ║
║ [2] You are solely responsible for your actions.                ║
║                                                                 ║
║ To proceed, you must SIGN your name below.                      ║
╚═════════════════════════════════════════════════════════════════╝
""", "red")


def show_banner():
    """Display a banner appropriate to the terminal width"""
    width = get_terminal_width()
    if width >= 85:
        print(color(BIG_BANNER, "red"))
    else:
        print(color(SMALL_BANNER, "red"))


def get_signed_name():
    if CONSENT_FILE.exists():
        try:
            for line in CONSENT_FILE.read_text().splitlines():
                if line.startswith("Signed by:"):
                    return line.replace("Signed by:", "").strip()
        except Exception:
            pass
    return "user"


def show_welcome_message():
    signed_name = get_signed_name()
    print(color(f"\n+=== Welcome back {signed_name} ===+\n", "green"))

def show_hacker_consent():
    """Prompts the user for first-run consent and saves signature."""
    first_time = not CONSENT_FILE.exists()
    if not first_time:
        return  

    print(CONSENT_ART)

    if not sys.stdin.isatty():
        print_warning("Non-interactive execution detected.")
        print_error("This tool must be run interactively for legal acknowledgment.")
        sys.exit(1)

    try:
        while True:
            response = input("→ Do you acknowledge full legal responsibility? (yes/no): ").strip().lower()
            if response in {"yes", "y"}:
                break
            elif response in {"no", "n"}:
                print_error("Consent not granted. Exiting.")
                sys.exit(1)
            else:
                print_warning("Please type 'yes' or 'no'.")

        print_info("Please type your full name to sign the following agreement:\n")
        print_info("I confirm that I will only use Blackline for authorized, ethical, and legal security testing.\n")

        while True:
            signature = input("Signed by: ").strip()
            if signature:
                break
            else:
                print_warning("Please enter your name to proceed.")

        # Save consent file
        try:
            CONSENT_FILE.write_text(
                "I confirm that I will only use Blackline for authorized, ethical, and legal security testing.\n\n"
                f"Signed by: {signature}\n"
                f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            )

            print_success(f"\n✓ Consent saved in {CONSENT_FILE}.")
            print_step("\n[+] Performing first-run setup...")

            try:
                handle_update(merge=False)
            except Exception as e:
                print_error(f"Auto-update failed: {e}")

        except Exception as e:
            print_error(f"Failed to save consent file: {e}")
            sys.exit(1)

        input("\n→ Press Enter to continue...")
        handle_clear()

    except KeyboardInterrupt:
        print_error("\n[x] Interrupted. Exiting.")
        sys.exit(1)