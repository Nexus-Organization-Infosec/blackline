# frontend/commands/utils/clear_cmd.py 
 
import os
from utils.display import print_error

def handle_clear():
    try:
        if os.name == 'nt': 
            os.system('cls')
        else:
            os.system('clear')
    except Exception:
        print_error("Failed to clear terminal.")
