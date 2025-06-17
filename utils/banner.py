"""
Banner utility for AutoReconX
Displays ASCII art and version information.
"""

import sys
from colorama import init, Fore, Style

# Initialize colorama for cross-platform colored output
init(autoreset=True)

VERSION = "1.0.0"
AUTHOR = "AutoReconX Team"


def display_banner():
    """Display the AutoReconX banner with version info."""
    banner = f"""
{Fore.CYAN}{Style.BRIGHT}
   ___         __        ____                     _  __
  / _ | __ __ / /_ ___  / __ \ ___  ____ ___   ___ | |/ /
 / __ |/ // // __// _ \/ /_/ // _ \/ __// _ \ / _ ||   / 
/_/ |_|\\___/ \\__/ \\___/\\_, / \\___/\\__/ \\___/ \\___//_/|_|  
                      /___/                             
{Style.RESET_ALL}
{Fore.GREEN}AutoReconX - Automated Pentesting Agent v{VERSION}{Style.RESET_ALL}
{Fore.YELLOW}Author: {AUTHOR}{Style.RESET_ALL}
{Fore.RED}⚠️  For Educational and Authorized Testing Only ⚠️{Style.RESET_ALL}
{'-' * 60}
"""
    print(banner)


def display_module_banner(module_name, description=""):
    """Display a banner for individual modules."""
    print(f"\n{Fore.CYAN}[{module_name.upper()}]{Style.RESET_ALL}")
    if description:
        print(f"{Fore.YELLOW}{description}{Style.RESET_ALL}")
    print(f"{'-' * 50}")


def display_status(message, status="INFO"):
    """Display colored status messages."""
    colors = {
        "INFO": Fore.BLUE,
        "SUCCESS": Fore.GREEN,
        "WARNING": Fore.YELLOW,
        "ERROR": Fore.RED,
        "CRITICAL": Fore.MAGENTA
    }
    
    color = colors.get(status.upper(), Fore.WHITE)
    print(f"{color}[{status}]{Style.RESET_ALL} {message}")


if __name__ == "__main__":
    # Test the banner
    display_banner()
    display_module_banner("Scanner", "Network reconnaissance module")
    display_status("This is a test message", "SUCCESS") 