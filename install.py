#!/usr/bin/env python3
"""
Firefox Forensics Tool - Installation Script
Cross-platform Python setup script for installing dependencies.

Usage:
    python3 install.py
    python3 install.py --check
    python3 install.py --help
"""

import os
import sys
import subprocess
import platform
import shutil
from pathlib import Path


# Colors for terminal output
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    END = '\033[0m'


def colorize(text: str, color: str) -> str:
    """Add color to text if terminal supports it."""
    if sys.stdout.isatty():
        return f"{color}{text}{Colors.END}"
    return text


def print_banner():
    """Print setup banner."""
    print(colorize("""
╔══════════════════════════════════════════════════════════════════════╗
║  🔧 Firefox Forensics Tool - Python Setup Script                     ║
║  Cross-platform dependency installer                                 ║
╚══════════════════════════════════════════════════════════════════════╝
""", Colors.CYAN))


def detect_os() -> tuple[str, str]:
    """Detect operating system and package manager.
    
    Returns:
        Tuple of (os_type, package_manager_command)
    """
    system = platform.system().lower()
    
    if system == 'darwin':
        return 'macos', 'brew install nss'
    
    if system == 'linux':
        # Try to detect Linux distribution
        try:
            with open('/etc/os-release', 'r') as f:
                os_release = f.read().lower()
        except FileNotFoundError:
            os_release = ''
        
        # Arch-based
        if 'arch' in os_release or 'manjaro' in os_release or Path('/etc/arch-release').exists():
            return 'arch', 'sudo pacman -Sy --noconfirm nss'
        
        # Debian-based
        if 'debian' in os_release or 'ubuntu' in os_release or 'mint' in os_release:
            return 'debian', 'sudo apt-get update && sudo apt-get install -y libnss3'
        
        # Fedora-based
        if 'fedora' in os_release or 'rhel' in os_release or 'centos' in os_release:
            return 'fedora', 'sudo dnf install -y nss'
        
        # openSUSE
        if 'suse' in os_release:
            return 'opensuse', 'sudo zypper install -y mozilla-nss'
        
        return 'linux-unknown', None
    
    if system == 'windows':
        return 'windows', None
    
    return 'unknown', None


def check_python_version() -> bool:
    """Check if Python version is compatible."""
    print(f"{colorize('[INFO]', Colors.BLUE)} Checking Python version...")
    
    version = sys.version_info
    version_str = f"{version.major}.{version.minor}.{version.micro}"
    
    if version.major >= 3 and version.minor >= 9:
        print(f"{colorize('[✓]', Colors.GREEN)} Python {version_str} - OK")
        return True
    elif version.major >= 3 and version.minor >= 6:
        print(f"{colorize('[!]', Colors.YELLOW)} Python {version_str} - Works but 3.9+ recommended")
        return True
    else:
        print(f"{colorize('[✗]', Colors.RED)} Python {version_str} - Python 3.9+ required")
        return False


def check_nss_library() -> tuple[bool, str]:
    """Check if NSS library is available."""
    print(f"{colorize('[INFO]', Colors.BLUE)} Checking NSS library...")
    
    import ctypes
    
    nss_paths = [
        '/usr/lib/libnss3.so',
        '/usr/lib64/libnss3.so',
        '/usr/lib/x86_64-linux-gnu/libnss3.so',
        '/usr/lib/i386-linux-gnu/libnss3.so',
        '/opt/homebrew/lib/libnss3.dylib',
        '/usr/local/lib/libnss3.dylib',
        'libnss3.so',
        'nss3.dll',
    ]
    
    for path in nss_paths:
        try:
            ctypes.CDLL(path)
            print(f"{colorize('[✓]', Colors.GREEN)} NSS library found: {path}")
            return True, path
        except OSError:
            continue
    
    print(f"{colorize('[✗]', Colors.RED)} NSS library not found")
    return False, None


def check_firefox_installation() -> tuple[str, str]:
    """Check Firefox installation type."""
    print(f"{colorize('[INFO]', Colors.BLUE)} Checking Firefox installation...")
    
    home = Path.home()
    
    # Check for Snap
    snap_paths = [home / 'snap' / 'firefox', Path('/snap/firefox')]
    for path in snap_paths:
        if path.exists():
            print(f"{colorize('[!]', Colors.YELLOW)} Snap Firefox detected: {path}")
            return 'snap', str(path)
    
    # Check for Flatpak
    flatpak_path = home / '.var' / 'app' / 'org.mozilla.firefox'
    if flatpak_path.exists():
        print(f"{colorize('[!]', Colors.YELLOW)} Flatpak Firefox detected: {flatpak_path}")
        return 'flatpak', str(flatpak_path)
    
    # Check for native
    native_paths = [Path('/usr/bin/firefox'), Path('/usr/lib/firefox')]
    for path in native_paths:
        if path.exists():
            print(f"{colorize('[✓]', Colors.GREEN)} Native Firefox found: {path}")
            return 'native', str(path)
    
    print(f"{colorize('[!]', Colors.YELLOW)} Firefox installation not detected")
    return 'unknown', None


def install_nss_library(os_type: str, install_cmd: str) -> bool:
    """Install NSS library using system package manager."""
    if not install_cmd:
        print(f"{colorize('[✗]', Colors.RED)} No package manager command available for {os_type}")
        print_manual_install_instructions()
        return False
    
    print(f"{colorize('[INFO]', Colors.BLUE)} Installing NSS library...")
    print(f"    Command: {install_cmd}")
    
    response = input("\nProceed with installation? [Y/n] ").strip().lower()
    if response in ('n', 'no'):
        print(f"{colorize('[!]', Colors.YELLOW)} Installation skipped")
        return False
    
    try:
        # Run the install command
        subprocess.run(install_cmd, shell=True, check=True)
        print(f"{colorize('[✓]', Colors.GREEN)} NSS library installed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"{colorize('[✗]', Colors.RED)} Installation failed: {e}")
        return False


def print_manual_install_instructions():
    """Print manual installation instructions."""
    print(f"""
{colorize('Manual Installation Instructions:', Colors.BOLD)}

  Arch Linux / Manjaro:
    sudo pacman -S nss

  Ubuntu / Debian / Linux Mint:
    sudo apt install libnss3

  Fedora / RHEL / CentOS:
    sudo dnf install nss

  openSUSE:
    sudo zypper install mozilla-nss

  macOS (Homebrew):
    brew install nss

  Windows:
    NSS is typically bundled with Firefox on Windows.
    Make sure Firefox is installed.
""")


def print_snap_flatpak_warning(install_type: str):
    """Print warning about Snap/Flatpak Firefox."""
    if install_type == 'snap':
        print(colorize("""
╔══════════════════════════════════════════════════════════════════════╗
║  ⚠️  WARNING: Snap Firefox Detected                                  ║
╠══════════════════════════════════════════════════════════════════════╣
║  Password decryption will NOT work with Snap Firefox.               ║
║  Snap Firefox uses its own bundled NSS library in a sandbox.        ║
║                                                                     ║
║  Options:                                                           ║
║  1. Export passwords via Firefox UI (Settings → Passwords)         ║
║  2. Install native Firefox instead of Snap                          ║
╚══════════════════════════════════════════════════════════════════════╝
""", Colors.YELLOW))
    
    elif install_type == 'flatpak':
        print(colorize("""
╔══════════════════════════════════════════════════════════════════════╗
║  ⚠️  WARNING: Flatpak Firefox Detected                               ║
╠══════════════════════════════════════════════════════════════════════╣
║  Password decryption will NOT work with Flatpak Firefox.            ║
║  Flatpak Firefox uses its own bundled NSS library in a sandbox.     ║
║                                                                     ║
║  Options:                                                           ║
║  1. Export passwords via Firefox UI (Settings → Passwords)         ║
║  2. Install native Firefox instead of Flatpak                       ║
╚══════════════════════════════════════════════════════════════════════╝
""", Colors.YELLOW))


def print_success():
    """Print success message and usage instructions."""
    print(colorize("""
╔══════════════════════════════════════════════════════════════════════╗
║  ✅ Setup Complete!                                                   ║
╚══════════════════════════════════════════════════════════════════════╝
""", Colors.GREEN))
    
    print(f"""{colorize('Usage:', Colors.BOLD)}
  
  # Extract all forensic data:
  python3 main.py ~/.mozilla/firefox/your-profile/

  # Check environment compatibility:
  python3 main.py --check-env ~/.mozilla/firefox/your-profile/

  # Decrypt passwords only:
  python3 nss_decrypt.py ~/.mozilla/firefox/your-profile/

  # Auto-detect and select profile:
  python3 main.py
""")


def main():
    """Main installation function."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Firefox Forensics Tool Setup')
    parser.add_argument('--check', action='store_true', help='Check environment only')
    args = parser.parse_args()
    
    print_banner()
    
    # Detect OS
    os_type, install_cmd = detect_os()
    print(f"{colorize('[INFO]', Colors.BLUE)} Detected OS: {os_type}")
    
    # Check Python version
    if not check_python_version():
        print(f"\n{colorize('[✗]', Colors.RED)} Please install Python 3.9 or higher")
        return 1
    
    # Check NSS library
    nss_ok, nss_path = check_nss_library()
    
    # Check Firefox installation
    ff_type, ff_path = check_firefox_installation()
    
    # Show warnings for Snap/Flatpak
    if ff_type in ('snap', 'flatpak'):
        print_snap_flatpak_warning(ff_type)
    
    # If only checking, exit here
    if args.check:
        print(f"\n{colorize('Summary:', Colors.BOLD)}")
        print(f"  Python:  {'✓' if True else '✗'}")
        print(f"  NSS:     {'✓' if nss_ok else '✗'}")
        print(f"  Firefox: {ff_type}")
        return 0 if nss_ok else 1
    
    # Install NSS if missing
    if not nss_ok:
        if os_type == 'windows':
            print(f"\n{colorize('[INFO]', Colors.BLUE)} Windows detected")
            print("NSS is typically bundled with Firefox on Windows.")
            print("Make sure Firefox is installed, or install NSS manually.")
        else:
            print(f"\n{colorize('[INFO]', Colors.BLUE)} NSS library needs to be installed")
            if install_nss_library(os_type, install_cmd):
                nss_ok, _ = check_nss_library()
    
    if nss_ok:
        print_success()
        return 0
    else:
        print(f"\n{colorize('[!]', Colors.YELLOW)} Setup completed with warnings")
        print("Password decryption may not work without NSS library.")
        print_manual_install_instructions()
        return 1


if __name__ == '__main__':
    sys.exit(main())
