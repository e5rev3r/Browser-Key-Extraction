#!/usr/bin/env python3
"""Browser Forensics Extraction Tool.

A comprehensive Python utility for extracting and analyzing forensic artifacts
from web browsers including Firefox and Chromium-based browsers.

Supported browsers:
- Firefox (Gecko engine)
- Chrome, Chromium, Edge, Brave, Opera, Vivaldi (Chromium engine)

Usage:
    python main.py                    # Auto-detect all browsers
    python main.py -b firefox         # Firefox only
    python main.py -b chrome          # Chrome only
    python main.py /path/to/profile   # Specific profile path
    python main.py --list-browsers    # List detected browsers
"""

import argparse
import csv
import logging
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple


# =============================================================================
# Auto Dependency Checker - Runs on startup
# =============================================================================

def check_and_install_dependencies():
    """Check and install required dependencies automatically."""
    missing = []
    
    # Check pycryptodome (required for Chromium password decryption)
    try:
        from Crypto.Cipher import AES
    except ImportError:
        missing.append("pycryptodome")
    
    # Check secretstorage (optional for Linux GNOME keyring)
    if sys.platform == "linux":
        try:
            import secretstorage
        except ImportError:
            pass  # Optional, don't add to missing
    
    if missing:
        print(f"\033[93m[!] Missing dependencies: {', '.join(missing)}\033[0m")
        print(f"\033[96m[*] Installing automatically...\033[0m")
        
        try:
            for pkg in missing:
                subprocess.check_call(
                    [sys.executable, "-m", "pip", "install", "--quiet", pkg],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
            print(f"\033[92m[+] Dependencies installed successfully!\033[0m\n")
        except subprocess.CalledProcessError:
            print(f"\033[91m[!] Failed to install. Run: pip install {' '.join(missing)}\033[0m")
            print(f"\033[93m[*] Continuing without Chromium password decryption...\033[0m\n")
        except Exception as e:
            print(f"\033[91m[!] Install error: {e}\033[0m\n")


# Run dependency check on import
check_and_install_dependencies()

from browser_profiles import (
    BrowserProfile, BrowserType, BrowserFamily, BrowserInstallation,
    detect_all_browsers, detect_browser_from_path,
)
from extractors import FirefoxExtractor, ChromiumExtractor
from sql_queries import FIREFOX_QUERIES, CHROMIUM_QUERIES


def setup_logging(log_level: int = logging.INFO) -> logging.Logger:
    """Configure logging for the forensics tool."""
    logger = logging.getLogger("browser_forensics")
    logger.setLevel(log_level)
    handler = logging.StreamHandler()
    handler.setLevel(log_level)
    handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
    logger.addHandler(handler)
    return logger


# =============================================================================
# ANSI Colors for Terminal Output
# =============================================================================

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    RESET = '\033[0m'


def colorize(text: str, color: str) -> str:
    """Apply color to text if terminal supports it."""
    return f"{color}{text}{Colors.RESET}" if sys.stdout.isatty() else text


def safe_print(text: str):
    """Print with fallback for encoding issues."""
    try:
        print(text)
    except UnicodeEncodeError:
        print(text.encode('ascii', 'replace').decode('ascii'))


# =============================================================================
# UI Functions
# =============================================================================

def print_banner():
    """Print the tool banner."""
    banner = f"""
{colorize('=' * 72, Colors.CYAN)}
{colorize('  BROWSER FORENSICS EXTRACTION TOOL', Colors.BOLD + Colors.WHITE)}
{colorize('  Firefox | Chrome | Edge | Brave | Opera | Vivaldi', Colors.YELLOW)}
{colorize('=' * 72, Colors.CYAN)}
"""
    safe_print(banner)


def print_system_info():
    """Print system information."""
    import platform
    print(f"\n{colorize('[*] System:', Colors.CYAN)} {platform.system()} {platform.release()} ({platform.machine()})")


def print_goodbye():
    """Print goodbye message."""
    print(f"\n{colorize('Thank you for using Browser Forensics Tool!', Colors.CYAN)}")


def print_detected_browsers(installations: List[BrowserInstallation], filter_browser: str = None) -> Optional[Dict[int, BrowserProfile]]:
    """Print detected browsers and return a map of index to profile."""
    if filter_browser and filter_browser != "auto":
        installations = [i for i in installations if i.browser_type.value.lower() == filter_browser.lower()]

    if not installations:
        print(f"\n{colorize('[!] No browsers detected.', Colors.RED)}")
        return None

    total_profiles = sum(len(i.profiles) for i in installations)
    print(f"\n{colorize('[+]', Colors.GREEN)} Found {colorize(str(len(installations)), Colors.YELLOW)} browser(s) with {colorize(str(total_profiles), Colors.YELLOW)} profile(s)")
    print(f"\n{colorize('Available Profiles:', Colors.CYAN)}")
    print(colorize('─' * 50, Colors.CYAN))

    idx = 1
    profile_map = {}

    for installation in installations:
        family = "Gecko" if installation.browser_family == BrowserFamily.GECKO else "Chromium"
        print(f"\n  {colorize(installation.browser_type.value.upper(), Colors.BOLD + Colors.WHITE)} ({family})")

        for profile in installation.profiles:
            default = colorize(' (default)', Colors.GREEN) if profile.is_default else ''
            name = profile.display_name.split(" - ", 1)[1] if " - " in profile.display_name else profile.profile_name
            print(f"    {colorize(f'[{idx}]', Colors.YELLOW)} {name}{default}")
            profile_map[idx] = profile
            idx += 1

    print(f"\n  {colorize('[0]', Colors.RED)} Exit")
    return profile_map


def prompt_browser_selection(filter_browser: str = None) -> Optional[BrowserProfile]:
    """Prompt user to select a browser profile."""
    print_system_info()
    print(f"\n{colorize('[*] Scanning for browsers...', Colors.CYAN)}")
    
    installations = detect_all_browsers()
    profile_map = print_detected_browsers(installations, filter_browser)

    if not profile_map:
        return None

    default_idx = next((i for i, p in profile_map.items() if p.is_default), 1)

    while True:
        try:
            response = input(f"\n{colorize('?', Colors.GREEN)} Select profile [{default_idx}]: ").strip()
            if not response:
                return profile_map[default_idx]
            if response == '0':
                return None
            choice = int(response)
            if choice in profile_map:
                print(f"  {colorize('[+]', Colors.GREEN)} Selected: {profile_map[choice].display_name}")
                return profile_map[choice]
            print(f"  {colorize('Invalid choice', Colors.YELLOW)}")
        except (ValueError, KeyboardInterrupt, EOFError):
            print()
            return None


# =============================================================================
# Terminal Display Functions
# =============================================================================

def print_history(rows: List[Dict], limit: int = 50):
    """Print browsing history to terminal."""
    if not rows:
        print(f"\n{colorize('[*] No history found.', Colors.YELLOW)}")
        return

    print(f"\n{colorize('[BROWSING HISTORY]', Colors.BOLD + Colors.CYAN)} ({len(rows)} entries)")
    print(colorize('─' * 70, Colors.CYAN))

    for i, row in enumerate(rows[:limit], 1):
        url = str(row.get('url', row.get('URL', 'N/A')))[:70]
        title = str(row.get('title', row.get('Title', '')))[:50]
        time = row.get('visit_time', row.get('last_visit', ''))
        print(f"  {colorize(f'[{i}]', Colors.YELLOW)} {title}")
        print(f"      {colorize('URL:', Colors.CYAN)} {url}")
        if time:
            print(f"      {colorize('Time:', Colors.CYAN)} {time}")

    if len(rows) > limit:
        print(f"\n  ... and {len(rows) - limit} more entries")


def print_cookies(rows: List[Dict], limit: int = 50):
    """Print cookies to terminal."""
    if not rows:
        print(f"\n{colorize('[*] No cookies found.', Colors.YELLOW)}")
        return

    print(f"\n{colorize('[COOKIES]', Colors.BOLD + Colors.MAGENTA)} ({len(rows)} entries)")
    print(colorize('─' * 70, Colors.MAGENTA))

    for i, row in enumerate(rows[:limit], 1):
        host = row.get('host', row.get('host_key', 'N/A'))
        name = row.get('name', 'N/A')
        expires = row.get('expires', row.get('expiry', 'Session'))
        print(f"  {colorize(f'[{i}]', Colors.YELLOW)} {host} - {name}")
        print(f"      {colorize('Expires:', Colors.CYAN)} {expires}")

    if len(rows) > limit:
        print(f"\n  ... and {len(rows) - limit} more cookies")


def print_downloads(rows: List[Dict], limit: int = 30):
    """Print downloads to terminal."""
    if not rows:
        print(f"\n{colorize('[*] No downloads found.', Colors.YELLOW)}")
        return

    print(f"\n{colorize('[DOWNLOADS]', Colors.BOLD + Colors.GREEN)} ({len(rows)} entries)")
    print(colorize('─' * 70, Colors.GREEN))

    for i, row in enumerate(rows[:limit], 1):
        target = row.get('target_path', row.get('target', 'N/A'))
        filename = Path(str(target)).name if target else "Unknown"
        url = str(row.get('url', row.get('download_url', '')))[:60]
        print(f"  {colorize(f'[{i}]', Colors.YELLOW)} {filename}")
        print(f"      {colorize('URL:', Colors.CYAN)} {url}")

    if len(rows) > limit:
        print(f"\n  ... and {len(rows) - limit} more downloads")


def print_bookmarks(rows: List[Dict], limit: int = 50):
    """Print bookmarks to terminal."""
    if not rows:
        print(f"\n{colorize('[*] No bookmarks found.', Colors.YELLOW)}")
        return

    print(f"\n{colorize('[BOOKMARKS]', Colors.BOLD + Colors.BLUE)} ({len(rows)} entries)")
    print(colorize('─' * 70, Colors.BLUE))

    for i, row in enumerate(rows[:limit], 1):
        title = str(row.get('title', row.get('name', '')))[:50]
        url = str(row.get('url', ''))[:60]
        print(f"  {colorize(f'[{i}]', Colors.YELLOW)} {title}")
        print(f"      {colorize('URL:', Colors.CYAN)} {url}")

    if len(rows) > limit:
        print(f"\n  ... and {len(rows) - limit} more bookmarks")


def print_autofill(rows: List[Dict], limit: int = 50):
    """Print autofill data to terminal."""
    if not rows:
        print(f"\n{colorize('[*] No autofill data found.', Colors.YELLOW)}")
        return

    print(f"\n{colorize('[AUTOFILL DATA]', Colors.BOLD + Colors.YELLOW)} ({len(rows)} entries)")
    print(colorize('─' * 70, Colors.YELLOW))

    for i, row in enumerate(rows[:limit], 1):
        field = row.get('name', row.get('fieldname', 'N/A'))
        value = str(row.get('value', ''))[:50]
        count = row.get('count', row.get('timesUsed', ''))
        print(f"  {colorize(f'[{i}]', Colors.YELLOW)} {field}: {colorize(value, Colors.GREEN)}")
        if count:
            print(f"      {colorize('Used:', Colors.CYAN)} {count} times")

    if len(rows) > limit:
        print(f"\n  ... and {len(rows) - limit} more entries")


def print_passwords_firefox(passwords: List):
    """Print decrypted Firefox passwords."""
    if not passwords:
        print(f"\n{colorize('[*] No saved passwords found.', Colors.YELLOW)}")
        return

    print(f"\n{colorize('=' * 70, Colors.RED)}")
    print(f"{colorize('[!] DECRYPTED PASSWORDS', Colors.BOLD + Colors.RED)}")
    print(f"{colorize('=' * 70, Colors.RED)}")

    for i, pwd in enumerate(passwords, 1):
        print(f"\n{colorize(f'[{i}]', Colors.YELLOW)} {colorize(pwd.hostname, Colors.MAGENTA)}")
        print(f"    {colorize('Username:', Colors.CYAN)} {colorize(pwd.username, Colors.GREEN + Colors.BOLD)}")
        print(f"    {colorize('Password:', Colors.CYAN)} {colorize(pwd.password, Colors.RED + Colors.BOLD)}")
        if pwd.times_used:
            print(f"    {colorize('Times Used:', Colors.CYAN)} {pwd.times_used}")

    print(f"\n{colorize('═' * 70, Colors.RED)}")
    print(f"{colorize(f'Total: {len(passwords)} password(s) decrypted', Colors.BOLD + Colors.RED)}")


def print_passwords_chromium(credentials: List):
    """Print decrypted Chromium passwords."""
    if not credentials:
        print(f"\n{colorize('[*] No saved passwords found.', Colors.YELLOW)}")
        return

    print(f"\n{colorize('=' * 70, Colors.RED)}")
    print(f"{colorize('[!] DECRYPTED PASSWORDS', Colors.BOLD + Colors.RED)}")
    print(f"{colorize('=' * 70, Colors.RED)}")

    for i, cred in enumerate(credentials, 1):
        print(f"\n{colorize(f'[{i}]', Colors.YELLOW)} {colorize(cred.signon_realm, Colors.MAGENTA)}")
        print(f"    {colorize('URL:', Colors.CYAN)} {cred.url}")
        print(f"    {colorize('Username:', Colors.CYAN)} {colorize(cred.username, Colors.GREEN + Colors.BOLD)}")
        print(f"    {colorize('Password:', Colors.CYAN)} {colorize(cred.password, Colors.RED + Colors.BOLD)}")
        if cred.times_used:
            print(f"    {colorize('Times Used:', Colors.CYAN)} {cred.times_used}")

    print(f"\n{colorize('═' * 70, Colors.RED)}")
    print(f"{colorize(f'Total: {len(credentials)} password(s) decrypted', Colors.BOLD + Colors.RED)}")


# =============================================================================
# Extraction Functions
# =============================================================================

def extract_firefox(
    profile_path: Path,
    output_dir: Path,
    logger: logging.Logger,
    skip_passwords: bool = False,
    print_only: bool = False,
    categories: List[str] = None,
) -> bool:
    """Extract data from a Firefox profile."""
    
    if categories is None:
        categories = ['all']
    extract_all = 'all' in categories

    print(f"\n{colorize('=' * 60, Colors.CYAN)}")
    print(f"{colorize('Extracting from Firefox', Colors.CYAN)}")
    print(f"{colorize(f'Profile: {profile_path.name}', Colors.WHITE)}")
    print(f"{colorize('=' * 60, Colors.CYAN)}\n")

    extractor = FirefoxExtractor(profile_path)
    all_data = {}

    # Extract data
    print(f"{colorize('[*] Extracting data...', Colors.CYAN)}")

    if extract_all or 'history' in categories:
        data = extractor.get_history()
        if data:
            all_data['history'] = data
            print(f"  {colorize('✓', Colors.GREEN)} History: {len(data)} records")
            if print_only:
                print_history(data)

    if extract_all or 'cookies' in categories:
        data = extractor.get_cookies()
        if data:
            all_data['cookies'] = data
            print(f"  {colorize('✓', Colors.GREEN)} Cookies: {len(data)} records")
            if print_only:
                print_cookies(data)

    if extract_all or 'bookmarks' in categories:
        data = extractor.get_bookmarks()
        if data:
            all_data['bookmarks'] = data
            print(f"  {colorize('✓', Colors.GREEN)} Bookmarks: {len(data)} records")
            if print_only:
                print_bookmarks(data)

    if extract_all or 'autofill' in categories or 'forms' in categories:
        data = extractor.get_form_history()
        if data:
            all_data['autofill'] = data
            print(f"  {colorize('✓', Colors.GREEN)} Autofill: {len(data)} records")
            if print_only:
                print_autofill(data)

    # Decrypt passwords
    if not skip_passwords and (extract_all or 'passwords' in categories):
        print(f"\n{colorize('[*] Attempting password decryption...', Colors.CYAN)}")
        try:
            from nss_decrypt import decrypt_firefox_passwords, validate_environment, MasterPasswordRequired
            
            validate_environment(profile_path)
            passwords, error = decrypt_firefox_passwords(profile_path, "")
            
            if error and "master password" in error.lower():
                import getpass
                pwd = getpass.getpass(f"{colorize('Enter master password: ', Colors.YELLOW)}")
                if pwd:
                    passwords, error = decrypt_firefox_passwords(profile_path, pwd)
            
            if passwords:
                all_data['passwords'] = passwords
                print(f"  {colorize('✓', Colors.GREEN)} Passwords: {len(passwords)} decrypted")
                print_passwords_firefox(passwords)
            elif error:
                print(f"  {colorize('✗', Colors.RED)} {error}")
            else:
                print(f"  {colorize('•', Colors.YELLOW)} No saved passwords")
        except Exception as e:
            print(f"  {colorize('✗', Colors.RED)} Password decryption failed: {e}")

    if print_only:
        print_goodbye()
        return True

    # Save to files
    output_dir.mkdir(parents=True, exist_ok=True)
    csv_dir = output_dir / "csv"
    csv_dir.mkdir(exist_ok=True)

    print(f"\n{colorize('[*] Saving reports...', Colors.CYAN)}")
    
    for name, data in all_data.items():
        if name == 'passwords':
            continue  # Don't save passwords to CSV
        if data and isinstance(data, list) and isinstance(data[0], dict):
            csv_path = csv_dir / f"{name}.csv"
            with open(csv_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=data[0].keys())
                writer.writeheader()
                writer.writerows(data)
            print(f"  {colorize('✓', Colors.GREEN)} {csv_path.name}")

    # Summary
    summary_path = output_dir / "summary.txt"
    with open(summary_path, 'w') as f:
        f.write(f"Firefox Forensics Extraction\n{'=' * 40}\n\n")
        f.write(f"Profile: {profile_path}\n")
        f.write(f"Time: {datetime.now().isoformat()}\n\n")
        f.write("Extracted Data:\n")
        for name, data in all_data.items():
            count = len(data) if isinstance(data, list) else 1
            f.write(f"  {name}: {count} records\n")

    print(f"  {colorize('✓', Colors.GREEN)} summary.txt")

    print(f"\n{colorize('=' * 60, Colors.GREEN)}")
    print(f"{colorize('Extraction Complete!', Colors.GREEN)}")
    print(f"{colorize(f'Output: {output_dir}', Colors.WHITE)}")
    print(f"{colorize('=' * 60, Colors.GREEN)}")

    print_goodbye()
    return True


def extract_chromium(
    profile: BrowserProfile,
    output_dir: Path,
    logger: logging.Logger,
    skip_passwords: bool = False,
    print_only: bool = False,
    categories: List[str] = None,
) -> bool:
    """Extract data from a Chromium-based browser profile."""
    
    if categories is None:
        categories = ['all']
    extract_all = 'all' in categories

    browser_name = profile.browser_type.value
    profile_name = profile.display_name.split(" - ", 1)[1] if " - " in profile.display_name else profile.profile_name

    print(f"\n{colorize('=' * 60, Colors.CYAN)}")
    print(f"{colorize(f'Extracting from {browser_name}', Colors.CYAN)}")
    print(f"{colorize(f'Profile: {profile_name}', Colors.WHITE)}")
    print(f"{colorize('=' * 60, Colors.CYAN)}\n")

    all_data = {}

    with ChromiumExtractor(profile.profile_path, profile.user_data_dir) as extractor:
        print(f"{colorize('[*] Extracting data...', Colors.CYAN)}")

        if extract_all or 'history' in categories:
            data = extractor.get_history()
            if data:
                all_data['history'] = data
                print(f"  {colorize('✓', Colors.GREEN)} History: {len(data)} records")
                if print_only:
                    print_history(data)

        if extract_all or 'cookies' in categories:
            data = extractor.get_cookies()
            if data:
                all_data['cookies'] = data
                print(f"  {colorize('✓', Colors.GREEN)} Cookies: {len(data)} records")
                if print_only:
                    print_cookies(data)

        if extract_all or 'downloads' in categories:
            data = extractor.get_downloads()
            if data:
                all_data['downloads'] = data
                print(f"  {colorize('✓', Colors.GREEN)} Downloads: {len(data)} records")
                if print_only:
                    print_downloads(data)

        if extract_all or 'bookmarks' in categories:
            data = extractor.flatten_bookmarks()
            if data:
                all_data['bookmarks'] = data
                print(f"  {colorize('✓', Colors.GREEN)} Bookmarks: {len(data)} records")
                if print_only:
                    print_bookmarks(data)

        if extract_all or 'autofill' in categories or 'forms' in categories:
            data = extractor.get_autofill()
            if data:
                all_data['autofill'] = data
                print(f"  {colorize('✓', Colors.GREEN)} Autofill: {len(data)} records")
                if print_only:
                    print_autofill(data)

        if extract_all or 'extensions' in categories:
            data = extractor.get_extensions()
            if data:
                all_data['extensions'] = data
                print(f"  {colorize('✓', Colors.GREEN)} Extensions: {len(data)}")

    # Decrypt passwords
    if not skip_passwords and (extract_all or 'passwords' in categories):
        print(f"\n{colorize('[*] Attempting password decryption...', Colors.CYAN)}")
        try:
            from chromium_decrypt import decrypt_chromium_passwords, check_decryption_requirements
            
            reqs_met, missing = check_decryption_requirements()
            if not reqs_met:
                print(f"  {colorize('✗', Colors.RED)} Missing: {', '.join(missing)}")
            else:
                credentials, errors = decrypt_chromium_passwords(profile.profile_path, profile.user_data_dir)
                if credentials:
                    all_data['passwords'] = credentials
                    print(f"  {colorize('✓', Colors.GREEN)} Passwords: {len(credentials)} decrypted")
                    print_passwords_chromium(credentials)
                elif errors:
                    print(f"  {colorize('✗', Colors.RED)} {errors[0] if errors else 'Unknown error'}")
                else:
                    print(f"  {colorize('•', Colors.YELLOW)} No saved passwords")
        except Exception as e:
            print(f"  {colorize('✗', Colors.RED)} Password decryption failed: {e}")

    if print_only:
        print_goodbye()
        return True

    # Save to files
    output_dir.mkdir(parents=True, exist_ok=True)
    csv_dir = output_dir / "csv"
    csv_dir.mkdir(exist_ok=True)

    print(f"\n{colorize('[*] Saving reports...', Colors.CYAN)}")
    
    for name, data in all_data.items():
        if name == 'passwords':
            continue
        if data and isinstance(data, list) and len(data) > 0 and isinstance(data[0], dict):
            csv_path = csv_dir / f"{name}.csv"
            with open(csv_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=data[0].keys())
                writer.writeheader()
                writer.writerows(data)
            print(f"  {colorize('✓', Colors.GREEN)} {csv_path.name}")

    # Summary
    summary_path = output_dir / "summary.txt"
    with open(summary_path, 'w') as f:
        f.write(f"{browser_name} Forensics Extraction\n{'=' * 40}\n\n")
        f.write(f"Profile: {profile.profile_path}\n")
        f.write(f"Time: {datetime.now().isoformat()}\n\n")
        f.write("Extracted Data:\n")
        for name, data in all_data.items():
            count = len(data) if isinstance(data, list) else 1
            f.write(f"  {name}: {count} records\n")

    print(f"  {colorize('✓', Colors.GREEN)} summary.txt")

    print(f"\n{colorize('=' * 60, Colors.GREEN)}")
    print(f"{colorize('Extraction Complete!', Colors.GREEN)}")
    print(f"{colorize(f'Output: {output_dir}', Colors.WHITE)}")
    print(f"{colorize('=' * 60, Colors.GREEN)}")

    print_goodbye()
    return True


# =============================================================================
# Main Entry Point
# =============================================================================

def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)

    parser.add_argument("profile", nargs="?", help="Path to browser profile (auto-detect if not provided)")
    parser.add_argument("-b", "--browser", choices=["firefox", "chrome", "chromium", "edge", "brave", "opera", "vivaldi", "auto"], default="auto", help="Browser to extract from")
    parser.add_argument("--list-browsers", action="store_true", help="List detected browsers and exit")
    parser.add_argument("-o", "--output", help="Output directory")
    parser.add_argument("-e", "--extract", nargs="+", choices=["history", "cookies", "passwords", "downloads", "bookmarks", "autofill", "extensions", "all"], default=["all"], help="Categories to extract")
    parser.add_argument("--print-only", action="store_true", help="Print to terminal only (no files)")
    parser.add_argument("--no-passwords", action="store_true", help="Skip password decryption")
    parser.add_argument("-n", "--no-interactive", action="store_true", help="Disable interactive prompts")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("-q", "--quiet", action="store_true", help="Quiet output")
    parser.add_argument("--check-env", action="store_true", help="Check environment and exit")

    args = parser.parse_args()

    # Setup logging
    log_level = logging.DEBUG if args.verbose else logging.WARNING if args.quiet else logging.INFO
    logger = setup_logging(log_level)

    print_banner()

    # Handle --list-browsers
    if args.list_browsers:
        print_system_info()
        print(f"\n{colorize('[*] Scanning for browsers...', Colors.CYAN)}")
        installations = detect_all_browsers()
        print_detected_browsers(installations, args.browser if args.browser != "auto" else None)
        return 0

    # Handle --check-env
    if args.check_env:
        print(f"\n{colorize('Environment Check:', Colors.CYAN)}")
        
        # Chromium
        print(f"\n{colorize('Chromium Browsers:', Colors.YELLOW)}")
        try:
            from chromium_decrypt import check_decryption_requirements
            met, missing = check_decryption_requirements()
            print(f"  {colorize('✓', Colors.GREEN)} Ready" if met else f"  {colorize('✗', Colors.RED)} Missing: {', '.join(missing)}")
        except ImportError:
            print(f"  {colorize('✗', Colors.RED)} chromium_decrypt not found")

        # Firefox
        print(f"\n{colorize('Firefox:', Colors.YELLOW)}")
        try:
            from nss_decrypt import run_environment_check
            run_environment_check(Path(args.profile) if args.profile else None)
        except ImportError:
            print(f"  {colorize('✗', Colors.RED)} nss_decrypt not found")
        return 0

    # Determine profile
    if args.profile:
        profile_path = Path(args.profile).expanduser().resolve()
        if not profile_path.exists():
            print(f"{colorize('[!] Profile not found:', Colors.RED)} {profile_path}")
            return 1

        detected = detect_browser_from_path(profile_path)
        if detected:
            browser_type, browser_family = detected
            selected_profile = BrowserProfile(
                browser_type=browser_type,
                browser_family=browser_family,
                profile_name=profile_path.name,
                profile_path=profile_path,
                user_data_dir=profile_path.parent,
                display_name=f"{browser_type.value} - {profile_path.name}"
            )
        else:
            # Try to guess
            if (profile_path / "places.sqlite").exists():
                selected_profile = BrowserProfile(
                    browser_type=BrowserType.FIREFOX,
                    browser_family=BrowserFamily.GECKO,
                    profile_name=profile_path.name,
                    profile_path=profile_path,
                    user_data_dir=profile_path.parent,
                )
            elif (profile_path / "History").exists():
                selected_profile = BrowserProfile(
                    browser_type=BrowserType.CHROMIUM,
                    browser_family=BrowserFamily.CHROMIUM,
                    profile_name=profile_path.name,
                    profile_path=profile_path,
                    user_data_dir=profile_path.parent,
                )
            else:
                print(f"{colorize('[!] Could not determine browser type', Colors.RED)}")
                return 1
    else:
        selected_profile = prompt_browser_selection(args.browser if args.browser != "auto" else None)
        if selected_profile is None:
            print_goodbye()
            return 0

    # Determine output directory
    browser_name = selected_profile.browser_type.value.lower()
    if args.output:
        output_dir = Path(args.output)
    else:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = Path.home() / "Downloads" / f"{browser_name}_forensics_{timestamp}"

    # Run extraction
    try:
        if selected_profile.browser_family == BrowserFamily.GECKO:
            success = extract_firefox(
                selected_profile.profile_path,
                output_dir,
                logger,
                skip_passwords=args.no_passwords,
                print_only=args.print_only,
                categories=args.extract,
            )
        else:
            success = extract_chromium(
                selected_profile,
                output_dir,
                logger,
                skip_passwords=args.no_passwords,
                print_only=args.print_only,
                categories=args.extract,
            )
        return 0 if success else 1

    except KeyboardInterrupt:
        print(f"\n{colorize('Interrupted by user', Colors.YELLOW)}")
        print_goodbye()
        return 130
    except Exception as e:
        logger.exception(f"Error: {e}")
        print_goodbye()
        return 1


if __name__ == "__main__":
    sys.exit(main())
