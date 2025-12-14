#!/usr/bin/env python3
"""Firefox Forensics Extraction Tool.

A comprehensive Python utility for extracting and analyzing forensic artifacts
from Firefox profiles including browsing history, cookies, form data, permissions,
and more. Results are exported in multiple formats (HTML, CSV, Markdown).

Usage:
    python main.py /path/to/firefox/profile
    python main.py ~/.mozilla/firefox/xxxx.default-release
    python main.py --help

"""

import argparse
import logging
import sys
import os
from datetime import datetime
from pathlib import Path

from extractor import (
    FirefoxDatabaseExtractor,
    FirefoxJSONExtractor,
    ForensicReportGenerator,
    ExtractionResult,
)
from queries import QUERY_REGISTRY
from utils import (
    setup_logging,
    create_output_directory,
    validate_profile_path,
    expand_firefox_path,
    get_profile_info,
    format_bytes,
    ProgressTracker,
    sanitize_filename,
)
from formatters import (
    ForensicData,
    ReportGenerator,
    extract_credentials_from_data,
)
from nss_decrypt import (
    decrypt_firefox_passwords,
    check_master_password_required,
    DecryptedLogin,
    MasterPasswordRequired,
    UnsupportedEnvironment,
    NSSLibraryMissing,
    OSKeyringLocked,
    run_environment_check,
    validate_environment,
)


# ANSI color codes for terminal output
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    RESET = '\033[0m'


def colorize(text: str, color: str) -> str:
    """Apply color to text if terminal supports it."""
    if sys.stdout.isatty():
        return f"{color}{text}{Colors.RESET}"
    return text


def print_banner():
    """Print the tool banner."""
    banner = f"""
{colorize('╔══════════════════════════════════════════════════════════════════════╗', Colors.CYAN)}
{colorize('║', Colors.CYAN)}  {colorize('🔍 FIREFOX FORENSICS EXTRACTION TOOL', Colors.BOLD + Colors.WHITE)}                           {colorize('║', Colors.CYAN)}
{colorize('║', Colors.CYAN)}  {colorize('Extract • Analyze • Report', Colors.YELLOW)}                                       {colorize('║', Colors.CYAN)}
{colorize('╚══════════════════════════════════════════════════════════════════════╝', Colors.CYAN)}
"""
    print(banner)


def print_credentials_summary(credentials: list):
    """Print highlighted credentials to terminal."""
    if not credentials:
        print(f"\n{colorize('ℹ️  No credentials found in this profile.', Colors.YELLOW)}")
        return
    
    print(f"\n{colorize('═' * 70, Colors.RED)}")
    print(f"{colorize('🔐 CREDENTIALS & SENSITIVE DATA FOUND', Colors.BOLD + Colors.RED)}")
    print(f"{colorize('═' * 70, Colors.RED)}")
    
    for i, cred in enumerate(credentials, 1):
        print(f"\n{colorize(f'[{i}]', Colors.YELLOW)} {colorize(cred.get('type', 'Unknown'), Colors.MAGENTA)}")
        print(f"    {colorize('Source:', Colors.CYAN)} {cred.get('source', 'Unknown')}")
        print(f"    {colorize('Field:', Colors.CYAN)} {colorize(cred.get('field', 'Unknown'), Colors.YELLOW)}")
        print(f"    {colorize('Value:', Colors.CYAN)} {colorize(str(cred.get('value', '')), Colors.GREEN + Colors.BOLD)}")
        
        extra = cred.get('extra', {})
        if extra:
            for k, v in extra.items():
                print(f"    {colorize(f'{k}:', Colors.CYAN)} {v}")
    
    print(f"\n{colorize('═' * 70, Colors.RED)}")
    print(f"{colorize(f'Total: {len(credentials)} credential(s) found', Colors.BOLD + Colors.RED)}")
    print(f"{colorize('═' * 70, Colors.RED)}\n")


def print_decrypted_passwords(passwords: list):
    """Print decrypted Firefox passwords to terminal."""
    if not passwords:
        print(f"\n{colorize('ℹ️  No saved passwords found in this profile.', Colors.YELLOW)}")
        return
    
    print(f"\n{colorize('═' * 70, Colors.RED)}")
    print(f"{colorize('🔓 DECRYPTED SAVED PASSWORDS', Colors.BOLD + Colors.RED)}")
    print(f"{colorize('═' * 70, Colors.RED)}")
    
    for i, pwd in enumerate(passwords, 1):
        print(f"\n{colorize(f'[{i}]', Colors.YELLOW)} {colorize(pwd.hostname, Colors.MAGENTA)}")
        print(f"    {colorize('Username:', Colors.CYAN)} {colorize(pwd.username, Colors.GREEN + Colors.BOLD)}")
        print(f"    {colorize('Password:', Colors.CYAN)} {colorize(pwd.password, Colors.RED + Colors.BOLD)}")
        if pwd.times_used:
            print(f"    {colorize('Times Used:', Colors.CYAN)} {pwd.times_used}")
        if pwd.form_submit_url:
            print(f"    {colorize('Submit URL:', Colors.CYAN)} {pwd.form_submit_url}")
    
    print(f"\n{colorize('═' * 70, Colors.RED)}")
    print(f"{colorize(f'Total: {len(passwords)} saved password(s) decrypted', Colors.BOLD + Colors.RED)}")
    print(f"{colorize('═' * 70, Colors.RED)}\n")


def prompt_master_password() -> str:
    """Prompt user for Firefox master password."""
    import getpass
    print(f"\n{colorize('🔐 This profile has a master password set.', Colors.YELLOW)}")
    try:
        password = getpass.getpass(f"{colorize('?', Colors.GREEN)} Enter master password: ")
        return password
    except (KeyboardInterrupt, EOFError):
        print()
        return ""


def print_goodbye():
    """Print goodbye message."""
    print(f"\n{colorize('═' * 70, Colors.CYAN)}")
    print(f"{colorize('👋 Thank you for using Firefox Forensics Tool!', Colors.BOLD + Colors.CYAN)}")
    print(f"{colorize('   Goodbye!', Colors.CYAN)}")
    print(f"{colorize('═' * 70, Colors.CYAN)}\n")


def prompt_yes_no(question: str, default: bool = True) -> bool:
    """Prompt user for yes/no answer."""
    default_str = "Y/n" if default else "y/N"
    prompt = f"{colorize('?', Colors.GREEN)} {question} [{default_str}]: "
    
    while True:
        try:
            response = input(prompt).strip().lower()
            if not response:
                return default
            if response in ['y', 'yes']:
                return True
            if response in ['n', 'no']:
                return False
            print(f"  {colorize('Please enter y or n', Colors.YELLOW)}")
        except (KeyboardInterrupt, EOFError):
            print()
            return False


def prompt_path(question: str, default: str = None) -> Path:
    """Prompt user for a directory path.
    
    Returns:
        Path object or None if user wants to exit (entered 0).
    """
    default_display = f" [{default}]" if default else ""
    prompt = f"{colorize('?', Colors.GREEN)} {question}{default_display} (enter {colorize('0', Colors.YELLOW)} to exit): "
    
    while True:
        try:
            response = input(prompt).strip()
            
            # Check for exit
            if response == '0':
                return None
            
            if not response and default:
                response = default
            
            if not response:
                print(f"  {colorize('Please enter a path or 0 to exit', Colors.YELLOW)}")
                continue
            
            # Expand ~ and environment variables
            expanded = os.path.expanduser(os.path.expandvars(response))
            path = Path(expanded)
            
            # Check if directory exists
            if path.exists():
                if path.is_dir():
                    return path
                else:
                    print(f"  {colorize(f'{path} exists but is not a directory', Colors.RED)}")
                    continue
            
            # Directory doesn't exist - ask permission to create
            print(f"  {colorize(f'Directory does not exist:', Colors.YELLOW)} {path}")
            create = prompt_yes_no(f"Create directory '{path}'?")
            
            if create:
                try:
                    path.mkdir(parents=True, exist_ok=True)
                    print(f"  {colorize('✓', Colors.GREEN)} Directory created: {path}")
                    return path
                except Exception as e:
                    print(f"  {colorize(f'Cannot create directory: {e}', Colors.RED)}")
                    # Ask for another path
                    continue
            else:
                # User doesn't want to create - ask for another path
                print(f"  {colorize('Please enter a different path or 0 to exit', Colors.YELLOW)}")
                continue
                
        except (KeyboardInterrupt, EOFError):
            print()
            return None


def get_firefox_profiles() -> list:
    """Read Firefox profiles.ini and return list of profiles.
    
    Returns:
        List of dicts with profile info: {'name': str, 'path': str, 'is_default': bool, 'full_path': Path}
    """
    import configparser
    
    firefox_dir = Path.home() / ".mozilla" / "firefox"
    profiles_ini = firefox_dir / "profiles.ini"
    
    if not profiles_ini.exists():
        return []
    
    profiles = []
    default_path = None
    
    try:
        config = configparser.ConfigParser()
        config.read(profiles_ini)
        
        # First pass: find the default path from Install sections
        for section in config.sections():
            if section.startswith('Install'):
                if config.has_option(section, 'Default'):
                    default_path = config.get(section, 'Default')
                    break
        
        # Second pass: collect all profiles
        for section in config.sections():
            if section.startswith('Profile'):
                name = config.get(section, 'Name', fallback='Unknown')
                path = config.get(section, 'Path', fallback='')
                is_relative = config.getboolean(section, 'IsRelative', fallback=True)
                
                if is_relative:
                    full_path = firefox_dir / path
                else:
                    full_path = Path(path)
                
                # Check if this is the default profile
                is_default = (path == default_path) if default_path else False
                
                if full_path.exists():
                    profiles.append({
                        'name': name,
                        'path': path,
                        'is_default': is_default,
                        'full_path': full_path
                    })
    except Exception:
        return []
    
    return profiles


def prompt_profile_selection() -> Path:
    """Prompt user to select a Firefox profile.
    
    Returns:
        Path to selected profile or None if cancelled.
    """
    profiles = get_firefox_profiles()
    
    if not profiles:
        print(f"{colorize('No Firefox profiles found in ~/.mozilla/firefox/', Colors.RED)}")
        return None
    
    print(f"\n{colorize('Available Firefox Profiles:', Colors.CYAN)}")
    print(f"{colorize('─' * 50, Colors.CYAN)}")
    
    for i, profile in enumerate(profiles, 1):
        default_marker = colorize(' (default)', Colors.GREEN + Colors.BOLD) if profile['is_default'] else ''
        print(f"  {colorize(f'[{i}]', Colors.YELLOW)} {profile['name']}{default_marker}")
        print(f"      {colorize('Path:', Colors.CYAN)} {profile['path']}")
    
    print(f"  {colorize('[0]', Colors.RED)} Exit")
    print()
    
    # Find default profile index
    default_idx = next((i for i, p in enumerate(profiles, 1) if p['is_default']), 1)
    
    prompt = f"{colorize('?', Colors.GREEN)} Select profile [{default_idx}]: "
    
    while True:
        try:
            response = input(prompt).strip()
            
            if not response:
                # Use default
                return profiles[default_idx - 1]['full_path']
            
            if response == '0':
                return None
            
            try:
                choice = int(response)
                if 1 <= choice <= len(profiles):
                    selected = profiles[choice - 1]
                    print(f"  {colorize('✓', Colors.GREEN)} Selected: {selected['name']}")
                    return selected['full_path']
                else:
                    print(f"  {colorize(f'Please enter a number between 1 and {len(profiles)}, or 0 to exit', Colors.YELLOW)}")
            except ValueError:
                print(f"  {colorize('Please enter a valid number', Colors.YELLOW)}")
                
        except (KeyboardInterrupt, EOFError):
            print()
            return None


def prompt_formats() -> list:
    """Prompt user for output formats."""
    print(f"\n{colorize('Select output formats:', Colors.CYAN)}")
    print(f"  {colorize('[1]', Colors.YELLOW)} HTML  - Interactive web report with styling")
    print(f"  {colorize('[2]', Colors.YELLOW)} CSV   - Spreadsheet-compatible data files")
    print(f"  {colorize('[3]', Colors.YELLOW)} MD    - Markdown documentation")
    print(f"  {colorize('[A]', Colors.GREEN)} All formats (recommended)")
    
    prompt = f"{colorize('?', Colors.GREEN)} Enter choices (e.g., 1,2,3 or A) [A]: "
    
    while True:
        try:
            response = input(prompt).strip().upper()
            if not response or response == 'A':
                return ['html', 'csv', 'md']
            
            formats = []
            for choice in response.replace(' ', '').split(','):
                if choice == '1':
                    formats.append('html')
                elif choice == '2':
                    formats.append('csv')
                elif choice == '3':
                    formats.append('md')
                elif choice == 'A':
                    return ['html', 'csv', 'md']
            
            if formats:
                return list(set(formats))  # Remove duplicates
            
            print(f"  {colorize('Invalid choice. Enter 1, 2, 3, or A', Colors.YELLOW)}")
            
        except (KeyboardInterrupt, EOFError):
            print()
            return ['html', 'csv', 'md']


def extract_databases(
    extractor: FirefoxDatabaseExtractor,
    output_dir: Path,
    logger: logging.Logger,
) -> tuple:
    """Extract all SQLite databases from profile.
    
    Returns:
        Tuple of (results list, queries dict)
    """
    results = []
    all_queries = {}    # {query_name: [rows]} - Only store query results, not raw tables
    
    db_paths = extractor.find_databases()
    total_tables = 0
    total_rows = 0

    logger.info(f"Found {len(db_paths)} SQLite databases")

    for db_path in db_paths:
        db_name = db_path.stem
        logger.info(f"Processing {db_path.name}...")

        # Get tables
        tables = extractor.get_tables(db_path)
        logger.info(f"  Found {len(tables)} tables")
        total_tables += len(tables)

        # Run forensic queries for this database (this is what we really need)
        query_results = {}
        if db_path.name in QUERY_REGISTRY:
            queries = QUERY_REGISTRY[db_path.name]
            for query_name, query_sql in queries.items():
                try:
                    rows, row_count = extractor.run_forensic_query(db_path, query_sql)
                    if rows:
                        all_queries[query_name] = rows
                        query_results[query_name] = row_count
                        total_rows += row_count
                        logger.debug(f"    Query '{query_name}': {row_count} rows")
                except Exception as e:
                    logger.error(f"    Error executing query '{query_name}': {e}")

        results.append(
            ExtractionResult(
                success=True,
                database=db_path.name,
                rows_extracted=sum(query_results.values()) if query_results else 0,
                output_path=output_dir,
            )
        )

    return results, all_queries, total_tables, total_rows


def extract_json_artifacts(
    extractor: FirefoxDatabaseExtractor,
    output_dir: Path,
    logger: logging.Logger,
) -> dict:
    """Extract and process JSON files from profile.
    
    Returns:
        Dictionary of JSON data.
    """
    json_data = {}
    json_paths = extractor.find_json_files()

    if not json_paths:
        logger.info("No JSON files found in profile")
        return json_data

    logger.info(f"Found {len(json_paths)} JSON files")
    artifacts_dir = output_dir / "artifacts"
    artifacts_dir.mkdir(exist_ok=True)

    for json_path in json_paths:
        logger.info(f"Processing {json_path.name}...")

        # Parse JSON based on filename
        if json_path.name in ["extensions.json", "addons.json"]:
            summary = FirefoxJSONExtractor.parse_extensions(json_path)
        elif json_path.name == "search.json":
            summary = FirefoxJSONExtractor.parse_search_engines(json_path)
        else:
            summary = FirefoxJSONExtractor.parse_json_file(json_path)

        json_data[json_path.name] = summary

        # Save processed JSON
        output_path = artifacts_dir / json_path.name
        FirefoxJSONExtractor.save_json_report(summary, output_path)
        logger.debug(f"  Saved processed JSON to {output_path.name}")

    return json_data


def extract_profile(
    profile_path: Path,
    output_dir: Path,
    logger: logging.Logger,
    formats: list = None,
    interactive: bool = True,
    format_provided: bool = False,
    output_provided: bool = False,
) -> bool:
    """Main orchestration function for profile extraction.
    
    Args:
        profile_path: Path to Firefox profile.
        output_dir: Output directory path.
        logger: Logger instance.
        formats: List of output formats ['html', 'csv', 'md']
        interactive: Whether to prompt for user input.
        format_provided: Whether -f flag was provided (skip format prompt).
        output_provided: Whether -o flag was provided (skip output prompt).
    
    Returns:
        True if extraction completed successfully.
    """
    if formats is None:
        formats = ['html', 'csv', 'md']
    
    print_banner()

    # Validate profile
    logger.info(f"Validating profile at {profile_path}...")
    if not validate_profile_path(profile_path):
        logger.error(f"Invalid Firefox profile: {profile_path}")
        return False

    # Get profile info
    profile_info = get_profile_info(profile_path)
    
    print(f"{colorize('📁 Profile:', Colors.CYAN)} {profile_info['name']}")
    print(f"{colorize('📍 Path:', Colors.CYAN)} {profile_path}")
    print(f"{colorize('💾 Size:', Colors.CYAN)} {profile_info.get('total_size_formatted', 'unknown')}")
    print(f"{colorize('📄 Files:', Colors.CYAN)} {profile_info.get('file_count', 'unknown')}")
    print()

    # Interactive prompts
    if interactive:
        # Only prompt for formats if -f flag was not provided
        if not format_provided:
            formats = prompt_formats()
        
        # Always save to disk, but ask for path if -o was not provided
        if not output_provided:
            output_dir = prompt_path(
                "Enter output directory",
                default=str(output_dir)
            )
            if output_dir is None:
                # User entered 0 to exit
                print_goodbye()
                return False

    # Create output directories
    print(f"\n{colorize('Creating output directory:', Colors.CYAN)} {output_dir}")
    output_dir.mkdir(parents=True, exist_ok=True)

    # Initialize extractor
    try:
        extractor = FirefoxDatabaseExtractor(profile_path)
    except Exception as e:
        logger.error(f"Failed to initialize extractor: {e}")
        return False

    # Extract databases
    print(f"\n{colorize('═' * 70, Colors.BLUE)}")
    print(f"{colorize('📊 Extracting SQLite Databases', Colors.BOLD + Colors.BLUE)}")
    print(f"{colorize('═' * 70, Colors.BLUE)}")
    db_results, all_queries, total_tables, total_rows = extract_databases(extractor, output_dir, logger)

    # Extract JSON artifacts
    print(f"\n{colorize('═' * 70, Colors.BLUE)}")
    print(f"{colorize('📄 Extracting JSON Artifacts', Colors.BOLD + Colors.BLUE)}")
    print(f"{colorize('═' * 70, Colors.BLUE)}")
    json_data = extract_json_artifacts(extractor, output_dir, logger)

    # Extract credentials from all data
    print(f"\n{colorize('═' * 70, Colors.MAGENTA)}")
    print(f"{colorize('🔐 Analyzing for Credentials', Colors.BOLD + Colors.MAGENTA)}")
    print(f"{colorize('═' * 70, Colors.MAGENTA)}")
    
    credentials = extract_credentials_from_data({}, all_queries, json_data)
    
    # Print credentials to terminal (highlighted)
    print_credentials_summary(credentials)

    # Decrypt saved passwords
    print(f"\n{colorize('═' * 70, Colors.RED)}")
    print(f"{colorize('🔓 Decrypting Saved Passwords', Colors.BOLD + Colors.RED)}")
    print(f"{colorize('═' * 70, Colors.RED)}")
    
    decrypted_passwords = []
    
    # Check environment before attempting decryption
    try:
        validate_environment(profile_path)
    except UnsupportedEnvironment as e:
        print(f"  {colorize('❌ UNSUPPORTED ENVIRONMENT', Colors.RED)}")
        print(f"  {colorize(str(e), Colors.YELLOW)}")
        error = str(e)
        passwords = []
    except NSSLibraryMissing as e:
        print(f"  {colorize('❌ MISSING LIBRARY', Colors.RED)}")
        print(f"  {colorize(str(e), Colors.YELLOW)}")
        error = str(e)
        passwords = []
    except OSKeyringLocked as e:
        print(f"  {colorize('❌ OS KEYRING LOCKED', Colors.RED)}")
        print(f"  {colorize(str(e), Colors.YELLOW)}")
        error = str(e)
        passwords = []
    else:
        # Environment OK - proceed with decryption
        # First try without master password
        passwords, error = decrypt_firefox_passwords(profile_path, "")
        
        if error and "master password" in error.lower():
            # Master password is required
            if interactive:
                master_password = prompt_master_password()
                if master_password:
                    passwords, error = decrypt_firefox_passwords(profile_path, master_password)
                else:
                    print(f"  {colorize('⚠ Skipping password decryption (no master password provided)', Colors.YELLOW)}")
                    error = None  # User chose to skip
            else:
                print(f"  {colorize('⚠ Master password required but running non-interactively', Colors.YELLOW)}")
        
        if error:
            print(f"  {colorize(f'⚠ Password decryption failed: {error}', Colors.YELLOW)}")
        elif passwords:
            decrypted_passwords = passwords
            print_decrypted_passwords(passwords)
            
            # Add decrypted passwords to credentials list
            for pwd in passwords:
                credentials.append({
                    'type': 'Saved Password',
                    'source': 'logins.json (decrypted)',
                    'field': 'password',
                    'value': pwd.password,
                    'extra': {
                        'URL': pwd.hostname,
                        'Username': pwd.username,
                        'Times Used': pwd.times_used or 0,
                    }
                })

    # Calculate summary stats (use values from extract_databases)
    summary = {
        'databases': len(db_results),
        'tables': total_tables,
        'total_rows': total_rows,
        'json_files': len(json_data),
        'credentials': len(credentials),
        'decrypted_passwords': len(decrypted_passwords)
    }

    # Create ForensicData object
    forensic_data = ForensicData(
        profile_path=str(profile_path),
        profile_name=profile_info['name'],
        extraction_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        databases={},  # We don't store raw database tables anymore
        queries=all_queries,
        json_artifacts=json_data,
        credentials=credentials,
        summary=summary
    )

    # Generate reports in requested formats
    print(f"\n{colorize('═' * 70, Colors.GREEN)}")
    print(f"{colorize('📝 Generating Reports', Colors.BOLD + Colors.GREEN)}")
    print(f"{colorize('═' * 70, Colors.GREEN)}")
    
    report_gen = ReportGenerator(forensic_data)
    
    if 'html' in formats:
        html_path = output_dir / f"forensics_report.html"
        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(report_gen.html_formatter.generate())
        print(f"  {colorize('✓', Colors.GREEN)} HTML Report: {html_path}")
    
    if 'md' in formats:
        md_path = output_dir / f"forensics_report.md"
        with open(md_path, 'w', encoding='utf-8') as f:
            f.write(report_gen.md_formatter.generate())
        print(f"  {colorize('✓', Colors.GREEN)} Markdown Report: {md_path}")
    
    if 'csv' in formats:
        csv_dir = output_dir / "csv_export"
        csv_files = report_gen.csv_formatter.save_all(csv_dir)
        print(f"  {colorize('✓', Colors.GREEN)} CSV Files: {len(csv_files)} files in {csv_dir}")
    
    # Generate master report (legacy format)
    master_report = ForensicReportGenerator.generate_master_report(
        profile_path, db_results, json_data, output_dir
    )
    master_report_path = output_dir / "master_report.md"
    master_report_path.write_text(master_report)

    # Summary
    print(f"\n{colorize('═' * 70, Colors.GREEN)}")
    print(f"{colorize('✅ EXTRACTION COMPLETE', Colors.BOLD + Colors.GREEN)}")
    print(f"{colorize('═' * 70, Colors.GREEN)}")
    
    print(f"\n{colorize('Summary:', Colors.CYAN)}")
    print(f"  • Databases processed: {colorize(str(summary['databases']), Colors.YELLOW)}")
    print(f"  • Tables extracted: {colorize(str(summary['tables']), Colors.YELLOW)}")
    total_rows_str = f"{summary['total_rows']:,}"
    print(f"  • Total rows: {colorize(total_rows_str, Colors.YELLOW)}")
    print(f"  • JSON artifacts: {colorize(str(summary['json_files']), Colors.YELLOW)}")
    print(f"  • Credentials found: {colorize(str(summary['credentials']), Colors.RED + Colors.BOLD)}")
    print(f"  • Passwords decrypted: {colorize(str(summary.get('decrypted_passwords', 0)), Colors.RED + Colors.BOLD)}")
    
    print(f"\n{colorize('Output saved to:', Colors.CYAN)} {output_dir}")
    print(f"\n{colorize('Files created:', Colors.CYAN)}")
    for subdir in ["databases", "forensics", "reports", "artifacts", "csv_export"]:
        subpath = output_dir / subdir
        if subpath.exists():
            file_count = len(list(subpath.rglob("*.*")))
            print(f"  📁 {subdir}/: {file_count} files")
    
    # List main reports
    for report_file in output_dir.glob("forensics_report.*"):
        print(f"  📄 {report_file.name}")

    print_goodbye()
    return True


def main():
    """Main entry point with CLI argument parsing."""
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "profile",
        nargs="?",
        help="Path to Firefox profile directory (optional - will auto-detect if not provided)",
    )

    parser.add_argument(
        "--output",
        "-o",
        default=None,
        help="Output directory name (default: ~/Downloads/firefox_forensics_output)",
    )

    parser.add_argument(
        "--format",
        "-f",
        choices=['html', 'csv', 'md', 'all'],
        default='all',
        help="Output format (default: all)",
    )

    parser.add_argument(
        "--no-interactive",
        "-n",
        action="store_true",
        help="Disable interactive prompts (use defaults)",
    )

    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose logging (DEBUG level)",
    )

    parser.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        help="Suppress non-critical output",
    )

    parser.add_argument(
        "--list-queries",
        action="store_true",
        help="List all available forensic queries and exit",
    )

    parser.add_argument(
        "--check-env",
        action="store_true",
        help="Check environment compatibility for password decryption and exit",
    )

    args = parser.parse_args()

    # Setup logging
    log_level = logging.DEBUG if args.verbose else logging.WARNING if args.quiet else logging.INFO
    logger = setup_logging(log_level)

    # Handle --check-env
    if args.check_env:
        print_banner()
        profile = Path(args.profile) if args.profile else None
        ok = run_environment_check(profile)
        return 0 if ok else 1

    # Handle --list-queries
    if args.list_queries:
        print_banner()
        print(f"{colorize('Available Forensic Queries:', Colors.CYAN)}\n")
        for db_name, queries in QUERY_REGISTRY.items():
            print(f"{colorize(db_name, Colors.YELLOW)}:")
            for query_name in queries:
                print(f"  • {query_name}")
            print()
        return 0

    # Handle profile path - auto-detect if not provided
    if args.profile:
        # User provided profile path
        try:
            profile_path = expand_firefox_path(args.profile)
        except Exception as e:
            logger.error(f"Invalid profile path: {e}")
            return 1
    else:
        # Auto-detect: show profile selection
        print_banner()
        profile_path = prompt_profile_selection()
        if profile_path is None:
            print_goodbye()
            return 0

    # Parse formats - track if user explicitly specified format
    format_provided = args.format != 'all'
    if args.format == 'all':
        formats = ['html', 'csv', 'md']
    else:
        formats = [args.format]

    # Track if user specified output path
    output_provided = args.output is not None
    if args.output:
        output_dir = Path(args.output)
    else:
        output_dir = Path.home() / "Downloads" / "firefox_forensics_output"

    # Run extraction
    try:
        interactive = not args.no_interactive
        success = extract_profile(
            profile_path,
            output_dir,
            logger,
            formats=formats,
            interactive=interactive,
            format_provided=format_provided,
            output_provided=output_provided,
        )
        return 0 if success else 1
    except KeyboardInterrupt:
        print(f"\n{colorize('Extraction interrupted by user', Colors.YELLOW)}")
        print_goodbye()
        return 130
    except Exception as e:
        logger.exception(f"Unexpected error during extraction: {e}")
        print_goodbye()
        return 1


if __name__ == "__main__":
    sys.exit(main())
