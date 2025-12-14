"""Firefox Password Decryption Module.

Uses Mozilla's NSS (Network Security Services) library to decrypt
saved passwords from Firefox profiles.

This module handles:
- logins.json (encrypted credentials)
- key4.db (master key database, SQLite + NSS format)
- Both master password protected and unprotected profiles

Unsupported cases (detected and refused):
- Snap/Flatpak Firefox installations (sandboxed, different NSS)
- OS keyring–locked profiles (GNOME Keyring / KWallet integration)
- Missing libnss3 library

Requirements:
- libnss3 system library (usually pre-installed on Linux)
- Native Firefox installation (not Snap/Flatpak)
- No pip packages needed
"""

import ctypes
from ctypes import (
    c_void_p, c_char_p, c_uint, c_int, c_size_t, c_ubyte,
    POINTER, Structure, byref, cast, create_string_buffer
)
import json
import base64
import sqlite3
import os
import sys
import subprocess
from pathlib import Path
from dataclasses import dataclass
from typing import Optional, List, Tuple
import tempfile
import shutil


# NSS Library structures and constants
class SECItem(Structure):
    """NSS SECItem structure for binary data."""
    _fields_ = [
        ('type', c_uint),
        ('data', POINTER(c_ubyte)),
        ('len', c_uint),
    ]


class NSSError(Exception):
    """NSS operation failed."""
    pass


class MasterPasswordRequired(Exception):
    """Master password is required but not provided."""
    pass


class ProfileNotFound(Exception):
    """Firefox profile not found."""
    pass


class UnsupportedEnvironment(Exception):
    """Firefox environment is not supported for decryption."""
    pass


class NSSLibraryMissing(Exception):
    """NSS library (libnss3) is not installed."""
    pass


class OSKeyringLocked(Exception):
    """Profile uses OS keyring which is locked or unavailable."""
    pass


# =============================================================================
# Environment Detection Functions
# =============================================================================

def detect_firefox_installation_type() -> Tuple[str, Optional[str]]:
    """Detect how Firefox is installed on the system.
    
    Returns:
        Tuple of (installation_type, details)
        installation_type: 'native', 'snap', 'flatpak', 'unknown'
        details: Additional information or path
    """
    # Check for Snap Firefox
    snap_firefox_paths = [
        Path('/snap/firefox'),
        Path(os.path.expanduser('~/snap/firefox')),
    ]
    for snap_path in snap_firefox_paths:
        if snap_path.exists():
            return 'snap', str(snap_path)
    
    # Check if Firefox binary is a snap
    try:
        result = subprocess.run(
            ['which', 'firefox'],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            firefox_path = result.stdout.strip()
            if '/snap/' in firefox_path:
                return 'snap', firefox_path
    except Exception:
        pass
    
    # Check for Flatpak Firefox
    flatpak_firefox_paths = [
        Path(os.path.expanduser('~/.var/app/org.mozilla.firefox')),
        Path('/var/lib/flatpak/app/org.mozilla.firefox'),
    ]
    for flatpak_path in flatpak_firefox_paths:
        if flatpak_path.exists():
            return 'flatpak', str(flatpak_path)
    
    # Check if Firefox is installed via flatpak
    try:
        result = subprocess.run(
            ['flatpak', 'list', '--app'],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0 and 'org.mozilla.firefox' in result.stdout.lower():
            return 'flatpak', 'org.mozilla.firefox'
    except Exception:
        pass
    
    # Check for native installation
    native_paths = [
        Path('/usr/bin/firefox'),
        Path('/usr/lib/firefox'),
        Path('/opt/firefox'),
    ]
    for native_path in native_paths:
        if native_path.exists():
            # Verify it's not a snap wrapper
            if native_path.is_file():
                try:
                    with open(native_path, 'rb') as f:
                        header = f.read(100)
                        if b'snap' in header.lower():
                            return 'snap', str(native_path)
                except Exception:
                    pass
            return 'native', str(native_path)
    
    return 'unknown', None


def is_snap_profile(profile_path: Path) -> bool:
    """Check if a profile path belongs to Snap Firefox."""
    profile_str = str(profile_path).lower()
    return '/snap/' in profile_str or 'snap/firefox' in profile_str


def is_flatpak_profile(profile_path: Path) -> bool:
    """Check if a profile path belongs to Flatpak Firefox."""
    profile_str = str(profile_path).lower()
    return '.var/app/org.mozilla.firefox' in profile_str or 'flatpak' in profile_str


def check_nss_library_available() -> Tuple[bool, Optional[str], Optional[str]]:
    """Check if libnss3 is available on the system.
    
    Returns:
        Tuple of (available, library_path, error_message)
    """
    nss_paths = [
        '/usr/lib/libnss3.so',
        '/usr/lib64/libnss3.so',
        '/usr/lib/x86_64-linux-gnu/libnss3.so',
        '/usr/lib/i386-linux-gnu/libnss3.so',
    ]
    
    for path in nss_paths:
        if os.path.exists(path):
            try:
                ctypes.CDLL(path)
                return True, path, None
            except OSError as e:
                return False, path, f"Found but cannot load: {e}"
    
    # Try loading by name
    try:
        ctypes.CDLL('libnss3.so')
        return True, 'libnss3.so', None
    except OSError:
        pass
    
    return False, None, "libnss3 library not found"


def check_os_keyring_integration(profile_path: Path) -> Tuple[bool, Optional[str]]:
    """Check if the profile uses OS keyring integration.
    
    Firefox can be configured to use GNOME Keyring or KWallet
    instead of its own key4.db for storing the master key.
    
    Returns:
        Tuple of (uses_keyring, keyring_type)
    """
    # Check for GNOME Keyring integration indicator files
    prefs_path = profile_path / 'prefs.js'
    user_prefs_path = profile_path / 'user.js'
    
    keyring_indicators = [
        'security.osclientcerts.autoload',
        'network.negotiate-auth.using-native-gsslib',
        'security.enterprise_roots.enabled',
    ]
    
    for prefs_file in [prefs_path, user_prefs_path]:
        if prefs_file.exists():
            try:
                with open(prefs_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    
                    # Check for explicit keyring usage
                    if 'gnome-keyring' in content.lower():
                        return True, 'GNOME Keyring'
                    if 'kwallet' in content.lower():
                        return True, 'KWallet'
            except Exception:
                pass
    
    # Check for pkcs11.txt which indicates hardware token/keyring usage
    pkcs11_path = profile_path / 'pkcs11.txt'
    if pkcs11_path.exists():
        try:
            with open(pkcs11_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                if 'gnome' in content.lower() or 'p11-kit' in content.lower():
                    return True, 'GNOME Keyring (PKCS#11)'
                if 'kwallet' in content.lower():
                    return True, 'KWallet (PKCS#11)'
        except Exception:
            pass
    
    # Check if key4.db exists but is suspiciously small (might be keyring-managed)
    key4_path = profile_path / 'key4.db'
    if key4_path.exists():
        try:
            size = key4_path.stat().st_size
            # A nearly empty key4.db (<4KB) might indicate keyring usage
            if size < 4096:
                # Verify by checking if there's actual key material
                conn = sqlite3.connect(f"file:{key4_path}?mode=ro", uri=True)
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM nssPrivate")
                count = cursor.fetchone()[0]
                conn.close()
                if count == 0:
                    return True, 'OS Keyring (empty key4.db)'
        except Exception:
            pass
    
    return False, None


def get_installation_help(install_type: str) -> str:
    """Get help text for unsupported installation types."""
    
    if install_type == 'snap':
        return """
╔══════════════════════════════════════════════════════════════════════════════╗
║  UNSUPPORTED: Snap Firefox Detected                                          ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  Snap Firefox runs in a sandbox with its own bundled NSS library.            ║
║  The system libnss3 cannot access Snap Firefox's encrypted data.             ║
║                                                                              ║
║  OPTIONS:                                                                    ║
║                                                                              ║
║  1. Export passwords from Firefox:                                           ║
║     Firefox → Settings → Passwords → ⋮ (menu) → Export Logins               ║
║                                                                              ║
║  2. Install native Firefox (Arch Linux):                                     ║
║     $ sudo snap remove firefox                                               ║
║     $ sudo pacman -S firefox                                                 ║
║                                                                              ║
║  3. Install native Firefox (Ubuntu/Debian):                                  ║
║     $ sudo snap remove firefox                                               ║
║     $ sudo add-apt-repository ppa:mozillateam/ppa                            ║
║     $ echo 'Package: *' | sudo tee /etc/apt/preferences.d/mozilla-firefox    ║
║     $ echo 'Pin: release o=LP-PPA-mozillateam' | sudo tee -a ...             ║
║     $ echo 'Pin-Priority: 1001' | sudo tee -a ...                            ║
║     $ sudo apt update && sudo apt install firefox                            ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝"""
    
    elif install_type == 'flatpak':
        return """
╔══════════════════════════════════════════════════════════════════════════════╗
║  UNSUPPORTED: Flatpak Firefox Detected                                       ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  Flatpak Firefox runs in a sandbox with its own bundled NSS library.         ║
║  The system libnss3 cannot access Flatpak Firefox's encrypted data.          ║
║                                                                              ║
║  OPTIONS:                                                                    ║
║                                                                              ║
║  1. Export passwords from Firefox:                                           ║
║     Firefox → Settings → Passwords → ⋮ (menu) → Export Logins               ║
║                                                                              ║
║  2. Install native Firefox:                                                  ║
║     $ flatpak uninstall org.mozilla.firefox                                  ║
║     $ sudo pacman -S firefox          # Arch Linux                           ║
║     $ sudo apt install firefox-esr    # Debian                               ║
║     $ sudo dnf install firefox        # Fedora                               ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝"""
    
    return ""


def get_nss_install_help() -> str:
    """Get help text for installing libnss3."""
    return """
╔══════════════════════════════════════════════════════════════════════════════╗
║  MISSING: libnss3 Library Not Found                                          ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  The Mozilla NSS library is required to decrypt Firefox passwords.           ║
║                                                                              ║
║  INSTALL libnss3:                                                            ║
║                                                                              ║
║  Arch Linux:                                                                 ║
║     $ sudo pacman -S nss                                                     ║
║                                                                              ║
║  Ubuntu/Debian:                                                              ║
║     $ sudo apt install libnss3                                               ║
║                                                                              ║
║  Fedora/RHEL:                                                                ║
║     $ sudo dnf install nss                                                   ║
║                                                                              ║
║  openSUSE:                                                                   ║
║     $ sudo zypper install mozilla-nss                                        ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝"""


def get_keyring_help(keyring_type: str) -> str:
    """Get help text for OS keyring locked profiles."""
    return f"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  UNSUPPORTED: OS Keyring Integration Detected ({keyring_type:^18})       ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  This Firefox profile uses the OS keyring to store encryption keys.          ║
║  Direct decryption is not possible without keyring access.                   ║
║                                                                              ║
║  OPTIONS:                                                                    ║
║                                                                              ║
║  1. Export passwords from Firefox:                                           ║
║     Firefox → Settings → Passwords → ⋮ (menu) → Export Logins               ║
║                                                                              ║
║  2. Ensure keyring is unlocked:                                              ║
║     - GNOME: Keyring unlocks on login (check seahorse)                       ║
║     - KDE: KWallet should prompt or be unlocked                              ║
║                                                                              ║
║  3. Disable keyring integration in Firefox:                                  ║
║     about:config → security.osclientcerts.autoload → false                   ║
║     (Requires setting a master password instead)                             ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝"""


def validate_environment(profile_path: Path) -> Tuple[bool, Optional[str]]:
    """Validate that the environment supports password decryption.
    
    Args:
        profile_path: Path to Firefox profile
    
    Returns:
        Tuple of (is_valid, error_message_with_help)
    
    Raises:
        UnsupportedEnvironment: If environment is not supported
        NSSLibraryMissing: If libnss3 is not available
        OSKeyringLocked: If profile uses OS keyring
    """
    errors = []
    
    # 1. Check for libnss3
    nss_available, nss_path, nss_error = check_nss_library_available()
    if not nss_available:
        help_text = get_nss_install_help()
        raise NSSLibraryMissing(f"libnss3 not available: {nss_error}\n{help_text}")
    
    # 2. Check for Snap profile
    if is_snap_profile(profile_path):
        help_text = get_installation_help('snap')
        raise UnsupportedEnvironment(f"Snap Firefox profile detected\n{help_text}")
    
    # 3. Check for Flatpak profile
    if is_flatpak_profile(profile_path):
        help_text = get_installation_help('flatpak')
        raise UnsupportedEnvironment(f"Flatpak Firefox profile detected\n{help_text}")
    
    # 4. Check Firefox installation type (warning only for non-matching)
    install_type, install_path = detect_firefox_installation_type()
    if install_type in ('snap', 'flatpak'):
        # Profile might be from a different Firefox installation
        # This is a warning, not an error
        pass
    
    # 5. Check for OS keyring integration
    uses_keyring, keyring_type = check_os_keyring_integration(profile_path)
    if uses_keyring:
        help_text = get_keyring_help(keyring_type or 'Unknown')
        raise OSKeyringLocked(f"Profile uses {keyring_type}\n{help_text}")
    
    return True, None


def print_environment_status(profile_path: Optional[Path] = None) -> dict:
    """Print and return environment status for diagnostics.
    
    Returns:
        Dictionary with environment status
    """
    status = {
        'nss_available': False,
        'nss_path': None,
        'firefox_type': 'unknown',
        'firefox_path': None,
        'profile_type': None,
        'uses_keyring': False,
        'keyring_type': None,
        'supported': False,
        'errors': [],
    }
    
    # Check NSS
    nss_available, nss_path, nss_error = check_nss_library_available()
    status['nss_available'] = nss_available
    status['nss_path'] = nss_path
    if not nss_available:
        status['errors'].append(f"NSS: {nss_error}")
    
    # Check Firefox installation
    install_type, install_path = detect_firefox_installation_type()
    status['firefox_type'] = install_type
    status['firefox_path'] = install_path
    if install_type in ('snap', 'flatpak'):
        status['errors'].append(f"Firefox installed via {install_type}")
    
    # Check profile if provided
    if profile_path:
        profile_path = Path(profile_path)
        
        if is_snap_profile(profile_path):
            status['profile_type'] = 'snap'
            status['errors'].append("Profile is from Snap Firefox")
        elif is_flatpak_profile(profile_path):
            status['profile_type'] = 'flatpak'
            status['errors'].append("Profile is from Flatpak Firefox")
        else:
            status['profile_type'] = 'native'
        
        uses_keyring, keyring_type = check_os_keyring_integration(profile_path)
        status['uses_keyring'] = uses_keyring
        status['keyring_type'] = keyring_type
        if uses_keyring:
            status['errors'].append(f"Profile uses {keyring_type}")
    
    # Determine overall support
    status['supported'] = len(status['errors']) == 0
    
    return status


@dataclass
class DecryptedLogin:
    """Represents a decrypted login entry."""
    url: str
    username: str
    password: str
    hostname: str
    form_submit_url: Optional[str] = None
    http_realm: Optional[str] = None
    time_created: Optional[int] = None
    time_last_used: Optional[int] = None
    time_password_changed: Optional[int] = None
    times_used: Optional[int] = None


class NSSDecryptor:
    """Handles Firefox password decryption using NSS library."""
    
    # NSS library paths to try
    NSS_LIBRARY_PATHS = [
        '/usr/lib/libnss3.so',
        '/usr/lib64/libnss3.so',
        '/usr/lib/x86_64-linux-gnu/libnss3.so',
        '/usr/lib/i386-linux-gnu/libnss3.so',
        'libnss3.so',
    ]
    
    def __init__(self):
        self._nss = None
        self._initialized = False
        self._profile_path: Optional[Path] = None
        self._temp_dir: Optional[Path] = None
        
    def _load_nss_library(self) -> ctypes.CDLL:
        """Load the NSS library."""
        for path in self.NSS_LIBRARY_PATHS:
            try:
                nss = ctypes.CDLL(path)
                return nss
            except OSError:
                continue
        
        raise NSSError(
            "Could not load NSS library (libnss3.so). "
            "Install it with: sudo pacman -S nss (Arch) or "
            "sudo apt install libnss3 (Debian/Ubuntu)"
        )
    
    def _setup_nss_functions(self):
        """Setup NSS function signatures."""
        # NSS_Init
        self._nss.NSS_Init.argtypes = [c_char_p]
        self._nss.NSS_Init.restype = c_int
        
        # NSS_Shutdown
        self._nss.NSS_Shutdown.argtypes = []
        self._nss.NSS_Shutdown.restype = c_int
        
        # PK11_GetInternalKeySlot
        self._nss.PK11_GetInternalKeySlot.argtypes = []
        self._nss.PK11_GetInternalKeySlot.restype = c_void_p
        
        # PK11_FreeSlot
        self._nss.PK11_FreeSlot.argtypes = [c_void_p]
        self._nss.PK11_FreeSlot.restype = None
        
        # PK11_CheckUserPassword
        self._nss.PK11_CheckUserPassword.argtypes = [c_void_p, c_char_p]
        self._nss.PK11_CheckUserPassword.restype = c_int
        
        # PK11_Authenticate
        self._nss.PK11_Authenticate.argtypes = [c_void_p, c_int, c_void_p]
        self._nss.PK11_Authenticate.restype = c_int
        
        # PK11SDR_Decrypt
        self._nss.PK11SDR_Decrypt.argtypes = [POINTER(SECItem), POINTER(SECItem), c_void_p]
        self._nss.PK11SDR_Decrypt.restype = c_int
        
        # SECITEM_FreeItem
        self._nss.SECITEM_FreeItem.argtypes = [POINTER(SECItem), c_int]
        self._nss.SECITEM_FreeItem.restype = None
        
        # PK11_NeedLogin
        self._nss.PK11_NeedLogin.argtypes = [c_void_p]
        self._nss.PK11_NeedLogin.restype = c_int
    
    def _create_temp_profile(self, profile_path: Path) -> Path:
        """Create a temporary copy of the profile for NSS.
        
        NSS modifies the database files, so we work on a copy.
        """
        self._temp_dir = Path(tempfile.mkdtemp(prefix='firefox_decrypt_'))
        
        # Copy only the necessary files
        files_to_copy = ['key4.db', 'key3.db', 'cert9.db', 'cert8.db', 'logins.json']
        
        for filename in files_to_copy:
            src = profile_path / filename
            if src.exists():
                shutil.copy2(src, self._temp_dir / filename)
        
        return self._temp_dir
    
    def _cleanup_temp(self):
        """Clean up temporary directory."""
        if self._temp_dir and self._temp_dir.exists():
            shutil.rmtree(self._temp_dir, ignore_errors=True)
            self._temp_dir = None
    
    def initialize(self, profile_path: Path, master_password: str = "") -> bool:
        """Initialize NSS with the Firefox profile.
        
        Args:
            profile_path: Path to Firefox profile directory
            master_password: Master password if set (empty string if none)
        
        Returns:
            True if initialization successful
        
        Raises:
            ProfileNotFound: If profile doesn't exist
            MasterPasswordRequired: If master password needed but not provided
            NSSError: If NSS initialization fails
            UnsupportedEnvironment: If Snap/Flatpak Firefox detected
            NSSLibraryMissing: If libnss3 not available
            OSKeyringLocked: If profile uses OS keyring
        """
        profile_path = Path(profile_path)
        
        if not profile_path.exists():
            raise ProfileNotFound(f"Profile not found: {profile_path}")
        
        # Validate environment before proceeding
        validate_environment(profile_path)
        
        # Check for key database
        key4_path = profile_path / 'key4.db'
        key3_path = profile_path / 'key3.db'
        
        if not key4_path.exists() and not key3_path.exists():
            raise ProfileNotFound(
                f"No key database found in profile. "
                f"Expected key4.db or key3.db at {profile_path}"
            )
        
        # Load NSS library
        self._nss = self._load_nss_library()
        self._setup_nss_functions()
        
        # Create temporary profile copy
        temp_profile = self._create_temp_profile(profile_path)
        self._profile_path = profile_path
        
        # Initialize NSS with the profile
        # Use sql: prefix for key4.db (SQLite format)
        config_dir = f"sql:{temp_profile}".encode('utf-8')
        
        result = self._nss.NSS_Init(config_dir)
        if result != 0:
            # Try without sql: prefix for older key3.db
            config_dir = str(temp_profile).encode('utf-8')
            result = self._nss.NSS_Init(config_dir)
            if result != 0:
                self._cleanup_temp()
                raise NSSError(f"NSS_Init failed with error code {result}")
        
        self._initialized = True
        
        # Get the internal key slot
        slot = self._nss.PK11_GetInternalKeySlot()
        if not slot:
            self.shutdown()
            raise NSSError("Failed to get internal key slot")
        
        try:
            # Check if master password is needed
            needs_login = self._nss.PK11_NeedLogin(slot)
            
            if needs_login:
                # Try to authenticate with provided password
                password = master_password.encode('utf-8') if master_password else b""
                auth_result = self._nss.PK11_CheckUserPassword(slot, password)
                
                if auth_result != 0:
                    if not master_password:
                        self.shutdown()
                        raise MasterPasswordRequired(
                            "This profile has a master password set. "
                            "Please provide the master password."
                        )
                    else:
                        self.shutdown()
                        raise NSSError("Invalid master password")
        finally:
            self._nss.PK11_FreeSlot(slot)
        
        return True
    
    def decrypt(self, encrypted_data: bytes) -> str:
        """Decrypt a piece of encrypted data.
        
        Args:
            encrypted_data: Base64-decoded encrypted data
        
        Returns:
            Decrypted string
        """
        if not self._initialized:
            raise NSSError("NSS not initialized. Call initialize() first.")
        
        # Create input SECItem
        input_item = SECItem()
        input_item.type = 0  # siBuffer
        input_item.data = cast(
            ctypes.create_string_buffer(encrypted_data, len(encrypted_data)),
            POINTER(c_ubyte)
        )
        input_item.len = len(encrypted_data)
        
        # Create output SECItem
        output_item = SECItem()
        output_item.type = 0
        output_item.data = None
        output_item.len = 0
        
        # Decrypt
        result = self._nss.PK11SDR_Decrypt(byref(input_item), byref(output_item), None)
        
        if result != 0:
            raise NSSError(f"Decryption failed with error code {result}")
        
        try:
            # Extract decrypted data
            decrypted = bytes(output_item.data[:output_item.len])
            return decrypted.decode('utf-8')
        finally:
            # Free the output item
            if output_item.data:
                self._nss.SECITEM_FreeItem(byref(output_item), 0)
    
    def decrypt_logins(self) -> List[DecryptedLogin]:
        """Decrypt all logins from the profile.
        
        Returns:
            List of decrypted login entries
        """
        if not self._initialized or not self._profile_path:
            raise NSSError("NSS not initialized. Call initialize() first.")
        
        logins_path = self._profile_path / 'logins.json'
        
        if not logins_path.exists():
            return []
        
        with open(logins_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        logins = data.get('logins', [])
        decrypted_logins = []
        
        for login in logins:
            try:
                # Decrypt username and password
                encrypted_username = base64.b64decode(login.get('encryptedUsername', ''))
                encrypted_password = base64.b64decode(login.get('encryptedPassword', ''))
                
                username = self.decrypt(encrypted_username) if encrypted_username else ''
                password = self.decrypt(encrypted_password) if encrypted_password else ''
                
                decrypted_logins.append(DecryptedLogin(
                    url=login.get('hostname', ''),
                    username=username,
                    password=password,
                    hostname=login.get('hostname', ''),
                    form_submit_url=login.get('formSubmitURL'),
                    http_realm=login.get('httpRealm'),
                    time_created=login.get('timeCreated'),
                    time_last_used=login.get('timeLastUsed'),
                    time_password_changed=login.get('timePasswordChanged'),
                    times_used=login.get('timesUsed'),
                ))
            except Exception as e:
                # Skip entries that fail to decrypt
                print(f"Warning: Failed to decrypt entry for {login.get('hostname', 'unknown')}: {e}",
                      file=sys.stderr)
                continue
        
        return decrypted_logins
    
    def shutdown(self):
        """Shutdown NSS and cleanup."""
        if self._initialized and self._nss:
            self._nss.NSS_Shutdown()
            self._initialized = False
        self._cleanup_temp()
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.shutdown()
        return False


def decrypt_firefox_passwords(
    profile_path: Path,
    master_password: str = ""
) -> Tuple[List[DecryptedLogin], Optional[str]]:
    """High-level function to decrypt Firefox passwords.
    
    Args:
        profile_path: Path to Firefox profile
        master_password: Master password if set
    
    Returns:
        Tuple of (list of decrypted logins, error message or None)
    """
    try:
        with NSSDecryptor() as decryptor:
            decryptor.initialize(profile_path, master_password)
            logins = decryptor.decrypt_logins()
            return logins, None
    except MasterPasswordRequired as e:
        return [], str(e)
    except ProfileNotFound as e:
        return [], str(e)
    except NSSError as e:
        return [], str(e)
    except UnsupportedEnvironment as e:
        return [], str(e)
    except NSSLibraryMissing as e:
        return [], str(e)
    except OSKeyringLocked as e:
        return [], str(e)
    except Exception as e:
        return [], f"Unexpected error: {str(e)}"


def check_master_password_required(profile_path: Path) -> bool:
    """Check if a profile requires a master password.
    
    Args:
        profile_path: Path to Firefox profile
    
    Returns:
        True if master password is required
    """
    key4_path = profile_path / 'key4.db'
    
    if not key4_path.exists():
        return False
    
    try:
        conn = sqlite3.connect(f"file:{key4_path}?mode=ro", uri=True)
        cursor = conn.cursor()
        
        # Check the metaData table for password-check entry
        cursor.execute(
            "SELECT item1, item2 FROM metaData WHERE id = 'password'"
        )
        row = cursor.fetchone()
        conn.close()
        
        if row:
            # If there's encrypted data, a master password might be set
            # The actual check requires NSS, but this is a quick heuristic
            return True
        
        return False
    except Exception:
        return False


def run_environment_check(profile_path: Optional[Path] = None, verbose: bool = True) -> bool:
    """Run environment checks and print results.
    
    Args:
        profile_path: Optional profile path to check
        verbose: Whether to print detailed output
    
    Returns:
        True if environment is supported
    """
    if verbose:
        print("\n" + "=" * 70)
        print("  FIREFOX PASSWORD DECRYPTION - ENVIRONMENT CHECK")
        print("=" * 70 + "\n")
    
    all_ok = True
    
    # 1. Check NSS library
    nss_ok, nss_path, nss_error = check_nss_library_available()
    if verbose:
        if nss_ok:
            print(f"✅ NSS Library: Found at {nss_path}")
        else:
            print(f"❌ NSS Library: NOT FOUND")
            print(f"   {nss_error}")
            all_ok = False
    
    # 2. Check Firefox installation type
    install_type, install_path = detect_firefox_installation_type()
    if verbose:
        if install_type == 'native':
            print(f"✅ Firefox Installation: Native ({install_path})")
        elif install_type == 'snap':
            print(f"⚠️  Firefox Installation: Snap detected ({install_path})")
            print(f"   Note: Snap Firefox profiles cannot be decrypted")
        elif install_type == 'flatpak':
            print(f"⚠️  Firefox Installation: Flatpak detected ({install_path})")
            print(f"   Note: Flatpak Firefox profiles cannot be decrypted")
        else:
            print(f"⚠️  Firefox Installation: Unknown")
    
    # Profile-specific checks - these are the actual blockers
    profile_ok = True
    profile_snap = False
    profile_flatpak = False
    profile_keyring = False
    
    # 3. Check profile if provided
    if profile_path:
        profile_path = Path(profile_path)
        if verbose:
            print(f"\n📁 Profile: {profile_path}")
        
        if not profile_path.exists():
            if verbose:
                print(f"   ❌ Profile directory does not exist")
            all_ok = False
            profile_ok = False
        else:
            # Check profile type
            if is_snap_profile(profile_path):
                if verbose:
                    print(f"   ❌ Profile Type: Snap (UNSUPPORTED)")
                all_ok = False
                profile_ok = False
                profile_snap = True
            elif is_flatpak_profile(profile_path):
                if verbose:
                    print(f"   ❌ Profile Type: Flatpak (UNSUPPORTED)")
                all_ok = False
                profile_ok = False
                profile_flatpak = True
            else:
                if verbose:
                    print(f"   ✅ Profile Type: Native")
            
            # Check keyring
            uses_keyring, keyring_type = check_os_keyring_integration(profile_path)
            if uses_keyring:
                if verbose:
                    print(f"   ❌ OS Keyring: {keyring_type} (UNSUPPORTED)")
                all_ok = False
                profile_ok = False
                profile_keyring = True
            else:
                if verbose:
                    print(f"   ✅ OS Keyring: Not used")
            
            # Check key database
            key4_path = profile_path / 'key4.db'
            key3_path = profile_path / 'key3.db'
            logins_path = profile_path / 'logins.json'
            
            if key4_path.exists():
                if verbose:
                    print(f"   ✅ Key Database: key4.db (SQLite format)")
            elif key3_path.exists():
                if verbose:
                    print(f"   ✅ Key Database: key3.db (Legacy format)")
            else:
                if verbose:
                    print(f"   ❌ Key Database: NOT FOUND")
                all_ok = False
                profile_ok = False
            
            if logins_path.exists():
                try:
                    with open(logins_path) as f:
                        data = json.load(f)
                        login_count = len(data.get('logins', []))
                    if verbose:
                        print(f"   ✅ Logins File: {login_count} saved login(s)")
                except Exception as e:
                    if verbose:
                        print(f"   ⚠️  Logins File: Error reading ({e})")
            else:
                if verbose:
                    print(f"   ⚠️  Logins File: Not found (no saved passwords)")
    
    if verbose:
        print("\n" + "-" * 70)
        if all_ok:
            print("✅ Environment is SUPPORTED for password decryption")
        else:
            print("❌ Environment is NOT SUPPORTED")
            # Show help based on the actual issue
            if profile_snap:
                print(get_installation_help('snap'))
            elif profile_flatpak:
                print(get_installation_help('flatpak'))
            elif profile_keyring:
                print(get_keyring_help(keyring_type or 'Unknown'))
            elif not nss_ok:
                print(get_nss_install_help())
        print()
    
    return all_ok


# CLI interface for standalone testing
if __name__ == '__main__':
    import argparse
    import getpass
    
    parser = argparse.ArgumentParser(
        description='Decrypt Firefox saved passwords',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s ~/.mozilla/firefox/abc123.default/
  %(prog)s --check ~/.mozilla/firefox/abc123.default/
  %(prog)s --check  # Check environment only
  %(prog)s -j ~/.mozilla/firefox/abc123.default/  # JSON output
"""
    )
    parser.add_argument('profile', nargs='?', help='Path to Firefox profile directory')
    parser.add_argument('-p', '--password', help='Master password (will prompt if needed)')
    parser.add_argument('-j', '--json', action='store_true', help='Output as JSON')
    parser.add_argument('-c', '--check', action='store_true', 
                        help='Check environment compatibility only')
    
    args = parser.parse_args()
    
    # Handle --check mode
    if args.check:
        profile = Path(args.profile) if args.profile else None
        ok = run_environment_check(profile)
        sys.exit(0 if ok else 1)
    
    # Normal decryption mode requires profile
    if not args.profile:
        parser.error("profile is required (or use --check for environment check)")
    
    profile = Path(args.profile)
    
    if not profile.exists():
        print(f"Error: Profile not found: {profile}", file=sys.stderr)
        sys.exit(1)
    
    # Run environment check first
    print("Checking environment...", file=sys.stderr)
    try:
        validate_environment(profile)
        print("✅ Environment OK\n", file=sys.stderr)
    except (UnsupportedEnvironment, NSSLibraryMissing, OSKeyringLocked) as e:
        print(f"\n{e}", file=sys.stderr)
        sys.exit(1)
    
    # Check if master password needed
    master_password = args.password or ""
    
    # Try to decrypt
    logins, error = decrypt_firefox_passwords(profile, master_password)
    
    if error:
        if "master password" in error.lower():
            # Prompt for password
            master_password = getpass.getpass("Master password: ")
            logins, error = decrypt_firefox_passwords(profile, master_password)
    
    if error:
        print(f"Error: {error}", file=sys.stderr)
        sys.exit(1)
    
    if not logins:
        print("No saved passwords found.")
        sys.exit(0)
    
    if args.json:
        output = [
            {
                'url': l.url,
                'username': l.username,
                'password': l.password,
                'times_used': l.times_used,
            }
            for l in logins
        ]
        print(json.dumps(output, indent=2))
    else:
        print(f"\nFound {len(logins)} saved password(s):\n")
        for i, login in enumerate(logins, 1):
            print(f"[{i}] {login.hostname}")
            print(f"    Username: {login.username}")
            print(f"    Password: {login.password}")
            if login.times_used:
                print(f"    Used: {login.times_used} times")
            print()
