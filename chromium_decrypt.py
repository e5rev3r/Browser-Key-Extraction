#!/usr/bin/env python3
"""Chromium Password and Cookie Decryption Module (Windows & Linux).

Decrypts saved passwords and cookies from Chromium-based browsers 
(Chrome, Edge, Brave, etc.) on Windows and Linux.

Encryption methods:
- Windows v10: AES-256-GCM with DPAPI-protected key (Chrome < 127)
- Windows v20: App-Bound Encryption with DPAPI + hardcoded keys (Chrome 127+)
- Windows Legacy: Direct DPAPI encryption (older Chrome)
- Linux: AES-256-GCM with key from GNOME Keyring/libsecret or hardcoded

Windows v20 Decryption (Chrome 127+):
- Requires Administrator privileges
- Uses LSASS impersonation for SYSTEM DPAPI context
- Handles flag 1 (AES), flag 2 (ChaCha20), flag 3 (NCrypt+XOR)

Requirements:
- Windows: pycryptodome, PythonForWindows (for v20 admin decryption)
- Linux: pycryptodome, secretstorage (optional, for GNOME Keyring)
"""

import base64
import io
import json
import os
import sqlite3
import shutil
import struct
import sys
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Tuple, Dict, Any

# Platform-specific imports
IS_WINDOWS = sys.platform == "win32"
IS_LINUX = sys.platform.startswith("linux")

if IS_WINDOWS:
    import ctypes
    from ctypes import wintypes


@dataclass
class DecryptedCredential:
    """Represents a decrypted browser credential."""
    url: str
    username: str
    password: str
    signon_realm: str
    date_created: Optional[str] = None
    date_last_used: Optional[str] = None
    times_used: int = 0


@dataclass
class DecryptedCookie:
    """Represents a decrypted browser cookie."""
    host: str
    name: str
    value: str
    path: str
    expires: Optional[str] = None
    created: Optional[str] = None
    is_secure: bool = False
    is_httponly: bool = False


class ChromiumDecryptionError(Exception):
    """Base exception for Chromium decryption errors."""
    pass


class EncryptionKeyNotFound(ChromiumDecryptionError):
    """Encryption key could not be found or extracted."""
    pass


class DecryptionFailed(ChromiumDecryptionError):
    """Password decryption failed."""
    pass


class DependencyMissing(ChromiumDecryptionError):
    """Required dependency is not installed."""
    pass


class V20EncryptionError(DecryptionFailed):
    """v20 App-Bound Encryption requires admin privileges."""
    pass


class AdminRequired(ChromiumDecryptionError):
    """Operation requires administrator privileges."""
    pass


# =============================================================================
# Windows DPAPI Functions (Windows only)
# =============================================================================

if IS_WINDOWS:
    class DATA_BLOB(ctypes.Structure):
        """Windows DATA_BLOB structure for DPAPI."""
        _fields_ = [
            ("cbData", wintypes.DWORD),
            ("pbData", ctypes.POINTER(ctypes.c_char)),
        ]


    def _win_dpapi_decrypt(encrypted_data: bytes) -> bytes:
        """Decrypt data using Windows DPAPI.
        
        Args:
            encrypted_data: DPAPI-encrypted bytes
        
        Returns:
            Decrypted bytes
        
        Raises:
            DecryptionFailed: If DPAPI decryption fails
        """
        crypt32 = ctypes.windll.crypt32
        kernel32 = ctypes.windll.kernel32
        
        input_blob = DATA_BLOB()
        input_blob.cbData = len(encrypted_data)
        input_blob.pbData = ctypes.cast(
            ctypes.create_string_buffer(encrypted_data, len(encrypted_data)),
            ctypes.POINTER(ctypes.c_char)
        )
        
        output_blob = DATA_BLOB()
        
        result = crypt32.CryptUnprotectData(
            ctypes.byref(input_blob),
            None, None, None, None, 0,
            ctypes.byref(output_blob)
        )
        
        if not result:
            raise DecryptionFailed(f"DPAPI decryption failed: {ctypes.GetLastError()}")
        
        decrypted = ctypes.string_at(output_blob.pbData, output_blob.cbData)
        kernel32.LocalFree(output_blob.pbData)
        
        return decrypted


# =============================================================================
# Linux Keyring Functions (Linux only)
# =============================================================================

if IS_LINUX:
    def _linux_get_keyring_password(browser: str = "chrome") -> Optional[bytes]:
        """Get encryption password from Linux keyring (GNOME Keyring/libsecret).
        
        Args:
            browser: Browser name (chrome, chromium, brave, etc.)
        
        Returns:
            Password bytes or None if not found
        """
        try:
            import secretstorage
            
            # Browser-specific identifiers
            browser_schemas = {
                "chrome": "chrome_libsecret_os_crypt_password_v2",
                "chromium": "chromium_libsecret_os_crypt_password_v2", 
                "brave": "brave_libsecret_os_crypt_password_v2",
                "edge": "edge_libsecret_os_crypt_password_v2",
                "opera": "opera_libsecret_os_crypt_password_v2",
                "vivaldi": "vivaldi_libsecret_os_crypt_password_v2",
            }
            
            schema_name = browser_schemas.get(browser.lower(), "chrome_libsecret_os_crypt_password_v2")
            
            bus = secretstorage.dbus_init()
            collection = secretstorage.get_default_collection(bus)
            
            for item in collection.get_all_items():
                if item.get_label() == schema_name:
                    return item.get_secret()
            
            # Fallback: try generic Chrome Safe Storage
            for item in collection.get_all_items():
                label = item.get_label().lower()
                if browser.lower() in label and ("safe" in label or "password" in label):
                    return item.get_secret()
                    
        except ImportError:
            pass  # secretstorage not installed
        except Exception:
            pass  # D-Bus or keyring error
        
        return None

    def _linux_derive_key(password: bytes) -> bytes:
        """Derive AES key from password using PBKDF2 (Linux method).
        
        Args:
            password: Password from keyring
        
        Returns:
            32-byte AES key
        """
        from hashlib import pbkdf2_hmac
        
        # Linux Chromium uses these fixed parameters
        salt = b"saltysalt"
        iterations = 1
        key_length = 16  # AES-128 on Linux
        
        return pbkdf2_hmac("sha1", password, salt, iterations, key_length)


    # Default password if keyring is not available
    LINUX_DEFAULT_PASSWORD = b"peanuts"


    def _linux_aes_cbc_decrypt(encrypted_data: bytes, key: bytes) -> bytes:
        """Decrypt AES-128-CBC encrypted data (Linux format).
        
        Linux Chromium uses AES-128-CBC with PKCS7 padding.
        Format: IV (16 bytes) + ciphertext
        
        Args:
            encrypted_data: IV + ciphertext
            key: 16-byte AES key
        
        Returns:
            Decrypted bytes with padding removed
        """
        try:
            from Crypto.Cipher import AES
            from Crypto.Util.Padding import unpad
        except ImportError:
            raise DependencyMissing(
                "pycryptodome is required for AES decryption. "
                "Install with: pip install pycryptodome"
            )
        
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]
        
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        decrypted = cipher.decrypt(ciphertext)
        
        # Remove PKCS7 padding
        return unpad(decrypted, AES.block_size)


# =============================================================================
# Admin/Privilege Functions
# =============================================================================

def is_admin() -> bool:
    """Check if running with administrator/root privileges."""
    if IS_WINDOWS:
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            return False
    else:
        # Linux: check for root
        return os.geteuid() == 0


def request_admin_elevation() -> bool:
    """Request UAC elevation by relaunching script as admin (Windows only).
    
    Returns:
        True if elevation was requested (script will exit), False if already admin or not Windows
    """
    if not IS_WINDOWS:
        return False
        
    if is_admin():
        return False
    
    script = sys.argv[0]
    params = ' '.join([f'"{arg}"' for arg in sys.argv[1:]])
    
    try:
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, f'"{script}" {params}', None, 1
        )
        return True
    except:
        return False


# =============================================================================
# v20 Admin Decryption (LSASS Impersonation) - Windows Only
# =============================================================================

# Cached v20 key per browser
_v20_key_cache: Dict[str, bytes] = {}


def _check_v20_dependencies() -> bool:
    """Check if v20 admin decryption dependencies are available (Windows only)."""
    if not IS_WINDOWS:
        return False
    try:
        import windows
        import windows.crypto
        from Crypto.Cipher import AES, ChaCha20_Poly1305
        return True
    except ImportError:
        return False


if IS_WINDOWS:
    @contextmanager
    def _impersonate_lsass():
        """Impersonate lsass.exe to get SYSTEM privilege for DPAPI."""
        import windows
        import windows.generated_def as gdef
        
        original_token = windows.current_thread.token
        try:
            windows.current_process.token.enable_privilege("SeDebugPrivilege")
            proc = next(p for p in windows.system.processes if p.name == "lsass.exe")
            lsass_token = proc.token
            impersonation_token = lsass_token.duplicate(
                type=gdef.TokenImpersonation,
                impersonation_level=gdef.SecurityImpersonation
            )
            windows.current_thread.token = impersonation_token
            yield
        finally:
            windows.current_thread.token = original_token

def _parse_key_blob(blob_data: bytes) -> dict:
    """Parse the decrypted v20 key blob structure.
    
    Handles multiple v20 formats:
    - Flag 1/2: AES-GCM or ChaCha20 with hardcoded keys (Chrome)
    - Flag 3: NCrypt + XOR + AES-GCM (Chrome)
    - 32-byte content: Raw key directly (Edge, Brave)
    """
    buffer = io.BytesIO(blob_data)
    parsed_data = {}

    header_len = struct.unpack('<I', buffer.read(4))[0]
    parsed_data['header'] = buffer.read(header_len)
    content_len = struct.unpack('<I', buffer.read(4))[0]
    
    # Check if this is a raw 32-byte key (Edge, Brave format)
    if content_len == 32:
        # The entire content is the raw key - no flag parsing needed
        raw_key = buffer.read(32)
        parsed_data['flag'] = 0  # Special flag for raw key
        parsed_data['raw_key'] = raw_key
        return parsed_data
    
    parsed_data['flag'] = buffer.read(1)[0]
    
    if parsed_data['flag'] in (1, 2):
        parsed_data['iv'] = buffer.read(12)
        parsed_data['ciphertext'] = buffer.read(32)
        parsed_data['tag'] = buffer.read(16)
    elif parsed_data['flag'] == 3:
        parsed_data['encrypted_aes_key'] = buffer.read(32)
        parsed_data['iv'] = buffer.read(12)
        parsed_data['ciphertext'] = buffer.read(32)
        parsed_data['tag'] = buffer.read(16)
    else:
        raise ValueError(f"Unsupported v20 flag: {parsed_data['flag']}")

    return parsed_data


def _decrypt_with_cng(input_data: bytes, key_name: str = "Google Chromekey1") -> bytes:
    """Decrypt data using Windows CNG NCrypt API."""
    import windows.generated_def as gdef
    
    ncrypt = ctypes.windll.NCRYPT
    hProvider = gdef.NCRYPT_PROV_HANDLE()
    
    status = ncrypt.NCryptOpenStorageProvider(
        ctypes.byref(hProvider), 
        "Microsoft Software Key Storage Provider", 0
    )
    if status != 0:
        raise DecryptionFailed(f"NCryptOpenStorageProvider failed: {status}")

    hKey = gdef.NCRYPT_KEY_HANDLE()
    status = ncrypt.NCryptOpenKey(hProvider, ctypes.byref(hKey), key_name, 0, 0)
    if status != 0:
        ncrypt.NCryptFreeObject(hProvider)
        raise DecryptionFailed(f"NCryptOpenKey failed: {status}")

    pcbResult = gdef.DWORD(0)
    input_buffer = (ctypes.c_ubyte * len(input_data)).from_buffer_copy(input_data)

    status = ncrypt.NCryptDecrypt(
        hKey, input_buffer, len(input_buffer), None,
        None, 0, ctypes.byref(pcbResult), 0x40
    )
    if status != 0:
        ncrypt.NCryptFreeObject(hKey)
        ncrypt.NCryptFreeObject(hProvider)
        raise DecryptionFailed(f"NCryptDecrypt size query failed: {status}")

    output_buffer = (ctypes.c_ubyte * pcbResult.value)()
    status = ncrypt.NCryptDecrypt(
        hKey, input_buffer, len(input_buffer), None,
        output_buffer, pcbResult.value, ctypes.byref(pcbResult), 0x40
    )
    
    ncrypt.NCryptFreeObject(hKey)
    ncrypt.NCryptFreeObject(hProvider)
    
    if status != 0:
        raise DecryptionFailed(f"NCryptDecrypt failed: {status}")

    return bytes(output_buffer[:pcbResult.value])


def _derive_v20_master_key(parsed_data: dict, browser_name: str = "chrome") -> bytes:
    """Derive the v20 master key based on flag type.
    
    Handles multiple v20 formats:
    - Flag 0: Raw key directly (Edge, Brave)
    - Flag 1: AES-GCM with hardcoded key (Chrome)
    - Flag 2: ChaCha20-Poly1305 with hardcoded key (Chrome)
    - Flag 3: NCrypt + XOR + AES-GCM (Chrome)
    """
    from Crypto.Cipher import AES, ChaCha20_Poly1305
    
    # Browser-specific CNG key names
    cng_key_names = {
        "chrome": "Google Chromekey1",
        "edge": "Microsoft Edgekey1",
        "brave": "Brave Softwarekey1",
    }
    
    if parsed_data['flag'] == 0:
        # Raw key format (Edge, Brave) - key is already decrypted
        return parsed_data['raw_key']
    
    if parsed_data['flag'] == 1:
        # AES-GCM with hardcoded key
        aes_key = bytes.fromhex("B31C6E241AC846728DA9C1FAC4936651CFFB944D143AB816276BCC6DA0284787")
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=parsed_data['iv'])
        return cipher.decrypt_and_verify(parsed_data['ciphertext'], parsed_data['tag'])
        
    elif parsed_data['flag'] == 2:
        # ChaCha20-Poly1305 with hardcoded key
        chacha_key = bytes.fromhex("E98F37D7F4E1FA433D19304DC2258042090E2D1D7EEA7670D41F738D08729660")
        cipher = ChaCha20_Poly1305.new(key=chacha_key, nonce=parsed_data['iv'])
        return cipher.decrypt_and_verify(parsed_data['ciphertext'], parsed_data['tag'])
        
    elif parsed_data['flag'] == 3:
        # NCrypt + XOR + AES-GCM
        xor_key = bytes.fromhex("CCF8A1CEC56605B8517552BA1A2D061C03A29E90274FB2FCF59BA4B75C392390")
        key_name = cng_key_names.get(browser_name.lower(), "Google Chromekey1")
        
        with _impersonate_lsass():
            decrypted_aes_key = _decrypt_with_cng(parsed_data['encrypted_aes_key'], key_name)
        
        xored_key = bytes([a ^ b for a, b in zip(decrypted_aes_key, xor_key)])
        cipher = AES.new(xored_key, AES.MODE_GCM, nonce=parsed_data['iv'])
        return cipher.decrypt_and_verify(parsed_data['ciphertext'], parsed_data['tag'])
    
    raise DecryptionFailed(f"Unknown v20 flag: {parsed_data['flag']}")


def get_v20_key_admin(user_data_dir: Path, browser_name: str = "chrome") -> Optional[bytes]:
    """Get v20 App-Bound Encryption key using admin privileges.
    
    Requires:
    - Administrator privileges
    - PythonForWindows library
    
    Args:
        user_data_dir: Path to browser's User Data directory
        browser_name: Browser name (chrome, edge, brave)
    
    Returns:
        32-byte AES key, or None if extraction fails
    """
    import windows
    import windows.crypto
    
    # Check cache first
    cache_key = f"{user_data_dir}:{browser_name}"
    if cache_key in _v20_key_cache:
        return _v20_key_cache[cache_key]
    
    local_state_path = user_data_dir / "Local State"
    if not local_state_path.exists():
        return None
    
    try:
        with open(local_state_path, "r", encoding="utf-8") as f:
            local_state = json.load(f)
        
        app_bound_key_b64 = local_state.get("os_crypt", {}).get("app_bound_encrypted_key")
        if not app_bound_key_b64:
            return None
        
        key_blob_encrypted = base64.b64decode(app_bound_key_b64)
        if key_blob_encrypted[:4] != b"APPB":
            return None
        
        key_blob_encrypted = key_blob_encrypted[4:]
        
        # Step 1: Decrypt with SYSTEM DPAPI (via LSASS impersonation)
        with _impersonate_lsass():
            key_blob_system = windows.crypto.dpapi.unprotect(key_blob_encrypted)
        
        # Step 2: Decrypt with User DPAPI
        key_blob_user = windows.crypto.dpapi.unprotect(key_blob_system)
        
        # Step 3: Parse and derive the master key
        parsed_data = _parse_key_blob(key_blob_user)
        master_key = _derive_v20_master_key(parsed_data, browser_name)
        
        # Cache the key
        _v20_key_cache[cache_key] = master_key
        
        return master_key
        
    except Exception as e:
        # Don't cache failures
        return None



# =============================================================================
# AES Decryption Functions
# =============================================================================

def _aes_gcm_decrypt(encrypted_data: bytes, key: bytes) -> bytes:
    """Decrypt AES-256-GCM encrypted data.
    
    Format: nonce (12 bytes) + ciphertext + tag (16 bytes)
    
    Args:
        encrypted_data: Encrypted bytes (nonce + ciphertext + tag)
        key: 32-byte AES key
    
    Returns:
        Decrypted bytes
    """
    try:
        from Crypto.Cipher import AES
    except ImportError:
        raise DependencyMissing(
            "pycryptodome is required for AES decryption. "
            "Install with: pip install pycryptodome"
        )
    
    nonce = encrypted_data[:12]
    ciphertext = encrypted_data[12:-16]
    tag = encrypted_data[-16:]
    
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)


# =============================================================================
# Key Extraction Functions
# =============================================================================

def get_encryption_key_windows(user_data_dir: Path) -> bytes:
    """Extract and decrypt the v10 AES key on Windows.
    
    The key is stored in Local State, encrypted with DPAPI.
    Format: "DPAPI" prefix (5 bytes) + DPAPI blob
    
    Args:
        user_data_dir: Path to browser's User Data directory
    
    Returns:
        32-byte AES decryption key
    """
    local_state_path = user_data_dir / "Local State"
    if not local_state_path.exists():
        raise EncryptionKeyNotFound(f"Local State not found: {local_state_path}")
    
    with open(local_state_path, "r", encoding="utf-8") as f:
        local_state = json.load(f)
    
    encrypted_key_b64 = local_state.get("os_crypt", {}).get("encrypted_key")
    if not encrypted_key_b64:
        raise EncryptionKeyNotFound("encrypted_key not found in Local State")
    
    encrypted_key = base64.b64decode(encrypted_key_b64)
    
    # Remove "DPAPI" prefix
    if encrypted_key[:5] != b"DPAPI":
        raise EncryptionKeyNotFound("Invalid key format (missing DPAPI prefix)")
    
    encrypted_key = encrypted_key[5:]
    
    # Decrypt with DPAPI
    return _win_dpapi_decrypt(encrypted_key)


def get_app_bound_key_windows(user_data_dir: Path, browser_name: str = "chrome") -> Optional[bytes]:
    """Get v20 App-Bound Encryption key.
    
    If running as admin with PythonForWindows, uses LSASS impersonation.
    Otherwise returns None (v20 data will show as protected).
    
    Args:
        user_data_dir: Path to browser's User Data directory
        browser_name: Browser name (chrome, edge, brave)
    
    Returns:
        32-byte AES key for v20 decryption, or None if not available
    """
    local_state_path = user_data_dir / "Local State"
    if not local_state_path.exists():
        return None
    
    # Check if there's a v20 key
    try:
        with open(local_state_path, "r", encoding="utf-8") as f:
            local_state = json.load(f)
        
        app_bound_key_b64 = local_state.get("os_crypt", {}).get("app_bound_encrypted_key")
        if not app_bound_key_b64:
            return None  # No v20 key present
            
    except (json.JSONDecodeError, IOError, KeyError):
        return None
    
    # If admin and dependencies available, use admin method
    if is_admin() and _check_v20_dependencies():
        try:
            return get_v20_key_admin(user_data_dir, browser_name)
        except Exception:
            pass
    
    # Fallback: try standard DPAPI (usually fails for v20)
    try:
        app_bound_key = base64.b64decode(app_bound_key_b64)
        if app_bound_key[:4] == b"APPB":
            decrypted = _win_dpapi_decrypt(app_bound_key[4:])
            if len(decrypted) >= 32:
                return decrypted[-32:]
    except:
        pass
    
    return None


if IS_LINUX:
    def get_encryption_key_linux(user_data_dir: Path, browser_name: str = "chrome") -> bytes:
        """Extract the AES key on Linux.
        
        Linux Chromium stores the key either in GNOME Keyring/libsecret
        or uses a hardcoded password "peanuts".
        
        Args:
            user_data_dir: Path to browser's User Data directory
            browser_name: Browser name for keyring lookup
        
        Returns:
            16-byte AES key (Linux uses AES-128)
        """
        # Try to get password from keyring first
        password = _linux_get_keyring_password(browser_name)
        
        if password is None:
            # Fallback to hardcoded password
            password = LINUX_DEFAULT_PASSWORD
        
        return _linux_derive_key(password)


def get_encryption_key(user_data_dir: Path, browser_name: str = "chrome") -> bytes:
    """Get the encryption key (cross-platform).
    
    Args:
        user_data_dir: Path to browser's User Data directory
        browser_name: Browser name (for Linux keyring lookup)
    
    Returns:
        AES decryption key
    """
    if IS_WINDOWS:
        return get_encryption_key_windows(user_data_dir)
    elif IS_LINUX:
        return get_encryption_key_linux(user_data_dir, browser_name)
    else:
        raise DependencyMissing(f"Unsupported platform: {sys.platform}")


# =============================================================================
# Check for v20 Encrypted Data
# =============================================================================

def has_v20_encrypted_data(profile_path: Path) -> Tuple[bool, int, int]:
    """Check if profile has v20 encrypted passwords or cookies.
    
    Returns:
        Tuple of (has_v20, password_count, cookie_count)
    """
    v20_passwords = 0
    v20_cookies = 0
    
    # Check passwords
    login_db = profile_path / "Login Data"
    if login_db.exists():
        try:
            temp_db = Path(tempfile.mkdtemp()) / "Login Data"
            shutil.copy2(login_db, temp_db)
            conn = sqlite3.connect(f"file:{temp_db}?mode=ro", uri=True)
            cursor = conn.cursor()
            cursor.execute("SELECT password_value FROM logins")
            for row in cursor.fetchall():
                if row[0] and row[0][:3] == b"v20":
                    v20_passwords += 1
            conn.close()
            shutil.rmtree(temp_db.parent, ignore_errors=True)
        except:
            pass
    
    # Check cookies
    for cookie_path in [profile_path / "Cookies", profile_path / "Network" / "Cookies"]:
        if cookie_path.exists():
            try:
                temp_db = Path(tempfile.mkdtemp()) / "Cookies"
                shutil.copy2(cookie_path, temp_db)
                conn = sqlite3.connect(f"file:{temp_db}?mode=ro", uri=True)
                cursor = conn.cursor()
                cursor.execute("SELECT encrypted_value FROM cookies")
                for row in cursor.fetchall():
                    if row[0] and row[0][:3] == b"v20":
                        v20_cookies += 1
                conn.close()
                shutil.rmtree(temp_db.parent, ignore_errors=True)
            except:
                pass
            break
    
    return (v20_passwords > 0 or v20_cookies > 0), v20_passwords, v20_cookies


# =============================================================================
# Password Decryption Functions
# =============================================================================

def decrypt_password_windows(encrypted_password: bytes, key: bytes, app_bound_key: bytes = None) -> str:
    """Decrypt a Chromium password on Windows.
    
    Handles v10 (AES-GCM), v20 (App-Bound Encryption), and legacy (DPAPI) formats.
    
    Args:
        encrypted_password: Encrypted password bytes
        key: AES decryption key (v10)
        app_bound_key: App-Bound Encryption key for v20 (if available)
    
    Returns:
        Decrypted password string
        
    Raises:
        V20EncryptionError: If v20 encryption is used and no key available
        DecryptionFailed: For other decryption failures
    """
    if not encrypted_password:
        return ""
    
    # v20 format: Chrome 127+ App-Bound Encryption
    if encrypted_password[:3] == b"v20":
        if app_bound_key:
            try:
                return _aes_gcm_decrypt(encrypted_password[3:], app_bound_key).decode("utf-8")
            except Exception as e:
                raise DecryptionFailed(f"v20 decryption failed: {e}")
        
        raise V20EncryptionError("v20 encryption - run as Administrator to decrypt")
    
    # v10 format: AES-256-GCM with DPAPI key
    if encrypted_password[:3] == b"v10":
        try:
            return _aes_gcm_decrypt(encrypted_password[3:], key).decode("utf-8")
        except Exception as e:
            raise DecryptionFailed(f"AES-GCM decryption failed: {e}")
    
    # Legacy format: Direct DPAPI
    try:
        return _win_dpapi_decrypt(encrypted_password).decode("utf-8")
    except Exception as e:
        raise DecryptionFailed(f"DPAPI decryption failed: {e}")


if IS_LINUX:
    def decrypt_password_linux(encrypted_password: bytes, key: bytes) -> str:
        """Decrypt a Chromium password on Linux.
        
        Handles v11 (AES-128-CBC) and v10 (AES-GCM) formats.
        
        Args:
            encrypted_password: Encrypted password bytes
            key: AES decryption key (16 bytes for Linux)
        
        Returns:
            Decrypted password string
        
        Raises:
            DecryptionFailed: If decryption fails
        """
        if not encrypted_password:
            return ""
        
        # v11 format: Linux AES-128-CBC (most common on Linux)
        if encrypted_password[:3] == b"v11":
            try:
                return _linux_aes_cbc_decrypt(encrypted_password[3:], key).decode("utf-8")
            except Exception as e:
                raise DecryptionFailed(f"v11 AES-CBC decryption failed: {e}")
        
        # v10 format: AES-GCM (less common on Linux but possible)
        if encrypted_password[:3] == b"v10":
            try:
                return _aes_gcm_decrypt(encrypted_password[3:], key).decode("utf-8")
            except Exception as e:
                raise DecryptionFailed(f"AES-GCM decryption failed: {e}")
        
        # No prefix - might be plaintext or unknown format
        try:
            # Try as plaintext
            return encrypted_password.decode("utf-8")
        except:
            raise DecryptionFailed("Unknown encryption format")


def decrypt_password(encrypted_password: bytes, key: bytes, app_bound_key: bytes = None) -> str:
    """Decrypt a password (cross-platform).
    
    Args:
        encrypted_password: Encrypted password bytes from database
        key: Decryption key
        app_bound_key: App-Bound Encryption key for v20 (Windows only)
    
    Returns:
        Decrypted password string
    """
    if IS_WINDOWS:
        return decrypt_password_windows(encrypted_password, key, app_bound_key)
    elif IS_LINUX:
        return decrypt_password_linux(encrypted_password, key)
    else:
        raise DependencyMissing(f"Unsupported platform: {sys.platform}")


# =============================================================================
# Cookie Decryption Functions
# =============================================================================

def decrypt_cookie_windows(encrypted_value: bytes, key: bytes, app_bound_key: bytes = None) -> str:
    """Decrypt a Chromium cookie value on Windows.
    
    Handles v10 (AES-GCM), v20 (App-Bound Encryption), and legacy (DPAPI) formats.
    Note: v20 cookies have a 32-byte metadata header after decryption.
    
    Args:
        encrypted_value: Encrypted cookie value bytes
        key: AES decryption key (v10)
        app_bound_key: App-Bound Encryption key for v20
    
    Returns:
        Decrypted cookie value string
    """
    if not encrypted_value:
        return ""
    
    # v20 format: Chrome 127+ App-Bound Encryption
    if encrypted_value[:3] == b"v20":
        if app_bound_key:
            try:
                # v20 cookies have 32-byte metadata header
                decrypted = _aes_gcm_decrypt(encrypted_value[3:], app_bound_key)
                if len(decrypted) > 32:
                    decrypted = decrypted[32:]  # Strip cookie metadata
                return decrypted.decode("utf-8")
            except Exception as e:
                raise DecryptionFailed(f"v20 cookie decryption failed: {e}")
        
        raise V20EncryptionError("v20 cookie - run as Administrator to decrypt")
    
    # v10 format: AES-256-GCM
    if encrypted_value[:3] == b"v10":
        try:
            return _aes_gcm_decrypt(encrypted_value[3:], key).decode("utf-8")
        except Exception as e:
            raise DecryptionFailed(f"AES-GCM cookie decryption failed: {e}")
    
    # Legacy format: Direct DPAPI
    try:
        return _win_dpapi_decrypt(encrypted_value).decode("utf-8")
    except Exception as e:
        raise DecryptionFailed(f"DPAPI cookie decryption failed: {e}")


if IS_LINUX:
    def decrypt_cookie_linux(encrypted_value: bytes, key: bytes) -> str:
        """Decrypt a Chromium cookie value on Linux.
        
        Handles v11 (AES-128-CBC) and v10 (AES-GCM) formats.
        
        Args:
            encrypted_value: Encrypted cookie value bytes
            key: AES decryption key (16 bytes for Linux)
        
        Returns:
            Decrypted cookie value string
        
        Raises:
            DecryptionFailed: If decryption fails
        """
        if not encrypted_value:
            return ""
        
        # v11 format: Linux AES-128-CBC
        if encrypted_value[:3] == b"v11":
            try:
                return _linux_aes_cbc_decrypt(encrypted_value[3:], key).decode("utf-8")
            except Exception as e:
                raise DecryptionFailed(f"v11 cookie decryption failed: {e}")
        
        # v10 format: AES-GCM (less common on Linux)
        if encrypted_value[:3] == b"v10":
            try:
                return _aes_gcm_decrypt(encrypted_value[3:], key).decode("utf-8")
            except Exception as e:
                raise DecryptionFailed(f"AES-GCM cookie decryption failed: {e}")
        
        # No prefix - might be plaintext
        try:
            return encrypted_value.decode("utf-8")
        except:
            raise DecryptionFailed("Unknown cookie encryption format")


def decrypt_cookie(encrypted_value: bytes, key: bytes, app_bound_key: bytes = None) -> str:
    """Decrypt a cookie value (cross-platform).
    
    Args:
        encrypted_value: Encrypted cookie value bytes from database
        key: Decryption key
        app_bound_key: App-Bound Encryption key for v20 (Windows only)
    
    Returns:
        Decrypted cookie value string
    """
    if IS_WINDOWS:
        return decrypt_cookie_windows(encrypted_value, key, app_bound_key)
    elif IS_LINUX:
        return decrypt_cookie_linux(encrypted_value, key)
    else:
        raise DependencyMissing(f"Unsupported platform: {sys.platform}")


def decrypt_chromium_cookies(
    profile_path: Path,
    user_data_dir: Path,
    browser_name: str = "chrome"
) -> Tuple[List[DecryptedCookie], List[str]]:
    """Decrypt all cookies from a Chromium profile.
    
    Args:
        profile_path: Path to browser profile directory
        user_data_dir: Path to User Data directory (contains Local State)
        browser_name: Browser name (chrome, edge, brave) for v20 key
    
    Returns:
        Tuple of (list of DecryptedCookie, list of error messages)
    """
    cookies: List[DecryptedCookie] = []
    errors: List[str] = []
    
    # Look for cookies in both standard and Network locations
    cookie_paths = [
        profile_path / "Cookies",
        profile_path / "Network" / "Cookies",
    ]
    
    cookies_db = None
    for path in cookie_paths:
        if path.exists():
            cookies_db = path
            break
    
    if not cookies_db:
        errors.append(f"Cookies database not found in: {profile_path}")
        return cookies, errors
    
    # Get decryption key
    try:
        key = get_encryption_key(user_data_dir, browser_name)
    except (EncryptionKeyNotFound, DependencyMissing) as e:
        errors.append(str(e))
        return cookies, errors
    
    # Get v20 key (Windows only, if admin and dependencies available)
    app_bound_key = None
    if IS_WINDOWS:
        app_bound_key = get_app_bound_key_windows(user_data_dir, browser_name)
    
    # Copy database to temp location
    temp_dir = Path(tempfile.mkdtemp(prefix="chromium_cookies_"))
    temp_db = temp_dir / "Cookies"
    
    try:
        shutil.copy2(cookies_db, temp_db)
        
        # Copy WAL files
        for suffix in ["-wal", "-shm", "-journal"]:
            wal_path = cookies_db.parent / f"Cookies{suffix}"
            if wal_path.exists():
                shutil.copy2(wal_path, temp_dir / f"Cookies{suffix}")
        
        conn = sqlite3.connect(f"file:{temp_db}?mode=ro", uri=True)
        # Use bytes text_factory to handle binary encrypted_value column properly
        conn.text_factory = bytes
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT host_key, name, encrypted_value, path,
                   creation_utc, expires_utc, is_secure, is_httponly
            FROM cookies
        """)
        
        v20_count = 0
        
        for row in cursor.fetchall():
            # Decode text fields from bytes if needed
            host_key = row[0].decode('utf-8', errors='replace') if isinstance(row[0], bytes) else (row[0] or "")
            name = row[1].decode('utf-8', errors='replace') if isinstance(row[1], bytes) else (row[1] or "")
            encrypted_value = row[2]  # Keep as bytes
            path = row[3].decode('utf-8', errors='replace') if isinstance(row[3], bytes) else (row[3] or "/")
            creation_utc = row[4]
            expires_utc = row[5]
            is_secure = bool(row[6])
            is_httponly = bool(row[7])
            
            # Decrypt cookie value
            try:
                value = decrypt_cookie(encrypted_value, key, app_bound_key) if encrypted_value else ""
            except V20EncryptionError:
                v20_count += 1
                value = "[v20 PROTECTED]"
            except DecryptionFailed as e:
                errors.append(f"Cookie {name}@{host_key}: {e}")
                value = "[DECRYPTION FAILED]"
            
            # Convert timestamps
            from sql_queries import webkit_to_unix
            from datetime import datetime, timezone
            
            created_str = ""
            if creation_utc:
                try:
                    unix_ts = webkit_to_unix(creation_utc)
                    if unix_ts > 0:
                        created_str = datetime.fromtimestamp(unix_ts, tz=timezone.utc).isoformat()
                except (ValueError, OSError):
                    pass
            
            expires_str = ""
            if expires_utc and expires_utc > 0:
                try:
                    unix_ts = webkit_to_unix(expires_utc)
                    if unix_ts > 0:
                        expires_str = datetime.fromtimestamp(unix_ts, tz=timezone.utc).isoformat()
                except (ValueError, OSError):
                    pass
            
            cookies.append(DecryptedCookie(
                host=host_key,
                name=name,
                value=value,
                path=path,
                expires=expires_str,
                created=created_str,
                is_secure=is_secure,
                is_httponly=is_httponly
            ))
        
        conn.close()
        
        if v20_count > 0 and not is_admin():
            errors.insert(0,
                f"{v20_count} cookie(s) use v20 encryption. Run as Administrator to decrypt."
            )
        
    except sqlite3.Error as e:
        errors.append(f"Database error: {e}")
    except Exception as e:
        errors.append(f"Unexpected error: {e}")
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)
    
    return cookies, errors


# =============================================================================
# Main Decryption Function
# =============================================================================

def decrypt_chromium_passwords(
    profile_path: Path,
    user_data_dir: Path,
    master_password: Optional[str] = None,
    browser_name: str = "chrome"
) -> Tuple[List[DecryptedCredential], List[str]]:
    """Decrypt all saved passwords from a Chromium profile.
    
    Args:
        profile_path: Path to browser profile directory
        user_data_dir: Path to User Data directory (contains Local State)
        master_password: Not used for Chromium (kept for API compatibility)
        browser_name: Browser name (chrome, edge, brave, etc.) for v20 key
    
    Returns:
        Tuple of (list of DecryptedCredential, list of error messages)
    """
    credentials: List[DecryptedCredential] = []
    errors: List[str] = []
    
    login_data_path = profile_path / "Login Data"
    if not login_data_path.exists():
        errors.append(f"Login Data not found: {login_data_path}")
        return credentials, errors
    
    # Get decryption key
    try:
        key = get_encryption_key(user_data_dir, browser_name)
    except (EncryptionKeyNotFound, DependencyMissing) as e:
        errors.append(str(e))
        return credentials, errors
    
    # Get App-Bound Encryption key for v20 passwords (Windows only, if admin)
    app_bound_key = None
    if IS_WINDOWS:
        app_bound_key = get_app_bound_key_windows(user_data_dir, browser_name)
    
    # Copy database to temp location (it may be locked)
    temp_dir = Path(tempfile.mkdtemp(prefix="chromium_passwords_"))
    temp_db = temp_dir / "Login Data"
    
    try:
        shutil.copy2(login_data_path, temp_db)
        
        # Also copy WAL file if exists
        wal_path = login_data_path.parent / "Login Data-wal"
        if wal_path.exists():
            shutil.copy2(wal_path, temp_dir / "Login Data-wal")
        
        # Connect and extract
        conn = sqlite3.connect(f"file:{temp_db}?mode=ro", uri=True)
        cursor = conn.cursor()
        
        # Query for logins
        cursor.execute("""
            SELECT 
                origin_url,
                action_url,
                username_value,
                password_value,
                signon_realm,
                date_created,
                date_last_used,
                times_used
            FROM logins
            WHERE blacklisted_by_user = 0
        """)
        v20_count = 0  # Track v20 encrypted passwords
        
        for row in cursor.fetchall():
            origin_url = row[0] or ""
            action_url = row[1] or ""
            username = row[2] or ""
            encrypted_password = row[3]
            signon_realm = row[4] or ""
            date_created = row[5]
            date_last_used = row[6]
            times_used = row[7] or 0
            
            # Decrypt password
            try:
                password = decrypt_password(encrypted_password, key, app_bound_key) if encrypted_password else ""
            except V20EncryptionError:
                v20_count += 1
                password = "[v20 PROTECTED - Run as Admin]"
            except DecryptionFailed as e:
                errors.append(f"Failed to decrypt password for {origin_url}: {e}")
                password = "[DECRYPTION FAILED]"
            
            # Convert timestamps
            from sql_queries import webkit_to_unix
            from datetime import datetime, timezone
            
            created_str = ""
            if date_created:
                try:
                    unix_ts = webkit_to_unix(date_created)
                    if unix_ts > 0:
                        created_str = datetime.fromtimestamp(unix_ts, tz=timezone.utc).isoformat()
                except (ValueError, OSError):
                    pass
            
            last_used_str = ""
            if date_last_used:
                try:
                    unix_ts = webkit_to_unix(date_last_used)
                    if unix_ts > 0:
                        last_used_str = datetime.fromtimestamp(unix_ts, tz=timezone.utc).isoformat()
                except (ValueError, OSError):
                    pass
            
            credentials.append(DecryptedCredential(
                url=action_url or origin_url,
                username=username,
                password=password,
                signon_realm=signon_realm,
                date_created=created_str,
                date_last_used=last_used_str,
                times_used=times_used
            ))
        
        conn.close()
        
        # Add warning about v20 encrypted passwords
        if v20_count > 0 and not is_admin():
            errors.insert(0, 
                f"{v20_count} password(s) use v20 encryption. "
                f"Run as Administrator to decrypt."
            )
        
    except sqlite3.Error as e:
        errors.append(f"Database error: {e}")
    except Exception as e:
        errors.append(f"Unexpected error: {e}")
    finally:
        # Cleanup
        shutil.rmtree(temp_dir, ignore_errors=True)
    
    return credentials, errors


def check_decryption_requirements() -> Tuple[bool, List[str]]:
    """Check if all requirements for password decryption are met.
    
    Returns:
        Tuple of (requirements_met, list of missing items)
    """
    missing = []
    
    # Check for pycryptodome
    try:
        from Crypto.Cipher import AES
    except ImportError:
        missing.append("pycryptodome (pip install pycryptodome)")
    
    # Check for v20 admin support
    if not _check_v20_dependencies():
        missing.append("PythonForWindows (pip install PythonForWindows) - for v20 admin decryption")
    
    return len(missing) == 0, missing


# =============================================================================
# CLI for testing
# =============================================================================

if __name__ == "__main__":
    from browser_profiles import detect_all_browsers, BrowserFamily
    
    print("Chromium Password Decryption Test (Windows)")
    print("=" * 50)
    print(f"Running as Admin: {is_admin()}")
    
    # Check requirements
    reqs_met, missing = check_decryption_requirements()
    if not reqs_met:
        print(f"Missing: {missing}")
    
    # Find a Chromium browser
    installations = detect_all_browsers()
    
    for inst in installations:
        if inst.browser_family == BrowserFamily.CHROMIUM and inst.profiles:
            profile = inst.profiles[0]
            browser = inst.browser_type.value.lower()
            print(f"\nTesting: {profile.display_name} ({browser})")
            
            # Check for v20
            has_v20, v20_pass, v20_cook = has_v20_encrypted_data(profile.profile_path)
            if has_v20:
                print(f"  v20 data found: {v20_pass} passwords, {v20_cook} cookies")
                if not is_admin():
                    print("  [!] Run as Administrator to decrypt v20 data")
            
            credentials, errors = decrypt_chromium_passwords(
                profile.profile_path, profile.user_data_dir, browser_name=browser
            )
            
            print(f"  Passwords: {len(credentials)}")
            for cred in credentials[:3]:
                print(f"    {cred.url[:40]}... | {cred.username} | {cred.password}")
            
            if errors:
                print(f"  Errors: {errors[0][:80]}...")
            
            break
    else:
        print("No Chromium browsers found!")
