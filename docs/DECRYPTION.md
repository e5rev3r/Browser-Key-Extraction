# Password Decryption

## Overview

| Browser | Method | Key Storage |
|---------|--------|-------------|
| Firefox | NSS PK11SDR_Decrypt | `key4.db` |
| Chromium (Windows) | DPAPI + AES-GCM | `Local State` |
| Chromium (Linux) | Keyring + AES-CBC | GNOME Keyring |
| Chrome 127+ (Windows) | App-Bound + AES-GCM | Encrypted in `Local State` |

---

## Firefox (NSS)

### How It Works

Firefox uses Mozilla's NSS (Network Security Services) library with PK11SDR_Decrypt function.

```
┌─────────────┐     ┌─────────────┐     ┌─────────────────┐
│ logins.json │────▶│   key4.db   │────▶│ PK11SDR_Decrypt │
│ (encrypted) │     │ (master key)│     │ (NSS library)   │
└─────────────┘     └─────────────┘     └────────┬────────┘
                                                 │
                                                 ▼
                                        ┌─────────────────┐
                                        │ Plain password  │
                                        └─────────────────┘
```

### Key Files

| File | Purpose |
|------|---------|
| `logins.json` | Stores encrypted credentials |
| `key4.db` | SQLCipher database with master key |

### Decryption Process

1. Load NSS library (`libnss3.so` / `nss3.dll`)
2. Initialize NSS with profile path
3. Read encrypted data from `logins.json`
4. Call `PK11SDR_Decrypt()` with encrypted blob
5. NSS handles key retrieval from `key4.db`

### Master Password

If set, NSS prompts for master password before decryption. Without correct password, decryption fails.

---

## Chromium v10 (Windows DPAPI)

### Encryption Identifier

```
Bytes 0-2: "v10" (0x763130)
```

### How It Works

```
┌───────────────┐     ┌───────────────┐     ┌─────────────────┐
│  Local State  │────▶│ CryptUnprotect│────▶│   AES-256-GCM   │
│ (DPAPI blob)  │     │    Data       │     │   Decryption    │
└───────────────┘     └───────────────┘     └────────┬────────┘
                                                     │
                                                     ▼
                                            ┌─────────────────┐
                                            │ Plain password  │
                                            └─────────────────┘
```

### Key Retrieval

1. Read `Local State` JSON file
2. Extract `os_crypt.encrypted_key`
3. Base64 decode
4. Strip "DPAPI" prefix (5 bytes)
5. Call `CryptUnprotectData()` → Master key

### Password Structure

```
[v10][12-byte IV][ciphertext][16-byte auth tag]
 3B      12B         var           16B
```

### Decryption

```python
from Crypto.Cipher import AES

cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
password = cipher.decrypt(ciphertext)
```

---

## Chromium v11 (Linux Keyring)

### Encryption Identifier

```
Bytes 0-2: "v11" (0x763131)
```

### How It Works

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  GNOME Keyring  │────▶│    PBKDF2       │────▶│   AES-128-CBC   │
│ (safe storage)  │     │  (key derive)   │     │   Decryption    │
└─────────────────┘     └─────────────────┘     └────────┬────────┘
                                                         │
                                                         ▼
                                                ┌─────────────────┐
                                                │ Plain password  │
                                                └─────────────────┘
```

### Key Retrieval

1. Connect to Secret Service (D-Bus)
2. Query for "Chrome Safe Storage" or browser-specific label
3. Retrieve password string
4. If not found, fallback to "peanuts"

**Key Sources (priority order):**
1. GNOME Keyring → "Chrome Safe Storage"
2. KDE Wallet → "Chrome Keys"
3. secret-tool CLI
4. Fallback: `"peanuts"`

### Key Derivation

```python
import hashlib

key = hashlib.pbkdf2_hmac(
    'sha1',
    password.encode(),    # From keyring
    b'saltysalt',         # Fixed salt
    1,                    # Single iteration
    dklen=16              # 128-bit key
)
```

### Password Structure

```
[v11][16-byte IV][ciphertext + padding]
 3B      16B           var
```

### Decryption

```python
from Crypto.Cipher import AES

cipher = AES.new(key, AES.MODE_CBC, iv=iv)
decrypted = cipher.decrypt(ciphertext)
password = decrypted.rstrip(b'\x00')  # Remove padding
```

---

## Chromium v20 (App-Bound Encryption)

### Encryption Identifier

```
Bytes 0-2: "v20" (0x763230)
```

### Introduction

Chrome 127+ (July 2024) introduced App-Bound Encryption on Windows. The encryption key is protected by the browser's code signature.

### How It Works

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  Local State    │────▶│   IElevator     │────▶│   AES-256-GCM   │
│ (app_bound_key) │     │ (COM Service)   │     │   Decryption    │
└─────────────────┘     └─────────────────┘     └────────┬────────┘
                                                         │
                                                         ▼
                                                ┌─────────────────┐
                                                │ Plain password  │
                                                └─────────────────┘
```

### Requirements

- **Administrator privileges** required
- **PythonForWindows** package for COM interface
- Only works on same machine where passwords were created

### Key Storage

```json
// Local State
{
  "os_crypt": {
    "app_bound_encrypted_key": "BASE64_ENCODED_KEY"
  }
}
```

### Password Structure

Same as v10:
```
[v20][12-byte IV][ciphertext][16-byte auth tag]
 3B      12B         var           16B
```

### Decryption Steps

1. Read `app_bound_encrypted_key` from `Local State`
2. Use IElevator COM interface to decrypt key
3. Use decrypted key with AES-256-GCM
4. Decrypt password blob

### Limitations

| Limitation | Impact |
|------------|--------|
| Admin required | Must elevate |
| Same user only | Cannot decrypt other users' data |
| Machine-bound | Key tied to specific install |

### Fallback

If v20 decryption fails, tool reports:
```
[v20 PROTECTED - Run as Admin]
```

---

## Version Detection

```python
def detect_version(encrypted_blob):
    prefix = encrypted_blob[:3]
    if prefix == b'v10':
        return 'v10'  # Windows DPAPI
    elif prefix == b'v11':
        return 'v11'  # Linux Keyring
    elif prefix == b'v20':
        return 'v20'  # App-Bound
    else:
        return 'unknown'
```

---

## Troubleshooting

| Issue | Cause | Solution |
|-------|-------|----------|
| NSS not found | Library missing | Install `libnss3` |
| DPAPI failed | Wrong user | Run as profile owner |
| Keyring locked | Session locked | Unlock keyring |
| v20 PROTECTED | Need elevation | Run as Administrator |
| Empty password | Decryption failed | Check browser version |

---

## Dependencies

| Package | Platform | Purpose |
|---------|----------|---------|
| `pycryptodome` | All | AES decryption |
| `secretstorage` | Linux | Keyring access |
| `PythonForWindows` | Windows | v20 App-Bound |
| `libnss3` | All | Firefox NSS |
