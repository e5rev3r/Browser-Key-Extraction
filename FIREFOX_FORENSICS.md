# Firefox Profile Forensics

## Overview
Firefox profiles contain browsing history, cookies, credentials, bookmarks, downloads, and cached content revealing user activity and authentication details.

**Profile Locations:**
- **Linux**: `~/.mozilla/firefox/<profile-name>/`
- **Windows**: `%APPDATA%\Mozilla\Firefox\Profiles\<profile-name>\`
- **macOS**: `~/Library/Application Support/Firefox/Profiles/<profile-name>/`

---

## Key Files & Directories

### Critical Databases (SQLite)
- **`places.sqlite`**: Browsing history, bookmarks, downloads, visit timestamps
- **`cookies.sqlite`**: HTTP cookies with domain, expiry, secure/httponly flags
- **`permissions.sqlite`**: Site permissions (geolocation, camera, microphone, notifications)
- **`formhistory.sqlite`**: Form inputs, search queries (may contain sensitive data)
- **`storage.sqlite`**: DOM storage (localStorage/sessionStorage), web app state
- **`favicons.sqlite`**: Website favicon cache (identifies visited sites)

### Configuration Files
- **`prefs.js`**: User preferences, extensions, homepage, language settings
- **`extensions.json`/`addons.json`**: Extension metadata, IDs, versions, permissions
- **`logins.json`**: Encrypted credentials (requires master password or key4.db)
- **`key4.db`/`key3.db`**: Master password hash and encryption keys

### Session & Cache
- **`sessionstore.jsonlz4`**: Current tabs, windows, form data (LZ4 compressed)
- **`cache2/entries/`**: Cached web content (images, scripts, pages)
- **`thumbnails/`**: Page thumbnail images (PNG format)
- **`bookmarkbackups/`**: Timestamped bookmark snapshots (gzipped JSON)

### Metadata
- **`times.json`**: Profile creation/first-use timestamps
- **`installs.ini`**: Installation date and build info

---

## Database Analysis

### places.sqlite - Browsing History & Bookmarks
**Tables**: `moz_places`, `moz_historyvisits`, `moz_bookmarks`

```bash
# Extract browsing history
sqlite3 places.sqlite "SELECT p.url, p.title, datetime(h.visit_date/1000000, 'unixepoch') as visit_time FROM moz_historyvisits h JOIN moz_places p ON h.place_id = p.id ORDER BY h.visit_date DESC;"

# Extract bookmarks
sqlite3 places.sqlite "SELECT b.title, p.url, datetime(b.dateAdded/1000, 'unixepoch') as created FROM moz_bookmarks b LEFT JOIN moz_places p ON b.fk = p.id WHERE b.type = 1;"

# Top 100 most visited sites
sqlite3 places.sqlite "SELECT url, visit_count, datetime(last_visit_date/1000000, 'unixepoch') as last_visit FROM moz_places ORDER BY visit_count DESC LIMIT 100;"
```

### cookies.sqlite - Authentication Tokens
**Table**: `moz_cookies` (fields: name, value, host, expiry, isSecure, isHttpOnly)

```bash
# List all cookies
sqlite3 cookies.sqlite "SELECT host, name, value, datetime(creationTime/1000000, 'unixepoch') as created FROM moz_cookies ORDER BY lastAccessed DESC;"

# Extract auth tokens
sqlite3 cookies.sqlite "SELECT host, name, value FROM moz_cookies WHERE name LIKE '%token%' OR name LIKE '%session%' OR name LIKE '%auth%';"
```

### formhistory.sqlite - User Inputs
**Table**: `moz_formhistory` (may contain passwords, emails, search queries)

```bash
# Extract form history
sqlite3 formhistory.sqlite "SELECT fieldname, value, datetime(lastUsed/1000, 'unixepoch') as last_used FROM moz_formhistory ORDER BY lastUsed DESC;"

# Find potential credentials
sqlite3 formhistory.sqlite "SELECT fieldname, value FROM moz_formhistory WHERE fieldname LIKE '%email%' OR fieldname LIKE '%username%';"
```

### permissions.sqlite - Site Permissions
**Table**: `moz_perms` (geolocation, camera, microphone access)

```bash
# List granted permissions
sqlite3 permissions.sqlite "SELECT origin, type, datetime(modificationTime/1000, 'unixepoch') as granted FROM moz_perms WHERE permission = 1 ORDER BY modificationTime DESC;"
```

---



## JSON File Extraction

```bash
# Extract extension info
cat extensions.json | jq '.addons[] | {id: .id, name: .name, version: .version, installDate: .installDate}'

# Decompress and extract session tabs
lz4 -d sessionstore.jsonlz4 sessionstore.json
cat sessionstore.json | jq '.windows[].tabs[] | {url: .entries[-1].url, title: .entries[-1].title}'

# Extract bookmark backups
gunzip -c bookmarkbackups/bookmarks-YYYYMMDD.json.gz | jq .
```

---

## Automated Extraction Script

```bash
#!/bin/bash
PROFILE="$HOME/.mozilla/firefox/<profile-name>"
OUT="./firefox_forensics"
mkdir -p "$OUT"

# Export all SQLite databases to CSV
for db in "$PROFILE"/*.sqlite; do
    [ -f "$db" ] || continue
    name=$(basename "$db" .sqlite)
    for table in $(sqlite3 "$db" ".tables"); do
        sqlite3 -header -csv "$db" "SELECT * FROM $table" > "$OUT/${name}_${table}.csv"
    done
done

# Copy configs and decompress sessions
cp "$PROFILE"/{prefs.js,extensions.json,logins.json} "$OUT/" 2>/dev/null
[ -f "$PROFILE/sessionstore.jsonlz4" ] && lz4 -d "$PROFILE/sessionstore.jsonlz4" "$OUT/sessionstore.json"
gunzip -c "$PROFILE/bookmarkbackups"/*.json.gz > "$OUT/bookmarks.json" 2>/dev/null

echo "Extraction complete: $OUT"
```

---

## Credential Decryption

**logins.json**: Encrypted credentials (NSS encryption)
**key4.db/key3.db**: Master password hash and decryption keys

### Using This Tool (Recommended)
```bash
# Windows or Linux - automatic decryption
python main.py --check-env  # Verify support
python main.py              # Interactive extraction with password decryption

# Non-interactive
python main.py /path/to/profile --output ./forensics --no-interactive
```

### Alternative: firefox-decrypt
```bash
# Using firefox-decrypt tool (https://github.com/unode/firefox_decrypt)
cp logins.json key4.db .
python3 firefox_decrypt.py . --format csv > decrypted_logins.csv
```

---

## Cache Recovery

```bash
# Extract cached content (use strings for text extraction)
find ~/.mozilla/firefox/<profile>/cache2/entries -type f -exec strings {} \; | head -50

# Copy thumbnails
cp ~/.mozilla/firefox/<profile>/thumbnails/* ./forensics_output/
```

---

## Common Forensic Queries

```sql
-- Sites visited in last 24 hours
SELECT p.url, datetime(h.visit_date/1000000, 'unixepoch') as visit_time 
FROM moz_historyvisits h JOIN moz_places p ON h.place_id = p.id 
WHERE h.visit_date > (strftime('%s', 'now') - 86400) * 1000000;

-- Extract emails from form history
SELECT DISTINCT value as email FROM moz_formhistory 
WHERE value LIKE '%@%.%' AND LENGTH(value) < 100;

-- Active auth sessions
SELECT host, name, datetime(creationTime/1000000, 'unixepoch') as created 
FROM moz_cookies WHERE name LIKE '%token%' OR name LIKE '%session%';

-- Referrer chain analysis
SELECT p.url, datetime(h.visit_date/1000000, 'unixepoch') as visit_time, 
ref.url as referrer FROM moz_historyvisits h 
JOIN moz_places p ON h.place_id = p.id 
LEFT JOIN moz_historyvisits ref_h ON h.from_visit = ref_h.id 
LEFT JOIN moz_places ref ON ref_h.place_id = ref.id 
ORDER BY h.visit_date DESC LIMIT 100;
```

---

## Integrity & Evidence Collection

```bash
# Generate SHA-256 hashes
find ~/.mozilla/firefox/<profile> -name "*.sqlite" -o -name "*.json" | xargs sha256sum > hashes.txt

# Timeline timestamps
find ~/.mozilla/firefox/<profile> -type f -exec stat -c "%y %n" {} \; > file_timeline.txt
```

**Collection Checklist**:
- Copy entire profile (preserve timestamps)
- Hash all files (SHA-256)
- Export databases to CSV
- Decompress sessions/bookmarks
- Document extensions
- Analyze cache/thumbnails
- Check for deleted SQLite journals
- Note master password status

