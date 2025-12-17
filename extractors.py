"""Database extraction for Firefox and Chromium browsers."""

import json
import shutil
import sqlite3
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from sql_queries import FIREFOX_QUERIES, CHROMIUM_QUERIES


class FirefoxExtractor:
    """Extract data from Firefox SQLite databases and JSON files."""

    def __init__(self, profile_path: Path):
        self.profile_path = Path(profile_path)
        if not self.profile_path.exists():
            raise FileNotFoundError(f"Profile not found: {profile_path}")

    def find_databases(self) -> List[Path]:
        """Find all SQLite databases in the profile."""
        return sorted(self.profile_path.glob("*.sqlite"))

    def find_json_files(self) -> List[Path]:
        """Find all JSON files in the profile."""
        return sorted(self.profile_path.glob("*.json"))

    def get_tables(self, db_path: Path) -> List[str]:
        """Get list of tables in a database."""
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
            tables = [row[0] for row in cursor.fetchall()]
            conn.close()
            return tables
        except sqlite3.Error:
            return []

    def run_query(self, db_path: Path, query: str) -> Tuple[List[Dict[str, Any]], int]:
        """Execute a SQL query and return results as dictionaries."""
        try:
            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(query)
            rows = [dict(row) for row in cursor.fetchall()]
            conn.close()
            return rows, len(rows)
        except sqlite3.Error as e:
            print(f"Query error on {db_path}: {e}")
            return [], 0

    def run_forensic_query(self, db_path: Path, query: str) -> Tuple[List[Dict[str, Any]], int]:
        """Alias for run_query for compatibility."""
        return self.run_query(db_path, query)

    def extract_all(self) -> Dict[str, List[Dict[str, Any]]]:
        """Extract all forensic data from the profile."""
        results = {}
        for db_path in self.find_databases():
            db_name = db_path.name
            if db_name in FIREFOX_QUERIES:
                for query_name, query_sql in FIREFOX_QUERIES[db_name].items():
                    rows, _ = self.run_query(db_path, query_sql)
                    if rows:
                        results[query_name] = rows
        return results

    def get_history(self) -> List[Dict[str, Any]]:
        """Get browsing history."""
        db_path = self.profile_path / "places.sqlite"
        if db_path.exists() and "places.sqlite" in FIREFOX_QUERIES:
            rows, _ = self.run_query(db_path, FIREFOX_QUERIES["places.sqlite"]["browsing_history"])
            return rows
        return []

    def get_cookies(self) -> List[Dict[str, Any]]:
        """Get all cookies."""
        db_path = self.profile_path / "cookies.sqlite"
        if db_path.exists() and "cookies.sqlite" in FIREFOX_QUERIES:
            rows, _ = self.run_query(db_path, FIREFOX_QUERIES["cookies.sqlite"]["all_cookies"])
            return rows
        return []

    def get_bookmarks(self) -> List[Dict[str, Any]]:
        """Get bookmarks."""
        db_path = self.profile_path / "places.sqlite"
        if db_path.exists() and "places.sqlite" in FIREFOX_QUERIES:
            rows, _ = self.run_query(db_path, FIREFOX_QUERIES["places.sqlite"]["bookmarks"])
            return rows
        return []

    def get_form_history(self) -> List[Dict[str, Any]]:
        """Get form autofill history."""
        db_path = self.profile_path / "formhistory.sqlite"
        if db_path.exists() and "formhistory.sqlite" in FIREFOX_QUERIES:
            rows, _ = self.run_query(db_path, FIREFOX_QUERIES["formhistory.sqlite"]["all_form_history"])
            return rows
        return []

    @staticmethod
    def parse_extensions(json_path: Path) -> Dict[str, Any]:
        """Parse Firefox extensions.json or addons.json."""
        try:
            with open(json_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            addons = data.get("addons", [])
            return {
                "total": len(addons),
                "addons": [
                    {"id": a.get("id"), "name": a.get("name"), "version": a.get("version"),
                     "active": a.get("active"), "type": a.get("type")}
                    for a in addons
                ]
            }
        except Exception:
            return {"error": "Failed to parse"}

    @staticmethod
    def parse_json(json_path: Path) -> Dict[str, Any]:
        """Generic JSON parser."""
        try:
            with open(json_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {"error": "Failed to parse"}


class ChromiumExtractor:
    """Extract data from Chromium-based browser databases.
    
    Creates temporary copies of databases since Chromium locks them while running.
    """

    def __init__(self, profile_path: Path, user_data_dir: Path = None):
        self.profile_path = Path(profile_path)
        self.user_data_dir = Path(user_data_dir) if user_data_dir else self.profile_path.parent
        self._temp_dir: Optional[Path] = None
        self._db_copies: Dict[str, Path] = {}

    def __enter__(self):
        self._temp_dir = Path(tempfile.mkdtemp(prefix="chromium_forensics_"))
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.cleanup()

    def cleanup(self):
        """Remove temporary database copies."""
        if self._temp_dir and self._temp_dir.exists():
            shutil.rmtree(self._temp_dir, ignore_errors=True)
        self._db_copies.clear()

    def _get_db_copy(self, db_name: str) -> Optional[Path]:
        """Get a safe copy of a database file."""
        if db_name in self._db_copies:
            return self._db_copies[db_name]

        original = self.profile_path / db_name
        if not original.exists():
            return None

        if self._temp_dir is None:
            self._temp_dir = Path(tempfile.mkdtemp(prefix="chromium_forensics_"))

        temp_path = self._temp_dir / db_name
        try:
            shutil.copy2(original, temp_path)
            # Copy WAL files if they exist
            for suffix in ["-wal", "-shm", "-journal"]:
                wal = original.parent / f"{db_name}{suffix}"
                if wal.exists():
                    shutil.copy2(wal, self._temp_dir / f"{db_name}{suffix}")
            self._db_copies[db_name] = temp_path
            return temp_path
        except (IOError, OSError):
            return None

    def find_databases(self) -> List[str]:
        """Find known Chromium databases."""
        known = ["History", "Cookies", "Login Data", "Web Data", "Shortcuts", "Favicons"]
        return [db for db in known if (self.profile_path / db).exists()]

    def find_json_files(self) -> List[Path]:
        """Find important JSON files."""
        files = []
        for name in ["Bookmarks", "Preferences", "Secure Preferences"]:
            path = self.profile_path / name
            if path.exists():
                files.append(path)
        local_state = self.user_data_dir / "Local State"
        if local_state.exists():
            files.append(local_state)
        return files

    def get_tables(self, db_name: str) -> List[str]:
        """Get tables in a database."""
        db_path = self._get_db_copy(db_name)
        if not db_path:
            return []
        try:
            conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
            tables = [row[0] for row in cursor.fetchall()]
            conn.close()
            return tables
        except sqlite3.Error:
            return []

    def run_query(self, db_name: str, query: str) -> Tuple[List[Dict[str, Any]], int]:
        """Execute a query on a database."""
        db_path = self._get_db_copy(db_name)
        if not db_path:
            return [], 0
        try:
            conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(query)
            rows = [dict(row) for row in cursor.fetchall()]
            conn.close()
            return rows, len(rows)
        except sqlite3.Error as e:
            print(f"Query error on {db_name}: {e}")
            return [], 0

    def extract_all(self) -> Dict[str, List[Dict[str, Any]]]:
        """Extract all forensic data."""
        results = {}
        for db_name, queries in CHROMIUM_QUERIES.items():
            for query_name, query_sql in queries.items():
                rows, _ = self.run_query(db_name, query_sql)
                if rows:
                    results[query_name] = rows
        return results

    def get_history(self) -> List[Dict[str, Any]]:
        """Get browsing history."""
        if "History" in CHROMIUM_QUERIES:
            rows, _ = self.run_query("History", CHROMIUM_QUERIES["History"]["browsing_history"])
            return rows
        return []

    def get_cookies(self) -> List[Dict[str, Any]]:
        """Get all cookies."""
        if "Cookies" in CHROMIUM_QUERIES:
            rows, _ = self.run_query("Cookies", CHROMIUM_QUERIES["Cookies"]["all_cookies"])
            return rows
        return []

    def get_downloads(self) -> List[Dict[str, Any]]:
        """Get downloads."""
        if "History" in CHROMIUM_QUERIES:
            rows, _ = self.run_query("History", CHROMIUM_QUERIES["History"]["downloads"])
            return rows
        return []

    def get_logins(self) -> List[Dict[str, Any]]:
        """Get saved login entries (passwords encrypted)."""
        if "Login Data" in CHROMIUM_QUERIES:
            rows, _ = self.run_query("Login Data", CHROMIUM_QUERIES["Login Data"]["all_logins"])
            return rows
        return []

    def get_autofill(self) -> List[Dict[str, Any]]:
        """Get autofill data."""
        if "Web Data" in CHROMIUM_QUERIES:
            rows, _ = self.run_query("Web Data", CHROMIUM_QUERIES["Web Data"]["autofill"])
            return rows
        return []

    def extract_bookmarks(self) -> Optional[Dict[str, Any]]:
        """Extract bookmarks from JSON."""
        bookmarks_path = self.profile_path / "Bookmarks"
        if not bookmarks_path.exists():
            return None
        try:
            with open(bookmarks_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            return None

    def flatten_bookmarks(self) -> List[Dict[str, Any]]:
        """Flatten bookmark tree into a list."""
        data = self.extract_bookmarks()
        if not data:
            return []

        bookmarks = []

        def traverse(node, path=""):
            if node.get("type") == "url":
                bookmarks.append({
                    "name": node.get("name", ""),
                    "url": node.get("url", ""),
                    "path": path,
                    "date_added": node.get("date_added", ""),
                })
            for child in node.get("children", []):
                traverse(child, f"{path}/{node.get('name', '')}")

        roots = data.get("roots", {})
        for root_name, root_node in roots.items():
            traverse(root_node, root_name)

        return bookmarks

    def get_extensions(self) -> List[Dict[str, Any]]:
        """Get installed extensions from Preferences."""
        prefs_path = self.profile_path / "Preferences"
        if not prefs_path.exists():
            return []
        try:
            with open(prefs_path, "r", encoding="utf-8") as f:
                prefs = json.load(f)
            extensions_settings = prefs.get("extensions", {}).get("settings", {})
            extensions = []
            for ext_id, ext_info in extensions_settings.items():
                manifest = ext_info.get("manifest", {})
                extensions.append({
                    "id": ext_id,
                    "name": manifest.get("name", ext_info.get("name", "Unknown")),
                    "version": manifest.get("version", ""),
                    "description": manifest.get("description", "")[:100] if manifest.get("description") else "",
                    "enabled": ext_info.get("state", 0) == 1,
                })
            return extensions
        except (json.JSONDecodeError, IOError):
            return []
