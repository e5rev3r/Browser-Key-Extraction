#!/usr/bin/env python3
"""
Firefox Forensics - Timestamp Normalization Module
===================================================
Handles Firefox timestamp conversion to forensic-standard formats.
Provides both raw values and ISO-8601 UTC representations.
"""

from datetime import datetime, timezone
from typing import Any, Dict, Optional, Union


# Firefox timestamp field patterns
TIMESTAMP_FIELD_PATTERNS = [
    'time', 'date', 'created', 'modified', 'accessed', 'expir', 
    'last', 'first', 'when', 'added', 'updated', 'visit', 'used'
]


def detect_timestamp_type(value: Any) -> str:
    """Detect the type of timestamp based on magnitude.
    
    Firefox uses different timestamp formats:
    - Microseconds since Unix epoch (places.sqlite: visit_date)
    - Milliseconds since Unix epoch (cookies.sqlite: expiry, logins.json)
    - Seconds since Unix epoch (some fields)
    
    Args:
        value: Numeric timestamp value.
        
    Returns:
        String indicating timestamp type: 'microseconds', 'milliseconds', 'seconds', 'unknown'
    """
    if value is None or not isinstance(value, (int, float)):
        return 'unknown'
    
    try:
        ts = float(value)
        
        if ts > 1e15:  # Greater than ~31,688 years in milliseconds
            return 'microseconds'
        elif ts > 1e12:  # Greater than ~31 years in seconds
            return 'milliseconds'
        elif ts > 1e9:  # Greater than 1970-01-12 in milliseconds
            return 'seconds'
        else:
            return 'unknown'
    except (ValueError, TypeError):
        return 'unknown'


def is_timestamp_field(field_name: str) -> bool:
    """Check if a field name suggests it contains a timestamp.
    
    Args:
        field_name: Name of the field to check.
        
    Returns:
        True if field name suggests a timestamp.
    """
    if not field_name:
        return False
    
    field_lower = str(field_name).lower()
    return any(pattern in field_lower for pattern in TIMESTAMP_FIELD_PATTERNS)


def normalize_firefox_timestamp(value: Any, field_name: str = "") -> Optional[Dict[str, Any]]:
    """Convert Firefox timestamp to normalized forensic format.
    
    Args:
        value: Timestamp value to convert.
        field_name: Optional field name to help detect timestamp type.
        
    Returns:
        Dictionary with raw and UTC values, or None if not a valid timestamp.
        
    Example:
        {
            "raw": 1764022467770000,
            "utc": "2025-11-24T18:14:27Z",
            "local": "2025-11-24 19:14:27",
            "type": "microseconds"
        }
    """
    if value is None or value == '' or value == 0:
        return None
    
    try:
        ts = float(value)
        ts_type = detect_timestamp_type(ts)
        
        # Convert to seconds based on detected type
        if ts_type == 'microseconds':
            ts_seconds = ts / 1000000
        elif ts_type == 'milliseconds':
            ts_seconds = ts / 1000
        elif ts_type == 'seconds':
            ts_seconds = ts
        else:
            return None
        
        # Sanity check: between 2000 and 2100
        if not (946684800 < ts_seconds < 4102444800):
            return None
        
        utc_dt = datetime.fromtimestamp(ts_seconds, tz=timezone.utc)
        local_dt = datetime.fromtimestamp(ts_seconds)
        
        return {
            "raw": int(value),
            "utc": utc_dt.strftime('%Y-%m-%dT%H:%M:%SZ'),
            "local": local_dt.strftime('%Y-%m-%d %H:%M:%S'),
            "type": ts_type
        }
        
    except (ValueError, OSError, OverflowError, TypeError):
        return None


def normalize_row_timestamps(row: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize all timestamp fields in a data row.
    
    Args:
        row: Dictionary containing data row.
        
    Returns:
        New dictionary with timestamps normalized.
    """
    result = {}
    
    for key, value in row.items():
        # Check if this field might be a timestamp
        if is_timestamp_field(key) and isinstance(value, (int, float)) and value > 1000000000:
            normalized = normalize_firefox_timestamp(value, key)
            if normalized:
                result[key] = normalized
            else:
                result[key] = value
        else:
            result[key] = value
    
    return result


def format_timestamp_for_display(value: Any, field_name: str = "") -> str:
    """Format a timestamp for human-readable display.
    
    Args:
        value: Timestamp value.
        field_name: Optional field name.
        
    Returns:
        Formatted string or original value as string.
    """
    normalized = normalize_firefox_timestamp(value, field_name)
    
    if normalized:
        return f"{normalized['local']} (UTC: {normalized['utc']})"
    
    return str(value) if value is not None else ''


def get_current_timestamp_utc() -> str:
    """Get current time as ISO-8601 UTC string.
    
    Returns:
        Current time in format: "2025-12-15T10:30:00Z"
    """
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def get_current_timestamp_local() -> str:
    """Get current time as local string.
    
    Returns:
        Current local time in format: "2025-12-15 11:30:00"
    """
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')


class TimestampNormalizer:
    """Batch timestamp normalizer for forensic data processing."""
    
    def __init__(self):
        """Initialize normalizer."""
        self.stats = {
            'fields_processed': 0,
            'timestamps_normalized': 0,
            'conversion_failures': 0
        }
    
    def normalize_findings(self, findings: Dict[str, list]) -> Dict[str, list]:
        """Normalize timestamps in all findings.
        
        Args:
            findings: Dictionary mapping category names to lists of items.
            
        Returns:
            New dictionary with normalized timestamps.
        """
        result = {}
        
        for category, items in findings.items():
            normalized_items = []
            
            for item in items:
                if isinstance(item, dict):
                    normalized_item = self.normalize_row(item)
                    normalized_items.append(normalized_item)
                else:
                    normalized_items.append(item)
            
            result[category] = normalized_items
        
        return result
    
    def normalize_row(self, row: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize a single row of data.
        
        Args:
            row: Data row dictionary.
            
        Returns:
            Normalized row dictionary.
        """
        result = {}
        
        for key, value in row.items():
            self.stats['fields_processed'] += 1
            
            # Check if this might be a timestamp
            if is_timestamp_field(key) and isinstance(value, (int, float)) and value > 1000000000:
                normalized = normalize_firefox_timestamp(value, key)
                
                if normalized:
                    result[key] = normalized
                    self.stats['timestamps_normalized'] += 1
                else:
                    result[key] = value
                    self.stats['conversion_failures'] += 1
            else:
                result[key] = value
        
        return result
    
    def get_stats(self) -> Dict[str, int]:
        """Get normalization statistics.
        
        Returns:
            Statistics dictionary.
        """
        return self.stats.copy()


# Cookie-specific timestamp handling
def normalize_cookie_expiry(expiry_value: Any) -> Optional[Dict[str, Any]]:
    """Normalize cookie expiry timestamp.
    
    Cookie expiry in Firefox is typically stored as Unix seconds.
    
    Args:
        expiry_value: Cookie expiry timestamp.
        
    Returns:
        Normalized timestamp dictionary or None.
    """
    if expiry_value is None or expiry_value == 0:
        return None
    
    try:
        ts = float(expiry_value)
        
        # Cookie expiry is typically in seconds
        # Special case: 0 means session cookie
        if ts == 0:
            return {"raw": 0, "utc": "Session Cookie", "local": "Session Cookie", "type": "session"}
        
        # Sanity check for cookies (between 2000 and 2100)
        if not (946684800 < ts < 4102444800):
            return None
        
        utc_dt = datetime.fromtimestamp(ts, tz=timezone.utc)
        local_dt = datetime.fromtimestamp(ts)
        
        # Check if expired
        now = datetime.now(timezone.utc)
        is_expired = utc_dt < now
        
        return {
            "raw": int(expiry_value),
            "utc": utc_dt.strftime('%Y-%m-%dT%H:%M:%SZ'),
            "local": local_dt.strftime('%Y-%m-%d %H:%M:%S'),
            "type": "seconds",
            "expired": is_expired
        }
        
    except (ValueError, OSError, OverflowError, TypeError):
        return None


# History-specific timestamp handling  
def normalize_visit_timestamp(visit_date: Any) -> Optional[Dict[str, Any]]:
    """Normalize Firefox visit_date timestamp.
    
    Firefox stores visit_date in microseconds since Unix epoch.
    
    Args:
        visit_date: Visit date from places.sqlite.
        
    Returns:
        Normalized timestamp dictionary or None.
    """
    if visit_date is None or visit_date == 0:
        return None
    
    try:
        ts = float(visit_date)
        
        # Firefox visit_date is in microseconds
        ts_seconds = ts / 1000000
        
        # Sanity check
        if not (946684800 < ts_seconds < 4102444800):
            return None
        
        utc_dt = datetime.fromtimestamp(ts_seconds, tz=timezone.utc)
        local_dt = datetime.fromtimestamp(ts_seconds)
        
        return {
            "raw": int(visit_date),
            "utc": utc_dt.strftime('%Y-%m-%dT%H:%M:%SZ'),
            "local": local_dt.strftime('%Y-%m-%d %H:%M:%S'),
            "type": "microseconds"
        }
        
    except (ValueError, OSError, OverflowError, TypeError):
        return None
