#!/usr/bin/env python3
"""
Android Forensic Timeline Builder  v1.0 (Optimised)
Parses SQLite databases from Android extractions and builds a unified timeline.
Extracts timestamps AND associated message/content/info from every app.
"""

import os
import zipfile
import sqlite3
import json
import re
import shutil
import tempfile
import threading
import traceback
import csv
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone, timedelta
from pathlib import Path
from collections import defaultdict

import tkinter as tk
from tkinter import ttk, filedialog, messagebox

# ─────────────────────────────────────────────────────────────────────────────
#  TIMESTAMP CONSTANTS (unchanged)
# ─────────────────────────────────────────────────────────────────────────────

YEAR_MIN = 1990
YEAR_MAX = 2035

UNIX_S_MIN   = 631_152_000           # 1990-01-01
UNIX_S_MAX   = 2_051_222_400         # 2035-01-01
UNIX_MS_MIN  = UNIX_S_MIN  * 1_000
UNIX_MS_MAX  = UNIX_S_MAX  * 1_000
UNIX_US_MIN  = UNIX_S_MIN  * 1_000_000
UNIX_US_MAX  = UNIX_S_MAX  * 1_000_000
UNIX_NS_MIN  = UNIX_S_MIN  * 1_000_000_000
UNIX_NS_MAX  = UNIX_S_MAX  * 1_000_000_000

WEBKIT_OFFSET_US = 11_644_473_600_000_000
WEBKIT_MIN = WEBKIT_OFFSET_US + UNIX_S_MIN * 1_000_000
WEBKIT_MAX = WEBKIT_OFFSET_US + UNIX_S_MAX * 1_000_000

FILETIME_OFFSET = 116_444_736_000_000_000
FILETIME_MIN = FILETIME_OFFSET + UNIX_S_MIN * 10_000_000
FILETIME_MAX = FILETIME_OFFSET + UNIX_S_MAX * 10_000_000

APPLE_OFFSET_S = 978_307_200
# Apple epoch (seconds since 2001-01-01). Clamp MIN to year 2005 to avoid
# negative values and collision with tiny integers like 0/1/flags.
APPLE_S_MIN  = max(UNIX_S_MIN - APPLE_OFFSET_S, 126_230_400)  # 2005-01-01 Apple epoch
APPLE_S_MAX  = UNIX_S_MAX  - APPLE_OFFSET_S
APPLE_MS_MIN = max(APPLE_S_MIN * 1_000, 126_230_400_000)
APPLE_MS_MAX = APPLE_S_MAX * 1_000

JDN_UNIX_EPOCH = 2_440_587.5
JDN_MIN = JDN_UNIX_EPOCH + UNIX_S_MIN / 86400
JDN_MAX = JDN_UNIX_EPOCH + UNIX_S_MAX / 86400

# Unix minutes (seen in battery/usage-stats DBs, some health aggregates)
UNIX_MIN_MIN = UNIX_S_MIN  // 60          # 10_519_200
UNIX_MIN_MAX = UNIX_S_MAX  // 60          # 34_187_040

# Unix hours (seen in aggregated analytics / health step-count DBs)
UNIX_HR_MIN  = UNIX_S_MIN  // 3_600       # 175_320
UNIX_HR_MAX  = UNIX_S_MAX  // 3_600       # 569_784

# Unix days (seen in Google Fit daily summaries, Samsung Health aggregates)
# Carefully bounded so they don't collide with small integer IDs:
# day 7_305 = 1990-01-01, day 23_741 = 2035-01-01
UNIX_DAY_MIN = UNIX_S_MIN  // 86_400      # 7_305
UNIX_DAY_MAX = UNIX_S_MAX  // 86_400      # 23_741

# Stricter floor for divided-epoch formats (days/hours/minutes).
# Small integers like duration values (e.g. 7326 ms of fg_time) can fall
# inside the day/hour/minute ranges and produce false 1990s timestamps.
# Requiring the resolved timestamp to be >= 2000-01-01 eliminates these.
_DIVIDED_EPOCH_FLOOR_S = 946_684_800      # 2000-01-01 00:00:00 UTC
UNIX_DAY_MIN_STRICT  = _DIVIDED_EPOCH_FLOOR_S // 86_400    # 10_957
UNIX_HR_MIN_STRICT   = _DIVIDED_EPOCH_FLOOR_S // 3_600     # 262_980
UNIX_MIN_MIN_STRICT  = _DIVIDED_EPOCH_FLOOR_S // 60        # 15_778_080

# ─────────────────────────────────────────────────────────────────────────────
#  COLUMN NAME PATTERNS (unchanged)
# ─────────────────────────────────────────────────────────────────────────────

TS_COLUMNS = re.compile(
    r'(^|[_\-])(time(stamp)?|date(time)?|created?(_at|_on)?|modif(ied|y)(_at)?|'
    r'updated?(_at)?|sent(_at)?|receiv(ed|e)(_at)?|deliver(ed|y)(_at)?|'
    r'last[_\-]?(visit|access|seen|used|active|online|read|msg|message)|'
    r'first[_\-]?(visit|seen|access)|'
    r'added?(_at)?|deleted?(_at)?|read(_at)?|played?(_at)?|viewed?(_at)?|'
    r'synced?(_at)?|expir(es?|ed|y|ation)(_at)?|changed?(_at)?|'
    r'pinned?(_at)?|archived?(_at)?|joined?(_at)?|left(_at)?|'
    r'logged?(_at|_in|_out)?|started?(_at)?|ended?(_at)?|'
    r'posted?(_at)?|publi(shed|c)(_at)?|edit(ed)?(_at)?|'
    r'scheduled?(_at)?|reminded?(_at)?|notif(ied|y)(_at)?|'
    r'call(ed)?(_at)?|install(ed)?(_at)?|launch(ed)?(_at)?|open(ed)?(_at)?|'
    # Android MediaStore columns (external.db / internal.db)
    r'date[_\-]?(taken|added|modified|expires?)|'
    r'capture[_\-]?time|taken[_\-]?at|'
    # Messaging-specific (WhatsApp msgstore.db, Telegram cache4.db, Viber)
    r'msg[_\-]?time|chat[_\-]?time|receipt[_\-]?(server[_\-]?)?timestamp|'
    r'receipt[_\-]?device[_\-]?timestamp|server[_\-]?timestamp|'
    # Analytics / crash reporting (Firebase, Crashlytics local cache DBs)
    r'event[_\-]?(time|date)|session[_\-]?(start|end|time)|'
    # System / battery / health DBs
    r'boot[_\-]?time|wakeup[_\-]?time|measured[_\-]?at|recorded[_\-]?at|'
    r'access[_\-]?(time|date)|'
    # Task / alarm / calendar apps
    r'due[_\-]?(date|at)|alarm[_\-]?time|'
    # Contacts DB
    r'birth(day|date)|connected[_\-]?at|disconnected[_\-]?at|'
    r'ts|tms|epoch|millis|micros|nanos|unix)($|[_\-])',
    re.IGNORECASE
)

CONTENT_COLUMNS = re.compile(
    r'(^|[_\-])(body|text|message|msg|content|data|subject|title|'
    r'description|desc|note|memo|summary|snippet|preview|'
    r'address|number|name|contact|sender|recipient|from|to|'
    r'url|uri|link|path|filename|file|query|search|'
    r'value|detail|info|extra|payload|raw)($|[_\-])',
    re.IGNORECASE
)

# ─────────────────────────────────────────────────────────────────────────────
#  APP PATTERNS & COLORS (unchanged)
# ─────────────────────────────────────────────────────────────────────────────

APP_PATTERNS = {
    "WhatsApp":      ["whatsapp", "com.whatsapp"],
    "Telegram":      ["telegram", "org.telegram"],
    "Signal":        ["signal", "org.thoughtcrime"],
    "Instagram":     ["instagram", "com.instagram"],
    "Facebook":      ["facebook", "com.facebook"],
    "Twitter/X":     ["twitter", "com.twitter", "com.x.android"],
    "Gmail":         ["gmail", "com.google.android.gm"],
    "Chrome":        ["chrome", "com.android.chrome", "com.google.chrome"],
    "Contacts":      ["contacts", "com.android.providers.contacts"],
    "SMS/MMS":       ["mmssms", "telephony", "com.android.providers.telephony"],
    "Calendar":      ["calendar", "com.android.providers.calendar"],
    "Media/Gallery": ["media", "external.db", "internal.db", "gallery"],
    "Browser":       ["browser", "com.android.browser", "webviewbrowser"],
    "Downloads":     ["downloads", "com.android.providers.downloads"],
    "Settings":      ["settings", "com.android.providers.settings"],
    "Maps":          ["maps", "com.google.android.apps.maps"],
    "YouTube":       ["youtube", "com.google.android.youtube"],
    "Snapchat":      ["snapchat", "com.snapchat"],
    "TikTok":        ["tiktok", "com.zhiliaoapp", "musical.ly"],
    "Viber":         ["viber", "com.viber"],
    "Line":          ["line", "jp.naver.line"],
    "WeChat":        ["wechat", "com.tencent.mm"],
    "Discord":       ["discord", "com.discord"],
    "LinkedIn":      ["linkedin", "com.linkedin"],
    "Skype":         ["skype", "com.skype"],
    "Email":         ["email", "com.android.email", "com.mail"],
    "Notes":         ["notes", "memo", "com.samsung.notes"],
    "Call Log":      ["calllog", "call_log", "dialer"],
    "Keyboard":      ["keyboard", "latinime", "swiftkey", "gboard"],
    "Clipboard":     ["clipboard"],
    "Location":      ["location", "gps", "gnss"],
    "Battery":       ["battery", "health"],
    "Spotify":       ["spotify", "com.spotify"],
    "Uber":          ["uber", "com.ubercab"],
    "Amazon":        ["amazon", "com.amazon"],
    "Netflix":       ["netflix", "com.netflix"],
    "PayPal":        ["paypal", "com.paypal"],
    "Zoom":          ["zoom", "us.zoom"],
    "Teams":         ["teams", "com.microsoft.teams"],
}

APP_COLORS = {
    "WhatsApp": "#25D366", "Telegram": "#2CA5E0", "Signal": "#3A76F0",
    "Instagram": "#E1306C", "Facebook": "#1877F2", "Twitter/X": "#1DA1F2",
    "Gmail": "#EA4335", "Chrome": "#FBBC05", "Contacts": "#34A853",
    "SMS/MMS": "#FF6D00", "Calendar": "#4285F4", "Media/Gallery": "#AB47BC",
    "Browser": "#FF7043", "Downloads": "#78909C", "Settings": "#607D8B",
    "Maps": "#00ACC1", "YouTube": "#FF0000", "Snapchat": "#FFFC00",
    "TikTok": "#EE1D52", "Viber": "#7360F2", "Line": "#00C300",
    "WeChat": "#07C160", "Discord": "#5865F2", "LinkedIn": "#0A66C2",
    "Skype": "#00AFF0", "Email": "#FF6F00", "Notes": "#FDD835",
    "Keyboard": "#26A69A", "Clipboard": "#8D6E63", "Location": "#EF5350",
    "Battery": "#66BB6A", "Call Log": "#FF8A65", "Spotify": "#1DB954",
    "Uber": "#CCCCCC", "Amazon": "#FF9900", "Netflix": "#E50914",
    "PayPal": "#009CDE", "Zoom": "#2D8CFF", "Teams": "#6264A7",
    "Unknown": "#90A4AE",
}


_PKG_RE = re.compile(
    r'[/\\]([a-zA-Z][a-zA-Z0-9_]*(?:\.[a-zA-Z][a-zA-Z0-9_]*)+)[/\\]'
)

def detect_app(path_str: str) -> str:
    low = path_str.lower()
    for app, patterns in APP_PATTERNS.items():
        for p in patterns:
            if p in low:
                return app
    # Fall back to extracting the package/folder name from the path
    # e.g. /data/data/com.hotstar.android/databases/x.db → com.hotstar.android
    matches = _PKG_RE.findall(path_str)
    if matches:
        # Pick the longest match (most specific package name)
        return max(matches, key=len)
    return "Unknown"


# ─────────────────────────────────────────────────────────────────────────────
#  TIMESTAMP PARSING (unchanged, but small optimisation)
# ─────────────────────────────────────────────────────────────────────────────

_ISO_FMTS = [
    "%Y-%m-%d %H:%M:%S",    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%dT%H:%M:%SZ",   "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S.%fZ",
    "%Y/%m/%d %H:%M:%S",    "%Y/%m/%d %H:%M",
    "%d/%m/%Y %H:%M:%S",    "%d-%m-%Y %H:%M:%S",
    "%m/%d/%Y %H:%M:%S",    "%Y-%m-%d",
    "%d %b %Y %H:%M:%S",
    "%a, %d %b %Y %H:%M:%S %z",
    "%a %b %d %H:%M:%S %Z %Y",
]
_TZ_STRIP = re.compile(r'\s*[+-]\d{2}:?\d{2}$')


def _ok(dt: datetime) -> datetime | None:
    return dt if YEAR_MIN <= dt.year <= YEAR_MAX else None


def _unix(v: float) -> datetime | None:
    try:
        return _ok(datetime.fromtimestamp(v, tz=timezone.utc))
    except (OSError, OverflowError, ValueError):
        return None


def parse_timestamp(value) -> datetime | None:
    """
    Try every timestamp encoding used in Android SQLite databases.
    Returns a UTC datetime or None.
    """
    if value is None:
        return None

    # ── String ───────────────────────────────────────────────────────────────
    if isinstance(value, str):
        s = value.strip()
        if not s:
            return None
        s_no_tz = _TZ_STRIP.sub('', s).strip()
        for fmt in _ISO_FMTS:
            for cand in (s, s_no_tz):
                try:
                    dt = datetime.strptime(cand, fmt)
                    if YEAR_MIN <= dt.year <= YEAR_MAX:
                        return (dt.replace(tzinfo=timezone.utc)
                                if dt.tzinfo is None
                                else dt.astimezone(timezone.utc))
                except ValueError:
                    continue
        # Try parsing as number stored as string
        try:
            value = float(s) if '.' in s else int(s)
        except (ValueError, TypeError):
            return None

    # ── Float (Julian Day or fractional seconds) ─────────────────────────────
    if isinstance(value, float):
        if JDN_MIN <= value <= JDN_MAX:
            dt = _unix((value - JDN_UNIX_EPOCH) * 86400)
            if dt:
                return dt
        return _unix(value)

    # ── Integer ──────────────────────────────────────────────────────────────
    try:
        v = int(value)
    except (TypeError, ValueError):
        return None

    # Hard minimum: raised to UNIX_DAY_MIN_STRICT (day 10_957 = 2000-01-01)
    # to prevent small duration values (ms/µs counts) from being misread as
    # divided-epoch timestamps while still supporting days/hours/minutes formats.
    # Boolean flags (0,1), small IDs, and version codes are still rejected.
    if v < UNIX_DAY_MIN_STRICT:
        return None

    # ── Divided Unix epochs (small integers) ─────────────────────────────────
    # These must come FIRST — their numeric ranges are below UNIX_S_MIN so the
    # existing range checks above would never reach them.

    # Unix days — Google Fit daily summaries, Samsung Health aggregates
    # Strict floor (day 10_957 = 2000-01-01) prevents small duration values
    # (e.g. 7326 ms of fg_time) from being misread as 1990s timestamps.
    if UNIX_DAY_MIN_STRICT <= v <= UNIX_DAY_MAX:
        dt = _unix(v * 86_400)
        if dt:
            return dt

    # Unix hours — aggregated analytics, some health DBs
    # Strict floor (hr 262_980 = 2000-01-01) for same reason.
    if UNIX_HR_MIN_STRICT <= v <= UNIX_HR_MAX:
        dt = _unix(v * 3_600)
        if dt:
            return dt

    # Unix minutes — battery stats, screen on/off logs, usage stats
    # Strict floor (min 15_778_080 = 2000-01-01) for same reason.
    if UNIX_MIN_MIN_STRICT <= v <= UNIX_MIN_MAX:
        dt = _unix(v * 60)
        if dt:
            return dt

    # ── Standard epoch formats ────────────────────────────────────────────────
    # Hard floor for all remaining formats: nothing below UNIX_S_MIN is valid.
    if v < UNIX_S_MIN:
        return None

    # Unix nanoseconds  (~19 digits)
    if UNIX_NS_MIN <= v <= UNIX_NS_MAX:
        dt = _unix(v / 1_000_000_000)
        if dt:
            return dt

    # Windows FILETIME (100-ns since 1601)
    if FILETIME_MIN <= v <= FILETIME_MAX:
        dt = _unix((v - FILETIME_OFFSET) / 10_000_000)
        if dt:
            return dt

    # WebKit/Chrome microseconds (since 1601)
    if WEBKIT_MIN <= v <= WEBKIT_MAX:
        dt = _unix((v - WEBKIT_OFFSET_US) / 1_000_000)
        if dt:
            return dt

    # Unix microseconds
    if UNIX_US_MIN <= v <= UNIX_US_MAX:
        dt = _unix(v / 1_000_000)
        if dt:
            return dt

    # Apple epoch milliseconds (since 2001)
    if APPLE_MS_MIN <= v <= APPLE_MS_MAX:
        dt = _unix(v / 1_000 + APPLE_OFFSET_S)
        if dt:
            return dt

    # Unix milliseconds
    if UNIX_MS_MIN <= v <= UNIX_MS_MAX:
        dt = _unix(v / 1_000)
        if dt:
            return dt

    # Apple epoch seconds (since 2001)
    if APPLE_S_MIN <= v <= APPLE_S_MAX:
        dt = _unix(v + APPLE_OFFSET_S)
        if dt:
            return dt

    # Unix seconds
    if UNIX_S_MIN <= v <= UNIX_S_MAX:
        return _unix(v)

    return None


# ─────────────────────────────────────────────────────────────────────────────
#  COLUMN HELPERS (optimised probing)
# ─────────────────────────────────────────────────────────────────────────────

def is_timestamp_column(name: str) -> bool:
    # First reject known non-timestamp column names
    if NON_TS_COLUMNS.search(name):
        return False
    return bool(TS_COLUMNS.search(name))

def is_content_column(name: str) -> bool:
    return bool(CONTENT_COLUMNS.search(name))

def is_numeric_type(col_type: str) -> bool:
    t = (col_type or "").upper().strip()
    if not t:
        return True   # SQLite blank affinity = stores anything
    return any(k in t for k in ("INT", "REAL", "NUMERIC", "FLOAT", "DOUBLE",
                                 "DECIMAL", "NUMBER", "LONG", "BIG"))

# Columns whose names look timestamp-ish but are NOT timestamps
NON_TS_COLUMNS = re.compile(
    r'(^|[_\-])(id|_id|rowid|size|count|num|number|version|code|flag|'
    r'status|state|type|kind|mode|level|rank|order|index|seq|sequence|'
    r'duration|length|width|height|rating|score|price|amount|'
    r'weight|age|priority|permission|uid|gid|pid|tid|port|'
    r'color|colour|alpha|hash|checksum|crc|magic|offset|position|'
    r'retry|attempt|error|errno|result|response|percent|ratio|'
    r'latitude|longitude|accuracy|altitude|bearing|speed|'
    r'byte|bit|char|word|block|page|sector|cluster|'
    r'max|min|avg|sum|total|limit|quota|capacity|'
    r'answered|missed|ring|rang|duration|'
    r'is_[a-z]|has_[a-z]|can_[a-z]|should_[a-z]|'   # boolean flags: is_read, has_content…
    r'bool|boolean|enabled|disabled|visible|hidden|'
    r'active|deleted|archived|blocked|banned|verified|'
    r'sort|weight|importance|confidence|probability|'
    # Guard new TS_COLUMNS additions against count/id false positives
    r'times[_\-]contacted|access[_\-]count|session[_\-]?(id|count)|'
    r'event[_\-]?(id|count|type)|alarm[_\-]?(id|count)|'
    r'birth[_\-]?(year|place|country)|capture[_\-]?(id|count)|'
    r'msg[_\-]?(id|count|type)|chat[_\-]?(id|count|type))($|[_\-])',
    re.IGNORECASE
)


def _probe_timestamps_fast(cur, table: str, col: str) -> bool:
    """
    Fast timestamp column detection: check min/max range of the column.
    If both min and max fall inside any of the plausible timestamp ranges,
    we consider it a timestamp column.
    """
    try:
        cur.execute(f'SELECT MIN("{col}"), MAX("{col}") FROM "{table}" WHERE "{col}" IS NOT NULL')
        min_val, max_val = cur.fetchone()
        if min_val is None or max_val is None:
            return False

        try:
            min_num = float(min_val) if '.' in str(min_val) else int(min_val)
            max_num = float(max_val) if '.' in str(max_val) else int(max_val)
        except (ValueError, TypeError):
            return False

        # Hard floor — anything below UNIX_DAY_MIN cannot be a real timestamp
        if max_num < UNIX_DAY_MIN:
            return False

        ranges = [
            (UNIX_NS_MIN,       UNIX_NS_MAX),
            (FILETIME_MIN,      FILETIME_MAX),
            (WEBKIT_MIN,        WEBKIT_MAX),
            (UNIX_US_MIN,       UNIX_US_MAX),
            (APPLE_MS_MIN,      APPLE_MS_MAX),
            (UNIX_MS_MIN,       UNIX_MS_MAX),
            (APPLE_S_MIN,       APPLE_S_MAX),
            (UNIX_S_MIN,        UNIX_S_MAX),
            (UNIX_MIN_MIN_STRICT, UNIX_MIN_MAX),   # Unix minutes (strict floor)
            (UNIX_HR_MIN_STRICT,  UNIX_HR_MAX),    # Unix hours  (strict floor)
            (UNIX_DAY_MIN_STRICT, UNIX_DAY_MAX),   # Unix days   (strict floor)
        ]
        for low, high in ranges:
            if low <= min_num <= high and low <= max_num <= high:
                return True
        return False
    except Exception:
        return False

def _extract_content(row, content_cols: list[str]) -> str:
    """Pull the best human-readable content from a row alongside a timestamp."""
    priority = ["body", "text", "message", "msg", "subject", "content",
                "data", "address", "number", "name", "url", "query", "title"]
    ordered = sorted(content_cols,
                     key=lambda c: next(
                         (i for i, p in enumerate(priority) if p in c.lower()), 99))
    parts = []
    for col in ordered:
        try:
            v = row[col]
            if v is None:
                continue
            s = str(v).strip()
            if not s or s.lower() in ("null", "none", "0", ""):
                continue
            try:            # skip pure numbers (IDs etc.)
                float(s)
                continue
            except ValueError:
                pass
            parts.append(s)
            if len(parts) >= 4:
                break
        except Exception:
            pass
    return "  |  ".join(parts)


# ─────────────────────────────────────────────────────────────────────────────
#  DATABASE PARSER (optimised, no row_data stored)
# ─────────────────────────────────────────────────────────────────────────────

def find_db_files(root: str, progress_cb=None) -> list[str]:
    """
    Walk the directory tree and return all SQLite database paths.
    Files with known DB extensions are accepted immediately.
    Files with unknown extensions are magic-byte checked concurrently.
    """
    magic = b'SQLite format 3'
    definite: list[str] = []
    candidates: list[str] = []
    for dirpath, _, filenames in os.walk(root):
        for fn in filenames:
            fp = os.path.join(dirpath, fn)
            ext = Path(fn).suffix.lower()
            if ext in ('.db', '.sqlite', '.sqlite3', '.db3', '.sdb'):
                definite.append(fp)
            elif ext not in ('.db-shm', '.db-wal'):
                candidates.append(fp)
    found: list[str] = list(definite)
    if progress_cb and found:
        progress_cb(len(found))
    def _check_magic(fp: str):
        try:
            with open(fp, 'rb') as f:
                return fp if f.read(15) == magic else None
        except Exception:
            return None
    magic_workers = min(32, max(8, (os.cpu_count() or 4) * 4))
    batch_size = 50
    completed = 0
    with ThreadPoolExecutor(max_workers=magic_workers) as pool:
        futures = {pool.submit(_check_magic, fp): fp for fp in candidates}
        for future in as_completed(futures):
            result = future.result()
            if result:
                found.append(result)
            completed += 1
            if progress_cb and completed % batch_size == 0:
                progress_cb(len(found))
    if progress_cb:
        progress_cb(len(found))
    return found


def parse_db(db_path: str, app_name: str) -> list[dict]:
    """
    Extract timestamps + content from every table in a SQLite database.
    """
    events = []
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=5)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [r[0] for r in cur.fetchall()]

        for table in tables:
            if table.startswith("sqlite_"):
                continue
            try:
                cur.execute(f'PRAGMA table_info("{table}")')
                col_infos = cur.fetchall()

                ts_cols: set[str] = set()
                content_cols: list[str] = []

                for ci in col_infos:
                    col_name = ci[1]
                    col_type = ci[2] or ""
                    if is_content_column(col_name):
                        content_cols.append(col_name)
                    if is_timestamp_column(col_name):
                        ts_cols.add(col_name)
                    elif is_numeric_type(col_type) and not NON_TS_COLUMNS.search(col_name):
                        # Statistical range+distribution check
                        if _probe_timestamps_fast(cur, table, col_name):
                            ts_cols.add(col_name)

                if not ts_cols:
                    continue

                # Determine if table has rowid (almost always true)
                has_rowid = True
                try:
                    cur.execute(f'SELECT rowid FROM "{table}" LIMIT 1')
                except sqlite3.OperationalError:
                    has_rowid = False

                cur.execute(f'SELECT * FROM "{table}" LIMIT 100000')
                rows = cur.fetchall()
                for row in rows:
                    row_dict = dict(row)  # used for content extraction only
                    for col in ts_cols:
                        try:
                            val = row[col]
                            dt = parse_timestamp(val)
                            if dt:
                                event = {
                                    "datetime":  dt,
                                    "app":       app_name,
                                    "db_file":   os.path.basename(db_path),
                                    "db_path":   db_path,
                                    "table":     table,
                                    "column":    col,
                                    "raw_value": str(val),
                                    "content":   _extract_content(row_dict, content_cols),
                                    # Store reference for full row retrieval later
                                    "_rowid":    row["rowid"] if has_rowid and "rowid" in row.keys() else None,
                                }
                                events.append(event)
                        except Exception:
                            pass
            except Exception:
                pass
        conn.close()
    except Exception:
        pass
    return events



# ─────────────────────────────────────────────────────────────────────────────
#  DEVICE ARTIFACT SCANNER
#  Searches the extraction root for known Android system artifacts that reveal
#  the device setup / first-use date, regardless of input type (ZIP / folder).
#  Returns a dict with findings; never raises — missing artifacts skipped silently.
# ─────────────────────────────────────────────────────────────────────────────

def _parse_ms_ts(v) -> "datetime | None":
    """Parse a Unix-millisecond integer to UTC datetime, or None."""
    try:
        ms = int(v)
        if 1_000_000_000_000 <= ms <= 2_100_000_000_000:
            return datetime.fromtimestamp(ms / 1000, tz=timezone.utc)
    except (TypeError, ValueError):
        pass
    return None


def scan_device_artifacts(root: str) -> dict:
    """
    Search *root* for the five canonical Android system artifacts:
      1. packages.xml          → firstInstallTime / lastUpdateTime per app
      2. package-usage-stats/  → first/last use times
      3. accounts.db           → Google/Samsung account added-to-device time
      4. GMS databases         → device registration timestamp
      5. WifiConfigStore.xml   → first WiFi network creation time

    Returns:
      {
        "device_setup_date": datetime | None,   # earliest credible date found
        "sources": [{"artifact": str, "detail": str, "date": datetime}, ...],
        "packages": {"com.foo": {"first_install": datetime, "last_update": datetime}, ...}
      }
    """
    import xml.etree.ElementTree as ET

    result = {"device_setup_date": None, "sources": [], "packages": {}}
    candidate_dates: list = []

    def _note(artifact: str, detail: str, dt: datetime):
        result["sources"].append({"artifact": artifact, "detail": detail, "date": dt})
        candidate_dates.append(dt)

    # Build a single index over the whole tree (one os.walk instead of 8).
    # _file_index: lowercase filename → [full paths]
    # _dir_index:  lowercase dirname  → [full paths]
    _file_index: dict = {}
    _dir_index:  dict = {}
    _MAX_DEPTH = 14
    for dirpath, dirs, files in os.walk(root):
        depth = dirpath.replace(root, "").count(os.sep)
        if depth >= _MAX_DEPTH:
            dirs.clear()
            continue
        for fn in files:
            key = fn.lower()
            _file_index.setdefault(key, []).append(os.path.join(dirpath, fn))
        for dn in dirs:
            key = dn.lower()
            _dir_index.setdefault(key, []).append(os.path.join(dirpath, dn))

    def _find_file(target_name: str, max_depth: int = 14):
        """Yield all paths matching target_name anywhere under root."""
        yield from _file_index.get(target_name.lower(), [])

    def _find_dir(target_name: str, max_depth: int = 14):
        """Yield all directories matching target_name anywhere under root."""
        yield from _dir_index.get(target_name.lower(), [])

    # 1. packages.xml ──────────────────────────────────────────────────────────
    for px_path in _find_file("packages.xml"):
        try:
            tree = ET.parse(px_path)
            earliest_sys = None
            for pkg in tree.iter("package"):
                name = pkg.get("name", "")
                fit  = _parse_ms_ts(pkg.get("firstInstallTime"))
                lut  = _parse_ms_ts(pkg.get("lastUpdateTime"))
                if fit:
                    result["packages"].setdefault(name, {})["first_install"] = fit
                if lut:
                    result["packages"].setdefault(name, {})["last_update"]   = lut
                code = pkg.get("codePath", "")
                if fit and (code.startswith("/system") or code.startswith("/product")):
                    if earliest_sys is None or fit < earliest_sys:
                        earliest_sys = fit
            if earliest_sys:
                _note("packages.xml",
                      f"Earliest system package install: {earliest_sys.strftime('%Y-%m-%d')}",
                      earliest_sys)
        except Exception:
            pass

    # 2. package-usage-stats/ ─────────────────────────────────────────────────
    for pu_dir in _find_dir("package-usage-stats"):
        try:
            for fn in os.listdir(pu_dir):
                if not fn.endswith(".xml"):
                    continue
                fp = os.path.join(pu_dir, fn)
                try:
                    et = ET.parse(fp)
                    for node in et.iter():
                        for attr in ("beginTime", "endTime", "firstTimeUsed", "lastTimeUsed"):
                            dt = _parse_ms_ts(node.get(attr))
                            if dt:
                                _note("package-usage-stats",
                                      f"{fn} / {node.tag}.{attr}: {dt.strftime('%Y-%m-%d')}",
                                      dt)
                except Exception:
                    pass
        except Exception:
            pass
        break   # only first directory hit

    # 3. accounts.db ──────────────────────────────────────────────────────────
    for acct_path in _find_file("accounts.db"):
        try:
            conn = sqlite3.connect(f"file:{acct_path}?mode=ro", uri=True, timeout=5)
            cur  = conn.cursor()
            for tbl in ("accounts_ce", "accounts"):
                try:
                    cur.execute(
                        f'SELECT name, type, last_password_entry_time_millis_epoch, '                        f'creation_time FROM "{tbl}" LIMIT 50')
                    for row in cur.fetchall():
                        for val in row[2:]:
                            dt = _parse_ms_ts(val)
                            if dt:
                                label = f"{row[1] or '?'} / {row[0] or '?'}"
                                _note("accounts.db",
                                      f"Account '{label}' time: {dt.strftime('%Y-%m-%d')}",
                                      dt)
                except Exception:
                    pass
            conn.close()
        except Exception:
            pass

    # 4. GMS databases ────────────────────────────────────────────────────────
    GMS_DBS = ("dg.db", "herrevad.db", "gass.db", "phenotype.db")
    for gms_name in GMS_DBS:
        for gms_path in _find_file(gms_name):
            if "com.google.android.gms" not in gms_path:
                continue
            try:
                conn = sqlite3.connect(f"file:{gms_path}?mode=ro", uri=True, timeout=5)
                cur  = conn.cursor()
                cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
                tables = [r[0] for r in cur.fetchall()]
                for tbl in tables:
                    try:
                        cur.execute(f'PRAGMA table_info("{tbl}")')
                        cols = [r[1] for r in cur.fetchall()]
                        ts_cols = [c for c in cols if any(
                            k in c.lower() for k in
                            ("time", "date", "timestamp", "created", "registered"))]
                        for tc in ts_cols[:3]:
                            cur.execute(
                                f'SELECT MIN("{tc}") FROM "{tbl}" '                                f'WHERE "{tc}" IS NOT NULL AND "{tc}" > 0')
                            row = cur.fetchone()
                            if row and row[0]:
                                dt = _parse_ms_ts(row[0])
                                if dt:
                                    _note("GMS DB",
                                          f"{gms_name}/{tbl}.{tc}: {dt.strftime('%Y-%m-%d')}",
                                          dt)
                    except Exception:
                        pass
                conn.close()
            except Exception:
                pass

    # 5. WifiConfigStore.xml ──────────────────────────────────────────────────
    for wifi_path in _find_file("WifiConfigStore.xml"):
        try:
            et = ET.parse(wifi_path)
            for node in et.iter():
                for attr in ("WallClockTimeMs", "CreationTime", "lastUpdateTime",
                             "wallClockCreationTimeMs"):
                    dt = _parse_ms_ts(node.get(attr))
                    if dt:
                        _note("WifiConfigStore.xml",
                              f"Network config time: {dt.strftime('%Y-%m-%d')}",
                              dt)
        except Exception:
            pass

    # Derive device setup date = earliest credible date across all artifacts
    floor_dt = datetime(2010, 1, 1, tzinfo=timezone.utc)
    valid = [d for d in candidate_dates if d >= floor_dt]
    if valid:
        result["device_setup_date"] = min(valid)

    return result

# ─────────────────────────────────────────────────────────────────────────────
#  GUI (optimised with threading pool, debounced search, lazy row viewer)
# ─────────────────────────────────────────────────────────────────────────────

BG     = "#F5F7FA"
BG2    = "#FFFFFF"
BG3    = "#E8ECF0"
ACCENT = "#1A6FD4"
ACCENT2= "#1A8C3A"
WARN   = "#D93025"
TEXT   = "#1A1A2E"
TEXT2  = "#5A6478"
BORDER = "#C8D0DC"
TL_TEXT = "#000000"        # universal dark black for timeline rows
IST_OFFSET = timezone(timedelta(hours=5, minutes=30))

TZ_OPTIONS = {
    "UTC+0  (UTC)":        timezone.utc,
    "UTC+5:30 (IST)":      timezone(timedelta(hours=5,  minutes=30)),
    "UTC+1  (CET)":        timezone(timedelta(hours=1)),
    "UTC+2  (EET)":        timezone(timedelta(hours=2)),
    "UTC+3  (MSK)":        timezone(timedelta(hours=3)),
    "UTC+4  (GST)":        timezone(timedelta(hours=4)),
    "UTC+6  (BST)":        timezone(timedelta(hours=6)),
    "UTC+7  (ICT)":        timezone(timedelta(hours=7)),
    "UTC+8  (CST)":        timezone(timedelta(hours=8)),
    "UTC+9  (JST)":        timezone(timedelta(hours=9)),
    "UTC+10 (AEST)":       timezone(timedelta(hours=10)),
    "UTC-5  (EST)":        timezone(timedelta(hours=-5)),
    "UTC-6  (CST)":        timezone(timedelta(hours=-6)),
    "UTC-7  (MST)":        timezone(timedelta(hours=-7)),
    "UTC-8  (PST)":        timezone(timedelta(hours=-8)),
}


class AndroidTimelineApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Android Forensic Timeline Builder")
        self.geometry("1500x920")
        self.minsize(1100, 700)
        self.configure(bg=BG)
        self.resizable(True, True)

        self.events: list[dict] = []
        self.filtered_events: list[dict] = []
        self.tmp_dir: str | None = None
        self.active_apps: set[str] = set()
        self.filter_app_var = tk.StringVar(value="All")
        self.selected_apps: set[str] = set()   # empty = All apps
        self.search_var = tk.StringVar()
        self.sort_col = "datetime"
        self.sort_asc = True
        self.loading = False
        self._search_after_id = None   # for debouncing
        self._populate_after_id = None
        # New in v1.4
        self.bookmarks: set[int] = set()          # indices into self.events
        self.content_only_var   = tk.BooleanVar(value=False)
        self.bookmarks_only_var = tk.BooleanVar(value=False)
        self.date_from_var = tk.StringVar()
        self.date_to_var   = tk.StringVar()
        self._stop_flag    = False
        self.show_ist_var  = tk.BooleanVar(value=False)   # kept for compat
        self.tz_var        = tk.StringVar(value="UTC+0  (UTC)")
        self._parse_start_time: float | None = None   # wall-clock start (scan + parse)
        self._timer_after_id   = None                  # for elapsed ticker
        self.device_info: dict = {}                    # populated by scan_device_artifacts

        self._setup_styles()
        self._build_ui()

    # ── Styles ────────────────────────────────────────────────────────────────

    def _setup_styles(self):
        s = ttk.Style(self)
        s.theme_use("clam")
        s.configure(".", background=BG, foreground=TEXT, fieldbackground=BG2,
                    bordercolor=BORDER, troughcolor=BG2,
                    selectbackground=ACCENT, selectforeground=BG)
        s.configure("Treeview", background=BG2, foreground=TEXT,
                    fieldbackground=BG2, rowheight=28, borderwidth=0, relief="flat",
                    font=("Consolas", 10))
        s.configure("Treeview.Heading", background=BG3, foreground=ACCENT,
                    font=("Consolas", 10, "bold"), relief="groove", borderwidth=1)
        s.map("Treeview",
              background=[("selected", "#D6E8FF")], foreground=[("selected", "#000000")])
        s.map("Treeview.Heading", background=[("active", "#C8D4E8"), ("pressed", "#B8C4D8")])
        for sb in ("Vertical.TScrollbar", "Horizontal.TScrollbar"):
            s.configure(sb, background=BG3, troughcolor=BG,
                        bordercolor=BORDER, arrowcolor=TEXT2)
        s.configure("TCombobox", fieldbackground=BG2, background=BG2,
                    foreground=TEXT, bordercolor=BORDER)
        s.configure("TProgressbar", troughcolor=BG3, background=ACCENT2, borderwidth=0)

    # ── UI ────────────────────────────────────────────────────────────────────

    def _build_ui(self):
        # ── Header bar ────────────────────────────────────────────────────────
        hdr = tk.Frame(self, bg=BG2, height=40)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)

        # Left: logo + title + subtitle
        tk.Label(hdr, text="⬡", font=("Consolas", 16, "bold"),
                 fg=ACCENT, bg=BG2).pack(side="left", padx=(14, 6), pady=4)
        tk.Label(hdr, text="ANDROID FORENSIC TIMELINE",
                 font=("Consolas", 12, "bold"), fg=TEXT, bg=BG2).pack(side="left", pady=4)
        tk.Label(hdr, text="v1.0", font=("Consolas", 8, "bold"),
                 fg=TEXT2, bg=BG2).pack(side="left", padx=(8, 0), pady=4)
        tk.Label(hdr, text=" | NOT FOR DEEP ANALYSIS | FOR TIMELINE ONLY | MANUAL VERIFICATION REQUIRED",
                 font=("Consolas", 8), fg=TEXT2, bg=BG2).pack(side="left", pady=4)

        # Right cluster: checkboxes + event count — fills the empty header space
        right_cluster = tk.Frame(hdr, bg=BG2)
        right_cluster.pack(side="right", padx=(0, 16), pady=4)

        self._header_count = tk.StringVar(value="")
        tk.Label(right_cluster, textvariable=self._header_count,
                 font=("Consolas", 9, "bold"), fg=ACCENT2, bg=BG2).pack(side="right", padx=(12, 0))

        # Thin vertical separator between checkboxes and count
        tk.Frame(right_cluster, bg=BORDER, width=1).pack(side="right", fill="y", padx=(8, 8), pady=6)

        for var, label in ((self.bookmarks_only_var, "⭐ Bookmarks"),
                           (self.content_only_var,   "💬 Content only")):
            tk.Checkbutton(right_cluster, text=label, variable=var,
                           command=self._apply_filter,
                           font=("Consolas", 8), fg=TEXT2, bg=BG2,
                           activebackground=BG2, selectcolor=BG3,
                           highlightthickness=0, bd=0,
                           activeforeground=TEXT).pack(side="right", padx=(0, 4))

        # ── Controls row ──────────────────────────────────────────────────────
        ctrl = tk.Frame(self, bg=BG, pady=3)
        ctrl.pack(fill="x", padx=12)

        # Group 1: Load
        self._btn(ctrl, "🗜️ Open ZIP",    self._open_zip,    ACCENT,    BG).pack(side="left", padx=(0, 4))
        self._btn(ctrl, "📁 Open Folder", self._open_folder, ACCENT,    BG).pack(side="left", padx=(0, 4))
        self._btn(ctrl, "⏹ Stop",         self._stop_parse,  WARN,      BG).pack(side="left", padx=(0, 4))
        self._btn(ctrl, "🔄 Reparse",     self._reparse,     ACCENT2,   BG).pack(side="left", padx=(0, 0))

        # Separator
        tk.Frame(ctrl, bg=BORDER, width=1).pack(side="left", fill="y", padx=10, pady=4)

        # Group 2: Export + Chart
        self._btn(ctrl, "💾 CSV",   self._export_csv,   "#F0883E", BG).pack(side="left", padx=(0, 4))
        self._btn(ctrl, "💾 JSON",  self._export_json,  "#BC8CFF", BG).pack(side="left", padx=(0, 4))
        self._btn(ctrl, "📊 Chart", self._show_density, "#E3B341", BG).pack(side="left", padx=(0, 0))

        # Separator
        tk.Frame(ctrl, bg=BORDER, width=1).pack(side="left", fill="y", padx=10, pady=4)

        # Group 3: Search
        tk.Label(ctrl, text="🔍", font=("Consolas", 11), fg=TEXT2, bg=BG).pack(side="left")
        self.search_entry = tk.Entry(
            ctrl, textvariable=self.search_var,
            font=("Consolas", 10), bg=BG2, fg=TEXT, insertbackground=ACCENT,
            relief="flat", bd=0, width=20,
            highlightthickness=1, highlightcolor=ACCENT, highlightbackground=BORDER)
        self.search_entry.pack(side="left", padx=(4, 0), ipady=5)
        self.search_var.trace_add("write", self._on_search_change)

        # Separator
        tk.Frame(ctrl, bg=BORDER, width=1).pack(side="left", fill="y", padx=10, pady=4)

        # Group 4: App filter (multi-select)
        tk.Label(ctrl, text="App:", font=("Consolas", 9, "bold"), fg=TEXT2, bg=BG).pack(side="left")
        self._app_btn_var = tk.StringVar(value="All")
        self.app_combo_btn = tk.Button(
            ctrl, textvariable=self._app_btn_var,
            font=("Consolas", 9), fg=TEXT, bg=BG2,
            activebackground=BG3, relief="flat", bd=0,
            anchor="w", padx=8, pady=4, cursor="hand2",
            highlightthickness=1, highlightbackground=BORDER,
            highlightcolor=ACCENT, width=26,
            command=self._open_app_picker)
        self.app_combo_btn.pack(side="left", padx=(6, 0))

        # ── Date range row ────────────────────────────────────────────────────
        dr = tk.Frame(self, bg=BG3, pady=4)
        dr.pack(fill="x")

        # TZ selector — pack right FIRST so it anchors to far right
        self.tz_combo = ttk.Combobox(dr, textvariable=self.tz_var,
                                     values=list(TZ_OPTIONS.keys()),
                                     state="readonly", width=16, font=("Consolas", 8))
        self.tz_combo.pack(side="right", padx=(0, 12), ipady=2)
        tk.Label(dr, text="TZ:", font=("Consolas", 8, "bold"),
                 fg=ACCENT2, bg=BG3).pack(side="right", padx=(0, 4))
        tk.Frame(dr, bg=BORDER, width=1).pack(side="right", fill="y", padx=(6, 6), pady=3)
        self.tz_combo.bind("<<ComboboxSelected>>", lambda _: self._on_tz_change())

        # From Setup Date — pack right of the divider
        self._setup_date_btn = self._btn(dr, "📅 From Setup Date",
                                         self._filter_from_setup_date, ACCENT2, BG3)
        self._setup_date_btn.pack(side="right", padx=(0, 4))
        tk.Frame(dr, bg=BORDER, width=1).pack(side="right", fill="y", padx=(6, 6), pady=3)

        # Left side: From / To fields
        tk.Label(dr, text="  From:", font=("Consolas", 8, "bold"), fg=TEXT2, bg=BG3).pack(side="left")
        tk.Entry(dr, textvariable=self.date_from_var,
                 font=("Consolas", 8), bg=BG2, fg=TEXT, insertbackground=ACCENT,
                 relief="flat", bd=0, width=19,
                 highlightthickness=1, highlightcolor=ACCENT,
                 highlightbackground=BORDER).pack(side="left", padx=(4, 2), ipady=3)
        self._btn(dr, "📆", lambda: self._pick_date(self.date_from_var), TEXT2, BG3).pack(side="left", padx=(0, 10))

        tk.Label(dr, text="To:", font=("Consolas", 8, "bold"), fg=TEXT2, bg=BG3).pack(side="left")
        tk.Entry(dr, textvariable=self.date_to_var,
                 font=("Consolas", 8), bg=BG2, fg=TEXT, insertbackground=ACCENT,
                 relief="flat", bd=0, width=19,
                 highlightthickness=1, highlightcolor=ACCENT,
                 highlightbackground=BORDER).pack(side="left", padx=(4, 2), ipady=3)
        self._btn(dr, "📆", lambda: self._pick_date(self.date_to_var), TEXT2, BG3).pack(side="left", padx=(0, 10))

        self._btn(dr, "Apply", self._apply_filter, ACCENT2, BG3).pack(side="left", padx=(0, 4))
        self._btn(dr, "Clear", self._clear_range,  TEXT2,   BG3).pack(side="left", padx=(0, 10))

        tk.Frame(dr, bg=BORDER, width=1).pack(side="left", fill="y", padx=(0, 8), pady=3)

        tk.Label(dr, text="YYYY-MM-DD or YYYY-MM-DD HH:MM:SS",
                 font=("Consolas", 7), fg=TEXT2, bg=BG3).pack(side="left", padx=(0, 8))

        tk.Label(dr, text="Quick:", font=("Consolas", 7, "bold"),
                 fg=TEXT2, bg=BG3).pack(side="left", padx=(0, 4))
        for label, days in (("1d", 1), ("7d", 7), ("30d", 30), ("1y", 365)):
            self._btn(dr, label, lambda d=days: self._quick_range(d),
                      TEXT2, BG3).pack(side="left", padx=(0, 3))

        # Status bar
        sb = tk.Frame(self, bg=BG3, height=28)
        sb.pack(fill="x", side="bottom")
        sb.pack_propagate(False)
        self.status_var = tk.StringVar(value="Ready — open a ZIP or folder to begin")
        tk.Label(sb, textvariable=self.status_var, font=("Consolas", 8),
                 fg=TEXT2, bg=BG3, anchor="w").pack(side="left", padx=12, fill="y")
        self.count_var = tk.StringVar(value="0 events")
        tk.Label(sb, textvariable=self.count_var, font=("Consolas", 8, "bold"),
                 fg=ACCENT, bg=BG3, anchor="e").pack(side="right", padx=12, fill="y")
        self.elapsed_var = tk.StringVar(value="")
        tk.Label(sb, textvariable=self.elapsed_var, font=("Consolas", 8),
                 fg=ACCENT2, bg=BG3, anchor="e").pack(side="right", padx=(0, 8), fill="y")
        tk.Label(sb, text="⏱ Timestamps shown to millisecond precision where available",
                 font=("Consolas", 7), fg=TEXT2, bg=BG3, anchor="e").pack(
                 side="right", padx=(0, 12), fill="y")

        self._progress_var = tk.DoubleVar(value=0)
        self.progress = ttk.Progressbar(self, variable=self._progress_var,
                                        maximum=100, style="TProgressbar",
                                        mode="indeterminate")
        # Progress bar lives at the bottom (above status bar) — hidden until loading
        self.progress.pack(fill="x", side="bottom", padx=0, pady=0, ipady=1)
        self.progress.pack_forget()

        # Main pane
        pane = tk.PanedWindow(self, orient="horizontal", bg=BG,
                              sashwidth=4, sashrelief="flat", sashpad=0)
        pane.pack(fill="both", expand=True, padx=10, pady=(2, 4))
        self._h_pane = pane

        # ── Left: stats ──────────────────────────────────────────────────────
        self._left_panel_visible = True
        self._left_panel_width   = 260

        left = tk.Frame(pane, bg=BG2, width=260)
        left.pack_propagate(False)
        pane.add(left, minsize=200)
        self._left_frame = left

        lh = tk.Frame(left, bg=BG2)
        lh.pack(fill="x", padx=10, pady=(10, 4))
        tk.Label(lh, text="APP BREAKDOWN", font=("Consolas", 9, "bold"),
                 fg=ACCENT, bg=BG2, anchor="w").pack(side="left")

        sc_frame = tk.Frame(left, bg=BG2)
        sc_frame.pack(fill="both", expand=True, padx=6, pady=4)
        self._left_sc_frame = sc_frame
        self.stats_canvas = tk.Canvas(sc_frame, bg=BG2, highlightthickness=0)
        stats_vsb = ttk.Scrollbar(sc_frame, orient="vertical",
                                   command=self.stats_canvas.yview)
        self.stats_frame = tk.Frame(self.stats_canvas, bg=BG2)
        self.stats_frame.bind("<Configure>", lambda e: self.stats_canvas.configure(
            scrollregion=self.stats_canvas.bbox("all")))
        self.stats_canvas.create_window((0, 0), window=self.stats_frame, anchor="nw")
        self.stats_canvas.configure(yscrollcommand=stats_vsb.set)
        stats_vsb.pack(side="right", fill="y")
        self.stats_canvas.pack(side="left", fill="both", expand=True)

        # ── Right: vertical pane [table | detail] ────────────────────────────
        vpane = tk.PanedWindow(pane, orient="vertical", bg=BG,
                               sashwidth=4, sashrelief="flat")
        pane.add(vpane, minsize=700)
        self._v_pane = vpane

        # Timeline table
        tbl = tk.Frame(vpane, bg=BG)
        vpane.add(tbl, minsize=300)

        # Persistent toolbar at top of table pane — always visible, holds both toggles
        tbar = tk.Frame(tbl, bg=BG3, height=24)
        tbar.pack(fill="x", side="top")
        tbar.pack_propagate(False)
        self._left_toggle_btn = tk.Button(
            tbar, text="◀ Hide App Panel", font=("Consolas", 7, "bold"),
            fg=TEXT2, bg=BG3, activebackground=BG2, activeforeground=ACCENT,
            relief="flat", bd=0, padx=8, pady=2, cursor="hand2",
            highlightthickness=0,
            command=self._toggle_left_panel)
        self._left_toggle_btn.pack(side="left", padx=(4, 0))
        self._det_toggle_btn = tk.Button(
            tbar, text="▼ Hide Event Detail", font=("Consolas", 7, "bold"),
            fg=TEXT2, bg=BG3, activebackground=BG2, activeforeground=ACCENT,
            relief="flat", bd=0, padx=8, pady=2, cursor="hand2",
            highlightthickness=0,
            command=self._toggle_detail_panel)
        self._det_toggle_btn.pack(side="right", padx=(0, 4))

        cols       = ("bm", "datetime", "app", "db_file", "table", "column", "content", "source_path", "raw_value")
        col_labels = ("★", "Timestamp (UTC)", "App", "Database File", "Table", "Column", "Content / Text", "Source Path", "Raw Value")
        col_widths = (30, 190, 115, 190, 140, 130, 400, 300, 130)

        vsb2 = ttk.Scrollbar(tbl, orient="vertical")
        hsb2 = ttk.Scrollbar(tbl, orient="horizontal")
        self.tree = ttk.Treeview(tbl, columns=cols, show="headings",
                                  yscrollcommand=vsb2.set, xscrollcommand=hsb2.set,
                                  selectmode="browse")
        vsb2.config(command=self.tree.yview)
        hsb2.config(command=self.tree.xview)
        for col, lbl, w in zip(cols, col_labels, col_widths):
            # Must pass text= and command= in ONE call — a second call without text= resets it
            self.tree.heading(col, text=lbl, command=lambda c=col: self._sort_by(c))
            self.tree.column(col, width=w, minwidth=40, stretch=False)
        self._ts_col_idx = 1   # index of datetime column in col_labels
        vsb2.pack(side="right", fill="y")
        hsb2.pack(side="bottom", fill="x")
        self.tree.pack(fill="both", expand=True)
        self.tree.bind("<<TreeviewSelect>>", self._on_select)
        self.tree.bind("<Double-1>", self._on_double_click)
        self.tree.bind("<Button-3>", self._on_right_click)
        self.tree.bind("<Control-b>", lambda _: self._toggle_bookmark())

        # Block column header drag-reordering (allow only resize at edges)
        self._drag_col      = None
        self._drag_start_x  = None
        def _heading_press(event):
            region = self.tree.identify_region(event.x, event.y)
            col    = self.tree.identify_column(event.x)
            self._drag_col     = col
            self._drag_start_x = event.x
            self._drag_region  = region
        def _heading_motion(event):
            if self._drag_col and self._drag_region == "heading":
                # If the cursor has moved onto a separator, this is a resize — leave it alone
                if self.tree.identify_region(event.x, event.y) == "separator":
                    return
                if abs(event.x - self._drag_start_x) > 4:
                    self.tree.column(self._drag_col, width=self.tree.column(self._drag_col, "width"))
                    return "break"
        def _heading_release(event):
            self._drag_col = None
        self.tree.bind("<ButtonPress-1>",   _heading_press)
        self.tree.bind("<B1-Motion>",       _heading_motion)
        self.tree.bind("<ButtonRelease-1>", _heading_release)

        # Zebra stripe tags
        self.tree.tag_configure("even", background="#FFFFFF", foreground="#000000")
        self.tree.tag_configure("odd",  background="#EEF4FF", foreground="#000000")

        # Context menu
        self._ctx = tk.Menu(self, tearoff=0, bg=BG3, fg=TEXT,
                            activebackground=ACCENT, activeforeground=BG,
                            font=("Consolas", 9))
        self._ctx.add_command(label="⭐  Bookmark / Unbookmark", command=self._toggle_bookmark)
        self._ctx.add_command(label="📋  Copy content",          command=self._copy_content)
        self._ctx.add_command(label="📋  Copy timestamp",        command=self._copy_timestamp)
        self._ctx.add_separator()
        self._ctx.add_command(label="🔍  Filter this app",       command=self._ctx_filter_app)
        self._ctx.add_command(label="🗄️  Set DB as search term", command=self._ctx_filter_db)

        # Detail panel
        det = tk.Frame(vpane, bg=BG3)
        vpane.add(det, minsize=140)
        self._det_frame      = det
        self._det_visible    = True
        self._det_min_height = 140

        dh = tk.Frame(det, bg=BG3)
        dh.pack(fill="x", padx=10, pady=(6, 2))
        tk.Label(dh, text="EVENT DETAIL", font=("Consolas", 8, "bold"),
                 fg=ACCENT, bg=BG3).pack(side="left")
        tk.Label(dh, text="  double-click → full row viewer  |  right-click → menu  |  Ctrl+B → bookmark",
                 font=("Consolas", 7), fg=TEXT2, bg=BG3).pack(side="left", padx=6)

        self._det_body = tk.Frame(det, bg=BG3)
        self._det_body.pack(fill="both", expand=True)

        dtf = tk.Frame(self._det_body, bg=BG3)
        dtf.pack(fill="both", expand=True, padx=10, pady=(0, 6))
        dvsb = ttk.Scrollbar(dtf, orient="vertical")
        self.detail_text = tk.Text(
            dtf, font=("Consolas", 9), fg=TEXT, bg=BG3,
            relief="flat", bd=0, wrap="word", height=5,
            yscrollcommand=dvsb.set, state="disabled",
            insertbackground=ACCENT, highlightthickness=0)
        dvsb.config(command=self.detail_text.yview)
        dvsb.pack(side="right", fill="y")
        self.detail_text.pack(fill="both", expand=True)

    def _btn(self, parent, text, cmd, fg, bg):
        return tk.Button(parent, text=text, command=cmd,
                         font=("Consolas", 9, "bold"),
                         fg=fg, bg=BG3, activebackground=BG2,
                         activeforeground=fg, relief="flat",
                         cursor="hand2", bd=0, padx=12, pady=6,
                         highlightthickness=1, highlightbackground=BORDER)

    # ── Panel toggle helpers ──────────────────────────────────────────────────

    def _toggle_left_panel(self):
        """Hide / show the App Breakdown left panel — truly removes it from the sash."""
        if self._left_panel_visible:
            try:
                self._left_panel_width = self._left_frame.winfo_width() or 260
            except Exception:
                self._left_panel_width = 260
            self._h_pane.forget(self._left_frame)
            self._left_toggle_btn.config(text="▶ Hide App Panel")
            self._left_panel_visible = False
        else:
            self._h_pane.add(self._left_frame, minsize=200, before=self._v_pane)
            self._left_frame.config(width=self._left_panel_width)
            self._left_toggle_btn.config(text="◀ Hide App Panel")
            self._left_panel_visible = True

    def _toggle_detail_panel(self):
        """Hide / show the Hide Event Detail panel — truly removes it from the sash."""
        if self._det_visible:
            self._v_pane.forget(self._det_frame)
            self._det_toggle_btn.config(text="▲ Hide Event Detail")
            self._det_visible = False
        else:
            self._v_pane.add(self._det_frame, minsize=self._det_min_height)
            self._det_toggle_btn.config(text="▼ Hide Event Detail")
            self._det_visible = True

    def _on_tz_change(self):
        """Timezone dropdown changed — repopulate with new tz."""
        self._populate_tree_chunked(self.filtered_events)

    def _pick_date(self, target_var: tk.StringVar):
        """Open a simple calendar pop-up to pick a date and optional time."""
        win = tk.Toplevel(self)
        win.title("Pick Date")
        win.configure(bg=BG)
        win.resizable(False, False)
        win.grab_set()

        now = datetime.now(timezone.utc)
        # Try to pre-fill from existing value
        try:
            pre = datetime.strptime(target_var.get().strip()[:10], "%Y-%m-%d")
            cur_year, cur_month = pre.year, pre.month
        except Exception:
            cur_year, cur_month = now.year, now.month

        state = {"year": cur_year, "month": cur_month, "day": None}

        header_var = tk.StringVar()
        days_frame = tk.Frame(win, bg=BG)

        def _render():
            header_var.set(f"  {datetime(state['year'], state['month'], 1).strftime('%B %Y')}  ")
            for w in days_frame.winfo_children():
                w.destroy()
            import calendar
            cal = calendar.monthcalendar(state["year"], state["month"])
            for c, dn in enumerate(["Mo", "Tu", "We", "Th", "Fr", "Sa", "Su"]):
                tk.Label(days_frame, text=dn, font=("Consolas", 8, "bold"),
                         fg=ACCENT, bg=BG, width=3).grid(row=0, column=c, padx=1)
            for r, week in enumerate(cal, 1):
                for c, d in enumerate(week):
                    if d == 0:
                        tk.Label(days_frame, text="", bg=BG, width=3).grid(row=r, column=c)
                    else:
                        is_sel = (d == state["day"])
                        btn = tk.Button(
                            days_frame, text=str(d), width=3,
                            font=("Consolas", 8),
                            fg=BG if is_sel else TEXT,
                            bg=ACCENT if is_sel else BG2,
                            activebackground=ACCENT, activeforeground=BG,
                            relief="flat", bd=0, cursor="hand2",
                            command=lambda dd=d: _select_day(dd))
                        btn.grid(row=r, column=c, padx=1, pady=1)

        def _select_day(d):
            state["day"] = d
            _render()

        def _prev_month():
            if state["month"] == 1:
                state["month"], state["year"] = 12, state["year"] - 1
            else:
                state["month"] -= 1
            _render()

        def _next_month():
            if state["month"] == 12:
                state["month"], state["year"] = 1, state["year"] + 1
            else:
                state["month"] += 1
            _render()

        # Nav row
        nav = tk.Frame(win, bg=BG)
        nav.pack(padx=10, pady=(10, 4))
        tk.Button(nav, text="◀", command=_prev_month, font=("Consolas", 10),
                  fg=ACCENT, bg=BG, relief="flat", cursor="hand2", bd=0).pack(side="left")
        tk.Label(nav, textvariable=header_var, font=("Consolas", 10, "bold"),
                 fg=TEXT, bg=BG, width=16).pack(side="left")
        tk.Button(nav, text="▶", command=_next_month, font=("Consolas", 10),
                  fg=ACCENT, bg=BG, relief="flat", cursor="hand2", bd=0).pack(side="left")

        days_frame.pack(padx=10, pady=4)

        # Time row
        tf = tk.Frame(win, bg=BG)
        tf.pack(padx=10, pady=(4, 2))
        tk.Label(tf, text="Time (HH:MM:SS):", font=("Consolas", 8), fg=TEXT2, bg=BG).pack(side="left")
        time_var = tk.StringVar(value="00:00:00")
        tk.Entry(tf, textvariable=time_var, font=("Consolas", 9), bg=BG2, fg=TEXT,
                 insertbackground=ACCENT, relief="flat", bd=0, width=10,
                 highlightthickness=1, highlightcolor=ACCENT,
                 highlightbackground=BORDER).pack(side="left", padx=(6, 0), ipady=3)

        def _apply():
            if state["day"] is None:
                messagebox.showwarning("No Day Selected", "Please click a day first.", parent=win)
                return
            t = time_var.get().strip()
            # validate / normalise time
            for fmt in ("%H:%M:%S", "%H:%M"):
                try:
                    datetime.strptime(t, fmt)
                    break
                except ValueError:
                    pass
            else:
                t = "00:00:00"
            if len(t) == 5:
                t += ":00"
            val = f"{state['year']:04d}-{state['month']:02d}-{state['day']:02d} {t}"
            target_var.set(val)
            win.destroy()

        bf = tk.Frame(win, bg=BG)
        bf.pack(pady=(4, 10))
        tk.Button(bf, text="Set Date", command=_apply,
                  font=("Consolas", 9, "bold"), fg=BG, bg=ACCENT2,
                  relief="flat", cursor="hand2", padx=14, pady=5).pack(side="left", padx=4)
        tk.Button(bf, text="Cancel", command=win.destroy,
                  font=("Consolas", 9), fg=TEXT2, bg=BG3,
                  relief="flat", cursor="hand2", padx=10, pady=5).pack(side="left", padx=4)

        _render()

    # ── Elapsed / ETA ticker ─────────────────────────────────────────────────

    def _start_elapsed_ticker(self):
        """Start the wall-clock ticker from the moment we begin (scan + parse)."""
        import time as _time
        self._parse_start_time = _time.monotonic()
        self._tick_elapsed()

    def _tick_elapsed(self):
        """Update the elapsed / ETA label every second while loading."""
        import time as _time
        if not self.loading or self._parse_start_time is None:
            return
        elapsed = _time.monotonic() - self._parse_start_time
        h, rem  = divmod(int(elapsed), 3600)
        m, s    = divmod(rem, 60)
        if h:
            elapsed_str = f"{h}h {m:02d}m {s:02d}s"
        elif m:
            elapsed_str = f"{m}m {s:02d}s elapsed"
        else:
            elapsed_str = f"{s}s elapsed"

        # ETA: use _parse_phase_start so scan time doesn't inflate the estimate.
        # _parse_phase_start is set when we switch to determinate mode.
        eta_str = ""
        pct = self._progress_var.get()
        parse_start = getattr(self, "_parse_phase_start", None)
        if parse_start is not None and pct > 1.0:
            parse_elapsed = _time.monotonic() - parse_start
            eta_s = max(0.0, parse_elapsed / (pct / 100.0) - parse_elapsed)
            eh, er = divmod(int(eta_s), 3600)
            em, es = divmod(er, 60)
            if eh:
                eta_str = f"  ·  ETA {eh}h {em:02d}m"
            elif em:
                eta_str = f"  ·  ETA {em}m {es:02d}s"
            else:
                eta_str = f"  ·  ETA ~{max(1, es)}s"

        self.elapsed_var.set(f"⏱ {elapsed_str}{eta_str}")
        self._timer_after_id = self.after(1000, self._tick_elapsed)

    def _stop_elapsed_ticker(self):
        """Stop the ticker and freeze the final elapsed time on the label."""
        import time as _time
        if self._timer_after_id:
            self.after_cancel(self._timer_after_id)
            self._timer_after_id = None
        if self._parse_start_time is not None:
            elapsed = _time.monotonic() - self._parse_start_time
            h, rem  = divmod(int(elapsed), 3600)
            m, s    = divmod(rem, 60)
            if h:
                self.elapsed_var.set(f"⏱ {h}h {m:02d}m {s:02d}s total")
            elif m:
                self.elapsed_var.set(f"⏱ {m}m {s:02d}s total")
            else:
                self.elapsed_var.set(f"⏱ {s}s total")
            self._parse_start_time = None

    # ── Source loading (with parallel parsing) ───────────────────────────────

    def _open_zip(self):
        p = filedialog.askopenfilename(
            title="Select Android Extraction ZIP",
            filetypes=[("ZIP archives", "*.zip"), ("All files", "*.*")])
        if p:
            self._start_parse(p, is_zip=True)

    def _open_folder(self):
        p = filedialog.askdirectory(
            title="Select Android Extraction Folder (e.g. /data/data)")
        if p:
            self._start_parse(p, is_zip=False)

    def _reparse(self):
        if not self.events:
            messagebox.showinfo("No Data", "Load a ZIP or folder first.")
            return
        self._apply_filter()

    def _start_parse(self, path: str, is_zip: bool):
        if self.loading:
            return
        self.loading = True
        self._stop_flag = False
        self.events.clear()
        self.filtered_events.clear()
        self.bookmarks.clear()
        self._clear_tree()
        self._update_stats([])
        self._progress_var.set(0)
        self.elapsed_var.set("")
        self._parse_phase_start = None   # reset ETA clock
        self.progress.config(mode="indeterminate")
        self.progress.pack(fill="x", side="bottom", padx=0, pady=0, ipady=1)
        self.progress.start(12)   # animate immediately while scanning
        self.status_var.set("Please wait. This might take a moment…")
        self.count_var.set("Scanning…")
        self._start_elapsed_ticker()   # begin wall-clock timer from scan start
        threading.Thread(target=self._parse_worker,
                         args=(path, is_zip), daemon=True).start()

    def _parse_worker(self, path: str, is_zip: bool):
        try:
            root = path
            if is_zip:
                self.tmp_dir = tempfile.mkdtemp(prefix="android_tl_")
                self.after(0, lambda: self.status_var.set("Extracting ZIP…"))
                with zipfile.ZipFile(path, 'r') as z:
                    for member in z.namelist():
                        target = os.path.realpath(os.path.join(self.tmp_dir, member))
                        if not target.startswith(os.path.realpath(self.tmp_dir)):
                            raise ValueError(f"Unsafe path in ZIP: {member}")
                    z.extractall(self.tmp_dir)
                root = self.tmp_dir

            # ── Step 1: scan system artifacts for device setup date ────────────────
            self.after(0, lambda: self.status_var.set(
                "Calculating device setup time from system Artifacts..."))
            self.device_info = scan_device_artifacts(root)
            _setup_dt   = self.device_info.get("device_setup_date")
            _n_sigs     = len(self.device_info.get("sources", []))
            def _show_artifact_status(dt=_setup_dt, n=_n_sigs):
                if dt:
                    self.status_var.set(
                        f"Artifacts scanned ({n} signals)  —  "
                        f"Device setup approx {dt.strftime('%Y-%m-%d')}  —  "
                        f"Now scanning databases…")
                else:
                    self.status_var.set(
                        "No system artifacts found (partial extraction?)  —  Scanning databases…")
            self.after(0, _show_artifact_status)

            # ── Step 2: find all SQLite databases ───────────────────────────────
            db_files = find_db_files(root, progress_cb=lambda n: self.after(0,
                lambda n=n: (
                    self.status_var.set(f"Please wait. This might take a moment…  ({n} databases found so far)"),
                    self.count_var.set(f"{n} DBs found"),
                )))
            total = len(db_files)

            # Switch from indeterminate bounce → determinate progress bar
            def _switch_to_determinate():
                import time as _time
                self.progress.stop()
                self.progress.config(mode="determinate")
                self._progress_var.set(0)
                self._parse_phase_start = _time.monotonic()   # ETA clock starts here
                self.status_var.set(f"Found {total} database file(s) — parsing with {min(16, (os.cpu_count() or 4) * 2)} workers…")
            self.after(0, _switch_to_determinate)

            all_events = []
            completed = 0
            lock = threading.Lock()

            def parse_one(db_path):
                nonlocal completed
                if self._stop_flag:
                    return []
                app = detect_app(db_path)
                evs = parse_db(db_path, app)
                with lock:
                    completed += 1
                    pct = (completed / total * 100) if total else 100
                    total_so_far = len(all_events) + len(evs)
                    msg = (f"[{completed}/{total}]  {os.path.basename(db_path)}"
                           f"  ({app}) → {len(evs)} events")
                    self.after(0, lambda m=msg, p=pct, n=total_so_far: (
                        self.status_var.set(m),
                        self._progress_var.set(p),
                        self._header_count.set(f"{n:,} events found"),
                        self.count_var.set(f"{n:,} events"),
                    ))
                return evs

            # I/O-bound SQLite reads benefit from more workers than CPU count
            max_workers = min(16, (os.cpu_count() or 4) * 2)
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = [executor.submit(parse_one, fp) for fp in db_files]
                for future in as_completed(futures):
                    if self._stop_flag:
                        break
                    try:
                        all_events.extend(future.result())
                    except Exception:
                        pass

            all_events.sort(key=lambda e: e["datetime"])

            # Deduplicate: same (datetime, app, db_path, table, column, raw_value)
            # means the exact same row+column was parsed more than once (e.g. WAL
            # duplicate, same DB copied to multiple paths with identical basename).
            # Keeps first occurrence; preserves all legitimately distinct events.
            seen_keys: set[tuple] = set()
            deduped: list[dict] = []
            for ev in all_events:
                key = (
                    ev["datetime"],
                    ev["app"],
                    ev["db_path"],
                    ev["table"],
                    ev["column"],
                    ev["raw_value"],
                )
                if key not in seen_keys:
                    seen_keys.add(key)
                    deduped.append(ev)
            all_events = deduped

            self.events = all_events
            self.after(0, self._finish_parse)
        except Exception as ex:
            tb = traceback.format_exc()
            self.after(0, lambda: self._parse_error(str(ex), tb))

    def _finish_parse(self):
        self.loading = False
        self._stop_elapsed_ticker()    # freeze final elapsed time
        self.progress.stop()
        self._progress_var.set(100)
        self.progress.pack_forget()
        apps = sorted(set(e["app"] for e in self.events))
        self.active_apps = set(apps)
        self.selected_apps = set()   # reset to "All"
        self._update_app_btn_label()
        self._apply_filter()
        n_content = sum(1 for e in self.events if e["content"])
        stopped = "  ⚠ STOPPED EARLY" if self._stop_flag else ""

        # artifact summary for status bar
        di       = self.device_info
        setup_dt = di.get("device_setup_date")
        n_sigs   = len(di.get("sources", []))
        n_pkgs   = len(di.get("packages", {}))
        if setup_dt:
            art_str = (f"  |  Device setup approx {setup_dt.strftime('%Y-%m-%d')}"
                       f" ({n_sigs} signals, {n_pkgs} pkgs)")
        else:
            art_str = "  |  No system artifacts found"

        self.status_var.set(
            f"Done{stopped} — {len(self.events):,} events  |  {n_content:,} with content  |  "
            f"{len(apps)} app(s)  |  "
            f"{len(set(e['db_file'] for e in self.events))} DB(s){art_str}")
        self._header_count.set(f"{len(self.events):,} events")

        # open the artifact report window if anything was found
        if di.get("sources") or di.get("packages"):
            self.after(200, lambda: self._show_artifact_report(di))

    def _show_artifact_report(self, di: dict):
        """Pop-up window showing all system artifact findings."""
        win = tk.Toplevel(self)
        win.title("Device System Artifact Report")
        win.geometry("820x560")
        win.configure(bg=BG)

        tk.Label(win, text="Device System Artifact Report",
                 font=("Consolas", 11, "bold"), fg=ACCENT, bg=BG).pack(
                 anchor="w", padx=14, pady=(12, 2))

        setup_dt = di.get("device_setup_date")
        summary  = (f"  Estimated device setup date: {setup_dt.strftime('%Y-%m-%d %H:%M:%S')} UTC"
                    if setup_dt else "  No device setup date could be determined.")
        tk.Label(win, text=summary, font=("Consolas", 10, "bold"),
                 fg=ACCENT2, bg=BG).pack(anchor="w", padx=14, pady=(0, 4))
        tk.Label(win,
                 text="  Events before this date may be from cloud backup / another device, not this handset.",
                 font=("Consolas", 8), fg=WARN, bg=BG).pack(anchor="w", padx=14, pady=(0, 2))
        tk.Label(win,
                 text="  \U0001f4a1 Tip: Use the  \U0001f4c5 From Setup Date  button in the date bar to instantly filter the\n"
                      "       timeline to events on or after this date — showing only on-device activity.",
                 font=("Consolas", 10, "bold"), fg=ACCENT2, bg=BG, justify="left").pack(anchor="w", padx=14, pady=(0, 8))

        # ── Signal table ─────────────────────────────────────────────────────
        tk.Label(win, text="Artifact Signals Found:",
                 font=("Consolas", 9, "bold"), fg=TEXT, bg=BG).pack(anchor="w", padx=14)

        frm = tk.Frame(win, bg=BG)
        frm.pack(fill="both", expand=True, padx=14, pady=(2, 4))
        vsb = ttk.Scrollbar(frm, orient="vertical")
        txt = tk.Text(frm, font=("Consolas", 8), fg=TEXT, bg=BG2,
                      relief="flat", bd=0, wrap="none",
                      yscrollcommand=vsb.set, highlightthickness=0)
        vsb.config(command=txt.yview)
        vsb.pack(side="right", fill="y")
        txt.pack(fill="both", expand=True)

        txt.tag_configure("hdr",  foreground=ACCENT,  font=("Consolas", 8, "bold"))
        txt.tag_configure("date", foreground=ACCENT2, font=("Consolas", 8, "bold"))
        txt.tag_configure("dim",  foreground=TEXT2)

        sources = di.get("sources", [])
        if sources:
            txt.insert("end", f"{'ARTIFACT':<30}  {'DATE':<14}  DETAIL\n", "hdr")
            txt.insert("end", "-" * 90 + "\n", "dim")
            for s in sorted(sources, key=lambda x: x["date"]):
                line = (f"{s['artifact']:<30}  "
                        f"{s['date'].strftime('%Y-%m-%d'):<14}  "
                        f"{s['detail']}\n")
                txt.insert("end", line)
        else:
            txt.insert("end", "  No artifact signals found.\n", "dim")

        # ── Package install summary ───────────────────────────────────────────
        packages = di.get("packages", {})
        if packages:
            txt.insert("end", "\n")
            txt.insert("end", f"{'PACKAGE':<50}  {'FIRST INSTALL':<20}  LAST UPDATE\n", "hdr")
            txt.insert("end", "-" * 100 + "\n", "dim")
            for pkg, info in sorted(packages.items(),
                                     key=lambda x: x[1].get("first_install", datetime.max.replace(tzinfo=timezone.utc))):
                fi = info.get("first_install")
                lu = info.get("last_update")
                line = (f"{pkg[:48]:<50}  "
                        f"{fi.strftime('%Y-%m-%d %H:%M') if fi else 'N/A':<20}  "
                        f"{lu.strftime('%Y-%m-%d %H:%M') if lu else 'N/A'}\n")
                txt.insert("end", line)

        txt.config(state="disabled")

        tk.Button(win, text="Close", command=win.destroy,
                  font=("Consolas", 9), fg=WARN, bg=BG3,
                  relief="flat", padx=12, pady=4, cursor="hand2").pack(pady=(0, 10))

    def _update_app_btn_label(self):
        """Update the App button label to reflect current selection."""
        if not self.selected_apps:
            self._app_btn_var.set("All")
        elif len(self.selected_apps) == 1:
            self._app_btn_var.set(next(iter(self.selected_apps)))
        else:
            self._app_btn_var.set(f"{len(self.selected_apps)} apps selected")

    def _open_app_picker(self):
        """Open a large multi-select popup for filtering by app (Eric Zimmerman style)."""
        apps = sorted(self.active_apps) if self.active_apps else []

        win = tk.Toplevel(self)
        win.title("Filter by App")
        win.configure(bg=BG)
        win.resizable(True, True)
        win.grab_set()

        # Position near the button
        try:
            bx = self.app_combo_btn.winfo_rootx()
            by = self.app_combo_btn.winfo_rooty() + self.app_combo_btn.winfo_height()
        except Exception:
            bx, by = 400, 200
        win.geometry(f"320x520+{bx}+{by}")

        # ── Search box ────────────────────────────────────────────────────────
        sf = tk.Frame(win, bg=BG)
        sf.pack(fill="x", padx=10, pady=(10, 4))
        tk.Label(sf, text="Enter text to search…", font=("Consolas", 8),
                 fg=TEXT2, bg=BG).pack(anchor="w")
        search_var = tk.StringVar()
        search_entry = tk.Entry(sf, textvariable=search_var, font=("Consolas", 9),
                                bg=BG2, fg=TEXT, insertbackground=ACCENT,
                                relief="flat", bd=0,
                                highlightthickness=1, highlightcolor=ACCENT,
                                highlightbackground=BORDER)
        search_entry.pack(fill="x", ipady=4, pady=(2, 0))

        # ── Checkbox list in a scrollable canvas ──────────────────────────────
        list_frame_outer = tk.Frame(win, bg=BORDER, bd=1, relief="flat")
        list_frame_outer.pack(fill="both", expand=True, padx=10, pady=4)

        canvas = tk.Canvas(list_frame_outer, bg=BG2, highlightthickness=0)
        vsb = ttk.Scrollbar(list_frame_outer, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)

        list_inner = tk.Frame(canvas, bg=BG2)
        canvas_window = canvas.create_window((0, 0), window=list_inner, anchor="nw")

        def _on_frame_configure(e):
            canvas.configure(scrollregion=canvas.bbox("all"))
        list_inner.bind("<Configure>", _on_frame_configure)

        def _on_canvas_configure(e):
            canvas.itemconfig(canvas_window, width=e.width)
        canvas.bind("<Configure>", _on_canvas_configure)

        # Mouse wheel scroll
        def _on_mousewheel(e):
            canvas.yview_scroll(int(-1 * (e.delta / 120)), "units")
        canvas.bind_all("<MouseWheel>", _on_mousewheel)

        # Build checkbox variables — pre-check currently selected apps
        check_vars: dict[str, tk.BooleanVar] = {}
        check_widgets: list[tuple[str, tk.Checkbutton]] = []

        def _rebuild_list(filter_text=""):
            for w in list_inner.winfo_children():
                w.destroy()
            check_widgets.clear()
            ft = filter_text.lower().strip()

            # "(All)" row first
            all_cb = tk.Checkbutton(
                list_inner, text="(All)",
                font=("Consolas", 9, "bold"), fg=ACCENT, bg=BG2,
                activebackground=BG2, selectcolor=BG3,
                highlightthickness=0, bd=0, anchor="w",
                command=lambda: _toggle_all())
            all_cb.pack(fill="x", padx=6, pady=1)

            visible_apps = [a for a in apps if ft in a.lower()] if ft else apps
            for app in visible_apps:
                if app not in check_vars:
                    check_vars[app] = tk.BooleanVar(value=(app in self.selected_apps))
                cb = tk.Checkbutton(
                    list_inner, text=app,
                    variable=check_vars[app],
                    font=("Consolas", 9), fg=TEXT, bg=BG2,
                    activebackground=BG2, selectcolor=BG3,
                    highlightthickness=0, bd=0, anchor="w")
                cb.pack(fill="x", padx=6, pady=1)
                check_widgets.append((app, cb))

        def _toggle_all():
            # If all visible are checked → uncheck all; else check all
            visible = [a for a, _ in check_widgets]
            all_checked = all(check_vars[a].get() for a in visible if a in check_vars)
            for a in visible:
                if a in check_vars:
                    check_vars[a].set(not all_checked)

        def _on_search(*args):
            _rebuild_list(search_var.get().lower().strip())
        search_var.trace_add("write", _on_search)

        _rebuild_list()

        # ── Buttons ───────────────────────────────────────────────────────────
        bf = tk.Frame(win, bg=BG3)
        bf.pack(fill="x", padx=10, pady=(0, 10))

        def _apply():
            checked = {a for a, var in check_vars.items() if var.get()}
            self.selected_apps = checked
            self._update_app_btn_label()
            self._apply_filter()
            canvas.unbind_all("<MouseWheel>")
            win.destroy()

        def _clear():
            for v in check_vars.values():
                v.set(False)

        tk.Button(bf, text="Apply", command=_apply,
                  font=("Consolas", 9, "bold"), fg=BG, bg=ACCENT2,
                  relief="flat", cursor="hand2", padx=14, pady=5).pack(side="left", padx=(0, 6))
        tk.Button(bf, text="Clear Filter", command=_clear,
                  font=("Consolas", 9), fg=TEXT2, bg=BG3,
                  relief="flat", cursor="hand2", padx=10, pady=5).pack(side="left", padx=(0, 6))
        tk.Button(bf, text="Close", command=lambda: [canvas.unbind_all("<MouseWheel>"), win.destroy()],
                  font=("Consolas", 9), fg=WARN, bg=BG3,
                  relief="flat", cursor="hand2", padx=10, pady=5).pack(side="right")

        win.protocol("WM_DELETE_WINDOW", lambda: [canvas.unbind_all("<MouseWheel>"), win.destroy()])
        search_entry.focus_set()

    def _parse_error(self, msg: str, tb: str):
        self.loading = False
        self._stop_elapsed_ticker()
        self.progress.stop()
        self._progress_var.set(0)
        self.progress.pack_forget()
        self.status_var.set(f"Error: {msg}")
        messagebox.showerror("Parse Error", f"{msg}\n\n{tb[:800]}")

    # ── Search debouncing ────────────────────────────────────────────────────

    def _on_search_change(self, *args):
        if self._search_after_id:
            self.after_cancel(self._search_after_id)
        self._search_after_id = self.after(300, self._apply_filter)

    # ── Date range helpers ───────────────────────────────────────────────────

    def _parse_date(self, s: str) -> datetime | None:
        s = s.strip()
        if not s:
            return None
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
            try:
                return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
            except ValueError:
                pass
        return None

    def _clear_range(self):
        self.date_from_var.set("")
        self.date_to_var.set("")
        self._apply_filter()

    def _quick_range(self, days: int):
        now = datetime.now(timezone.utc)
        self.date_to_var.set(now.strftime("%Y-%m-%d %H:%M:%S"))
        self.date_from_var.set((now - timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S"))
        self._apply_filter()

    def _filter_from_setup_date(self):
        """Set the From date to the detected device setup date and apply filter."""
        setup_dt = self.device_info.get("device_setup_date") if self.device_info else None
        if not setup_dt:
            messagebox.showinfo(
                "No Setup Date",
                "No device setup date was detected for this extraction.\n\n"
                "Load an extraction that contains system artifacts\n"
                "(packages.xml, accounts.db, WiFi config, or GMS databases)\n"
                "for this feature to work.",
            )
            return
        self.date_from_var.set(setup_dt.strftime("%Y-%m-%d %H:%M:%S"))
        self._apply_filter()

    def _stop_parse(self):
        self._stop_flag = True

    # ── Filter & display (optimised population) ──────────────────────────────

    def _apply_filter(self):
        search   = self.search_var.get().lower().strip()
        cnt_only = self.content_only_var.get()
        bm_only  = self.bookmarks_only_var.get()
        dt_from  = self._parse_date(self.date_from_var.get())
        dt_to    = self._parse_date(self.date_to_var.get())

        filtered = self.events
        if self.selected_apps:   # non-empty = restrict to selected apps
            filtered = [e for e in filtered if e["app"] in self.selected_apps]
        if dt_from:
            filtered = [e for e in filtered if e["datetime"] >= dt_from]
        if dt_to:
            filtered = [e for e in filtered if e["datetime"] <= dt_to]
        if cnt_only:
            filtered = [e for e in filtered if e["content"]]
        if bm_only:
            filtered = [e for e in filtered if e.get("bookmarked")]
        if search:
            filtered = [e for e in filtered if
                        search in e["db_file"].lower()   or
                        search in e["table"].lower()     or
                        search in e["column"].lower()    or
                        search in e["app"].lower()       or
                        search in e["content"].lower()   or
                        search in str(e["datetime"]).lower()]
        self.filtered_events = filtered
        self._populate_tree_chunked(filtered)
        self._update_stats(filtered)
        self.count_var.set(f"{len(filtered):,} events")

    def _clear_tree(self):
        self.tree.delete(*self.tree.get_children())

    def _populate_tree_chunked(self, events: list[dict], chunk_size=500):
        """Insert items in chunks to keep UI responsive."""
        self._clear_tree()
        if self._populate_after_id:
            self.after_cancel(self._populate_after_id)
            self._populate_after_id = None

        total = len(events)
        # Update heading label to match selected TZ — deferred so tkinter won't clobber it
        tz_key  = self.tz_var.get()
        tz_obj  = TZ_OPTIONS.get(tz_key, timezone.utc)
        # Build short label for column header e.g. "IST" or "UTC"
        tz_short = tz_key.split("(")[-1].rstrip(")").strip() if "(" in tz_key else tz_key
        def _fix_heading():
            self.tree.heading("datetime", text=f"Timestamp ({tz_short})")
        self.after(0, _fix_heading)

        if total == 0:
            return

        idx = 0
        def insert_chunk():
            nonlocal idx
            end = min(idx + chunk_size, total)
            for i in range(idx, end):
                e = events[i]
                ts_str = e["datetime"].astimezone(tz_obj).strftime("%Y-%m-%d  %H:%M:%S.%f")[:-3]
                row_tag = "odd" if i % 2 else "even"
                self.tree.insert("", "end", values=(
                    "⭐" if e.get("bookmarked") else "",
                    ts_str,
                    e["app"], e["db_file"], e["table"],
                    e["column"], e["content"],
                    e.get("db_path", ""),      # source_path moved before raw_value
                    e["raw_value"],
                ), tags=(row_tag,))
            idx = end
            if idx < total:
                self._populate_after_id = self.after(10, insert_chunk)
            else:
                self._populate_after_id = None
                self.after(0, _fix_heading)   # re-assert after all chunks done
            self.update_idletasks()
        insert_chunk()

    def _update_stats(self, events: list[dict]):
        for w in self.stats_frame.winfo_children():
            w.destroy()
        counts: dict[str, int] = defaultdict(int)
        for e in events:
            counts[e["app"]] += 1
        if not counts:
            tk.Label(self.stats_frame, text="No data",
                     font=("Consolas", 9), fg=TEXT2, bg=BG2).pack(anchor="w", padx=4)
            return
        total = sum(counts.values())
        for app, cnt in sorted(counts.items(), key=lambda x: -x[1]):
            color = APP_COLORS.get(app, APP_COLORS["Unknown"])
            row = tk.Frame(self.stats_frame, bg=BG2)
            row.pack(fill="x", pady=1)
            dot = tk.Label(row, text="●", fg=color, bg=BG2, font=("Consolas", 9))
            dot.pack(side="left", padx=(2, 2))
            # Count on the right first (so name gets remaining space)
            cnt_lbl = tk.Label(row, text=f"{cnt:,}", fg=TEXT2, bg=BG2,
                     font=("Consolas", 7), anchor="e", width=6)
            cnt_lbl.pack(side="right", padx=(0, 4))
            bar_w = max(2, int((cnt / total) * 40))
            cv = tk.Canvas(row, width=42, height=10, bg=BG2, highlightthickness=0)
            cv.pack(side="right", padx=(0, 2))
            cv.create_rectangle(0, 2, bar_w, 8, fill=color, outline="")
            # Name label — no fixed width, truncate with ellipsis if needed
            display = app if len(app) <= 22 else app[:20] + "…"
            name_lbl = tk.Label(row, text=display, fg=TEXT, bg=BG2,
                     font=("Consolas", 8), anchor="w", cursor="hand2")
            name_lbl.pack(side="left", fill="x", expand=True)
            def _filt(a=app):
                self.selected_apps = {a}
                self._update_app_btn_label()
                self._apply_filter()
            for w in (dot, row, name_lbl, cv, cnt_lbl):
                w.bind("<Button-1>", lambda ev, a=app: _filt(a))

    # ── Sort ──────────────────────────────────────────────────────────────────

    def _sort_by(self, col: str):
        if self.sort_col == col:
            self.sort_asc = not self.sort_asc
        else:
            self.sort_col, self.sort_asc = col, True
        self.filtered_events.sort(
            key=lambda e: str(e.get(col, "")), reverse=not self.sort_asc)
        self._populate_tree_chunked(self.filtered_events)

    # ── Right-click / bookmark / copy actions ────────────────────────────────

    def _selected_event(self) -> dict | None:
        sel = self.tree.selection()
        if not sel:
            return None
        idx = self.tree.index(sel[0])
        if idx >= len(self.filtered_events):
            return None
        return self.filtered_events[idx]

    def _on_right_click(self, event):
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            self._ctx.post(event.x_root, event.y_root)

    def _toggle_bookmark(self):
        e = self._selected_event()
        if not e:
            return
        e["bookmarked"] = not e.get("bookmarked", False)
        self._populate_tree_chunked(self.filtered_events)

    def _copy_content(self):
        e = self._selected_event()
        if e and e["content"]:
            self.clipboard_clear()
            self.clipboard_append(e["content"])

    def _copy_timestamp(self):
        e = self._selected_event()
        if e:
            self.clipboard_clear()
            self.clipboard_append(e["datetime"].strftime("%Y-%m-%d %H:%M:%S"))

    def _ctx_filter_app(self):
        e = self._selected_event()
        if e:
            self.selected_apps = {e["app"]}
            self._update_app_btn_label()
            self._apply_filter()

    def _ctx_filter_db(self):
        e = self._selected_event()
        if e:
            self.search_var.set(e["db_file"])

    # ── Density chart ─────────────────────────────────────────────────────────

    def _show_density(self):
        if not self.filtered_events:
            messagebox.showinfo("No Data", "Load and filter data first.")
            return
        win = tk.Toplevel(self)
        win.title("Timeline Density Chart")
        win.geometry("860x400")
        win.configure(bg=BG)
        tk.Label(win, text="EVENT DENSITY OVER TIME  (current filtered view)",
                 font=("Consolas", 10, "bold"), fg=ACCENT, bg=BG).pack(pady=(10, 4))

        cv = tk.Canvas(win, bg=BG2, highlightthickness=0)
        cv.pack(fill="both", expand=True, padx=14, pady=(0, 10))

        def draw(event=None):
            cv.delete("all")
            W, H = cv.winfo_width(), cv.winfo_height()
            if W < 50 or H < 50:
                return
            pad_l, pad_r, pad_t, pad_b = 60, 20, 20, 40

            dates = [e["datetime"] for e in self.filtered_events]
            d_min, d_max = min(dates), max(dates)
            span = (d_max - d_min).total_seconds()
            if span == 0:
                span = 1

            n_buckets = max(1, min(80, len(dates)))
            bucket_s  = span / n_buckets
            buckets: dict[int, dict[str, int]] = defaultdict(lambda: defaultdict(int))
            for e in self.filtered_events:
                b = int((e["datetime"] - d_min).total_seconds() / bucket_s)
                b = min(b, n_buckets - 1)
                buckets[b][e["app"]] += 1

            max_cnt  = max((sum(v.values()) for v in buckets.values()), default=1)
            chart_w  = W - pad_l - pad_r
            chart_h  = H - pad_t - pad_b
            bar_w    = max(1, chart_w / n_buckets - 1)

            for i in range(0, 5):
                y = pad_t + chart_h - (chart_h * i // 4)
                cv.create_line(pad_l, y, W - pad_r, y, fill=BORDER, dash=(2, 4))
                cv.create_text(pad_l - 4, y, text=str(max_cnt * i // 4),
                               anchor="e", fill=TEXT2, font=("Consolas", 7))

            for b in range(n_buckets):
                x0 = pad_l + b * (chart_w / n_buckets)
                x1 = x0 + bar_w
                y_base = pad_t + chart_h
                for app, cnt in buckets[b].items():
                    h = int(chart_h * cnt / max_cnt)
                    color = APP_COLORS.get(app, APP_COLORS["Unknown"])
                    cv.create_rectangle(x0, y_base - h, x1, y_base,
                                        fill=color, outline="")
                    y_base -= h

            for i in range(6):
                x  = pad_l + chart_w * i // 5
                b  = int(n_buckets * i // 5)
                dt = d_min + timedelta(seconds=bucket_s * b)
                cv.create_line(x, pad_t + chart_h, x, pad_t + chart_h + 4, fill=TEXT2)
                cv.create_text(x, pad_t + chart_h + 12,
                               text=dt.strftime("%m-%d %H:%M"),
                               anchor="n", fill=TEXT2, font=("Consolas", 7))

            cv.create_line(pad_l, pad_t, pad_l, pad_t + chart_h + 1, fill=TEXT2)
            cv.create_line(pad_l, pad_t + chart_h, W - pad_r, pad_t + chart_h, fill=TEXT2)

        cv.bind("<Configure>", draw)
        win.after(100, draw)

    # ── Detail & Row Viewer ───────────────────────────────────────────────────

    def _set_detail(self, text: str):
        self.detail_text.config(state="normal")
        self.detail_text.delete("1.0", "end")
        self.detail_text.insert("end", text)
        self.detail_text.config(state="disabled")

    def _on_select(self, _=None):
        sel = self.tree.selection()
        if not sel:
            return
        idx = self.tree.index(sel[0])
        if idx >= len(self.filtered_events):
            return
        e = self.filtered_events[idx]
        tz_key   = self.tz_var.get()
        tz_obj   = TZ_OPTIONS.get(tz_key, timezone.utc)
        tz_short = tz_key.split("(")[-1].rstrip(")").strip() if "(" in tz_key else tz_key
        def _fmt_human(dt):
            return dt.strftime('%d %B %Y, %H:%M:%S').lstrip('0')

        lines = [
            f"📅  {e['datetime'].strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]} UTC",
            f"📆  {_fmt_human(e['datetime'])} UTC",
        ]
        if tz_obj != timezone.utc:
            sel_dt = e['datetime'].astimezone(tz_obj)
            lines.append(f"🕐  {sel_dt.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]} {tz_short}")
            lines.append(f"📆  {_fmt_human(sel_dt)} {tz_short}")
        lines += [
            f"📱  App      : {e['app']}",
            f"🗄️  Database : {e['db_file']}",
            f"🏷️  Table    : {e['table']}",
            f"🔑  Column   : {e['column']}",
            f"⚙️  Raw Value: {e['raw_value']}",
            f"📂  Source   : {e.get('db_path', '')}",
        ]
        if e["content"]:
            lines.append(f"💬  Content  : {e['content']}")
        self._set_detail("\n".join(lines))

    def _on_double_click(self, _=None):
        sel = self.tree.selection()
        if not sel:
            return
        idx = self.tree.index(sel[0])
        if idx >= len(self.filtered_events):
            return
        event = self.filtered_events[idx]
        self._show_row_viewer(event)

    def _show_row_viewer(self, e: dict):
        """Pop-up: fetch full row from database on demand."""
        win = tk.Toplevel(self)
        win.title(f"Full Row — {e['app']} / {e['table']}")
        win.geometry("720x520")
        win.configure(bg=BG)

        tk.Label(win, text=f"📱 {e['app']}  ·  🗄️ {e['db_file']}  ·  🏷️ {e['table']}",
                 font=("Consolas", 9, "bold"), fg=ACCENT, bg=BG).pack(
                 fill="x", padx=12, pady=(10, 4))
        tk.Label(win,
                 text=f"📅 {e['datetime'].strftime('%Y-%m-%d %H:%M:%S')} UTC"
                      f"  (timestamp column: {e['column']})",
                 font=("Consolas", 9), fg=TEXT2, bg=BG).pack(
                 fill="x", padx=12, pady=(0, 8))

        frm = tk.Frame(win, bg=BG)
        frm.pack(fill="both", expand=True, padx=12, pady=(0, 4))
        vsb = ttk.Scrollbar(frm, orient="vertical")
        hsb = ttk.Scrollbar(frm, orient="horizontal")
        txt = tk.Text(frm, font=("Consolas", 9), fg=TEXT, bg=BG2,
                      relief="flat", bd=0, wrap="none",
                      yscrollcommand=vsb.set, xscrollcommand=hsb.set,
                      highlightthickness=0)
        vsb.config(command=txt.yview)
        hsb.config(command=txt.xview)
        vsb.pack(side="right", fill="y")
        hsb.pack(side="bottom", fill="x")
        txt.pack(fill="both", expand=True)

        txt.tag_configure("key",   foreground=ACCENT)
        txt.tag_configure("val",   foreground=TEXT)
        txt.tag_configure("ts",    foreground=ACCENT2)
        txt.tag_configure("empty", foreground=TEXT2)

        # Fetch the full row from the original database
        row_data = {}
        try:
            conn = sqlite3.connect(f"file:{e['db_path']}?mode=ro", uri=True, timeout=5)
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            if e.get("_rowid") is not None:
                cur.execute(f'SELECT * FROM "{e["table"]}" WHERE rowid = ?', (e["_rowid"],))
            else:
                # Fallback: try to match by the timestamp column value (less reliable)
                cur.execute(f'SELECT * FROM "{e["table"]}" WHERE "{e["column"]}" = ? LIMIT 1', (e["raw_value"],))
            row = cur.fetchone()
            if row:
                row_data = dict(row)
            conn.close()
        except Exception as ex:
            txt.insert("end", f"Error fetching row: {ex}\n", "empty")

        if row_data:
            for col, val in row_data.items():
                txt.insert("end", f"  {col:<32}", "key")
                if val is None or str(val).strip() == "":
                    txt.insert("end", "  (null)\n", "empty")
                elif col == e["column"]:
                    txt.insert("end", f"  {val}  ← timestamp\n", "ts")
                else:
                    txt.insert("end", f"  {val}\n", "val")
        else:
            txt.insert("end", "Row not found in database.\n", "empty")

        txt.config(state="disabled")

        tk.Button(win, text="Close", command=win.destroy,
                  font=("Consolas", 9), fg=WARN, bg=BG3,
                  relief="flat", padx=12, pady=4, cursor="hand2").pack(pady=(0, 10))

    # ── Export ─────────────────────────────────────────────────────────────────

    def _export_csv(self):
        if not self.filtered_events:
            messagebox.showinfo("No Data", "Nothing to export.")
            return
        fp = filedialog.asksaveasfilename(defaultextension=".csv",
                                          filetypes=[("CSV", "*.csv")],
                                          title="Save Timeline as CSV")
        if not fp:
            return
        import csv
        fields = ["datetime", "app", "db_file", "table", "column", "content", "raw_value"]
        with open(fp, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
            w.writeheader()
            for e in self.filtered_events:
                row = dict(e)
                row["datetime"] = e["datetime"].strftime("%Y-%m-%d %H:%M:%S")
                w.writerow(row)
        messagebox.showinfo("Export Complete",
                            f"Saved {len(self.filtered_events):,} events to:\n{fp}")

    def _export_json(self):
        if not self.filtered_events:
            messagebox.showinfo("No Data", "Nothing to export.")
            return
        fp = filedialog.asksaveasfilename(defaultextension=".json",
                                          filetypes=[("JSON", "*.json")],
                                          title="Save Timeline as JSON")
        if not fp:
            return
        out = [{
            "datetime":  e["datetime"].isoformat(),
            "app":       e["app"],
            "db_file":   e["db_file"],
            "table":     e["table"],
            "column":    e["column"],
            "content":   e["content"],
            "raw_value": e["raw_value"],
        } for e in self.filtered_events]
        with open(fp, "w", encoding="utf-8") as f:
            json.dump(out, f, indent=2, ensure_ascii=False)
        messagebox.showinfo("Export Complete",
                            f"Saved {len(self.filtered_events):,} events to:\n{fp}")

    def destroy(self):
        if self.tmp_dir and os.path.isdir(self.tmp_dir):
            try:
                shutil.rmtree(self.tmp_dir)
            except Exception:
                pass
        super().destroy()


# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app = AndroidTimelineApp()
    app.mainloop()