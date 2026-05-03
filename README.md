# Android Forensic Timeline Builder  (Powered by AI)

A simple GUI tool that parses SQLite databases from an Android extraction and builds a unified event timeline across all apps. The idea of the tool developed when attempting an android CTF where some tools missed and didn't show unknown or unpopular apps on the timeline, causing issues. It detects timestamps automatically and pulls associated content (messages, URLs, file paths, etc.) from the same row. Results can be exported to CSV and loaded directly into Eric Zimmerman's Timeline Explorer for further review.

Supports a wide range of apps - WhatsApp, Telegram, Signal, SMS, Call Log, Chrome, Gmail, Instagram, and more. For anything it doesn't recognise, it falls back to the package name extracted from the file path, and tries to get the timestamps. Once a timestamp column is found, it tries every encoding commonly seen in Android databases: Unix seconds, milliseconds, microseconds, nanoseconds, WebKit/Chrome microseconds (since 1601), Windows FILETIME, Apple epoch (seconds and milliseconds)

> **Note:** This tool is built for quick timelining, not deep forensic analysis. It won't decrypt databases, carve deleted records, or replace a proper forensic suite. Think of it as a fast first-look tool to get a chronological picture of device activity.

---

## Requirements

- Python 3.10 or higher
- Standard library only - no pip installs needed
- On Linux, tkinter may need a separate install: `sudo apt install python3-tk`

---

## Setup & Run
```
git clone https://github.com/dotslashed/Android-Forensic-Timeline/
```
**Windows (PowerShell)**
```powershell
cd Android-Forensic-Timeline
python android_timeline.py
```

**Windows (Command Prompt)**
```cmd
cd Android-Forensic-Timeline
python android_timeline.py
```

**Linux / macOS**
```bash
cd Android-Forensic-Timeline
python3 android_timeline.py
```

---

## Usage

Load a folder of `.db` files or a `.zip` archive from your extraction tool. The tool scans everything, builds the timeline, and lets you filter by app, date range, or keyword. Double-click any row to inspect the full database record. Export to CSV or JSON when done.

All databases are opened read-only - nothing is modified on disk. Timestamps and content extracted by the tool should always be manually verified before being used in any formal report or investigation.

## Screenshot

![Screenshot](overview.jpg)
