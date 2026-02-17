#!/usr/bin/env python3
"""
Yeyland Wutani - Network Discovery Pi
update-oui-db.py  —  Refresh the offline OUI vendor database

Downloads the authoritative IEEE MA-L OUI CSV and converts it to a compact
JSON file that network_utils.py loads on first use.  The full IEEE table
covers ~30,000 vendor prefixes, dramatically reducing "Unknown" results
compared to the small built-in fallback table.

Usage:
    python3 /opt/network-discovery/bin/update-oui-db.py
    (run automatically by install.sh and self-update.sh)

Output:
    /opt/network-discovery/data/oui.json
"""

import csv
import json
import sys
import urllib.request
from pathlib import Path

OUI_CSV_URL = "https://standards-oui.ieee.org/oui/oui.csv"

# Output path: <script_dir>/../data/oui.json works both in the git repo
# (Rasperry Pi Discovery Tool/bin/ -> Rasperry Pi Discovery Tool/data/)
# and on the Pi (/opt/network-discovery/bin/ -> /opt/network-discovery/data/).
OUTPUT_PATH = Path(__file__).resolve().parent.parent / "data" / "oui.json"


def download_csv(url: str, timeout: int = 30) -> str:
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "YeylandWutani-NetworkDiscovery/1.0"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", errors="replace")


def parse_csv(content: str) -> dict:
    """Parse IEEE OUI CSV into {XX:XX:XX: vendor} dict.

    IEEE CSV columns (after header row):
        Registry, Assignment, Organization Name, Organization Address
    'Assignment' is the 6-hex-digit OUI without separators, e.g. 'AABBCC'.
    """
    db: dict = {}
    reader = csv.reader(content.splitlines())
    next(reader, None)  # skip header line
    for row in reader:
        if len(row) < 3:
            continue
        assignment = row[1].strip().upper()   # e.g. "AABBCC"
        vendor     = row[2].strip()
        if len(assignment) == 6 and vendor:
            oui = f"{assignment[0:2]}:{assignment[2:4]}:{assignment[4:6]}"
            db[oui] = vendor
    return db


def main() -> int:
    print(f"Downloading OUI database from:\n  {OUI_CSV_URL}")
    try:
        content = download_csv(OUI_CSV_URL)
    except Exception as exc:
        print(f"ERROR: download failed — {exc}", file=sys.stderr)
        print("The built-in OUI table will be used as a fallback.", file=sys.stderr)
        return 1

    db = parse_csv(content)
    if not db:
        print("ERROR: parsed zero OUI entries — unexpected CSV format.", file=sys.stderr)
        return 1

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_PATH, "w") as fh:
        json.dump(db, fh, separators=(",", ":"))

    size_kb = OUTPUT_PATH.stat().st_size // 1024
    print(f"OK: {len(db):,} OUI entries written to:\n  {OUTPUT_PATH}  ({size_kb} KB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
