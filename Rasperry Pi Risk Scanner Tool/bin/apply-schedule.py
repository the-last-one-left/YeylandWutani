#!/usr/bin/env python3
"""
Yeyland Wutani - Risk Scanner Pi
apply-schedule.py  —  Apply schedule from config.json to systemd timer files.

Invoked as root by risk-scanner-apply-schedule.service, which is triggered by
the web dashboard via polkit when the user saves schedule settings.
"""

import json
import re
import subprocess
import sys
from pathlib import Path

CONFIG_PATH  = Path("/opt/risk-scanner/config/config.json")
SYSTEMD_DIR  = Path("/etc/systemd/system")
DAILY_TIMER  = SYSTEMD_DIR / "risk-scanner-daily.timer"
REPORT_TIMER = SYSTEMD_DIR / "risk-scanner-report.timer"

VALID_TIME = re.compile(r'^([01]\d|2[0-3]):[0-5]\d$')
VALID_DAYS = {"Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"}


def die(msg: str) -> None:
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(1)


def main() -> None:
    if not CONFIG_PATH.exists():
        die(f"Config not found: {CONFIG_PATH}")

    cfg   = json.loads(CONFIG_PATH.read_text())
    sched = cfg.get("schedule", {})

    scan_time   = sched.get("scan_time",   "02:00")
    report_day  = sched.get("report_day",  "Mon").capitalize()
    report_time = sched.get("report_time", "06:00")

    if not VALID_TIME.match(scan_time):
        die(f"Invalid scan_time in config: {scan_time!r}")
    if not VALID_TIME.match(report_time):
        die(f"Invalid report_time in config: {report_time!r}")
    if report_day not in VALID_DAYS:
        die(f"Invalid report_day in config: {report_day!r}")

    changed = False

    # ── Daily scan timer ──────────────────────────────────────────────────────
    if DAILY_TIMER.exists():
        original = DAILY_TIMER.read_text()
        updated  = re.sub(
            r'(OnCalendar=)\S.*',
            f'OnCalendar=*-*-* {scan_time}:00',
            original,
        )
        if updated != original:
            DAILY_TIMER.write_text(updated)
            print(f"Updated {DAILY_TIMER.name}: scan at {scan_time}")
            changed = True
        else:
            print(f"{DAILY_TIMER.name}: no change needed")
    else:
        print(f"WARNING: {DAILY_TIMER} not found — skipping", file=sys.stderr)

    # ── Weekly report timer ───────────────────────────────────────────────────
    if REPORT_TIMER.exists():
        original = REPORT_TIMER.read_text()
        updated  = re.sub(
            r'(OnCalendar=)\S.*',
            f'OnCalendar={report_day} {report_time}:00',
            original,
        )
        if updated != original:
            REPORT_TIMER.write_text(updated)
            print(f"Updated {REPORT_TIMER.name}: report {report_day} at {report_time}")
            changed = True
        else:
            print(f"{REPORT_TIMER.name}: no change needed")
    else:
        print(f"WARNING: {REPORT_TIMER} not found — skipping", file=sys.stderr)

    # ── Reload and restart timers if anything changed ─────────────────────────
    if changed:
        subprocess.run(["systemctl", "daemon-reload"], check=True)
        for timer in ("risk-scanner-daily.timer", "risk-scanner-report.timer"):
            r = subprocess.run(["systemctl", "restart", timer], capture_output=True)
            if r.returncode == 0:
                print(f"Restarted {timer}")
            else:
                print(f"WARNING: could not restart {timer}: {r.stderr.decode().strip()}", file=sys.stderr)

    print("Schedule apply complete.")


if __name__ == "__main__":
    main()
