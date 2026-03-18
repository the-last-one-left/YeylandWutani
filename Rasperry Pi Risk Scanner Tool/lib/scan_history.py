#!/usr/bin/env python3
"""
Yeyland Wutani - Risk Scanner Tool
scan_history.py - SQLite-backed scan history

Stores each scan run as:
  - A compressed BLOB of the full scan JSON (instant load, no file I/O)
  - Per-host summary rows for trend/history queries without decompressing

Also auto-migrates existing .json.gz archives on first use so existing
history survives the upgrade.
"""

import gzip
import io
import json
import logging
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

DB_PATH     = Path("/opt/risk-scanner/data/scan-history.sqlite")
HISTORY_DIR = Path("/opt/risk-scanner/data/history")

_db_ready = False

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scan_runs (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_time    TEXT    NOT NULL,
    host_count   INTEGER DEFAULT 0,
    vuln_count   INTEGER DEFAULT 0,
    kev_count    INTEGER DEFAULT 0,
    risk_score   INTEGER DEFAULT 0,
    risk_level   TEXT    DEFAULT 'LOW',
    duration_s   REAL    DEFAULT 0,
    archive_path TEXT,
    data         BLOB
);

CREATE INDEX IF NOT EXISTS idx_scan_time ON scan_runs(scan_time);

CREATE TABLE IF NOT EXISTS scan_hosts (
    scan_id    INTEGER NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    ip         TEXT    NOT NULL,
    hostname   TEXT    DEFAULT '',
    mac        TEXT    DEFAULT '',
    vendor     TEXT    DEFAULT '',
    category   TEXT    DEFAULT '',
    os_version TEXT    DEFAULT '',
    risk_score INTEGER DEFAULT 0,
    risk_level TEXT    DEFAULT 'LOW',
    vuln_count INTEGER DEFAULT 0,
    kev_count  INTEGER DEFAULT 0,
    open_ports TEXT    DEFAULT '[]',
    PRIMARY KEY (scan_id, ip)
);

CREATE INDEX IF NOT EXISTS idx_host_ip ON scan_hosts(ip);
"""


@contextmanager
def _conn():
    conn = sqlite3.connect(str(DB_PATH), timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def _init_db():
    global _db_ready
    if _db_ready:
        return
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with _conn() as c:
        c.executescript(_SCHEMA)
    _db_ready = True
    _migrate_legacy_archives()


def _compress(data: dict) -> bytes:
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", compresslevel=6) as gz:
        gz.write(json.dumps(data, default=str).encode("utf-8"))
    return buf.getvalue()


def _decompress(blob: bytes) -> dict:
    with gzip.GzipFile(fileobj=io.BytesIO(blob)) as gz:
        return json.loads(gz.read().decode("utf-8"))


def _extract_metrics(results: dict) -> dict:
    hosts = results.get("hosts", [])
    risk  = results.get("risk", {})

    vuln_count = sum(len(h.get("cve_matches", [])) for h in hosts)
    kev_count  = sum(
        1 for h in hosts
        for cve in h.get("cve_matches", [])
        if cve.get("kev")
    )

    scan_time = (
        results.get("scan_start")
        or results.get("scan_time")
        or datetime.now(timezone.utc).isoformat()
    )

    return {
        "scan_time":  scan_time,
        "host_count": len(hosts),
        "vuln_count": vuln_count,
        "kev_count":  kev_count,
        "risk_score": int(risk.get("score") or risk.get("environment_score") or 0),
        "risk_level": risk.get("level") or risk.get("environment_level") or "LOW",
        "duration_s": float(results.get("duration_s") or 0),
    }


# ── Public API ──────────────────────────────────────────────────────────────

def save_scan(results: dict, archive_path: str = None) -> int:
    """
    Store a scan result. Returns the new scan_run id.
    Full JSON is gzip-compressed into a BLOB; per-host summary rows
    are stored in scan_hosts for fast trend queries.
    """
    _init_db()
    m    = _extract_metrics(results)
    blob = _compress(results)

    with _conn() as c:
        cur = c.execute(
            "INSERT INTO scan_runs "
            "(scan_time, host_count, vuln_count, kev_count, risk_score, "
            " risk_level, duration_s, archive_path, data) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (m["scan_time"], m["host_count"], m["vuln_count"], m["kev_count"],
             m["risk_score"], m["risk_level"], m["duration_s"],
             str(archive_path) if archive_path else None,
             blob),
        )
        scan_id = cur.lastrowid

        host_rows = []
        for h in results.get("hosts", []):
            h_vuln = len(h.get("cve_matches", []))
            h_kev  = sum(1 for cve in h.get("cve_matches", []) if cve.get("kev"))
            host_rows.append((
                scan_id,
                h.get("ip", ""),
                h.get("hostname", ""),
                h.get("mac", ""),
                h.get("vendor", ""),
                h.get("category", ""),
                h.get("os_version", ""),
                int(h.get("risk_score") or 0),
                h.get("risk_level", "LOW"),
                h_vuln,
                h_kev,
                json.dumps(h.get("open_ports", [])),
            ))

        if host_rows:
            c.executemany(
                "INSERT OR IGNORE INTO scan_hosts "
                "(scan_id, ip, hostname, mac, vendor, category, os_version, "
                " risk_score, risk_level, vuln_count, kev_count, open_ports) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                host_rows,
            )

    logger.info(
        "scan_history: saved scan id=%d, %d hosts, %d vulns",
        scan_id, m["host_count"], m["vuln_count"],
    )
    return scan_id


def load_latest_scan() -> Optional[dict]:
    """Return the most recent scan's full data dict, or None."""
    _init_db()
    with _conn() as c:
        row = c.execute(
            "SELECT data FROM scan_runs ORDER BY scan_time DESC LIMIT 1"
        ).fetchone()
    if not row or not row["data"]:
        return None
    try:
        return _decompress(bytes(row["data"]))
    except Exception as e:
        logger.warning("scan_history: failed to decompress latest scan: %s", e)
        return None


def load_scan_by_id(scan_id: int) -> Optional[dict]:
    """Return a specific scan's full data by id, or None."""
    _init_db()
    with _conn() as c:
        row = c.execute(
            "SELECT data FROM scan_runs WHERE id = ?", (scan_id,)
        ).fetchone()
    if not row or not row["data"]:
        return None
    try:
        return _decompress(bytes(row["data"]))
    except Exception as e:
        logger.warning("scan_history: failed to decompress scan %d: %s", scan_id, e)
        return None


def list_scans(limit: int = 50) -> list:
    """Return summary rows (no BLOB) for the most recent scans."""
    _init_db()
    with _conn() as c:
        rows = c.execute(
            "SELECT id, scan_time, host_count, vuln_count, kev_count, "
            "       risk_score, risk_level, duration_s, archive_path "
            "FROM scan_runs ORDER BY scan_time DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [dict(r) for r in rows]


def get_trend_data(weeks: int = 12) -> list:
    """
    Return one data point per calendar week (most recent scan of that week)
    for the last `weeks` weeks. Pure SQL — no BLOB decompression.
    """
    _init_db()
    with _conn() as c:
        rows = c.execute(
            """
            SELECT
                strftime('%Y-%W', scan_time)  AS week,
                MAX(scan_time)                AS scan_time,
                risk_score,
                host_count,
                vuln_count,
                kev_count,
                risk_level,
                id
            FROM scan_runs
            WHERE scan_time >= datetime('now', ? || ' days')
            GROUP BY week
            ORDER BY week ASC
            """,
            (f"-{weeks * 7}",),
        ).fetchall()

        trend = []
        for row in rows:
            try:
                dt = datetime.fromisoformat(row["scan_time"].replace("Z", "+00:00"))
                counts = c.execute(
                    "SELECT "
                    "  SUM(CASE WHEN risk_level = 'CRITICAL' THEN 1 ELSE 0 END) AS critical_count, "
                    "  SUM(CASE WHEN risk_level = 'HIGH'     THEN 1 ELSE 0 END) AS high_count "
                    "FROM scan_hosts WHERE scan_id = ?",
                    (row["id"],),
                ).fetchone()
                trend.append({
                    "date":           dt.strftime("%Y-%m-%d"),
                    "week":           row["week"],
                    "risk_score":     row["risk_score"],
                    "critical_count": counts["critical_count"] or 0,
                    "high_count":     counts["high_count"] or 0,
                    "kev_count":      row["kev_count"],
                })
            except Exception as e:
                logger.debug("scan_history: trend row error: %s", e)

    return trend


def get_scan_count() -> int:
    _init_db()
    with _conn() as c:
        return c.execute("SELECT COUNT(*) FROM scan_runs").fetchone()[0]


def delete_oldest_scan() -> Optional[str]:
    """
    Delete the oldest scan run and its host rows (CASCADE).
    Also unlinks the .json.gz archive if it still exists.
    Returns the archive path that was deleted, or None.
    """
    _init_db()
    with _conn() as c:
        row = c.execute(
            "SELECT id, archive_path FROM scan_runs ORDER BY scan_time ASC LIMIT 1"
        ).fetchone()
        if not row:
            return None
        archive_path = row["archive_path"]
        c.execute("DELETE FROM scan_runs WHERE id = ?", (row["id"],))

    if archive_path:
        try:
            p = Path(archive_path)
            if p.exists():
                p.unlink()
        except Exception as e:
            logger.debug("scan_history: could not unlink archive %s: %s", archive_path, e)

    return archive_path


def clear_all_scans() -> dict:
    """Delete every scan run from the database and unlink all archive files.
    Returns {"deleted_runs": N, "deleted_archives": N}.
    """
    _init_db()
    deleted_archives = 0
    with _conn() as c:
        rows = c.execute("SELECT archive_path FROM scan_runs").fetchall()
        for row in rows:
            ap = row["archive_path"]
            if ap:
                try:
                    p = Path(ap)
                    if p.exists():
                        p.unlink()
                        deleted_archives += 1
                except Exception as e:
                    logger.debug("scan_history: could not unlink archive %s: %s", ap, e)
        c.execute("DELETE FROM scan_runs")
        deleted_runs = len(rows)

    logger.info("scan_history: cleared %d scan run(s), %d archive(s) deleted",
                deleted_runs, deleted_archives)
    return {"deleted_runs": deleted_runs, "deleted_archives": deleted_archives}


def _migrate_legacy_archives(history_dir: Path = HISTORY_DIR):
    """
    One-time import of existing .json.gz scan archives into SQLite.
    Skips archives whose path is already recorded in scan_runs.
    """
    history_dir = Path(history_dir)
    if not history_dir.exists():
        return

    archives = sorted(history_dir.glob("scan_*.json.gz"))
    if not archives:
        return

    with _conn() as c:
        existing = {
            r[0] for r in
            c.execute("SELECT archive_path FROM scan_runs WHERE archive_path IS NOT NULL")
        }

    to_import = [p for p in archives if str(p) not in existing]
    if not to_import:
        return

    logger.info("scan_history: migrating %d legacy archives to SQLite...", len(to_import))
    imported = 0
    for path in to_import:
        try:
            with gzip.open(path, "rt", encoding="utf-8") as f:
                data = json.load(f)
            save_scan(data, archive_path=str(path))
            imported += 1
        except Exception as e:
            logger.debug("scan_history: could not migrate %s: %s", path.name, e)

    if imported:
        logger.info("scan_history: migrated %d scan archives", imported)
