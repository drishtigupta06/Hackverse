import sqlite3
import os
import datetime
import json


DB_DIR = os.path.expanduser("~/.manifest_scanner")
DB_PATH = os.path.join(DB_DIR, "history.db")


class ScanHistory:
    def __init__(self, db_path=DB_PATH):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        db_dir = os.path.dirname(self.db_path) or "."
        os.makedirs(db_dir, exist_ok=True)
        conn = sqlite3.connect(self.db_path)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                apk_path TEXT NOT NULL,
                package_name TEXT DEFAULT '',
                app_name TEXT DEFAULT '',
                scan_date TEXT NOT NULL,
                duration_seconds REAL DEFAULT 0,
                total_findings INTEGER DEFAULT 0,
                critical_count INTEGER DEFAULT 0,
                high_count INTEGER DEFAULT 0,
                medium_count INTEGER DEFAULT 0,
                low_count INTEGER DEFAULT 0,
                exploitable_count INTEGER DEFAULT 0,
                validated_count INTEGER DEFAULT 0,
                sarif_path TEXT DEFAULT '',
                args_json TEXT DEFAULT '',
                notes TEXT DEFAULT ''
            )
        """)
        conn.commit()
        conn.close()

    def save_scan(self, apk_path, package_name="", app_name="", duration_seconds=0.0,
                  total_findings=0, critical_count=0, high_count=0, medium_count=0,
                  low_count=0, exploitable_count=0, validated_count=0,
                  sarif_path="", args_list=None):
        conn = sqlite3.connect(self.db_path)
        conn.execute("""
            INSERT INTO scans
                (apk_path, package_name, app_name, scan_date, duration_seconds,
                 total_findings, critical_count, high_count, medium_count, low_count,
                 exploitable_count, validated_count, sarif_path, args_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            apk_path, package_name, app_name,
            datetime.datetime.now().isoformat(),
            round(duration_seconds, 2),
            total_findings, critical_count, high_count, medium_count, low_count,
            exploitable_count, validated_count, sarif_path,
            json.dumps(args_list or [])
        ))
        scan_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        conn.commit()
        conn.close()
        return scan_id

    def list_scans(self, limit=20):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        rows = conn.execute("""
            SELECT id, apk_path, package_name, app_name, scan_date,
                   total_findings, critical_count, high_count, exploitable_count,
                   validated_count
            FROM scans
            ORDER BY id DESC
            LIMIT ?
        """, (limit,)).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def get_scan(self, scan_id):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        conn.close()
        if row:
            result = dict(row)
            if result.get("args_json"):
                try:
                    result["args"] = json.loads(result["args_json"])
                except (json.JSONDecodeError, TypeError):
                    result["args"] = []
            return result
        return None

    def compare_scans(self, id1, id2):
        s1 = self.get_scan(id1)
        s2 = self.get_scan(id2)
        if not s1 or not s2:
            missing = []
            if not s1:
                missing.append(str(id1))
            if not s2:
                missing.append(str(id2))
            return {"error": f"Scan(s) not found: {', '.join(missing)}"}

        return {
            "scan_1": s1,
            "scan_2": s2,
            "diff": {
                "total_findings": s2["total_findings"] - s1["total_findings"],
                "critical_count": s2["critical_count"] - s1["critical_count"],
                "high_count": s2["high_count"] - s1["high_count"],
                "exploitable_count": s2["exploitable_count"] - s1["exploitable_count"],
                "validated_count": s2["validated_count"] - s1["validated_count"],
            },
            "app": s1.get("app_name") or s1.get("package_name", ""),
        }

    def delete_scan(self, scan_id):
        conn = sqlite3.connect(self.db_path)
        conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        conn.commit()
        conn.close()

    def stats(self):
        conn = sqlite3.connect(self.db_path)
        row = conn.execute("""
            SELECT
                COUNT(*) as total_scans,
                COALESCE(SUM(total_findings), 0) as total_findings,
                COALESCE(SUM(critical_count), 0) as total_critical,
                COALESCE(SUM(high_count), 0) as total_high,
                COALESCE(SUM(exploitable_count), 0) as total_exploitable,
                COALESCE(AVG(critical_count + high_count), 0) as avg_critical_high
            FROM scans
        """).fetchone()
        conn.close()
        return {
            "total_scans": row[0],
            "total_findings": row[1],
            "total_critical": row[2],
            "total_high": row[3],
            "total_exploitable": row[4],
            "avg_critical_high_per_scan": round(row[5], 1),
        }
