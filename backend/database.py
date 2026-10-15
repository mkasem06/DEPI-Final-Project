
import sqlite3
import json
from pathlib import Path

# Database file location
DB_PATH = Path(__file__).resolve().parent / "scans.db"


def init_db():
    with sqlite3.connect(DB_PATH) as conn:

        # Create the table for new databases
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_url TEXT NOT NULL,
                scan_type TEXT NOT NULL,
                status TEXT NOT NULL,
                results TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Check the columns in the existing table
        columns = conn.execute(
            "PRAGMA table_info(scans)"
        ).fetchall()

        column_names = [column[1] for column in columns]

        # Add the results column if it doesn't exist
        if "results" not in column_names:
            conn.execute(
                "ALTER TABLE scans ADD COLUMN results TEXT"
            )

        conn.commit()


def save_scan(target_url, scan_type, status, results=None):
    with sqlite3.connect(DB_PATH) as conn:

        # Convert Python dictionary to JSON text
        results_json = (
            json.dumps(results)
            if results is not None
            else None
        )

        cursor = conn.execute(
            """
            INSERT INTO scans (
                target_url,
                scan_type,
                status,
                results
            )
            VALUES (?, ?, ?, ?)
            """,
            (
                target_url,
                scan_type,
                status,
                results_json
            )
        )

        conn.commit()

        # Return the ID of the new scan
        return cursor.lastrowid


def get_scan_history():
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row

        rows = conn.execute("""
            SELECT
                id,
                target_url,
                scan_type,
                status,
                created_at
            FROM scans
            ORDER BY id DESC
        """).fetchall()

        return [dict(row) for row in rows]


def get_scan_by_id(scan_id):
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row

        # Find one scan using its ID
        row = conn.execute(
            "SELECT * FROM scans WHERE id = ?",
            (scan_id,)
        ).fetchone()

        # Return None if the scan doesn't exist
        if row is None:
            return None

        # Convert SQLite row to dictionary
        scan = dict(row)

        # Convert saved JSON text back to Python data
        if scan["results"] is not None:
            scan["results"] = json.loads(scan["results"])

        return scan
