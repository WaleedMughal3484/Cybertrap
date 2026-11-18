
"""
CyberTrap - Automatic Cowrie Log Ingestion

Collects Cowrie JSON events from Docker and stores
new events in the existing SQLite database.

Run:
    python3 backend/ingestion.py

Run once:
    python3 backend/ingestion.py --once
"""

import argparse
import hashlib
import json
import sqlite3
import subprocess
import tempfile
import time

from datetime import datetime
from pathlib import Path


# ========================================
# CONFIGURATION
# ========================================

BASE_DIR = Path(__file__).resolve().parent.parent

DB_FILE = BASE_DIR / "backend" / "cybertrap.db"

CONTAINER_NAME = "cybertrap-cowrie"

COWRIE_LOG_PATH = (
    "/cowrie/cowrie-git/var/log/cowrie/cowrie.json"
)

POLL_INTERVAL = 10


# ========================================
# DATABASE
# ========================================

def initialize_database():
    """Create the table if it does not exist."""

    DB_FILE.parent.mkdir(parents=True, exist_ok=True)

    with sqlite3.connect(DB_FILE, timeout=15) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS attacks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_hash TEXT UNIQUE NOT NULL,
                timestamp TEXT,
                event_type TEXT,
                source_ip TEXT,
                username TEXT,
                command TEXT,
                session_id TEXT
            )
        """)

        conn.commit()


# ========================================
# DOCKER LOG COLLECTION
# ========================================

def collect_cowrie_logs():
    """
    Copy the current Cowrie JSON log from Docker.

    The temporary copy is deleted automatically.
    """

    with tempfile.TemporaryDirectory() as temp_dir:

        local_file = Path(temp_dir) / "cowrie.json"

        source = (
            f"{CONTAINER_NAME}:{COWRIE_LOG_PATH}"
        )

        result = subprocess.run(
            [
                "docker",
                "cp",
                source,
                str(local_file),
            ],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )

        if result.returncode != 0:
            raise RuntimeError(
                "Could not copy Cowrie logs: "
                + result.stderr.strip()
            )

        if not local_file.exists():
            raise FileNotFoundError(
                "Cowrie JSON log was not found."
            )

        return local_file.read_text(
            encoding="utf-8",
            errors="replace",
        )


# ========================================
# EVENT IMPORTING
# ========================================

def import_events(log_content):
    """Import new JSON events without duplicates."""

    imported = 0
    duplicates = 0
    invalid = 0

    with sqlite3.connect(DB_FILE, timeout=15) as conn:

        for line in log_content.splitlines():

            line = line.strip()

            if not line:
                continue

            try:
                event = json.loads(line)

                if not isinstance(event, dict):
                    invalid += 1
                    continue

            except json.JSONDecodeError:
                invalid += 1
                continue

            # Same hashing method as database.py.
            # This prevents previously imported events
            # from being inserted again.

            event_hash = hashlib.sha256(
                line.encode("utf-8")
            ).hexdigest()

            event_type = event.get("eventid")

            command = None

            if event_type == "cowrie.command.input":
                command = event.get("input")

            cursor = conn.execute("""
                INSERT OR IGNORE INTO attacks (
                    event_hash,
                    timestamp,
                    event_type,
                    source_ip,
                    username,
                    command,
                    session_id
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                event_hash,
                event.get("timestamp"),
                event_type,
                event.get("src_ip"),
                event.get("username"),
                command,
                event.get("session"),
            ))

            if cursor.rowcount == 1:
                imported += 1
            else:
                duplicates += 1

        conn.commit()

    return imported, duplicates, invalid


# ========================================
# DATABASE STATISTICS
# ========================================

def get_total_events():
    """Return the current database event count."""

    with sqlite3.connect(DB_FILE, timeout=15) as conn:
        row = conn.execute(
            "SELECT COUNT(*) FROM attacks"
        ).fetchone()

    return row[0]


# ========================================
# AUTOMATIC MONITOR
# ========================================

def check_for_events():
    """Perform one collection and import cycle."""

    log_content = collect_cowrie_logs()

    imported, duplicates, invalid = import_events(
        log_content
    )

    total = get_total_events()

    current_time = datetime.now().strftime(
        "%H:%M:%S"
    )

    print(
        f"[{current_time}] "
        f"New: {imported} | "
        f"Existing: {duplicates} | "
        f"Invalid: {invalid} | "
        f"Total stored: {total}",
        flush=True,
    )


def main():
    parser = argparse.ArgumentParser(
        description="CyberTrap Cowrie log collector"
    )

    parser.add_argument(
        "--once",
        action="store_true",
        help="Import logs once and exit",
    )

    args = parser.parse_args()

    initialize_database()

    print("=" * 45)
    print("CYBERTRAP AUTOMATIC LOG COLLECTOR")
    print("=" * 45)
    print(f"Container: {CONTAINER_NAME}")
    print(f"Database: {DB_FILE}")
    print(f"Polling interval: {POLL_INTERVAL} seconds")
    print()

    if args.once:
        try:
            check_for_events()
        except (
            RuntimeError,
            FileNotFoundError,
            subprocess.TimeoutExpired,
            OSError,
            sqlite3.Error,
        ) as error:
            print(f"Collector error: {error}")
            raise SystemExit(1)

        return

    print("Monitoring Cowrie events...")
    print("Press Ctrl+C to stop.\n")

    try:
        while True:

            try:
                check_for_events()

            except (
                RuntimeError,
                FileNotFoundError,
                subprocess.TimeoutExpired,
                OSError,
                sqlite3.Error,
            ) as error:
                print(
                    f"Collector error: {error}",
                    flush=True,
                )

            time.sleep(POLL_INTERVAL)

    except KeyboardInterrupt:
        print("\nCyberTrap collector stopped.")


if __name__ == "__main__":
    main()
