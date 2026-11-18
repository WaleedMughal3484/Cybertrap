
import sqlite3
import json
import hashlib
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
LOG_FILE = BASE_DIR / "honeypot" / "logs" / "cowrie.json"
DB_FILE = BASE_DIR / "backend" / "cybertrap.db"


def create_database():
    with sqlite3.connect(DB_FILE) as conn:
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

    print("Database initialized successfully!")


def import_logs():
    if not LOG_FILE.exists():
        print("Cowrie JSON log file not found!")
        return

    imported = 0
    skipped = 0

    with sqlite3.connect(DB_FILE) as conn:
        with LOG_FILE.open("r", encoding="utf-8") as file:
            for line in file:
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    skipped += 1
                    continue

                # Stable hash prevents duplicate imports.
                event_hash = hashlib.sha256(
                    line.strip().encode("utf-8")
                ).hexdigest()

                result = conn.execute("""
                    INSERT OR IGNORE INTO attacks
                    (event_hash, timestamp, event_type,
                     source_ip, username, command, session_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    event_hash,
                    event.get("timestamp"),
                    event.get("eventid"),
                    event.get("src_ip"),
                    event.get("username"),
                    event.get("input")
                    if event.get("eventid") == "cowrie.command.input"
                    else None,
                    event.get("session")
                ))

                imported += result.rowcount

        conn.commit()

    print(f"New events imported: {imported}")
    print(f"Malformed JSON lines skipped: {skipped}")



def show_statistics():
    with sqlite3.connect(DB_FILE) as conn:
        total = conn.execute(
            "SELECT COUNT(*) FROM attacks"
        ).fetchone()[0]

        print("\n===== CYBERTRAP DATABASE REPORT =====")
        print(f"Total stored events: {total}")

        print("\nEvents by type:")

        results = conn.execute("""
            SELECT event_type, COUNT(*)
            FROM attacks
            GROUP BY event_type
            ORDER BY COUNT(*) DESC
        """).fetchall()

        for event_type, count in results:
            print(f"{event_type}: {count}")


if __name__ == "__main__":
    create_database()
    import_logs()
    show_statistics()
