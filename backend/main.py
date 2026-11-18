
import sqlite3
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query

from backend.detection import detect_threats


app = FastAPI(
    title="CyberTrap Security API",
    description="SSH Honeypot Threat Intelligence Platform",
    version="1.1.0",
)

DB_FILE = (
    Path(__file__).resolve().parent / "cybertrap.db"
)


def get_connection():
    if not DB_FILE.exists():
        raise HTTPException(
            status_code=503,
            detail="CyberTrap database not found.",
        )

    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def get_all_events():
    with get_connection() as conn:
        rows = conn.execute("""
            SELECT
                id,
                timestamp,
                event_type,
                source_ip,
                username,
                command,
                session_id
            FROM attacks
            ORDER BY id ASC
        """).fetchall()

    return [dict(row) for row in rows]


@app.get("/")
def home():
    return {
        "message": "Welcome to CyberTrap!",
        "version": "1.1.0",
    }


@app.get("/api/health")
def health():
    return {
        "status": "running",
        "database_exists": DB_FILE.exists(),
    }


@app.get("/api/attacks")
def get_attacks(
    limit: int = Query(default=50, ge=1, le=500)
):
    with get_connection() as conn:
        rows = conn.execute("""
            SELECT
                id,
                timestamp,
                event_type,
                source_ip,
                username,
                command,
                session_id
            FROM attacks
            ORDER BY id DESC
            LIMIT ?
        """, (limit,)).fetchall()

    return [dict(row) for row in rows]


@app.get("/api/stats")
def get_stats():
    with get_connection() as conn:
        total = conn.execute(
            "SELECT COUNT(*) FROM attacks"
        ).fetchone()[0]

        successful = conn.execute("""
            SELECT COUNT(*)
            FROM attacks
            WHERE event_type = 'cowrie.login.success'
        """).fetchone()[0]

        failed = conn.execute("""
            SELECT COUNT(*)
            FROM attacks
            WHERE event_type = 'cowrie.login.failed'
        """).fetchone()[0]

        commands = conn.execute("""
            SELECT COUNT(*)
            FROM attacks
            WHERE event_type = 'cowrie.command.input'
        """).fetchone()[0]

        unique_ips = conn.execute("""
            SELECT COUNT(DISTINCT source_ip)
            FROM attacks
            WHERE source_ip IS NOT NULL
        """).fetchone()[0]

    return {
        "total_events": total,
        "successful_logins": successful,
        "failed_logins": failed,
        "commands_executed": commands,
        "unique_source_ips": unique_ips,
    }


@app.get("/api/commands")
def get_commands():
    with get_connection() as conn:
        rows = conn.execute("""
            SELECT command, COUNT(*) AS count
            FROM attacks
            WHERE event_type = 'cowrie.command.input'
              AND command IS NOT NULL
            GROUP BY command
            ORDER BY count DESC
        """).fetchall()

    return [dict(row) for row in rows]


@app.get("/api/alerts")
def get_alerts():
    events = get_all_events()
    alerts = detect_threats(events)

    return {
        "total_alerts": len(alerts),
        "high_severity": sum(
            1 for alert in alerts
            if alert["severity"] == "High"
        ),
        "medium_severity": sum(
            1 for alert in alerts
            if alert["severity"] == "Medium"
        ),
        "alerts": alerts,
    }
