
"""
CyberTrap - Automated Test Suite

Tests:
- SSH brute-force detection
- Login-after-failure detection
- Suspicious shell commands
- Download command detection
- Duplicate prevention
- Malformed log handling
- FastAPI endpoints
- Security alert responses

Run from the CyberTrap project root:
    python -m pytest tests/ -v
"""

import json
import sqlite3

import pytest
from fastapi.testclient import TestClient

from backend import ingestion, main
from backend.detection import detect_threats


# ============================================
# TEST HELPERS
# ============================================

def make_event(
    event_id,
    event_type,
    timestamp="2026-11-17T12:00:00Z",
    ip="192.0.2.10",
    username="root",
    command=None,
):
    """Create a fictional Cowrie database event."""

    return {
        "id": event_id,
        "timestamp": timestamp,
        "event_type": event_type,
        "source_ip": ip,
        "username": username,
        "command": command,
        "session_id": "test-session",
    }


def make_raw_event(
    event_id,
    event_type,
    command=None,
):
    """Create a fictional Cowrie JSON log event."""

    event = {
        "eventid": event_type,
        "timestamp": (
            f"2026-11-17T12:00:{event_id:02d}Z"
        ),
        "src_ip": "192.0.2.10",
        "username": "root",
        "session": "test-session",
    }

    if command is not None:
        event["input"] = command

    return event


# ============================================
# TEMPORARY DATABASE FIXTURE
# ============================================

@pytest.fixture
def test_database(tmp_path, monkeypatch):
    """
    Create an isolated SQLite database.

    Tests must never modify the real CyberTrap
    database containing captured SSH events.
    """

    database_path = tmp_path / "cybertrap_test.db"

    monkeypatch.setattr(
        ingestion,
        "DB_FILE",
        database_path,
    )

    monkeypatch.setattr(
        main,
        "DB_FILE",
        database_path,
    )

    ingestion.initialize_database()

    yield database_path


@pytest.fixture
def api_client(test_database):
    """Create a FastAPI test client."""

    with TestClient(main.app) as client:
        yield client


# ============================================
# DETECTION ENGINE TESTS
# ============================================

def test_brute_force_detection():
    """Five failures within 5 minutes trigger High."""

    events = []

    for i in range(5):
        events.append(
            make_event(
                event_id=i + 1,
                event_type="cowrie.login.failed",
                timestamp=(
                    f"2026-11-17T12:00:{i:02d}Z"
                ),
            )
        )

    alerts = detect_threats(events)

    brute_force = [
        alert
        for alert in alerts
        if alert["rule_id"] == "SSH_BRUTE_FORCE"
    ]

    assert len(brute_force) == 1
    assert brute_force[0]["severity"] == "High"


def test_no_brute_force_for_few_failures():
    """Two failures should not trigger brute force."""

    events = [
        make_event(
            1,
            "cowrie.login.failed",
        ),
        make_event(
            2,
            "cowrie.login.failed",
            timestamp="2026-11-17T12:01:00Z",
        ),
    ]

    alerts = detect_threats(events)

    assert not any(
        alert["rule_id"] == "SSH_BRUTE_FORCE"
        for alert in alerts
    )


def test_failures_outside_time_window():
    """Five failures spread over 20 minutes are not brute force."""

    events = []

    for i in range(5):
        events.append(
            make_event(
                i + 1,
                "cowrie.login.failed",
                timestamp=(
                    f"2026-11-17T12:{i * 5:02d}:00Z"
                ),
            )
        )

    alerts = detect_threats(events)

    assert not any(
        alert["rule_id"] == "SSH_BRUTE_FORCE"
        for alert in alerts
    )


def test_successful_login_after_failure():
    """A successful login after failure triggers an alert."""

    events = [
        make_event(
            1,
            "cowrie.login.failed",
            timestamp="2026-11-17T12:00:00Z",
        ),
        make_event(
            2,
            "cowrie.login.success",
            timestamp="2026-11-17T12:01:00Z",
        ),
    ]

    alerts = detect_threats(events)

    assert any(
        alert["rule_id"] == "LOGIN_AFTER_FAILURE"
        and alert["severity"] == "High"
        for alert in alerts
    )


def test_suspicious_command_detection():
    """System reconnaissance command triggers Medium."""

    events = [
        make_event(
            1,
            "cowrie.command.input",
            command="uname -a",
        )
    ]

    alerts = detect_threats(events)

    assert any(
        alert["rule_id"] == "SUSPICIOUS_COMMAND"
        and alert["severity"] == "Medium"
        for alert in alerts
    )


def test_download_command_detection():
    """A wget command triggers the transfer rule."""

    events = [
        make_event(
            1,
            "cowrie.command.input",
            command="wget https://example.com/file.txt",
        )
    ]

    alerts = detect_threats(events)

    assert any(
        alert["rule_id"] == "POTENTIAL_DOWNLOAD"
        and alert["severity"] == "High"
        for alert in alerts
    )


def test_normal_commands_no_alert():
    """Common shell commands should not trigger rules."""

    events = [
        make_event(
            1,
            "cowrie.command.input",
            command="whoami",
        ),
        make_event(
            2,
            "cowrie.command.input",
            command="pwd",
        ),
        make_event(
            3,
            "cowrie.command.input",
            command="ls",
        ),
    ]

    alerts = detect_threats(events)

    assert alerts == []


# ============================================
# DATABASE INGESTION TESTS
# ============================================

def test_database_prevents_duplicates(test_database):
    """Importing identical logs twice stores one event."""

    event = make_raw_event(
        1,
        "cowrie.login.failed",
    )

    log_content = json.dumps(event) + "\n"

    first = ingestion.import_events(log_content)
    second = ingestion.import_events(log_content)

    assert first == (1, 0, 0)
    assert second == (0, 1, 0)

    with sqlite3.connect(test_database) as conn:
        total = conn.execute(
            "SELECT COUNT(*) FROM attacks"
        ).fetchone()[0]

    assert total == 1


def test_malformed_json_is_skipped(test_database):
    """Invalid JSON must not interrupt ingestion."""

    valid_event = make_raw_event(
        1,
        "cowrie.session.connect",
    )

    log_content = (
        "this is not valid JSON\n"
        + json.dumps(valid_event)
        + "\n"
    )

    imported, duplicates, invalid = (
        ingestion.import_events(log_content)
    )

    assert imported == 1
    assert duplicates == 0
    assert invalid == 1


def test_command_saved_to_database(test_database):
    """Command events retain the shell command."""

    event = make_raw_event(
        1,
        "cowrie.command.input",
        command="whoami",
    )

    ingestion.import_events(
        json.dumps(event) + "\n"
    )

    with sqlite3.connect(test_database) as conn:
        command = conn.execute(
            "SELECT command FROM attacks"
        ).fetchone()[0]

    assert command == "whoami"


# ============================================
# FASTAPI TESTS
# ============================================

def test_home_endpoint(api_client):
    response = api_client.get("/")

    assert response.status_code == 200
    assert "CyberTrap" in response.json()["message"]


def test_health_endpoint(api_client):
    response = api_client.get("/api/health")

    assert response.status_code == 200
    assert response.json()["status"] == "running"
    assert response.json()["database_exists"] is True


def test_stats_endpoint(api_client):
    """Stats should reflect stored test records."""

    events = [
        make_raw_event(
            1,
            "cowrie.login.failed",
        ),
        make_raw_event(
            2,
            "cowrie.login.success",
        ),
        make_raw_event(
            3,
            "cowrie.command.input",
            command="whoami",
        ),
    ]

    log_content = "\n".join(
        json.dumps(event) for event in events
    )

    ingestion.import_events(log_content)

    response = api_client.get("/api/stats")

    assert response.status_code == 200

    data = response.json()

    assert data["total_events"] == 3
    assert data["failed_logins"] == 1
    assert data["successful_logins"] == 1
    assert data["commands_executed"] == 1
    assert data["unique_source_ips"] == 1


def test_attacks_endpoint(api_client):
    """The API should return stored events."""

    event = make_raw_event(
        1,
        "cowrie.session.connect",
    )

    ingestion.import_events(
        json.dumps(event) + "\n"
    )

    response = api_client.get("/api/attacks")

    assert response.status_code == 200

    attacks = response.json()

    assert len(attacks) == 1
    assert (
        attacks[0]["event_type"]
        == "cowrie.session.connect"
    )


def test_attacks_limit_validation(api_client):
    """Invalid query limits should be rejected."""

    response = api_client.get(
        "/api/attacks?limit=0"
    )

    assert response.status_code == 422


def test_commands_endpoint(api_client):
    """The API should aggregate recorded commands."""

    events = [
        make_raw_event(
            1,
            "cowrie.command.input",
            command="whoami",
        ),
        make_raw_event(
            2,
            "cowrie.command.input",
            command="whoami",
        ),
    ]

    ingestion.import_events(
        "\n".join(
            json.dumps(event) for event in events
        )
    )

    response = api_client.get("/api/commands")

    assert response.status_code == 200

    commands = response.json()

    assert len(commands) == 1
    assert commands[0]["command"] == "whoami"
    assert commands[0]["count"] == 2


def test_alerts_endpoint(api_client):
    """Failed then successful login creates an alert."""

    events = [
        make_raw_event(
            1,
            "cowrie.login.failed",
        ),
        make_raw_event(
            2,
            "cowrie.login.success",
        ),
    ]

    ingestion.import_events(
        "\n".join(
            json.dumps(event) for event in events
        )
    )

    response = api_client.get("/api/alerts")

    assert response.status_code == 200

    data = response.json()

    assert data["total_alerts"] == 1
    assert data["high_severity"] == 1

    assert (
        data["alerts"][0]["rule_id"]
        == "LOGIN_AFTER_FAILURE"
    )
