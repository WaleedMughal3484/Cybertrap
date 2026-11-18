
import re
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone


BRUTE_FORCE_LIMIT = 5
BRUTE_FORCE_WINDOW = timedelta(minutes=5)
LOGIN_SEQUENCE_WINDOW = timedelta(minutes=10)


def parse_timestamp(value):
    """Convert Cowrie timestamps into UTC datetime objects."""
    if not value:
        return None

    try:
        result = datetime.fromisoformat(
            value.replace("Z", "+00:00")
        )

        if result.tzinfo is None:
            result = result.replace(tzinfo=timezone.utc)

        return result.astimezone(timezone.utc)

    except (ValueError, TypeError, AttributeError):
        return None


def create_alert(
    rule_id,
    severity,
    title,
    description,
    event,
):
    """Create a structured security alert."""
    return {
        "id": f"{rule_id}-{event['id']}",
        "rule_id": rule_id,
        "severity": severity,
        "title": title,
        "description": description,
        "source_ip": event.get("source_ip"),
        "timestamp": event.get("timestamp"),
        "event_id": event["id"],
    }


def detect_threats(events):
    """
    Analyze stored Cowrie events and return security alerts.

    Detection rules:
    1. Repeated failed SSH logins
    2. Suspicious shell commands
    3. Potential file-download commands
    4. Failed logins followed by successful authentication
    """

    alerts = []

    failed_attempts = defaultdict(deque)
    last_brute_force_alert = {}

    # Track failed logins by source IP.
    recent_failures = defaultdict(deque)

    # Sort events chronologically.
    ordered_events = sorted(
        events,
        key=lambda event: (
            parse_timestamp(event.get("timestamp"))
            or datetime.min.replace(tzinfo=timezone.utc),
            event["id"],
        ),
    )

    suspicious_patterns = [
        (r"\bcat\s+/etc/(?:passwd|shadow)\b",
         "Sensitive account file access"),
        (r"\buname\s+-a\b",
         "System reconnaissance"),
        (r"\bwhoami\s*;\s*id\b",
         "Combined identity reconnaissance"),
        (r"\bchmod\s+777\b",
         "Unsafe permission modification"),
        (r"\brm\s+-rf\b",
         "Potentially destructive file deletion"),
        (r"\bnc\s+-e\b",
         "Potential remote shell activity"),
        (r"\bbash\s+-i\b",
         "Interactive shell activity"),
    ]

    download_pattern = (
        r"\b(?:curl|wget)\b"
        r"|python(?:3)?\s+-m\s+http\.server\b"
    )

    for event in ordered_events:
        event_type = event.get("event_type")
        ip = event.get("source_ip")
        timestamp = parse_timestamp(event.get("timestamp"))

        # ---------------------------------------
        # Rule 1: Repeated failed SSH logins
        # ---------------------------------------

        if (
            event_type == "cowrie.login.failed"
            and ip
            and timestamp
        ):
            attempts = failed_attempts[ip]
            attempts.append(timestamp)

            while (
                attempts
                and timestamp - attempts[0]
                > BRUTE_FORCE_WINDOW
            ):
                attempts.popleft()

            previous_alert = last_brute_force_alert.get(ip)

            if (
                len(attempts) >= BRUTE_FORCE_LIMIT
                and (
                    previous_alert is None
                    or timestamp - previous_alert
                    > BRUTE_FORCE_WINDOW
                )
            ):
                alerts.append(create_alert(
                    "SSH_BRUTE_FORCE",
                    "High",
                    "Possible SSH Brute-Force Attack",
                    (
                        f"{len(attempts)} failed SSH logins "
                        f"from {ip} within 5 minutes."
                    ),
                    event,
                ))

                last_brute_force_alert[ip] = timestamp

            recent_failures[ip].append(timestamp)

            while (
                recent_failures[ip]
                and timestamp - recent_failures[ip][0]
                > LOGIN_SEQUENCE_WINDOW
            ):
                recent_failures[ip].popleft()

        # ---------------------------------------
        # Rule 2: Failed logins followed by success
        # ---------------------------------------

        if (
            event_type == "cowrie.login.success"
            and ip
            and timestamp
        ):
            failures = recent_failures[ip]

            while (
                failures
                and timestamp - failures[0]
                > LOGIN_SEQUENCE_WINDOW
            ):
                failures.popleft()

            if failures:
                alerts.append(create_alert(
                    "LOGIN_AFTER_FAILURE",
                    "High",
                    "Successful Login After Failed Attempts",
                    (
                        f"Source {ip} successfully logged in "
                        f"after {len(failures)} failed attempt(s) "
                        "within 10 minutes."
                    ),
                    event,
                ))

            # Clear earlier failures after success.
            failures.clear()

        # ---------------------------------------
        # Rules 3 and 4: Suspicious commands
        # ---------------------------------------

        if event_type == "cowrie.command.input":
            command = (event.get("command") or "").strip()

            if not command:
                continue

            # Detect potential downloads.
            if re.search(
                download_pattern,
                command,
                re.IGNORECASE,
            ):
                alerts.append(create_alert(
                    "POTENTIAL_DOWNLOAD",
                    "High",
                    "Potential File Transfer Activity",
                    (
                        "A file-transfer-capable command "
                        f"was observed: {command[:160]}"
                    ),
                    event,
                ))

            # Detect suspicious shell patterns.
            matched_rules = []

            for pattern, reason in suspicious_patterns:
                if re.search(
                    pattern,
                    command,
                    re.IGNORECASE,
                ):
                    matched_rules.append(reason)

            if matched_rules:
                alerts.append(create_alert(
                    "SUSPICIOUS_COMMAND",
                    "Medium",
                    "Suspicious Shell Command",
                    (
                        f"Command: {command[:160]}. "
                        "Indicators: "
                        + ", ".join(matched_rules)
                    ),
                    event,
                ))

    # Return newest alerts first.
    return sorted(
        alerts,
        key=lambda alert: (
            parse_timestamp(alert["timestamp"])
            or datetime.min.replace(tzinfo=timezone.utc),
            alert["event_id"],
        ),
        reverse=True,
    )
