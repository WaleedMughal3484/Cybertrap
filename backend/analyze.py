import json
from pathlib import Path
from collections import Counter

LOG_FILE = Path(__file__).resolve().parent.parent / "honeypot/logs/cowrie.json"


def analyze_logs():
    if not LOG_FILE.exists():
        print("Error: Cowrie log file not found.")
        return

    event_counts = Counter()
    ip_counts = Counter()
    usernames = Counter()
    commands = Counter()

    total_events = 0

    with LOG_FILE.open("r", encoding="utf-8") as file:
        for line in file:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue

            total_events += 1

            event_type = event.get("eventid", "unknown")
            event_counts[event_type] += 1

            if event.get("src_ip"):
                ip_counts[event["src_ip"]] += 1

            if event_type in (
                "cowrie.login.failed",
                "cowrie.login.success",
            ):
                usernames[event.get("username", "unknown")] += 1

            if event_type == "cowrie.command.input":
                commands[event.get("input", "")] += 1

    print("\n===== CYBERTRAP SECURITY REPORT =====")
    print(f"Total Events: {total_events}")

    print("\nEvent Types:")
    for event, count in event_counts.most_common():
        print(f"  {event}: {count}")

    print("\nSource IP Addresses:")
    for ip, count in ip_counts.most_common():
        print(f"  {ip}: {count}")

    print("\nAttempted Usernames:")
    for username, count in usernames.most_common():
        print(f"  {username}: {count}")

    print("\nExecuted Commands:")
    for command, count in commands.most_common():
        print(f"  {command}: {count}")


if __name__ == "__main__":
    analyze_logs()