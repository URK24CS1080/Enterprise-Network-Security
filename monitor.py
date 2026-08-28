import csv
from pathlib import Path
from collections import Counter

BASE_DIR = Path(__file__).resolve().parent

EVENTS_FILE = BASE_DIR / "logs" / "security_events.csv"
ALERTS_FILE = BASE_DIR / "logs" / "alerts.csv"


def load_csv(file_path):
    with open(file_path, "r", newline="", encoding="utf-8") as file:
        return list(csv.DictReader(file))


def monitor():
    events = load_csv(EVENTS_FILE)
    alerts = load_csv(ALERTS_FILE)

    status_counts = Counter(event["status"] for event in events)
    severity_counts = Counter(event["severity"] for event in events)

    print("\n===== MEMBER 3 SECURITY MONITORING =====")

    print(f"\nTotal security events: {len(events)}")
    print(f"PASS events: {status_counts.get('PASS', 0)}")
    print(f"FAIL events: {status_counts.get('FAIL', 0)}")
    print(f"REVIEW events: {status_counts.get('REVIEW', 0)}")

    print("\nSeverity:")
    print(f"INFO: {severity_counts.get('INFO', 0)}")
    print(f"WARNING: {severity_counts.get('WARNING', 0)}")
    print(f"CRITICAL: {severity_counts.get('CRITICAL', 0)}")

    print(f"\nAlerts generated: {len(alerts)}")

    if alerts:
        print("\n===== ACTIVE ALERTS =====")

        for alert in alerts:
            print(
                f"[{alert['alert_level']}] "
                f"{alert['source']} ({alert['source_ip']}) -> "
                f"{alert['destination']} ({alert['destination_ip']})"
            )
            print(f"  {alert['message']}")

    print("\n===== MONITORING COMPLETE =====")


if __name__ == "__main__":
    monitor()