import csv
from datetime import datetime
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

INPUT_FILE = BASE_DIR / "data" / "policy_validation.csv"
OUTPUT_FILE = BASE_DIR / "logs" / "security_events.csv"

OUTPUT_FILE.parent.mkdir(exist_ok=True)


def create_security_logs():
    events = []

    with open(INPUT_FILE, "r", newline="", encoding="utf-8") as file:
        reader = csv.DictReader(file)

        for row in reader:
            status = row["Status"]

            if status in ("PASS", "FAIL", "REVIEW"):
                severity = "INFO"

                if status == "FAIL":
                    severity = "CRITICAL"
                elif status == "REVIEW":
                    severity = "WARNING"

                events.append({
                    "timestamp": datetime.now().isoformat(timespec="seconds"),
                    "test_id": row["Test_ID"],
                    "source": row["Source"],
                    "source_ip": row["Source_IP"],
                    "destination": row["Destination"],
                    "destination_ip": row["Destination_IP"],
                    "expected": row["Expected"],
                    "actual": row["Actual"],
                    "status": status,
                    "severity": severity,
                })

    fieldnames = [
        "timestamp",
        "test_id",
        "source",
        "source_ip",
        "destination",
        "destination_ip",
        "expected",
        "actual",
        "status",
        "severity",
    ]

    with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(events)

    print(f"Security log created: {OUTPUT_FILE}")
    print(f"Events recorded: {len(events)}")


if __name__ == "__main__":
    create_security_logs()