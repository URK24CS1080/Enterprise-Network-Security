import csv
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

INPUT_FILE = BASE_DIR / "logs" / "security_events.csv"
OUTPUT_FILE = BASE_DIR / "logs" / "alerts.csv"


def generate_alerts():
    alerts = []

    with open(INPUT_FILE, "r", newline="", encoding="utf-8") as file:
        reader = csv.DictReader(file)

        for row in reader:
            status = row["status"]

           
            if status == "FAIL":
                alert_level = "CRITICAL"
                message = (
                    f"Policy violation: {row['source']} "
                    f"({row['source_ip']}) accessed "
                    f"{row['destination']} ({row['destination_ip']}) "
                    f"when traffic should be {row['expected']}."
                )

                alerts.append({
                    "timestamp": row["timestamp"],
                    "test_id": row["test_id"],
                    "alert_level": alert_level,
                    "source": row["source"],
                    "source_ip": row["source_ip"],
                    "destination": row["destination"],
                    "destination_ip": row["destination_ip"],
                    "message": message,
                })

            elif status == "REVIEW":
                alert_level = "WARNING"
                message = (
                    f"Policy review required: {row['source']} "
                    f"({row['source_ip']}) → "
                    f"{row['destination']} ({row['destination_ip']}). "
                    f"Expected policy is not established; observed behavior: "
                    f"{row['actual']}."
                )

                alerts.append({
                    "timestamp": row["timestamp"],
                    "test_id": row["test_id"],
                    "alert_level": alert_level,
                    "source": row["source"],
                    "source_ip": row["source_ip"],
                    "destination": row["destination"],
                    "destination_ip": row["destination_ip"],
                    "message": message,
                })

    fieldnames = [
        "timestamp",
        "test_id",
        "alert_level",
        "source",
        "source_ip",
        "destination",
        "destination_ip",
        "message",
    ]

    with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(alerts)

    print(f"Alert file created: {OUTPUT_FILE}")
    print(f"Alerts generated: {len(alerts)}")


if __name__ == "__main__":
    generate_alerts()