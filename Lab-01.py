import csv
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

# Synthetic training data: no real credentials or user records.
events = [
    ("2026-11-02 09:00:12", 4625, "j.smith", "203.0.113.45"),
    ("2026-11-02 09:00:24", 4625, "j.smith", "203.0.113.45"),
    ("2026-11-02 09:01:08", 4625, "j.smith", "203.0.113.45"),
    ("2026-11-02 09:02:15", 4624, "j.smith", "203.0.113.45"),
    ("2026-11-02 08:00:10", 4625, "s.jones", "203.0.115.47"),
    ("2026-11-02 08:04:02", 4625, "s.jones", "203.0.115.47"),
]

path = Path("authentication_logs.csv")

with path.open("w", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)
    writer.writerow(["timestamp", "event_id", "user", "source_ip"])
    writer.writerows(events)

records = []
with path.open(newline="", encoding="utf-8") as f:
    for row in csv.DictReader(f):
        row["timestamp"] = datetime.strptime(
            row["timestamp"], "%Y-%m-%d %H:%M:%S"
        )
        row["event_id"] = int(row["event_id"])
        records.append(row)

# Group by source IP and account to avoid mixing users.
groups = defaultdict(list)
for record in records:
    groups[(record["source_ip"], record["user"])].append(record)

for (ip, user), group in groups.items():
    group.sort(key=lambda r: r["timestamp"])
    failures = [r for r in group if r["event_id"] == 4625]
    successes = [r for r in group if r["event_id"] == 4624]

    for success in successes:
        window_start = success["timestamp"] - timedelta(minutes=5)
        recent_failures = [
            r for r in failures
            if window_start <= r["timestamp"] < success["timestamp"]
        ]

        if len(recent_failures) >= 3:
            print("ALERT: Suspicious authentication sequence")
            print(f"Account: {user}")
            print(f"Source IP: {ip}")
            print(f"Failures before success: {len(recent_failures)}")
            print(f"Successful login: {success['timestamp']}")
            print("Assessment: Investigation required")
            print("severity: high")
