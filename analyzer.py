import pandas as pd

# Load the security log
logs = pd.read_csv("security_logs.csv")

# Convert timestamp text into actual date/time values
logs["timestamp"] = pd.to_datetime(logs["timestamp"])

print("=== CYBERSECURITY LOG ANALYZER ===")
print(f"Total events analyzed: {len(logs)}")

# Find failed login attempts888``
failed_logins = logs[
    (logs["event_type"] == "login") &
    (logs["status"] == "failed")
]

print(f"Failed login attempts: {len(failed_logins)}")

# Detect repeated failed logins within a short time period
print("\n=== SECURITY ALERTS ===")

alert_found = False

# Group failed login attempts by IP address
for ip, group in failed_logins.groupby("ip_address"):

    # Sort attempts by time
    group = group.sort_values("timestamp")

    # Check each 5-minute window
    for _, attempt in group.iterrows():

        start_time = attempt["timestamp"]
        end_time = start_time + pd.Timedelta(minutes=5)

        attempts_in_window = group[
            (group["timestamp"] >= start_time) &
            (group["timestamp"] <= end_time)
        ]

        attempt_count = len(attempts_in_window)

        if attempt_count >= 5:
            alert_found = True

            print("\n[HIGH] Possible Brute-Force Activity")
            print(f"IP Address: {ip}")
            print(f"Failed Attempts: {attempt_count}")
            print(f"Time Window: {start_time} to {end_time}")
            print("Reason: 5 or more failed logins occurred within 5 minutes.")

            break

        elif attempt_count >= 3:
            alert_found = True

            print("\n[MEDIUM] Suspicious Login Activity")
            print(f"IP Address: {ip}")
            print(f"Failed Attempts: {attempt_count}")
            print(f"Time Window: {start_time} to {end_time}")
            print("Reason: Multiple failed logins occurred within 5 minutes.")

            break

if not alert_found:
    print("No suspicious activity detected.")