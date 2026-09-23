import streamlit as st
import pandas as pd
from database import create_database, save_alert, get_alerts

# --------------------------------------------------
# PAGE SETTINGS
# --------------------------------------------------

st.set_page_config(
    page_title="Cybersecurity Threat Detection Dashboard",
    page_icon="🛡️",
    layout="wide"
)

# Create the SQLite database
create_database()

# --------------------------------------------------
# LOAD SECURITY LOGS
# --------------------------------------------------

uploaded_file = st.sidebar.file_uploader(
    "Upload Security Log",
    type=["csv"]
)

required_columns = {
    "timestamp",
    "username",
    "ip_address",
    "event_type",
    "status"
}

try:
    if uploaded_file is not None:
        logs = pd.read_csv(uploaded_file)
        st.sidebar.success("Uploaded log loaded successfully.")
    else:
        logs = pd.read_csv("security_logs.csv")
        st.sidebar.info("Using sample security log.")

    # Check required columns
    missing_columns = required_columns - set(logs.columns)

    if missing_columns:
        st.error(
            "Invalid security log. Missing required columns: "
            + ", ".join(missing_columns)
        )
        st.stop()

    # Convert timestamp column
    logs["timestamp"] = pd.to_datetime(
        logs["timestamp"],
        errors="coerce"
    )

    # Detect invalid timestamps
    if logs["timestamp"].isna().any():
        st.error(
            "Invalid timestamp detected. "
            "Please check the timestamp format in the CSV file."
        )
        st.stop()

except Exception as error:
    st.error(f"Unable to process security log: {error}")
    st.stop()

failed_logins = logs[
    (logs["event_type"] == "login") &
    (logs["status"] == "failed")
]

# --------------------------------------------------
# THREAT DETECTION
# --------------------------------------------------

alerts = []

for ip, group in failed_logins.groupby("ip_address"):

    group = group.sort_values("timestamp")

    for _, attempt in group.iterrows():

        start_time = attempt["timestamp"]
        end_time = start_time + pd.Timedelta(minutes=5)

        attempts_in_window = group[
            (group["timestamp"] >= start_time) &
            (group["timestamp"] <= end_time)
        ]

        attempt_count = len(attempts_in_window)

        if attempt_count >= 5:

            alerts.append({
                "severity": "HIGH",
                "threat": "Possible Brute-Force Activity",
                "ip_address": ip,
                "failed_attempts": attempt_count,
                "start_time": start_time,
                "reason": "5 or more failed logins within 5 minutes"
            })

            break

        elif attempt_count >= 3:

            alerts.append({
                "severity": "MEDIUM",
                "threat": "Suspicious Login Activity",
                "ip_address": ip,
                "failed_attempts": attempt_count,
                "start_time": start_time,
                "reason": "3 or more failed logins within 5 minutes"
            })

            break
# --------------------------------------------------
# UNUSUAL LOGIN TIME DETECTION
# --------------------------------------------------

successful_logins = logs[
    (logs["event_type"] == "login") &
    (logs["status"] == "success")
]

for _, login in successful_logins.iterrows():

    login_hour = login["timestamp"].hour

    # Flag successful logins between midnight and 5:00 AM
    if 0 <= login_hour < 5:

        alerts.append({
            "severity": "MEDIUM",
            "threat": "Unusual Login Time",
            "ip_address": login["ip_address"],
            "failed_attempts": 0,
            "start_time": login["timestamp"],
            "reason": "Successful login occurred between 12:00 AM and 5:00 AM"
        })
 # Save detected alerts to SQLite
for alert in alerts:
    save_alert(alert)
alerts_df = pd.DataFrame(alerts)

# --------------------------------------------------
# DASHBOARD HEADER
# --------------------------------------------------

st.title("🛡️ Cybersecurity Threat Detection Dashboard")

st.write(
    "Monitor authentication activity, analyze security logs, "
    "and identify suspicious login behavior."
)

st.divider()

# --------------------------------------------------
# SUMMARY METRICS
# --------------------------------------------------

col1, col2, col3, col4 = st.columns(4)

with col1:
    st.metric("Total Events", len(logs))

with col2:
    st.metric("Failed Logins", len(failed_logins))

with col3:
    st.metric("Unique IP Addresses", logs["ip_address"].nunique())

with col4:
    st.metric("Security Alerts", len(alerts))

st.divider()

# --------------------------------------------------
# ACTIVE THREATS
# --------------------------------------------------

st.subheader("🚨 Active Threats")

if len(alerts) == 0:

    st.success("No suspicious activity detected.")

else:

    for alert in alerts:

        if alert["severity"] == "HIGH":

            st.error(
                f"HIGH RISK — {alert['threat']} | "
                f"IP: {alert['ip_address']} | "
                f"Failed Attempts: {alert['failed_attempts']}"
            )

        elif alert["severity"] == "MEDIUM":

            st.warning(
                f"MEDIUM RISK — {alert['threat']} | "
                f"IP: {alert['ip_address']} | "
                f"Failed Attempts: {alert['failed_attempts']}"
            )

st.divider()

# --------------------------------------------------
# ALERT TABLE
# --------------------------------------------------

st.subheader("🔎 Security Alert Details")

if len(alerts_df) > 0:

    st.dataframe(
        alerts_df,
        use_container_width=True,
        hide_index=True
    )

else:

    st.info("No security alerts available.")

st.divider()

# --------------------------------------------------
# FAILED LOGIN CHART
# --------------------------------------------------

st.subheader("📊 Failed Login Attempts by IP Address")

failed_counts = (
    failed_logins.groupby("ip_address")
    .size()
    .reset_index(name="failed_attempts")
)

st.bar_chart(
    failed_counts,
    x="ip_address",
    y="failed_attempts"
)

st.divider()

# --------------------------------------------------
# RECENT SECURITY EVENTS
# --------------------------------------------------

st.subheader("📋 Recent Security Events")

st.dataframe(
    logs.sort_values("timestamp", ascending=False),
    use_container_width=True,
    hide_index=True
)
# --------------------------------------------------
# STORED ALERT HISTORY
# --------------------------------------------------

st.divider()

st.subheader("🗄️ Stored Alert History")

stored_alerts = get_alerts()

if stored_alerts:

    stored_alerts_df = pd.DataFrame(
        stored_alerts,
        columns=[
            "ID",
            "Severity",
            "Threat",
            "IP Address",
            "Failed Attempts",
            "Detection Time",
            "Reason"
        ]
    )

    st.dataframe(
        stored_alerts_df,
        use_container_width=True,
        hide_index=True
    )

else:
    st.info("No alerts have been stored yet.")