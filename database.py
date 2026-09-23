import sqlite3

DATABASE_NAME = "security_alerts.db"


def create_database():
    connection = sqlite3.connect(DATABASE_NAME)
    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            severity TEXT NOT NULL,
            threat TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            failed_attempts INTEGER,
            start_time TEXT NOT NULL,
            reason TEXT NOT NULL,
            UNIQUE(threat, ip_address, start_time)
        )
    """)

    connection.commit()
    connection.close()


def save_alert(alert):
    connection = sqlite3.connect(DATABASE_NAME)
    cursor = connection.cursor()

    cursor.execute("""
        INSERT OR IGNORE INTO alerts (
            severity,
            threat,
            ip_address,
            failed_attempts,
            start_time,
            reason
        )
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        alert["severity"],
        alert["threat"],
        alert["ip_address"],
        alert["failed_attempts"],
        str(alert["start_time"]),
        alert["reason"]
    ))

    connection.commit()
    connection.close()


def get_alerts():
    connection = sqlite3.connect(DATABASE_NAME)

    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            id,
            severity,
            threat,
            ip_address,
            failed_attempts,
            start_time,
            reason
        FROM alerts
        ORDER BY id DESC
    """)

    alerts = cursor.fetchall()

    connection.close()

    return alerts