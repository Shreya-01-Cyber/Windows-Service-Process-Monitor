
import json
import os
from datetime import datetime


def create_alert(
    category,
    message,
    severity="Medium",
    details=None
):

    alert = {
        "timestamp": datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        ),
        "category": category,
        "severity": severity,
        "message": message,
        "details": details or {}
    }

    return alert


def save_alerts(alerts):

    os.makedirs("reports", exist_ok=True)

    file_path = os.path.join(
        "reports",
        "alerts.json"
    )

    try:
        with open(file_path, "w", encoding="utf-8") as file:

            json.dump(
                alerts,
                file,
                indent=4
            )

        print("\nAlerts saved successfully!")
        print("File location:", file_path)

    except OSError as error:

        print("Error saving alerts:", error)


def display_alerts(alerts):

    print("\n===== SECURITY ALERT SUMMARY =====")

    if not alerts:
        print("No security alerts detected.")

    else:

        for index, alert in enumerate(alerts, start=1):

            print(f"\nAlert {index}")
            print("Category:", alert["category"])
            print("Severity:", alert["severity"])
            print("Message:", alert["message"])
            print("Timestamp:", alert["timestamp"])

    print("\nTotal Alerts:", len(alerts))


if __name__ == "__main__":

    # Sample alert for testing
    sample_alerts = [
        create_alert(
            category="Process Monitoring",
            message="Unusual parent-child process relationship",
            severity="Medium",
            details={
                "parent": "chrome.exe",
                "child": "cmd.exe",
                "parent_pid": 15908,
                "child_pid": 3032
            }
        )
    ]

    display_alerts(sample_alerts)

    save_alerts(sample_alerts)
