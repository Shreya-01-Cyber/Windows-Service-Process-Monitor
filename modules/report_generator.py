
import os
from datetime import datetime


def generate_report(
    processes,
    services,
    programs,
    alerts,
    signature_results=None
):
    os.makedirs("reports", exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    file_path = os.path.join(
        "reports",
        f"monitoring_report_{timestamp}.txt"
    )

    if signature_results is None:
        signature_results = []

    try:
        with open(file_path, "w", encoding="utf-8") as file:

            file.write("=" * 60 + "\n")
            file.write(" WINDOWS MONITORING AGENT REPORT\n")
            file.write("=" * 60 + "\n\n")

            file.write(
                "Scan Date and Time: "
                + datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                + "\n\n"
            )

            file.write("-" * 60 + "\n")
            file.write("MONITORING SUMMARY\n")
            file.write("-" * 60 + "\n")

            file.write(f"Total Processes: {len(processes)}\n")
            file.write(f"Total Services: {len(services)}\n")
            file.write(f"Total Startup Programs: {len(programs)}\n")
            file.write(f"Total Security Alerts: {len(alerts)}\n")
            file.write(
                f"Executable Files Checked: {len(signature_results)}\n"
            )

            file.write("\n" + "-" * 60 + "\n")
            file.write("DIGITAL SIGNATURE RESULTS\n")
            file.write("-" * 60 + "\n")

            if not signature_results:
                file.write("No executable signatures checked.\n")
            else:
                for index, result in enumerate(
                    signature_results, start=1
                ):
                    file.write(f"\nFile {index}\n")
                    file.write(f"Path: {result.get('file')}\n")
                    file.write(f"Status: {result.get('status')}\n")
                    file.write(f"Signer: {result.get('signer', 'Unknown')}\n")
                    file.write(f"Message: {result.get('message', '')}\n")

            file.write("\n" + "-" * 60 + "\n")
            file.write("SECURITY ALERT DETAILS\n")
            file.write("-" * 60 + "\n")

            if not alerts:
                file.write("No security alerts detected.\n")
            else:
                for index, alert in enumerate(alerts, start=1):
                    file.write(f"\nAlert {index}\n")
                    file.write(
                        f"Category: {alert.get('category', 'Unknown')}\n"
                    )
                    file.write(
                        f"Severity: {alert.get('severity', 'Unknown')}\n"
                    )
                    file.write(
                        f"Message: {alert.get('message', 'No message')}\n"
                    )
                    file.write(
                        f"Timestamp: {alert.get('timestamp', 'Unknown')}\n"
                    )
                    file.write(
                        f"Details: {alert.get('details', {})}\n"
                    )

            file.write("\n" + "=" * 60 + "\n")
            file.write("END OF REPORT\n")
            file.write("=" * 60 + "\n")

        print("\nMonitoring report generated successfully!")
        print("Report location:", file_path)

    except OSError as error:
        print("Error generating report:", error)


if __name__ == "__main__":
    print("Report Generator module loaded successfully.")
