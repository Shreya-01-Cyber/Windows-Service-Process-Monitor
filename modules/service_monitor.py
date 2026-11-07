
import subprocess
import json


def collect_services():

    command = [
        "powershell",
        "-NoProfile",
        "-Command",
        "Get-CimInstance Win32_Service | Select-Object Name, DisplayName, State, StartMode | ConvertTo-Json -Depth 2"
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        print("Error collecting services:")
        print(result.stderr)
        return []

    try:
        services = json.loads(result.stdout)

        if isinstance(services, dict):
            services = [services]

        return services

    except json.JSONDecodeError:
        print("Unable to read service information.")
        return []


def display_services(services):

    print("\n===== WINDOWS SERVICE MONITOR =====")

    for service in services:
        print(
            f"Name: {service.get('Name')} | "
            f"Status: {service.get('State')} | "
            f"Startup: {service.get('StartMode')}"
        )

    print("\nTotal Services:", len(services))


def audit_services(services):

    print("\n===== SERVICE AUDIT =====")

    alerts = []

    for service in services:

        name = service.get("Name")
        status = service.get("State")
        startup = service.get("StartMode")

        if startup == "Auto" and status != "Running":

            alerts.append({
                "service": name,
                "status": status,
                "startup": startup,
                "reason": "Automatic service is not running"
            })

    if not alerts:
        print("No unusual service configurations detected.")

    else:
        for alert in alerts:
            print(alert)

    print("\nTotal Service Alerts:", len(alerts))


if __name__ == "__main__":

    services = collect_services()

    display_services(services)

    audit_services(services)
