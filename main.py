from modules.signature_checker import check_signature, display_signature_result
from modules.signature_checker import check_signature, display_signature_result
from modules.report_generator import generate_report
from modules.alert_manager import (
    create_alert,
    save_alerts,
    display_alerts
)
from modules.process_monitor import collect_processes
from modules.process_tree import display_process_tree
from modules.detection_engine import detect_suspicious_relationships

from modules.service_monitor import (
    collect_services,
    display_services,
    audit_services
)

from modules.startup_audit import (
    collect_startup_programs,
    display_startup_programs,
    audit_startup_programs
)


def main():

    print("=" * 60)
    print(" WINDOWS SERVICE & PROCESS MONITORING AGENT")
    print("=" * 60)

    # 1. Process Monitoring
    print("\n[1] PROCESS MONITORING")

    processes = collect_processes()

    print("Total Processes Collected:", len(processes))

    # 2. Parent-Child Process Monitoring
    print("\n[2] PARENT-CHILD PROCESS MONITORING")

    display_process_tree(processes)

    # 3. Suspicious Process Detection
    print("\n[3] SUSPICIOUS PROCESS DETECTION")

    process_alerts = detect_suspicious_relationships(processes)

    if process_alerts:
        for alert in process_alerts:
            print(alert)
    else:
        print("No suspicious process relationships detected.")

    print("Total Process Alerts:", len(process_alerts))

    # 4. Windows Service Monitoring
    print("\n[4] WINDOWS SERVICE MONITORING")

    services = collect_services()

    display_services(services)

    # 5. Windows Service Audit
    print("\n[5] WINDOWS SERVICE AUDIT")

    audit_services(services)

    # 6. Startup Program Monitoring
    print("\n[6] STARTUP PROGRAM MONITORING")

    programs = collect_startup_programs()

    display_startup_programs(programs)

    # 7. Startup Security Audit
    print("\n[7] STARTUP SECURITY AUDIT")

    audit_startup_programs(programs)

    # 8. Digital Signature Monitoring
    print("\n[8] DIGITAL SIGNATURE MONITORING")

    signature_results = []

    checked_paths = set()

    for process in processes:
        exe_path = process.get("path")

        if not exe_path or exe_path in checked_paths:
            continue

        checked_paths.add(exe_path)

        result = check_signature(exe_path)
        signature_results.append(result)

        display_signature_result(result)

    print("\nTotal Executable Files Checked:", len(signature_results))
    # Check for suspicious digital signature statuses
    signature_alerts = []
    for result in signature_results:

        if result.get("status") in [
             "NotSigned",
             "HashMismatch",
             "NotTrusted",
             "UnknownError"
        ]:

             all_signature_alert = create_alert(
                category="Digital Signature Monitoring",
                message="Executable has an unusual digital signature status",
                severity="Medium",
                details=result
            )

             signature_alerts.append(all_signature_alert)

    # 9. Alert Management

    print("\n[8] ALERT MANAGEMENT")

    all_alerts = []

    # Process alerts
    for item in process_alerts:

        all_alerts.append(
            create_alert(
                category="Process Monitoring",
                message=item["reason"],
                severity="Medium",
                details=item
            )
        )

    # Service alerts
    service_alerts = []

    for service in services:

        if (
            service.get("StartMode") == "Auto"
            and service.get("State") != "Running"
        ):

            service_alerts.append(service)

    for item in service_alerts:

        all_alerts.append(
            create_alert(
                category="Windows Service Monitoring",
                message="Automatic service is not running",
                severity="Low",
                details=item
            )
        )
    # Digital Signature Alerts
    for item in signature_alerts:

        all_alerts.append(item)

    # Startup alerts
    suspicious_tools = [
        "powershell.exe",
        "cmd.exe",
        "wscript.exe",
        "cscript.exe",
        "mshta.exe"
    ]

    suspicious_locations = [
        "\\temp\\",
        "\\downloads\\"
    ]

    for program in programs:

        command = (program.get("Command") or "").lower()

        if any(tool in command for tool in suspicious_tools) or any(
            location in command for location in suspicious_locations
        ):

            all_alerts.append(
                create_alert(
                    category="Startup Monitoring",
                    message="Suspicious startup pattern detected",
                    severity="Medium",
                    details=program
                )
            )

    display_alerts(all_alerts)

    save_alerts(all_alerts)
    # 10. Generate Monitoring Report
    print("\n[9] REPORT GENERATION")

    generate_report(
        processes,
        services,
        programs,
        all_alerts,
        signature_results
    )

    # Final Summary
    print("\n" + "=" * 60)
    print(" MONITORING SCAN COMPLETED")
    print("=" * 60)

    print("Processes Collected:", len(processes))
    print("Services Collected:", len(services))
    print("Startup Programs Collected:", len(programs))

    print("\nAll monitoring modules executed successfully.")


if __name__ == "__main__":
    main()
