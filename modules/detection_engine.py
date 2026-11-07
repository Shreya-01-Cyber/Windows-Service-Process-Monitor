SUSPICIOUS_RELATIONSHIPS = {
    "winword.exe": ["powershell.exe", "cmd.exe", "wscript.exe"],
    "excel.exe": ["powershell.exe", "cmd.exe", "wscript.exe"],
    "outlook.exe": ["powershell.exe", "cmd.exe"],
    "chrome.exe": ["powershell.exe", "cmd.exe"],
}

def detect_suspicious_relationships(processes):

    process_map = {
        process["pid"]: process
        for process in processes
    }

    alerts = []

    for process in processes:

        parent_id = process["ppid"]
        parent = process_map.get(parent_id)

        if parent is None:
            continue

        parent_name = parent["name"].lower()
        child_name = process["name"].lower()

        if child_name in SUSPICIOUS_RELATIONSHIPS.get(parent_name, []):

            alert = {
                "parent": parent_name,
                "parent_pid": parent_id,
                "child": child_name,
                "child_pid": process["pid"],
                "reason": "Unusual parent-child process relationship"
            }

            alerts.append(alert)

    return alerts


if __name__ == "__main__":

    from process_monitor import collect_processes

    processes = collect_processes()

    alerts = detect_suspicious_relationships(processes)

    print("\n===== SUSPICIOUS PROCESS RELATIONSHIPS =====")

    if not alerts:
        print("No suspicious relationships detected.")

    else:
        for alert in alerts:
            print(alert)

    print("\nTotal Alerts:", len(alerts))