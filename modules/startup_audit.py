
import subprocess
import json


# STEP 1: Collect Windows startup programs
def collect_startup_programs():

    command = [
        "powershell",
        "-NoProfile",
        "-Command",
        "Get-CimInstance Win32_StartupCommand | "
        "Select-Object Name, Command, Location, User | "
        "ConvertTo-Json -Depth 2"
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        print("Error collecting startup programs:")
        print(result.stderr)
        return []

    try:
        if not result.stdout.strip():
            return []

        programs = json.loads(result.stdout)

        if isinstance(programs, dict):
            programs = [programs]

        return programs

    except json.JSONDecodeError:
        print("Unable to read startup information.")
        return []


# STEP 2: Display startup programs
def display_startup_programs(programs):

    print("\n===== WINDOWS STARTUP PROGRAM AUDIT =====")

    for program in programs:

        print("\nName:", program.get("Name"))
        print("Command:", program.get("Command"))
        print("Location:", program.get("Location"))
        print("User:", program.get("User"))

    print("\nTotal Startup Programs:", len(programs))


# STEP 3: Detect suspicious startup patterns
def audit_startup_programs(programs):

    print("\n===== STARTUP SECURITY AUDIT =====")

    alerts = []

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

        name = program.get("Name", "")
        command = program.get("Command", "") or ""

        command_lower = command.lower()

        reasons = []

        # Check for scripting and command interpreters
        for tool in suspicious_tools:

            if tool in command_lower:

                reasons.append(
                    "Startup command uses a scripting or command interpreter"
                )
                break

        # Check for commonly abused folders
        for location in suspicious_locations:

            if location in command_lower:

                reasons.append(
                    "Startup command launches from a commonly abused folder"
                )
                break

        # Store detected alerts
        if reasons:

            alerts.append({
                "name": name,
                "command": command,
                "reasons": reasons
            })

    # Display results
    if not alerts:

        print("No suspicious startup patterns detected.")

    else:

        for alert in alerts:

            print("\nProgram:", alert["name"])
            print("Command:", alert["command"])
            print("Reason:", ", ".join(alert["reasons"]))

    print("\nTotal Startup Alerts:", len(alerts))


# STEP 4: Main execution
if __name__ == "__main__":

    programs = collect_startup_programs()

    display_startup_programs(programs)

    audit_startup_programs(programs)
