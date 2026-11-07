# Windows Service & Process Monitoring Agent

A Python-based Windows security monitoring tool designed to collect system process and service information, identify potentially suspicious activity, and generate security reports.

## Project Overview

The Windows Service & Process Monitoring Agent performs user-mode monitoring of Windows processes, services, startup programs, and executable digital signatures.

It uses rule-based detection techniques to identify unusual process relationships, suspicious startup command patterns, and selected service or executable conditions.

## Features

- **Process Monitoring:** Collects running process information, including PID, parent PID, process name, executable path, and username.
- **Process Tree Analysis:** Displays parent-child process relationships.
- **Suspicious Relationship Detection:** Identifies selected unusual parent-child process combinations.
- **Windows Service Monitoring:** Collects service information and audits selected service conditions.
- **Startup Program Auditing:** Inspects Windows startup entries for potentially suspicious command patterns.
- **Digital Signature Verification:** Checks executable Authenticode signature status.
- **Security Alert Management:** Generates and stores categorized security alerts.
- **Report Generation:** Produces timestamped monitoring reports.

## Technologies Used

- Python
- psutil
- Windows PowerShell
- Windows Management Instrumentation (WMI/CIM)
- JSON
- Git and GitHub

## Project Structure

```text
Windows_Service_Process_Monitor/
│
├── main.py
├── requirements.txt
├── README.md
├── .gitignore
│
├── modules/
│   ├── process_monitor.py
│   ├── process_tree.py
│   ├── detection_engine.py
│   ├── service_monitor.py
│   ├── startup_audit.py
│   ├── signature_checker.py
│   ├── alert_manager.py
│   └── report_generator.py
│
├── rules/
│   ├── detection_rules.json
│   └── whitelist.json
│
├── tests/
│   ├── test_detection_engine.py
│   ├── test_process_monitor.py
│   └── test_service_monitor.py
│
├── docs/
│   ├── architecture.png
│   ├── project_documentation.docx
│   └── screenshots/
│
├── logs/
└── reports/
```

## Installation

### 1. Clone the repository

```bash
git clone YOUR_GITHUB_REPOSITORY_URL
cd Windows_Service_Process_Monitor
```

Replace `YOUR_GITHUB_REPOSITORY_URL` with your actual GitHub repository URL.

### 2. Create a virtual environment

```bash
python -m venv .venv
```

### 3. Activate the virtual environment

Windows Command Prompt:

```cmd
.venv\Scripts\activate
```

### 4. Install dependencies

```bash
pip install -r requirements.txt
```

## Running the Project

Run the monitoring agent from the project root:

```bash
python main.py
```

The program collects system information, performs monitoring and rule-based checks, displays security alerts, and generates a monitoring report.

## Output

The application generates:

- `reports/alerts.json` — structured security alert data.
- `reports/monitoring_report_YYYYMMDD_HHMMSS.txt` — timestamped monitoring report.

These are generated locally and excluded from Git tracking by default.

## Testing

The project contains test files in the `tests/` directory.

Test execution instructions will be added after the test suite and its dependencies have been verified.

## Limitations

- Uses user-mode monitoring and periodic collection rather than kernel-level monitoring.
- Detection is based on predefined rules and heuristics.
- Alerts indicate potentially suspicious patterns and do not confirm malware infections.
- Digital signature status alone cannot determine whether an executable is malicious.
- Monitoring coverage depends on Windows permissions and available system information.
- This project is a learning and monitoring prototype, not a replacement for a commercial EDR or antivirus solution.

## Future Improvements

- Continuous process monitoring.
- Configurable detection rules.
- Improved whitelist management.
- More detailed security event logging.
- Additional automated tests.
- Improved alert severity classification.

## Disclaimer

This project is developed for educational and cybersecurity learning purposes. Use it only on systems you own or have permission to monitor.
