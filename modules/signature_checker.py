
import subprocess
import json
import base64


def check_signature(file_path):

    # Safely encode the PowerShell script
    safe_path = file_path.replace("'", "''")

    script = f"""
    $ErrorActionPreference = 'Stop'

    try {{
        $filePath = '{safe_path}'

        $result = Get-AuthenticodeSignature `
            -LiteralPath $filePath `
            -ErrorAction Stop

        [PSCustomObject]@{{
            File = $result.Path
            Status = $result.Status.ToString()
            StatusMessage = $result.StatusMessage
            Signer = $result.SignerCertificate.Subject
            CheckError = $false
        }} | ConvertTo-Json -Compress
    }}
    catch {{
        [PSCustomObject]@{{
            CheckError = $true
            Error = $_.Exception.Message
        }} | ConvertTo-Json -Compress

        exit 1
    }}
    """

    encoded_script = base64.b64encode(
        script.encode("utf-16le")
    ).decode("ascii")

    command = [
        "powershell",
        "-NoProfile",
        "-NonInteractive",
        "-EncodedCommand",
        encoded_script
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=15
        )

        if not result.stdout.strip():
            return {
                "file": file_path,
                "status": "Error",
                "message": result.stderr.strip() or
                           "PowerShell returned no output.",
                "signer": "Not available"
            }

        data = json.loads(result.stdout)

        if result.returncode != 0 or data.get("CheckError"):
            return {
                "file": file_path,
                "status": "Error",
                "message": data.get(
                    "Error",
                    result.stderr.strip()
                ),
                "signer": "Not available"
            }

        return {
            "file": data.get("File", file_path),
            "status": data.get("Status", "Unknown"),
            "message": (
    "Digital signature verified successfully."
    if data.get("Status") == "Valid"
    else "No Authenticode digital signature was found."
    if data.get("Status") == "NotSigned"
    else data.get("StatusMessage", "")
),
            "signer": data.get("Signer") or "Not available"
        }

    except subprocess.TimeoutExpired:
        return {
            "file": file_path,
            "status": "Timeout",
            "message": "Signature check timed out.",
            "signer": "Not available"
        }

    except (json.JSONDecodeError, OSError) as error:
        return {
            "file": file_path,
            "status": "Error",
            "message": str(error),
            "signer": "Not available"
        }


def display_signature_result(result):

    print("\n===== DIGITAL SIGNATURE CHECK =====")
    print("File:", result["file"])
    print("Signature Status:", result["status"])
    print("Message:", result.get("message", ""))
    print("Signer:", result.get("signer", "Not available"))


if __name__ == "__main__":

    test_file = r"C:\Windows\System32\notepad.exe"

    result = check_signature(test_file)

    display_signature_result(result)
