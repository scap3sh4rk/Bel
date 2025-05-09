# STIG Code Version 2.2

## Requirements
- Add a extra column to the report saying whether the `machine is safe` for that particular rule `or not` or whether the `rule has to be manually verified`.

## Result
- Cleared the requirement that is mentioned above.
- I have added extra feature that can output the report in `html` format.

## Code
```
import json
import re
import subprocess
import csv
import os
import argparse
import logging
from datetime import datetime
from pathlib import Path
import sys

# Parse command-line arguments for script configuration
parser = argparse.ArgumentParser(description="Check STIG compliance for Windows Server 2019")
parser.add_argument("--json", default="microsoft_windows_server_2019.json", help="Path to STIG JSON file")
parser.add_argument("--output", default="stig_compliance_report.csv", help="Path to output file")
parser.add_argument("--format", choices=["csv", "html"], default="csv", help="Output format: csv or html")
parser.add_argument("--verbose", action="store_true", help="Enable detailed logging")
parser.add_argument("--severity", choices=["high", "medium", "low"], help="Filter by severity")
args = parser.parse_args()

# Configure logging to file and console
log_file = f"stig_check_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler(log_file), logging.StreamHandler()]
)
logger = logging.getLogger()

def validate_file_path(path):
    """
    Validate that the provided file path exists and is a file.

    Args:
        path (str): File path to validate

    Returns:
        Path: Resolved Path object

    Raises:
        SystemExit: If path is invalid or not a file
    """
    path = Path(path).resolve()
    if not path.exists():
        logger.error(f"File not found: {path}")
        sys.exit(1)
    if not path.is_file():
        logger.error(f"Path is not a file: {path}")
        sys.exit(1)
    return path

# Validate input and output file paths
json_file = validate_file_path(args.json)
# Adjust output file extension based on format
output_file = Path(args.output).resolve()
if args.format == "html" and output_file.suffix.lower() != ".html":
    output_file = output_file.with_suffix(".html")
elif args.format == "csv" and output_file.suffix.lower() != ".csv":
    output_file = output_file.with_suffix(".csv")

def is_domain_controller():
    """
    Check if the system is a domain controller using PowerShell.

    Returns:
        bool: True if system is a domain controller, False otherwise
    """
    try:
        result = subprocess.run(
            ["powershell", "-Command", "Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -ExpandProperty DomainRole"],
            capture_output=True, text=True, timeout=10
        )
        role = int(result.stdout.strip())
        return role in [4, 5]  # 4: Primary DC, 5: Backup DC
    except Exception as e:
        logger.error(f"Error checking domain controller status: {e}")
        return False

# Determine if system is a domain controller
is_dc = is_domain_controller()

# Cache registry queries to improve performance
registry_cache = {}

def query_registry(hive, path, value_name):
    """
    Query a registry value using PowerShell.

    Args:
        hive (str): Registry hive (e.g., HKEY_LOCAL_MACHINE)
        path (str): Registry path
        value_name (str): Name of the value to query

    Returns:
        tuple: (type, value, error)
            - type: Registry type (e.g., REG_DWORD) or status (NOT_PRESENT, ERROR)
            - value: Actual value or None
            - error: Error message or None
    """
    cache_key = f"{hive}\\{path}\\{value_name}"
    if cache_key in registry_cache:
        return registry_cache[cache_key]

    # Map hive to PowerShell shorthand
    hive_map = {"HKEY_LOCAL_MACHINE": "HKLM", "HKEY_CURRENT_USER": "HKCU"}
    hive_short = hive_map.get(hive, hive)

    # Sanitize inputs to prevent command injection
    path = path.replace('"', '').replace("'", '')
    value_name = value_name.replace('"', '').replace("'", '')

    # Construct PowerShell command to query registry
    ps_command = f"""
    try {{
        $key = Get-Item -Path "{hive_short}:{path}" -ErrorAction Stop
        $value = $key.GetValue("{value_name}", $null)
        if ($value -eq $null) {{
            Write-Output "NOT_PRESENT"
        }} else {{
            $type = $key.GetValueKind("{value_name}")
            Write-Output "$type|$value"
        }}
    }} catch {{
        if ($_.Exception.Message -like '*Cannot find path*') {{
            Write-Output "NOT_PRESENT"
        }} else {{
            Write-Output "ERROR|$($_.Exception.Message)"
        }}
    }}"""

    try:
        result = subprocess.run(
            ["powershell", "-ExecutionPolicy", "Bypass", "-Command", ps_command],
            capture_output=True, text=True, timeout=10
        )
        output = result.stdout.strip()
        if result.stderr:
            logger.warning(f"PowerShell stderr for {hive}\\{path}\\{value_name}: {result.stderr}")

        # Parse PowerShell output
        if output == "NOT_PRESENT":
            registry_cache[cache_key] = ("NOT_PRESENT", None, None)
            return "NOT_PRESENT", None, None
        elif output.startswith("ERROR|"):
            error_msg = output.split("|", 1)[1]
            registry_cache[cache_key] = ("ERROR", error_msg, None)
            return "ERROR", error_msg, None
        else:
            reg_type, reg_value = output.split("|", 1)
            if reg_type == "DWord":
                reg_value = int(reg_value)
            elif reg_type == "MultiString":
                reg_value = reg_value.split("\n")
            registry_cache[cache_key] = (reg_type, reg_value, None)
            return reg_type, reg_value, None
    except Exception as e:
        logger.error(f"Error querying registry {hive}\\{path}\\{value_name}: {e}")
        registry_cache[cache_key] = ("ERROR", str(e), None)
        return "ERROR", str(e), None

def parse_registry_details(checktext):
    """
    Extract registry details from checktext using regex patterns.

    Args:
        checktext (str): Checktext from STIG rule

    Returns:
        dict: Registry details (hive, path, value_name, type, value, checktext)
    """
    patterns = {
        "hive": r"Registry Hive:\s*(HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)",
        "path": r"Registry Path:\s*\\([^\\]+(?:\\[^\\]+)*)\\?",
        "value_name": r"Value Name:\s*(\S+)",
        "type": r"(?:Type|Value Type):\s*(REG_DWORD|REG_SZ|REG_MULTI_SZ|REG_BINARY)",
        "value": r"Value:\s*(0x[0-9a-fA-F]+|\d+|\S+(?:\s+\S+)*)"
    }
    details = {}
    for key, pattern in patterns.items():
        match = re.search(pattern, checktext, re.IGNORECASE)
        details[key] = match.group(1) if match else None
    details["checktext"] = checktext
    return details

def extract_desired_value(checktext):
    """
    Extract desired value for non-registry-based rules from checktext.

    Args:
        checktext (str): Checktext from STIG rule

    Returns:
        str: Desired value or fallback description
    """
    checktext = checktext.lower()
    if "get-windowsfeature" in checktext:
        return "Not installed"
    elif "account lockout threshold" in checktext:
        return "3 or less"
    elif "reset account lockout counter after" in checktext:
        return "15 minutes or greater"
    elif "temporary user accounts" in checktext:
        return "Maximum 72 hours"
    elif "auditpol" in checktext:
        return "Enabled"
    elif "event log file" in checktext:
        return "Eventlog, SYSTEM, Administrators - Full Control"
    elif "password never expires" in checktext:
        return "Must expire"
    elif "host-based firewall" in checktext:
        return "Installed and enabled"
    match = re.search(r"must be\s+(.+?)(?:[\.\n]|$)", checktext, re.IGNORECASE)
    return match.group(1).strip() if match else "See checktext"

def check_registry_compliance(details, actual_type, actual_value, error):
    """
    Check compliance for registry-based rules.

    Args:
        details (dict): Registry details (hive, path, value_name, type, value, checktext)
        actual_type (str): Actual registry type or status
        actual_value: Actual registry value
        error (str): Error message if any

    Returns:
        tuple: (compliance message, present value)
    """
    if error:
        return f"RULE NOT FOLLOWED (Error: {error})", actual_value or "Unknown"

    expected_type = details.get("type")
    expected_value = details.get("value")

    # Handle non-existent key/value
    if actual_type == "NOT_PRESENT":
        if "does not exist" in details.get("checktext", "").lower():
            return "RULE FOLLOWED (Key/Value does not exist as expected)", "Not present"
        return "RULE NOT FOLLOWED (Key/Value does not exist)", "Not present"

    # Check type mismatch
    if expected_type and actual_type != expected_type:
        return f"RULE NOT FOLLOWED (Type mismatch: expected {expected_type}, found {actual_type})", actual_value

    # Compare values based on type
    try:
        if expected_type == "REG_DWORD":
            expected = int(expected_value, 16) if expected_value.startswith("0x") else int(expected_value)
            if actual_value == expected:
                return f"RULE FOLLOWED (Value '{actual_value}' matches expected)", actual_value
            return f"RULE NOT FOLLOWED (Expected {expected}, found {actual_value})", actual_value
        elif expected_type == "REG_SZ":
            if actual_value == expected_value:
                return f"RULE FOLLOWED (Value '{actual_value}' matches expected)", actual_value
            return f"RULE NOT FOLLOWED (Expected '{expected_value}', found '{actual_value}')", actual_value
        elif expected_type == "REG_MULTI_SZ":
            expected_values = expected_value.split()
            if set(actual_value) == set(expected_values):
                return f"RULE FOLLOWED (Values match expected)", actual_value
            return f"RULE NOT FOLLOWED (Expected {expected_values}, found {actual_value})", actual_value
        else:
            return f"RULE NOT FOLLOWED (Unsupported type {expected_type})", actual_value
    except Exception as e:
        return f"RULE NOT FOLLOWED (Error comparing values: {e})", actual_value

def process_stig_rules():
    """
    Process STIG rules from JSON and generate a compliance report in the specified format.

    Reads JSON, checks each rule for compliance, and writes results to CSV or HTML.
    """
    # Load JSON file
    try:
        with open(json_file, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        logger.error(f"Error reading JSON file: {e}")
        sys.exit(1)

    # Extract findings
    findings = data.get("stig", {}).get("findings", {})
    if not findings:
        logger.error("No findings found in JSON")
        sys.exit(1)

    results = []
    stats = {"total": 0, "compliant": 0, "non_compliant": 0, "non_registry": 0, "skipped": 0}

    # Process each rule
    for rule_id, rule in findings.items():
        stats["total"] += 1
        checktext = rule.get("checktext", "")
        severity = rule.get("severity", "unknown")

        # Skip rules not matching severity filter
        if args.severity and severity != args.severity:
            continue

        # Handle domain controller-specific rules
        if "This applies to domain controllers" in checktext and not is_dc:
            result = {
                "Rule ID": rule_id,
                "Title": rule.get("title", ""),
                "Severity": severity,
                "Check ID": rule.get("checkid", ""),
                "Description": rule.get("description", ""),
                "Registry Hive": "N/A",
                "Registry Path": "N/A",
                "Value Name": "N/A",
                "Expected Type": "N/A",
                "Expected Value": "N/A",
                "Present Value": "N/A",
                "Compliance Report": "Skipped (Domain Controller Rule)",
                "Fix ID": rule.get("fixid", ""),
                "Result": "Manual Check Required"
            }
            stats["skipped"] += 1
            results.append(result)
            if args.verbose:
                logger.info(f"Skipped {rule_id}: Domain controller rule on non-DC")
            continue

        # Parse registry details
        details = parse_registry_details(checktext)
        is_registry_rule = all(details.get(k) for k in ["hive", "path", "value_name"])

        if is_registry_rule:
            # Query registry for registry-based rules
            actual_type, actual_value, error = query_registry(
                details["hive"], details["path"], details["value_name"]
            )
            compliance, present_value = check_registry_compliance(details, actual_type, actual_value, error)
            result = {
                "Rule ID": rule_id,
                "Title": rule.get("title", ""),
                "Severity": severity,
                "Check ID": rule.get("checkid", ""),
                "Description": rule.get("description", ""),
                "Registry Hive": details["hive"] or "N/A",
                "Registry Path": details["path"] or "N/A",
                "Value Name": details["value_name"] or "N/A",
                "Expected Type": details["type"] or "N/A",
                "Expected Value": details["value"] or "N/A",
                "Present Value": str(present_value) if present_value is not None else "N/A",
                "Compliance Report": compliance,
                "Fix ID": rule.get("fixid", ""),
                "Result": (
                    "Safe" if "RULE FOLLOWED" in compliance else
                    "Not Safe" if "RULE NOT FOLLOWED" in compliance else
                    "Manual Check Required"
                )
            }
            if "RULE FOLLOWED" in compliance:
                stats["compliant"] += 1
            else:
                stats["non_compliant"] += 1
        else:
            # Handle non-registry-based rules
            desired_value = extract_desired_value(checktext)
            result = {
                "Rule ID": rule_id,
                "Title": rule.get("title", ""),
                "Severity": severity,
                "Check ID": rule.get("checkid", ""),
                "Description": rule.get("description", ""),
                "Registry Hive": "N/A",
                "Registry Path": "N/A",
                "Value Name": "N/A",
                "Expected Type": "N/A",
                "Expected Value": desired_value,
                "Present Value": "N/A",
                "Compliance Report": "Not a registry-based rule",
                "Fix ID": rule.get("fixid", ""),
                "Result": "Manual Check Required"
            }
            stats["non_registry"] += 1

        results.append(result)
        if args.verbose:
            logger.info(
                f"Processed {rule_id}: {result['Compliance Report']} "
                f"(Severity: {severity}, Registry: {is_registry_rule}, "
                f"Expected: {result['Expected Value']}, Present: {result['Present Value']})"
            )

    # Sort results by severity (high > medium > low)
    severity_order = {"high": 1, "medium": 2, "low": 3, "unknown": 4}
    results.sort(key=lambda x: severity_order.get(x["Severity"], 4))

    # Write results to the specified format
    try:
        if args.format == "csv":
            with open(output_file, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=[
                    "Rule ID", "Title", "Severity", "Check ID", "Description",
                    "Registry Hive", "Registry Path", "Value Name", "Expected Type",
                    "Expected Value", "Present Value", "Compliance Report", "Fix ID", "Result"
                ])
                writer.writeheader()
                writer.writerows(results)
        else:  # html
            html_content = """
            <!DOCTYPE html>
            <html>
            <head>
                <title>STIG Compliance Report</title>
                <style>
                    table {
                        width: 100%;
                        border-collapse: collapse;
                        font-family: Arial, sans-serif;
                    }
                    th, td {
                        border: 1px solid #ddd;
                        padding: 8px;
                        text-align: left;
                    }
                    th {
                        background-color: #f2f2f2;
                    }
                    tr:nth-child(even) {
                        background-color: #f9f9f9;
                    }
                    .safe {
                        background-color: #ccffcc;
                    }
                    .not-safe {
                        background-color: #ffcccc;
                    }
                    .manual-check {
                        background-color: #ffffcc;
                    }
                </style>
            </head>
            <body>
                <h2>STIG Compliance Report</h2>
                <table>
                    <tr>
                        <th>Rule ID</th>
                        <th>Title</th>
                        <th>Severity</th>
                        <th>Check ID</th>
                        <th>Description</th>
                        <th>Registry Hive</th>
                        <th>Registry Path</th>
                        <th>Value Name</th>
                        <th>Expected Type</th>
                        <th>Expected Value</th>
                        <th>Present Value</th>
                        <th>Compliance Report</th>
                        <th>Fix ID</th>
                        <th>Result</th>
                    </tr>
            """
            for result in results:
                result_class = (
                    "safe" if result["Result"] == "Safe" else
                    "not-safe" if result["Result"] == "Not Safe" else
                    "manual-check"
                )
                html_content += "<tr>"
                for key in [
                    "Rule ID", "Title", "Severity", "Check ID", "Description",
                    "Registry Hive", "Registry Path", "Value Name", "Expected Type",
                    "Expected Value", "Present Value", "Compliance Report", "Fix ID"
                ]:
                    value = str(result[key]).replace("&", "&").replace("<", "<").replace(">", ">")
                    html_content += f"<td>{value}</td>"
                html_content += f'<td class="{result_class}">{result["Result"]}</td>'
                html_content += "</tr>"
            html_content += """
                </table>
            </body>
            </html>
            """
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(html_content)
        logger.info(f"Report written to {output_file}")
    except Exception as e:
        logger.error(f"Error writing {args.format.upper()} file: {e}")
        sys.exit(1)

    # Print compliance summary
    print("\nCompliance Summary:")
    print(f"Total Rules Processed: {stats['total']}")
    print(f"Compliant (Registry-Based): {stats['compliant']}")
    print(f"Non-Compliant (Registry-Based): {stats['non_compliant']}")
    print(f"Non-Registry-Based Rules: {stats['non_registry']}")
    print(f"Skipped (Domain Controller Rules): {stats['skipped']}")
    print(f"Log file: {log_file}")

if __name__ == "__main__":
    process_stig_rules()
```
