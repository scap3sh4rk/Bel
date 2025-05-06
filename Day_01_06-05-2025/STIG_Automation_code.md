# STIG Automation for windows server 2019
Security Technical implimentation Guide
## Code
```
import json
import subprocess
import re
import ctypes
import sys

# Check for administrative privileges
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

if not is_admin():
    print("Error: This script requires administrative privileges to access registry keys.")
    print("Please run the script as an administrator (e.g., right-click Command Prompt or PowerShell and select 'Run as administrator').")
    sys.exit(1)

# Load STIG JSON file
try:
    with open("microsoft_windows_server_2019.json", encoding='utf-8') as f:
        stig_data = json.load(f)
except FileNotFoundError:
    print("Error: JSON file 'microsoft_windows_server_2019.json' not found in the current directory.")
    sys.exit(1)
except json.JSONDecodeError:
    print("Error: Invalid JSON format in 'microsoft_windows_server_2019.json'.")
    sys.exit(1)

if not stig_data.get("stig", {}).get("findings"):
    print("Error: Invalid JSON structure: Missing 'stig.findings'.")
    sys.exit(1)

print("==== STIG Compliance Check: Windows Server 2019 ====\n")

# List to store non-registry-based rules for manual auditing
manual_audit_rules = []

# Normalize registry path
def normalize_path(hive, path):
    path = path.strip().strip("\\").replace("\\\\", "\\").replace("/", "\\")
    return f"{hive}\\{path}"

# Parse expected value
def parse_expected_value(value, expected_type):
    value = value.lower().strip()
    if expected_type == "REG_DWORD":
        if value.startswith("0x"):
            return str(int(value.split()[0], 16))  # Convert hex to decimal
        elif "(" in value and ")" in value:
            return value.split("(")[1].strip(")")
        return value
    elif expected_type == "REG_MULTI_SZ":
        return value.split(";")  # Assume semicolon-separated
    return value

# Check registry value
def check_registry_value(full_path, value_name, expected_type, expected_value, checktext):
    try:
        # Handle non-existence rules
        if "does not exist or is not configured" in checktext.lower():
            ps_command = f"Test-Path -Path 'Registry::{full_path}\\{value_name}'"
            result = subprocess.run(["powershell", "-Command", ps_command], capture_output=True, text=True, timeout=10)
            if result.stdout.strip() == "False":
                return True, "Registry value does not exist (compliant)"
            return False, "Registry value exists"

        # Handle range-based checks
        threshold = None
        comparison = None
        if "less than or equal to" in checktext.lower():
            comparison = "le"
            match = re.search(r"(\d+|\w+\s*\(\d+\))", expected_value)
            if match:
                threshold = int(match.group(1).split("(")[1].strip(")")) if "(" in match.group(1) else int(match.group(1))
        elif "greater than or equal to" in checktext.lower():
            comparison = "ge"
            match = re.search(r"(\d+|\w+\s*\(\d+\))", expected_value)
            if match:
                threshold = int(match.group(1).split("(")[1].strip(")")) if "(" in match.group(1) else int(match.group(1))

        # Handle multiple valid values
        valid_values = [expected_value]
        if " or " in expected_value:
            valid_values = expected_value.split(" or ")
        valid_values = [parse_expected_value(v, expected_type) for v in valid_values]

        # Get actual value and type
        ps_command = (
            f"$value = Get-ItemProperty -Path 'Registry::{full_path}' -Name '{value_name}' -ErrorAction Stop; "
            f"$valueType = (Get-Item -Path 'Registry::{full_path}').GetValueKind('{value_name}'); "
            f"if ($valueType -eq 'MultiString') {{ ($value.{value_name} -join ';') }} "
            f"elseif ($valueType -eq 'Binary') {{ ($value.{value_name} | ForEach-Object {{ '{{0:X2}}' -f $_ }}) -join '' }} "
            f"else {{ $value.{value_name} }}, $valueType"
        )
        result = subprocess.run(["powershell", "-Command", ps_command], capture_output=True, text=True, timeout=10)

        if result.returncode != 0:
            error_msg = result.stderr.strip() or "Registry value not found or inaccessible"
            return False, error_msg

        output_lines = result.stdout.strip().split("\n")
        actual_value = output_lines[0].lower()
        actual_type = output_lines[1].strip() if len(output_lines) > 1 else "Unknown"

        # Map PowerShell types to STIG types
        type_map = {
            "DWord": "REG_DWORD",
            "String": "REG_SZ",
            "MultiString": "REG_MULTI_SZ",
            "Binary": "REG_BINARY",
            "QWord": "REG_QWORD"
        }
        actual_type = type_map.get(actual_type, actual_type)

        if actual_type != expected_type:
            return False, f"Expected type '{expected_type}', found '{actual_type}'"

        # Perform comparison
        if threshold is not None and actual_value.isdigit():
            try:
                actual_num = int(actual_value)
                if (comparison == "le" and actual_num <= threshold) or (comparison == "ge" and actual_num >= threshold):
                    return True, "Value within expected range"
                return False, f"Expected {comparison} {threshold}, found {actual_num}"
            except ValueError:
                return False, f"Invalid numerical value '{actual_value}'"
        elif expected_type == "REG_MULTI_SZ":
            actual_values = actual_value.split(";")
            compliant = all(any(av.lower() == v for v in valid_values) for av in actual_values)
            if compliant:
                return True, "All multi-string values match"
            return False, f"Expected values {valid_values}, found {actual_values}"
        elif expected_type == "REG_BINARY":
            compliant = actual_value.lower() == expected_value.replace(" ", "").lower()
            if compliant:
                return True, "Binary value matches"
            return False, f"Expected binary {expected_value}, found {actual_value}"
        elif any(actual_value == v for v in valid_values):
            return True, "Value matches expected"
        else:
            return False, f"Expected one of {valid_values}, found '{actual_value}'"

    except subprocess.TimeoutExpired:
        return False, "PowerShell command timed out"
    except Exception as e:
        return False, f"Error: {str(e)}"

# Main processing
for rule_id, rule in stig_data['stig']['findings'].items():
    checktext = rule.get("checktext", "")
    title = rule.get("title", "")
    
    # Check if rule is registry-based
    if "Registry Hive:" not in checktext:
        manual_audit_rules.append((rule_id, title))
        print(f"{rule_id} Rule is not registry based, consider checking it manually")
        print("-" * 60)
        continue

    print(f"Checking: {rule_id} - {title}")
    try:
        lines = checktext.splitlines()
        # Extract fields with fallback for missing data
        hive = next((line.split(":", 1)[1].strip() for line in lines if line.startswith("Registry Hive")), None)
        path = next((line.split(":", 1)[1].strip() for line in lines if line.startswith("Registry Path")), None)
        value_name = next((line.split(":", 1)[1].strip() for line in lines if line.startswith("Value Name")), None)
        expected_type = next((line.split(":", 1)[1].strip() for line in lines if line.startswith("Type")), "REG_SZ")
        value_lines = [line.split(":", 1)[1].strip() for line in lines if line.startswith("Value") and "Type" not in line]
        expected_value = " ".join(value_lines).lower() if value_lines else ""

        if not all([hive, path, value_name]):
            print(f"{rule_id} Error: Missing required fields in checktext (Hive, Path, or Value Name)")
            print("-" * 60)
            continue

        full_path = normalize_path(hive, path)
        compliant, message = check_registry_value(full_path, value_name, expected_type, expected_value, checktext)

        if compliant:
            print(f"{rule_id} Rule FOLLOWED: {message}")
        else:
            print(f"{rule_id} Rule NOT FOLLOWED: {message}")

    except Exception as e:
        print(f"{rule_id} Error checking rule: {str(e)}")

    print("-" * 60)

# Report non-registry-based rules for manual auditing
if manual_audit_rules:
    print("\n==== Rules Requiring Manual Auditing ====\n")
    for rule_id, title in sorted(manual_audit_rules, key=lambda x: x[0]):  # Sort by rule ID
        print(f"{rule_id} - {title}")
else:
    print("\n==== No Rules Requiring Manual Auditing ====")

print("\n==== STIG Registry Check Completed ====")
```

### Instructions
- Make sure that the `microsoft_windows_server_2019.json` is in the same directory that the code is precent in.

### Scope
- The scope of the code is only the `registary` based rules were automated.
- It shows the manual required check rule identies together at one place.

### Testing:
- Checked only the compilation on windoes 10
