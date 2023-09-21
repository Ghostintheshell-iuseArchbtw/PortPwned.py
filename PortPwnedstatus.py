import re
from datetime import datetime
import os
import subprocess

# Function to parse Snort log entries
def parse_snort_log(log_file_path):
    parsed_entries = []

    try:
        with open(log_file_path, 'r') as log_file:
            for line in log_file:
                entry = parse_log_entry(line)
                if entry:
                    parsed_entries.append(entry)
    except FileNotFoundError:
        print(f"File not found: {log_file_path}")
    except Exception as e:
        print(f"An error occurred: {str(e)}")

    return parsed_entries

# Function to parse a single log entry
def parse_log_entry(log_entry):
    entry_pattern = re.compile(r"^\[(.*?)\]\s*\[.*?\]\s*\[(.*?)\]\s*(.*)$")
    match = entry_pattern.match(log_entry)
    
    if match:
        timestamp_str, rule_info, classification = match.groups()
        timestamp = parse_timestamp(timestamp_str)
        return {
            'timestamp': timestamp,
            'rule_info': rule_info.strip(),
            'classification': classification.strip()
        }
    
    return None

# Function to parse a timestamp string
def parse_timestamp(timestamp_str):
    try:
        return datetime.strptime(timestamp_str, "%m/%d-%H:%M:%S.%f")
    except ValueError:
        return None

# Function to check if Snort is running
def is_snort_running():
    try:
        result = subprocess.run(["systemctl", "is-active", "--quiet", "snort.service"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return result.returncode == 0
    except subprocess.CalledProcessError:
        return False

# Function to check if blacklisted IPs exist
def has_blacklisted_ips():
    try:
        blacklisted_ips_path = "/etc/blacklisted_ips.txt"
        with open(blacklisted_ips_path, "r") as file:
            return any(line.strip() for line in file)
    except FileNotFoundError:
        return False

# Function to check if iptables rules exist
def has_iptables_rules():
    try:
        result = subprocess.run(["iptables", "-L"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output = result.stdout.decode("utf-8")
        return "Chain INPUT (policy ACCEPT)" not in output
    except subprocess.CalledProcessError:
        return False

# Function to check if the script log file is accessible
def is_script_log_file_ok():
    script_log_path = "/var/log/script_log.txt"
    try:
        # Check if the log file is accessible
        with open(script_log_path, "a") as _:
            pass
        return True
    except Exception as e:
        with open("/root/error.txt", "a") as error_file:
            error_file.write(f"Error accessing log file: {str(e)}\n")
        return False

# Function to print blacklisted IPs
def print_blacklisted_ips():
    blacklisted_ips_path = "/etc/blacklisted_ips.txt"
    try:
        with open(blacklisted_ips_path, "r") as file:
            for line in file:
                ip = line.strip()
                print(f"{ip} has been PortPwned")
    except FileNotFoundError:
        pass

# Specify the path to your Snort alerts log file
log_file_path = "/var/log/snort/snort.alert.fast"

# Call the function to parse the log
parsed_entries = parse_snort_log(log_file_path)

# Print the parsed entries (or process them as needed)
for entry in parsed_entries:
    print("Timestamp:", entry['timestamp'])
    print("Rule Information:", entry['rule_info'])
    print("Classification:", entry['classification'])
    print("=" * 50)  # Separating lines for readability

# Print blacklisted IPs and their status
print_blacklisted_ips()

# Check the conditions and report PortPwned status
if (
    is_snort_running() and
    has_blacklisted_ips() and
    has_iptables_rules() and
    is_script_log_file_ok()
):
    print("PortPwned Operational")
else:
    print("PortPwned Dysfunctional")
