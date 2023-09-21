import re
from datetime import datetime
import os
import subprocess

# Constants
log_file_path = "/var/log/snort/snort.alert.fast"

# Function to parse Snort logs and find offending IPs
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

# Function to parse a log entry
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

# Function to parse a timestamp
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

# Function to check if iptables rules are configured
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
        with open(script_log_path, "a") as _:
            pass
        return True
    except Exception as e:
        with open("/root/error.txt", "a") as error_file:
            error_file.write(str(e) + "\n")
        return False

# Function to write the health status to a file
def write_script2_health_status(status):
    with open("/var/log/script2_health.txt", "w") as health_file:
        health_file.write("Script 2 Health Status:\n")
        health_file.write(f"Snort Running: {status['Snort Running']}\n")
        health_file.write(f"Blacklisted IPs Exist: {status['Blacklisted IPs Exist']}\n")
        health_file.write(f"Iptables Rules Configured: {status['Iptables Rules Configured']}\n")
        health_file.write(f"Log File OK: {status['Log File OK']}\n")

# Main function
def main():
    try:
        snort_running = is_snort_running()
        blacklisted_ips_exist = has_blacklisted_ips()
        iptables_rules_configured = has_iptables_rules()
        log_file_ok = is_script_log_file_ok()

        script2_status = {
            "Snort Running": snort_running,
            "Blacklisted IPs Exist": blacklisted_ips_exist,
            "Iptables Rules Configured": iptables_rules_configured,
            "Log File OK": log_file_ok,
        }

        # Write the health status to a file
        write_script2_health_status(script2_status)

        # Parse Snort logs and print the results
        log_entries = parse_snort_log(log_file_path)
        for entry in log_entries:
            print(f"Timestamp: {entry['timestamp']}")
            print(f"Rule Info: {entry['rule_info']}")
            print(f"Classification: {entry['classification']}\n")

    except Exception as e:
        print(f"An error occurred: {str(e)}")

if __name__ == "__main__":
    main()
