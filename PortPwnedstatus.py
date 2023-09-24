import os
import subprocess

def is_snort_running():
    try:
        # Use subprocess.check_call to run the command and raise an error if it fails
        subprocess.check_call(["systemctl", "is-active", "--quiet", "snort.service"])
        return True
    except subprocess.CalledProcessError:
        return False

def has_blacklisted_ips():
    blacklisted_ips_path = "/etc/blacklisted_ips.txt"
    try:
        # Use a context manager for file handling to ensure it's properly closed
        with open(blacklisted_ips_path, "r") as file:
            # Use any() with a generator expression to check if any lines are not empty
            return any(line.strip() for line in file)
    except FileNotFoundError:
        return False

def has_iptables_rules():
    try:
        # Use subprocess.check_output to capture the command's output
        output = subprocess.check_output(["iptables", "-L"], stderr=subprocess.STDOUT, text=True)
        return "Chain INPUT (policy ACCEPT)" not in output
    except subprocess.CalledProcessError:
        return False

def is_script_log_file_ok():
    script_log_path = "/var/log/script_log.txt"
    try:
        # Use a context manager for file handling to ensure it's properly closed
        with open(script_log_path, "a"):
            pass
        return True
    except Exception as e:
        # Handle specific exceptions (e.g., PermissionError) and log the error
        with open("/root/error.txt", "a") as error_file:
            error_file.write(f"Error accessing log file: {str(e)}\n")
        return False

if (
    is_snort_running() and
    has_blacklisted_ips() and
    has_iptables_rules() and
    is_script_log_file_ok()
):
    print("PortPwnedOperational")
else:
    print("PortPwnedDysfunctional")