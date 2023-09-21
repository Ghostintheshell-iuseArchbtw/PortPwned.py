import os
import re
import subprocess
import time

# Define paths
snort_log_path = "/path/to/snort.log"
blacklist_file = "blacklisted_ips.txt"
script_service_name = "my_script.service"
snort_service_name = "snort.service"
iptables_service_name = "iptables.service"

# Regular expression pattern for matching IP addresses in Snort logs
ip_pattern = re.compile(r"(\d+\.\d+\.\d+\.\d+)")

# Function to parse Snort logs and find offending IPs
def parse_snort_logs():
    offending_ips = set()
    with open(snort_log_path, "r") as log_file:
        for line in log_file:
            match = ip_pattern.search(line)
            if match:
                ip = match.group(1)
                offending_ips.add(ip)
    return offending_ips

# Function to load the previously blacklisted IPs
def load_blacklisted_ips(file_path):
    blacklisted_ips = set()
    try:
        with open(file_path, "r") as file:
            for line in file:
                blacklisted_ips.add(line.strip())
    except FileNotFoundError:
        pass
    return blacklisted_ips

# Function to blacklist an IP using iptables
def blacklist_ip(ip):
    try:
        subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
        print(f"IP {ip} has been blacklisted.")
    except subprocess.CalledProcessError as e:
        print(f"Error blacklisting IP {ip}: {e}")

# Function to configure and start Snort in daemon mode
def configure_and_start_snort():
    # Check if Snort is installed
    if not os.path.exists("/usr/sbin/snort"):
        print("Snort is not installed. Installing...")
        # Install Snort using apt
        subprocess.run(["apt", "update"], check=True)
        subprocess.run(["apt", "install", "snort", "-y"], check=True)

    # Check if Snort service is enabled and running
    if not is_service_running(snort_service_name):
        print("Snort is not running as a daemon. Configuring and starting...")
        # Configure Snort here, e.g., by copying the configuration files
        # Start Snort as a daemon
        subprocess.run(["systemctl", "start", snort_service_name], check=True)

# Function to configure iptables and set firewall rules
def configure_iptables():
    # Check if iptables is installed
    if not os.path.exists("/sbin/iptables"):
        print("iptables is not installed. Installing...")
        # Install iptables using apt
        subprocess.run(["apt", "update"], check=True)
        subprocess.run(["apt", "install", "iptables", "-y"], check=True)

    # Check if iptables service is enabled and running
    if not is_service_running(iptables_service_name):
        print("iptables is not running as a daemon. Configuring and starting...")
        # Configure iptables rules here
        # Example: subprocess.run(["iptables-restore", "/etc/iptables/rules.v4"], check=True)
        # Start iptables service
        subprocess.run(["systemctl", "start", iptables_service_name], check=True)

# Function to check if a systemd service is running
def is_service_running(service_name):
    try:
        subprocess.run(["systemctl", "is-active", "--quiet", service_name], check=True)
        return True
    except subprocess.CalledProcessError:
        return False

# Main function
def main():
    try:
        # Load previously blacklisted IPs
        blacklisted_ips = load_blacklisted_ips(blacklist_file)

        # Parse Snort logs
        offending_ips = parse_snort_logs()

        # Check for new offending IPs and blacklist them
        for ip in offending_ips:
            if ip not in blacklisted_ips:
                print(f"Blacklisting IP: {ip}")
                blacklist_ip(ip)
                blacklisted_ips.add(ip)

        # Save the updated list of blacklisted IPs
        save_blacklisted_ips(blacklist_file, blacklisted_ips)

        # Configure and start Snort if needed
        configure_and_start_snort()

        # Configure iptables if needed
        configure_iptables()
    except Exception as e:
        print(f"An error occurred: {str(e)}")

# Function to save the blacklisted IPs to a file
def save_blacklisted_ips(file_path, ips):
    with open(file_path, "w") as file:
        for ip in ips:
            file.write(ip + "\n")

if __name__ == "__main__":
    # Run the script every 30 minutes
    while True:
        main()
        time.sleep(30 * 60)  # Sleep for 30 minutes