import os
import re
import subprocess
import time
import logging
import signal
import sys  # Added sys for sys.exit(0)

# Define paths and configuration
snort_log_path = "/var/log/snort/snort.log"
blacklist_file = "/etc/blacklisted_ips.txt"
script_service_name = "my_script.service"
snort_service_name = "snort"
iptables_service_name = "iptables"
log_file_path = "/var/log/script_log.txt"

# Regular expression pattern for matching IP addresses in Snort logs
ip_pattern = re.compile(r"(\d+\.\d+\.\d+\.\d+)")

# Configure logging
logging.basicConfig(filename=log_file_path, level=logging.INFO,
                    format='%(asctime)s [%(levelname)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

# New function to gracefully stop services
def stop_service(service_name):
    try:
        subprocess.run(["systemctl", "stop", service_name], check=True)
        subprocess.run(["systemctl", "disable", service_name], check=True)
    except subprocess.CalledProcessError as e:
        logging.error(f"Error stopping/disabling service {service_name}: {e}")

# Function to handle script termination gracefully
def handle_termination(signal, frame):
    logging.info("Received termination signal. Stopping services and exiting gracefully.")
    stop_service(snort_service_name)
    stop_service(iptables_service_name)
    sys.exit(0)

# Function to parse Snort logs and find offending IPs
def parse_snort_logs():
    offending_ips = set()
    try:
        with open(snort_log_path, "r") as log_file:
            for line in log_file:
                match = ip_pattern.search(line)
                if match:
                    ip = match.group(1)
                    offending_ips.add(ip)
    except FileNotFoundError:
        logging.error(f"Snort log file not found at {snort_log_path}")
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
        logging.info(f"IP {ip} has been blacklisted.")
    except subprocess.CalledProcessError as e:
        logging.error(f"Error blacklisting IP {ip}: {e}")

# Function to configure and start Snort in daemon mode
def configure_and_start_snort():
    # Check if Snort is installed
    if not os.path.exists("/usr/sbin/snort"):
        logging.info("Snort is not installed. Installing...")
        # Install Snort using apt
        subprocess.run(["apt", "update"], check=True)
        subprocess.run(["apt", "install", "snort", "-y"], check=True)

    # Check if Snort service is enabled and running
    if not is_service_running(snort_service_name):
        logging.info("Snort is not running as a daemon. Configuring and starting...")
        # Configure Snort here, e.g., by copying the configuration files
        # Start Snort as a daemon
        subprocess.run(["systemctl", "start", snort_service_name], check=True)

# Function to configure iptables and set firewall rules
def configure_iptables():
    # Check if iptables is installed
    if not os.path.exists("/sbin/iptables"):
        logging.info("iptables is not installed. Installing...")
        # Install iptables using apt
        subprocess.run(["apt", "update"], check=True)
        subprocess.run(["apt", "install", "iptables", "-y"], check=True)

    # Check if iptables service is enabled and running
    if not is_service_running(iptables_service_name):
        logging.info("iptables is not running as a daemon. Configuring and starting...")
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
                logging.info(f"Blacklisting IP: {ip}")
                blacklist_ip(ip)
                blacklisted_ips.add(ip)

        # Save the updated list of blacklisted IPs
        save_blacklisted_ips(blacklist_file, blacklisted_ips)

        # Configure and start Snort if needed
        configure_and_start_snort()

        # Configure iptables if needed
        configure_iptables()
    except Exception as e:
        logging.error(f"An error occurred: {str(e)}")

# Function to save the blacklisted IPs to a file
def save_blacklisted_ips(file_path, ips):
    with open(file_path, "w") as file:
        for ip in ips:
            file.write(ip + "\n")

if __name__ == "__main__":
    signal.signal(signal.SIGINT, handle_termination)
    while True:
        main()
        logging.info("Waiting for 30 minutes before the next run...")
        time.sleep(30 * 60)  # Sleep for 30 minutes