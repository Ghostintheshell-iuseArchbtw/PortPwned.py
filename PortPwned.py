import os
import re
import subprocess
import time
import logging
import signal
import sys
import configparser

# Constants
CONFIG_FILE_PATH = "/etc/script_config.ini"
LOG_FILE_PATH = "/var/log/script_log.txt"
WAIT_TIME_MINUTES = 30

# Initialize configuration parser
config = configparser.ConfigParser()

# Function to create the configuration file with a template if it doesn't exist
def create_config_file():
    if not os.path.exists(CONFIG_FILE_PATH):
        config['Paths'] = {
            'SNORT_LOG_PATH': '/var/log/snort/snort.log',
            'BLACKLIST_FILE': '/etc/blacklisted_ips.txt',
        }
        config['Services'] = {
            'SCRIPT_SERVICE_NAME': 'my_script.service',
            'SNORT_SERVICE_NAME': 'snort',
            'IPTABLES_SERVICE_NAME': 'iptables',
        }
        with open(CONFIG_FILE_PATH, 'w') as configfile:
            config.write(configfile)

# Function to gracefully stop services
def stop_service(service_name):
    try:
        subprocess.run(["systemctl", "stop", service_name], check=True)
        subprocess.run(["systemctl", "disable", service_name], check=True)
    except subprocess.CalledProcessError as e:
        logging.error(f"Error stopping/disabling service {service_name}: {e}")

# Function to handle script termination gracefully
def handle_termination(signal, frame):
    logging.info("Received termination signal. Stopping services and exiting gracefully.")
    stop_service(SNORT_SERVICE_NAME)
    stop_service(IPTABLES_SERVICE_NAME)
    sys.exit(0)

# Function to parse Snort logs and find offending IPs
def parse_snort_logs():
    offending_ips = set()
    try:
        with open(SNORT_LOG_PATH, "r") as log_file:
            for line in log_file:
                match = IP_PATTERN.search(line)
                if match:
                    ip = match.group(1)
                    offending_ips.add(ip)
    except FileNotFoundError:
        logging.error(f"Snort log file not found at {SNORT_LOG_PATH}")
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

# Function to check if a systemd service is running
def is_service_running(service_name):
    try:
        subprocess.run(["systemctl", "is-active", "--quiet", service_name], check=True)
        return True
    except subprocess.CalledProcessError:
        return False

# Function to configure and start Snort in daemon mode
def configure_and_start_snort():
    # Check if Snort is installed
    if not os.path.exists("/usr/sbin/snort"):
        logging.info("Snort is not installed. Installing...")
        subprocess.run(["apt", "update"], check=True)
        subprocess.run(["apt", "install", "snort", "-y"], check=True)

    # Check if Snort service is enabled and running
    if not is_service_running(SNORT_SERVICE_NAME):
        logging.info("Snort is not running as a daemon. Configuring and starting...")
        # Configure Snort here
        subprocess.run(["systemctl", "start", SNORT_SERVICE_NAME], check=True)

# Function to configure iptables and set firewall rules
def configure_iptables():
    # Check if iptables is installed
    if not os.path.exists("/sbin/iptables"):
        logging.info("iptables is not installed. Installing...")
        subprocess.run(["apt", "update"], check=True)
        subprocess.run(["apt", "install", "iptables", "-y"], check=True)

    # Check if iptables service is enabled and running
    if not is_service_running(IPTABLES_SERVICE_NAME):
        logging.info("iptables is not running as a daemon. Configuring and starting...")
        # Configure iptables rules here
        subprocess.run(["systemctl", "start", IPTABLES_SERVICE_NAME], check=True)

# Function to save the blacklisted IPs to a file
def save_blacklisted_ips(file_path, ips):
    with open(file_path, "w") as file:
        for ip in ips:
            file.write(ip + "\n")

# Main function
def main():
    create_config_file()  # Create the config file if it doesn't exist

    # Read configuration values from the config file
    config.read(CONFIG_FILE_PATH)

    global SNORT_LOG_PATH
    SNORT_LOG_PATH = config.get("Paths", "SNORT_LOG_PATH")
    global BLACKLIST_FILE
    BLACKLIST_FILE = config.get("Paths", "BLACKLIST_FILE")
    global SCRIPT_SERVICE_NAME
    SCRIPT_SERVICE_NAME = config.get("Services", "SCRIPT_SERVICE_NAME")
    global SNORT_SERVICE_NAME
    SNORT_SERVICE_NAME = config.get("Services", "SNORT_SERVICE_NAME")
    global IPTABLES_SERVICE_NAME
    IPTABLES_SERVICE_NAME = config.get("Services", "IPTABLES_SERVICE_NAME")

    try:
        # Load previously blacklisted IPs
        blacklisted_ips = load_blacklisted_ips(BLACKLIST_FILE)

        # Parse Snort logs
        offending_ips = parse_snort_logs()

        # Check for new offending IPs and blacklist them
        for ip in offending_ips:
            if ip not in blacklisted_ips:
                logging.info(f"Blacklisting IP: {ip}")
                blacklist_ip(ip)
                blacklisted_ips.add(ip)

        # Save the updated list of blacklisted IPs
        save_blacklisted_ips(BLACKLIST_FILE, blacklisted_ips)

        # Configure and start Snort if needed
        configure_and_start_snort()

        # Configure iptables if needed
        configure_iptables()
    except Exception as e:
        logging.error(f"An error occurred: {str(e)}")

if __name__ == "__main__":
    signal.signal(signal.SIGINT, handle_termination)
    while True:
        main()
        logging.info(f"Waiting for {WAIT_TIME_MINUTES} minutes before the next run...")
        time.sleep(WAIT_TIME_MINUTES * 60)  # Convert to seconds
