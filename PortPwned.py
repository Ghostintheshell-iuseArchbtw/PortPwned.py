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
SNORT_LOG_PATH = "/var/log/snort/snort.log"
BLACKLIST_FILE = "/etc/blacklisted_ips.txt"
SCRIPT_SERVICE_NAME = "my_script.service"
SNORT_SERVICE_NAME = "snort.service"
IPTABLES_SERVICE_NAME = "iptables.service"
WAIT_TIME_MINUTES = 30

# Initialize configuration parser
config = configparser.ConfigParser()

# Configure logging
logging.basicConfig(filename="/var/log/script_log.txt", level=logging.INFO)

# Function to create the configuration file with a template if it doesn't exist
def create_config_file():
    if not os.path.exists(CONFIG_FILE_PATH):
        config['Paths'] = {
            'SNORT_LOG_PATH': SNORT_LOG_PATH,
            'BLACKLIST_FILE': BLACKLIST_FILE,
        }
        config['Services'] = {
            'SCRIPT_SERVICE_NAME': SCRIPT_SERVICE_NAME,
            'SNORT_SERVICE_NAME': SNORT_SERVICE_NAME,
            'IPTABLES_SERVICE_NAME': IPTABLES_SERVICE_NAME,
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
                match = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
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
        with open(file_path, "r", encoding='utf-8') as file:
            for line in file:
                blacklisted_ips.add(line.strip())
    except FileNotFoundError:
        pass
    except UnicodeDecodeError:
        logging.error(f"Error decoding file at {file_path}")
    return blacklisted_ips

# Function to blacklist an IP using iptables
def blacklist_ip(ip):
    try:
        subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
        logging.info(f"IP {ip} has been blacklisted.")
    except subprocess.CalledProcessError as e:
        logging.error(f"Error blacklisting IP {ip}: {e}")

# Function to check if a systemd service is enabled and running
def is_service_enabled_and_running(service_name):
    try:
        subprocess.run(["systemctl", "is-active", "--quiet", service_name], check=True)
        subprocess.run(["systemctl", "is-enabled", "--quiet", service_name], check=True)
        return True
    except subprocess.CalledProcessError:
        return False

# Function to create a systemd service file if it doesn't exist
def create_service_file(service_path, service_content):
    if not os.path.exists(service_path):
        with open(service_path, 'w') as service_file:
            service_file.write(service_content)

# Function to configure and start Snort in daemon mode
def configure_and_start_snort():
    # Check if Snort is installed
    if not os.path.exists("/usr/sbin/snort"):
        logging.info("Snort is not installed. Installing...")
        subprocess.run(["apt", "update"], check=True)
        subprocess.run(["apt", "install", "snort", "-y"], check=True)

    # Check if Snort service is enabled and running
    if not is_service_enabled_and_running(SNORT_SERVICE_NAME):
        logging.info("Snort is not running as a daemon. Configuring and starting...")
        # Configure Snort here
        snort_service_content = f"""
[Unit]
Description=Snort Intrusion Detection System
After=network.target

[Service]
Type=simple
ExecStart=/usr/sbin/snort -q -u snort -g snort -c /etc/snort/snort.conf -i eth0
Restart=always

[Install]
WantedBy=multi-user.target
"""
        create_service_file(f"/etc/systemd/system/{SNORT_SERVICE_NAME}", snort_service_content)
        subprocess.run(["systemctl", "enable", SNORT_SERVICE_NAME], check=True)
        subprocess.run(["systemctl", "start", SNORT_SERVICE_NAME], check=True)

# Function to configure iptables using UFW
def configure_iptables_with_ufw():
    # Check if UFW is installed
    if not os.path.exists("/usr/sbin/ufw"):
        logging.info("UFW is not installed. Installing...")
        subprocess.run(["apt", "update"], check=True)
        subprocess.run(["apt", "install", "ufw", "-y"], check=True)

    # Enable and start UFW
    try:
        subprocess.run(["ufw", "enable"], check=True, input="y\n", text=True)
        subprocess.run(["ufw", "status"], check=True)
    except subprocess.CalledProcessError as e:
        logging.error(f"Error enabling UFW: {e}")

# Function to display blacklisted IPs
def display_blacklisted_ips(file_path):
    blacklisted_ips = load_blacklisted_ips(file_path)
    if blacklisted_ips:
        print("Blacklisted IPs:")
        for ip in blacklisted_ips:
            print(ip)
    else:
        print("No blacklisted IPs found.")

# Main function
def main():
    create_config_file()  # Create the config file if it doesn't exist

    try:
        # Check and configure Snort
        configure_and_start_snort()

        # Check and configure iptables with UFW
        configure_iptables_with_ufw()

        # Display blacklisted IPs
        display_blacklisted_ips(config.get("Paths", "BLACKLIST_FILE"))

    except Exception as e:
        logging.error(f"An error occurred: {str(e)}")

if __name__ == "__main__":
    signal.signal(signal.SIGINT, handle_termination)
    while True:
        main()
        logging.info(f"Waiting for {WAIT_TIME_MINUTES} minutes before the next run...")
        time.sleep(WAIT_TIME_MINUTES * 60)