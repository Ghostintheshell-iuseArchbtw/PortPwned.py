import os
import re
import subprocess
import time
import logging
import signal
import sys
import configparser
from daemon import DaemonContext

# Constants
CONFIG_FILE_PATH = "/etc/script_config.ini"
SNORT_LOG_PATH = "/var/log/snort/snort.log"
BLACKLIST_FILE = "/etc/blacklisted_ips.txt"
SCRIPT_SERVICE_NAME = "my_script.service"
SNORT_SERVICE_NAME = "snort.service"
IPTABLES_SERVICE_NAME = "iptables.service"
LOG_FILE_PATH = "/var/log/script_log.txt"
WAIT_TIME_MINUTES = 30
PACKAGES_INSTALLED_FLAG_FILE = "/var/log/packages_installed.flag"

# Initialize configuration parser
config = configparser.ConfigParser()

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

# Function to check if packages are already installed
def are_packages_installed():
    try:
        subprocess.run(["dpkg", "-l", "package-name"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return True
    except subprocess.CalledProcessError:
        return False

# Function to download and configure packages
def download_and_configure_packages():
    if not os.path.exists(PACKAGES_INSTALLED_FLAG_FILE):
        print("Packages are not installed. Installing...")
        logging.info("Packages are not installed. Installing...")

        # Create the directory for the flag file if it doesn't exist
        flag_directory = os.path.dirname(PACKAGES_INSTALLED_FLAG_FILE)
        os.makedirs(flag_directory, exist_ok=True)

        subprocess.run(["apt", "update"], check=True)
        subprocess.run(["apt", "install", "package-name", "-y"], check=True)

        # Create the flag file to indicate that packages are installed
        open(PACKAGES_INSTALLED_FLAG_FILE, 'a').close()

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
        with open(SNORT_LOG_PATH, "rb") as log_file:
            for line in log_file:
                line = line.decode('utf-8', errors='ignore')
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
        print("Snort is not installed. Installing...")
        logging.info("Snort is not installed. Installing...")
        subprocess.run(["apt", "update"], check=True)
        subprocess.run(["apt", "install", "snort", "-y"], check=True)

    # Check if Snort service is enabled and running
    if not is_service_enabled_and_running(SNORT_SERVICE_NAME):
        print("Snort is not running as a daemon. Configuring and starting...")
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
        print("UFW is not installed. Installing...")
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
print(“Blacklisted IPs:”)
for ip in blacklisted_ips:
print(ip)
else:
print(“No blacklisted IPs found.”)

Main function

def main():
create_config_file()

global IP_PATTERN
IP_PATTERN = re.compile(r"(\d+\.\d+\.\d+\.\d+)")

try:
    # Check if packages are installed, and install them if needed
    download_and_configure_packages()

    # Check and configure Snort
    configure_and_start_snort()

    # Check and configure iptables with UFW
    configure_iptables_with_ufw()

    # Display blacklisted IPs
    display_blacklisted_ips(config.get("Paths", "BLACKLIST_FILE"))

except Exception as e:
    logging.error(f"An error occurred: {str(e)}")

if name == “main”:
signal.signal(signal.SIGINT, handle_termination)

if not os.path.exists("/var/log/first_run.flag"):
    with open("/var/log/first_run.flag", 'a'):
        os.utime("/var/log/first_run.flag", None)
    with DaemonContext():
        main()
        script1_status = check_script1_status()
        write_script1_health_status(script1_status)
        logging.info(f"Waiting for {WAIT_TIME_MINUTES} minutes before the next run...")
        time.sleep(WAIT_TIME_MINUTES * 60)
else:
    with DaemonContext():
        while True:
            main()
            script1_status = check_script1_status()
            write_script1_health_status(script1_status)
            logging.info(f"Waiting for {WAIT_TIME_MINUTES} minutes before the next run...")
            time.sleep(WAIT_TIME_MINUTES * 60)
