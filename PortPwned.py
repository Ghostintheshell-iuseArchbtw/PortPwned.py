import re
import subprocess
import time

# Define the path to the Snort log file
snort_log_path = "/path/to/snort.log"

# Define the path to the file where you want to keep track of banned IPs
blacklist_file = "blacklisted_ips.txt"

# Regular expression pattern for matching IP addresses in Snort logs
ip_pattern = re.compile(r"(\d+\.\d+\.\d+\.\d+)")

# Function to parse Snort logs and find offending IPs
def parse_snort_logs():
    offending_ips = set()  # Use a set to avoid duplicate IPs
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
    # Use subprocess to run iptables command
    try:
        subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
        print(f"IP {ip} has been blacklisted.")
    except subprocess.CalledProcessError as e:
        print(f"Error blacklisting IP {ip}: {e}")

# Main function to perform parsing and blacklisting
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
    except Exception as e:
        print(f"An error occurred: {str(e)}")

# Function to save the blacklisted IPs to a file
def save_blacklisted_ips(file_path, ips):
    with open(file_path, "w") as file:
        for ip in ips:
            file.write(ip + "\n")

if __name__ == "__main__":
    # Run the script every 2 hours (adjust timing as needed)
    while True:
        main()
        time.sleep(2 * 60 * 60)  # Sleep for 2 hours