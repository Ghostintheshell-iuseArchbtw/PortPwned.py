import subprocess

def is_snort_running():
    try:
        result = subprocess.run(["systemctl", "is-active", "--quiet", "snort.service"], capture_output=True, text=True)
        return result.returncode == 0
    except subprocess.CalledProcessError:
        return False

def has_blacklisted_ips():
    try:
        blacklisted_ips_path = "/etc/blacklisted_ips.txt"
        with open(blacklisted_ips_path, "r") as file:
            return any(line.strip() for line in file)
    except FileNotFoundError:
        return False

def has_iptables_rules():
    try:
        result = subprocess.run(["iptables", "-L"], capture_output=True, text=True)
        output = result.stdout
        return "Chain INPUT (policy ACCEPT)" not in output
    except subprocess.CalledProcessError:
        return False

def is_script_log_file_ok():
    script_log_path = "/var/log/script_log.txt"
    try:
        # Check if the log file is accessible
        with open(script_log_path, "a"):
            pass
        return True
    except Exception as e:
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

def has_blacklisted_ips():
    try:
        blacklisted_ips_path = "/etc/blacklisted_ips.txt"
        with open(blacklisted_ips_path, "r") as file:
            return any(line.strip() for line in file)
    except FileNotFoundError:
        return False

def has_iptables_rules():
    try:
        result = subprocess.run(["iptables", "-L"], capture_output=True, text=True)
        output = result.stdout
        return "Chain INPUT (policy ACCEPT)" not in output
    except subprocess.CalledProcessError:
        return False

def is_script_log_file_ok():
    script_log_path = "/var/log/script_log.txt"
    try:
        # Check if the log file is accessible
        with open(script_log_path, "a"):
            pass
        return True
    except Exception as e:
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

def is_snort_running():
    try:
        result = subprocess.run(["systemctl", "is-active", "--quiet", "snort.service"], capture_output=True)
        return result.returncode == 0
    except subprocess.CalledProcessError:
        return False

def has_blacklisted_ips():
    try:
        blacklisted_ips_path = "/etc/blacklisted_ips.txt"
        with open(blacklisted_ips_path, "r") as file:
            return any(line.strip() for line in file)
    except FileNotFoundError:
        return False

def has_iptables_rules():
    try:
        result = subprocess.run(["iptables", "-L"], capture_output=True, text=True)
        output = result.stdout
        return "Chain INPUT (policy ACCEPT)" not in output
    except subprocess.CalledProcessError:
        return False

def is_script_log_file_ok():
    script_log_path = "/var/log/script_log.txt"
    try:
        # Check if the log file is accessible
        with open(script_log_path, "a"):
            pass
        return True
    except Exception as e:
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

def has_blacklisted_ips():
    try:
        blacklisted_ips_path = "/etc/blacklisted_ips.txt"
        with open(blacklisted_ips_path, "r") as file:
            return any(line.strip() for line in file)
    except FileNotFoundError:
        return False

def has_iptables_rules():
    try:
        result = subprocess.run(["iptables", "-L"], stdout=subprocess.PIPE, stderr=subp>
        output = result.stdout.decode("utf-8")
        return "Chain INPUT (policy ACCEPT)" not in output  # Checks if INPUT chain has>
    except subprocess.CalledProcessError:
        return False

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

if (
    is_snort_running() and
    has_blacklisted_ips() and
    has_iptables_rules() and
    is_script_log_file_ok()
):
    print("PortPwnedOperational")
else:
    print("PortPwnedDysfunctional")
