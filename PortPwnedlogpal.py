# Define a function to parse and format Snort alerts
def parse_snort_log(log_file):
    with open(log_file, 'r') as file:
        lines = file.readlines()

    for line in lines:
        parts = line.split('[**]')
        if len(parts) >= 3:
            timestamp = parts[0].strip()
            rule_info = parts[1].strip()
            classification = parts[2].strip()

            print(f"Timestamp: {timestamp}")
            print(f"Rule Information: {rule_info}")
            print(f"Classification: {classification}")
            print("=" * 50)  # Separating lines for readability

# Specify the path to your Snort alerts log file
log_file_path = "/var/log/snort/snort.alert.fast"

# Call the function to parse and print the log
parse_snort_log(log_file_path)
