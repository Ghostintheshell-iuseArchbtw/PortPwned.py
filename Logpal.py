import re
from datetime import datetime

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

def parse_timestamp(timestamp_str):
    try:
        return datetime.strptime(timestamp_str, "%m/%d-%H:%M:%S.%f")
    except ValueError:
        # Handle parsing error, return None or raise an exception as needed
        return None

# Specify the path to your Snort alerts log file
log_file_path = "/var/log/snort/snort.alert.fast"

# Call the function to parse the log
parsed_entries = parse_snort_log(log_file_path)

# Print the parsed entries
for entry in parsed_entries:
    print("Timestamp:", entry['timestamp'])
    print("Rule Information:", entry['rule_info'])
    print("Classification:", entry['classification'])
    print("=" * 50)  # Separating lines for readability
