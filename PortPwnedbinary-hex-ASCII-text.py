import os

def analyze_binary_data(file_path):
    try:
        with open(file_path, 'rb') as binary_file:
            data = binary_file.read()
            hex_representation = data.hex().upper()  # Convert binary data to hexadecimal
            print("Hexadecimal representation of binary data:")
            print(hex_representation)
            
            # Attempt to find repeating patterns (4-byte sequences) in the hexadecimal data
            find_repeating_patterns(hex_representation)
            
            # Convert binary data to ASCII
            ascii_data = data.decode('ascii', errors='replace')
            print("\nASCII representation of the data:")
            print(ascii_data)
    except FileNotFoundError:
        print(f"File not found: {file_path}")
    except Exception as e:
        print(f"An error occurred: {str(e)}")

def find_repeating_patterns(hex_data):
    print("\nRepeating 4-byte patterns:")
    patterns = {}  # Dictionary to store patterns and their counts
    pattern_length = 8  # 8 characters represent 4 bytes in hexadecimal

    for i in range(len(hex_data) - pattern_length + 1):
        pattern = hex_data[i:i + pattern_length]
        if pattern in patterns:
            patterns[pattern] += 1
        else:
            patterns[pattern] = 1

    # Print patterns that repeat more than once
    for pattern, count in patterns.items():
        if count > 1:
            print(f"Pattern: {pattern} | Count: {count}")

def interpret_ascii_data(ascii_data):
    # Replace control characters and non-printable characters with spaces
    printable_data = ''.join(char if 32 <= ord(char) <= 126 else ' ' for char in ascii_data)
    return printable_data

if __name__ == "__main__":
    file_path = "/var/log/snort/snort.alert"  # Replace with the path to your binary file
    analyze_binary_data(file_path)
