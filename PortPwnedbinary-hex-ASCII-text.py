import os
import chardet

def analyze_binary_data(file_path, analysis_mode='all'):
    try:
        # Check if the file exists
        if not os.path.isfile(file_path):
            print(f"File not found: {file_path}")
            return

        with open(file_path, 'rb') as binary_file:
            data = binary_file.read()

            if analysis_mode == 'info':
                print(f"File Information:")
                display_file_info(file_path, data)

            if analysis_mode == 'stats' or analysis_mode == 'all':
                print(f"Byte Statistics:")
                display_byte_statistics(data)

            hex_representation = data.hex().upper()  # Convert binary data to hexadecimal
            print("\nHexadecimal representation of binary data:")
            print(hex_representation)

            if analysis_mode == 'all' or analysis_mode == 'repeating':
                # Attempt to find repeating patterns (4-byte sequences) in the hexadecimal data
                find_repeating_patterns(hex_representation)

            if analysis_mode == 'all' or analysis_mode == 'ascii':
                # Convert binary data to ASCII
                ascii_data = data.decode('ascii', errors='replace')
                print("\nASCII representation of the data:")
                print(interpret_ascii_data(ascii_data))

            if analysis_mode == 'all' or analysis_mode == 'encoding':
                # Detect encoding using chardet
                encoding_result = chardet.detect(data)
                detected_encoding = encoding_result['encoding']
                print(f"Detected encoding: {detected_encoding}")

    except Exception as e:
        print(f"An error occurred: {str(e)}")

def display_file_info(file_path, data):
    file_size = len(data)
    print(f"File Path: {file_path}")
    print(f"File Size: {file_size} bytes")

def display_byte_statistics(data):
    byte_counts = {}
    for byte in data:
        byte_hex = format(byte, '02X')  # Convert byte to uppercase hexadecimal
        if byte_hex in byte_counts:
            byte_counts[byte_hex] += 1
        else:
            byte_counts[byte_hex] = 1

    print("Byte Statistics:")
    for byte_hex, count in byte_counts.items():
        print(f"Byte: 0x{byte_hex} | Count: {count}")

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
    file_path = input("Enter the path to your binary file: ")  # Prompt the user for the binary file path
    analysis_mode = input("Choose analysis mode ('all', 'info', 'stats', 'repeating', 'ascii', 'encoding'): ").lower()
    analyze_binary_data(file_path, analysis_mode)
