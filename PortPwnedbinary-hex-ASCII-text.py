import os
import binascii
import chardet
import argparse
import textwrap

def analyze_binary_data(file_path, analysis_mode='all'):
    try:
        # Check if the file exists
        if not os.path.isfile(file_path):
            print(f"File not found: {file_path}")
            return

        with open(file_path, 'rb') as binary_file:
            data = binary_file.read()

            if analysis_mode == 'info' or analysis_mode == 'all':
                print(f"File Information:")
                display_file_info(file_path, data)

            if analysis_mode == 'stats' or analysis_mode == 'all':
                print(f"Byte Statistics:")
                display_byte_statistics(data)

            hex_representation = binascii.hexlify(data).decode('utf-8').upper()
            print("\nHexadecimal representation of binary data:")
            print(hex_representation)

            if analysis_mode == 'repeating' or analysis_mode == 'all':
                find_repeating_patterns(hex_representation)

            if analysis_mode == 'ascii' or analysis_mode == 'all':
                try:
                    ascii_data = data.decode('ascii', errors='replace')
                    print("\nASCII representation of the data:")
                    print(interpret_ascii_data(ascii_data))
                except UnicodeDecodeError:
                    print("\nUnable to decode binary data as ASCII.")

            if analysis_mode == 'encoding' or analysis_mode == 'all':
                encoding_result = chardet.detect(data)
                detected_encoding = encoding_result['encoding']
                print(f"\nDetected encoding: {detected_encoding}")

    except Exception as e:
        print(f"An error occurred: {str(e)}")

def display_file_info(file_path, data):
    file_size = len(data)
    print(f"File Path: {file_path}")
    print(f"File Size: {file_size} bytes")

def display_byte_statistics(data):
    byte_counts = {}
    for byte in data:
        byte_hex = format(byte, '02X')
        if byte_hex in byte_counts:
            byte_counts[byte_hex] += 1
        else:
            byte_counts[byte_hex] = 1

    print("Byte Statistics:")
    for byte_hex, count in byte_counts.items():
        print(f"Byte: 0x{byte_hex} | Count: {count}")

def find_repeating_patterns(hex_data):
    print("\nRepeating 4-byte patterns:")
    patterns = {}
    pattern_length = 8

    for i in range(len(hex_data) - pattern_length + 1):
        pattern = hex_data[i:i + pattern_length]
        if pattern in patterns:
            patterns[pattern] += 1
        else:
            patterns[pattern] = 1

    for pattern, count in patterns.items():
        if count > 1:
            print(f"Pattern: {pattern} | Count: {count}")

def interpret_ascii_data(ascii_data):
    printable_data = ''.join(char if 32 <= ord(char) <= 126 else ' ' for char in ascii_data)
    return printable_data

def main():
    parser = argparse.ArgumentParser(
        description='Analyze binary data in a file.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent('''
        Example:
        analyze_binary_data /path/to/binary/file --analysis-mode all
        ''')
    )
    parser.add_argument('file_path', help='Path to the binary file to analyze')
    parser.add_argument('--analysis-mode', choices=['all', 'info', 'stats', 'repeating', 'ascii', 'encoding'],
                        default='all', help='Choose analysis mode (default: all)')
    args = parser.parse_args()
    analyze_binary_data(args.file_path, args.analysis_mode)

if __name__ == "__main__":
    main()
