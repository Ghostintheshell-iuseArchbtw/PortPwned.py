import chardet

# Define the path to the "error.txt" file
data_file_path = '/root/PortPwned.py/nohup.out'

with open(data_file_path, 'rb') as file:
    raw_data = file.read()
    encoding_result = chardet.detect(raw_data)
    detected_encoding = encoding_result['encoding']

print(f"Detected encoding: {detected_encoding}")

