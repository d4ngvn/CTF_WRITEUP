# Key for decryption
XOR_KEY = 0x19

# Open the log file in binary read mode ('rb')
with open('logs', 'rb') as f:
    encrypted_data = f.read()

# Create a bytearray to store the decrypted data
decrypted_data = bytearray()

# Iterate through each byte in the encrypted data
for byte in encrypted_data:
    # Perform XOR decryption and append to the result
    decrypted_data.append(byte ^ XOR_KEY)

# Print the result to the console
print(decrypted_data.decode('utf-8', errors='ignore'))
