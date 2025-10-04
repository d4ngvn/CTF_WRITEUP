with open("output", "r") as file:
    raw_data = file.read().strip()

real_data = ""
i = 0
while i< len(raw_data):
    if raw_data[i:i+2] == "10":
        reverse_byte = raw_data[i+2:i+10].zfill(8)  # Correct zfill usage with width 8
        real_byte = reverse_byte[::-1]  # Reverse the binary string
        real_data += chr(int(real_byte, 2))  # Convert binary to byte, then to character
        i += 10
    else:
        i+=1
print(real_data)