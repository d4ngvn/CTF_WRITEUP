# yoU ART - EASY

## Challenge Description
We've discovered that the recent patch deleted critical files from the cybernetic enhancements. To restore functionality, we need to identify which files were removed.

Diagnostics checks run during the device's boot process and should reveal that information. We've connected our serial debugger to the device's debugging interface, capturing the output from the transmitting pin.

Can you analyze the data and help us pinpoint the missing files?

## Solution
1. Upon accessing the provided server, we received a very long binary string:
    ![Captured Binary Data](image.png)
2. Observing that the system could send an infinite sequence of `111...111`, we stopped and began analyzing the binary string.
3. Based on the challenge description and hints, we determined that the binary sequence of 0s and 1s represents raw data captured from a communication channel, specifically UART.

### UART Protocol Overview
UART (Universal Asynchronous Receiver-Transmitter) transmits data asynchronously, one bit at a time. A typical data frame for transmitting a byte has the following structure:

- **Idle State**: The line remains high (logic 1).
- **Start Bit**: The line is pulled low (logic 0) to signal the start of a byte.
- **Data Bits**: Usually 8 bits (1 byte), sent from the least significant bit (LSB) first. This is a critical detail.
- **Parity Bit** (Optional): Used for error checking, though often omitted.
- **Stop Bit**: The line is pulled high (logic 1) to signal the end of the frame. Typically, there is 1 or 2 stop bits.

By decoding the binary data using this structure, we can reconstruct the missing files.

### Idea

- Khi thử phân tích 1 đoạn đầu, ta thấy có vẻ như đoạn dữ liệu nhận được không theo cấu trúc thường gặp, nhưng vì ta biết flag có khả năng cao sẽ được giấu ở trong đoạn dữ liệu trên, và được lưu theo từng byte (8 bits) , LSB ở trước nên ta có thể làm như sau :
    - Vì flag sẽ có định dạng `HTB{}` nên trước tiên ta tìm vị trí của đoạn dữ liệu tương ứng với các ký tự đã biết của flag, ví dụ :
      - `H`: 00010010, `T` : 00101010
    - Thật sự tồn tại đoạn như vậy trong dữ liệu nhận được:
    - 
```
00010010 H
01110
00101010 T
11110
01000010  B
011110
11011110 {
0110
00100110 d
1111110
10011110  y 
11110
01110110   n
.....
```
- Qua đoạn dữ liệu trên thì ta xác định được cách mà dữ liệu được gửi, và cũng như cách decode nó qua script. Ý tưởng cơ bản là : duyệt qua từng phần tử, nếu phát hiện chuỗi `10` thì 8 kí tự sau đó chính là 8-bit (bị đảo ngược) của dữ liệu được gửi. 

```python
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
```
![alt text](image-1.png)
