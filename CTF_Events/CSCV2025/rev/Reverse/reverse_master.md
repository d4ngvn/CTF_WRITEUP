# Reverse Master
## Solution
- Ta được cung cấp 1 file .apk, trước tiên ta thử dùng `jadx-gui` để decompile : 
![image](https://hackmd.io/_uploads/SyToABQRex.png)

`MainActivity:` (đã rút gọn để dễ nhìn)
```java=
public class FlagLogicSummary {

    // 1. Khóa XOR cho nửa đầu của flag.
    public final byte[] xorKey = {66, 51, 122, 33, 86};

    // 2. Tên thư viện native chứa logic cho nửa sau.
    static {
        // Tên thư viện cần phân tích là "libnative-lib.so"
        System.loadLibrary("native-lib");
    }

    // 3. Hàm native sẽ được gọi để kiểm tra nửa sau.

    // Java_com_ctf_challenge_MainActivity_checkSecondHalf
    public final native boolean checkSecondHalf(String str);

    // 4. Logic xác thực flag (trích từ OnClickListener).
    public void validateFlag(String userInput) {
        // Kiểm tra định dạng cơ bản
        if (!userInput.startsWith("CSCV2025{") || !userInput.endsWith("}")) {
            return; // Sai định dạng
        }

        // Tách lấy nội dung flag bên trong dấu {}
        String flagContent = userInput.substring(9, userInput.length() - 1);
        
        // --- Bắt đầu xác thực nửa đầu (16 ký tự) ---

        // Dữ liệu đã mã hóa của nửa đầu được hardcode trong app.
        byte[] encryptedFirstHalf = {122, 86, 27, 22, 53, 35, 80, 77, 24, 98, 122, 7, 72, 21, 98, 114};
        byte[] decryptedBytes = new byte[16];

        // Vòng lặp giải mã bằng thuật toán repeating-key XOR.
        for (int i = 0; i < 16; i++) {
            decryptedBytes[i] = (byte) (encryptedFirstHalf[i] ^ xorKey[i % xorKey.length]);
        }
        
        String correctFirstHalf = new String(decryptedBytes);
        String inputFirstHalf = flagContent.substring(0, 16);

        // So sánh nửa đầu người dùng nhập với kết quả giải mã.
        if (!inputFirstHalf.equals(correctFirstHalf)) {
            return; // Nửa đầu sai
        }

        // --- Bắt đầu xác thực nửa sau ---
        
        // Nửa sau của nội dung flag được truyền vào hàm native.
        String inputSecondHalf = flagContent.substring(16);
        boolean isSecondHalfCorrect = checkSecondHalf(inputSecondHalf);

        if (isSecondHalfCorrect) {
            // 🎉 Flag chính xác!
        }
    }
}

```
- Ta có thể dễ dàng tìm được part1 của flag qua đoạn code python XOR đơn giản sau : 
```python=
encrypted_half = [122, 86, 27, 22, 53, 35, 80, 77, 24, 98, 122, 7, 72, 21, 98, 114]
key = [66, 51, 122, 33, 86]

decrypted_half = ""
for i in range(len(encrypted_half)):
    decrypted_byte = encrypted_half[i] ^ key[i % len(key)]
    decrypted_half += chr(decrypted_byte)

print(f"Nửa đầu của flag là: {decrypted_half}")
#output : 8ea7cac794842440
```

- Để tìm part2 của flag, ta cần phải xem được hàm `checkSecondHalf` từ thư viện `libnative-lib.so`
- Trước tiên ta extract file apk ra , có thể dùng `apktool` với command sau trên window `java -jar .\apktool.jar d -f   reverse-master.apk
- Sau đó ta tìm được thu viện `libnative-lib.so` tại `reverse-master\lib\arm64-v8a`
![image](https://hackmd.io/_uploads/S1tZlLm0gl.png)

- Sau đó ta dùng IDA để decompile nó và tìm hàm tương ứng.
![image](https://hackmd.io/_uploads/rJWKl87Rgg.png)

```cpp=
bool __fastcall Java_com_ctf_challenge_MainActivity_checkSecondHalf(__int64 a1, __int64 a2, __int64 a3)
{
  const char *v6; // x0
  const char *v7; // x21
  unsigned int v8; // w22
  __int64 v9; // x0
  int v10; // w22
  __int64 v11; // x0
  int v12; // [xsp+8h] [xbp-8h]
  int v13; // [xsp+8h] [xbp-8h]
  int v14; // [xsp+8h] [xbp-8h]
  int v15; // [xsp+8h] [xbp-8h]
  int v16; // [xsp+8h] [xbp-8h]
  int v17; // [xsp+Ch] [xbp-4h]
  int v18; // [xsp+Ch] [xbp-4h]
  int v19; // [xsp+Ch] [xbp-4h]
  int v20; // [xsp+Ch] [xbp-4h]
  int v21; // [xsp+Ch] [xbp-4h]

  if ( (sub_19CA0() & 1) != 0 )
  {
    __android_log_print(4, "Lib-Native", "Debugger detected in native code!");
    return 0LL;
  }
  else
  {
    v6 = (const char *)(*(__int64 (__fastcall **)(__int64, __int64, _QWORD))(*(_QWORD *)a1 + 1352LL))(a1, a3, 0LL);
    if ( v6 )
    {
      v7 = v6;
      v8 = strlen(v6);
      v17 = rand() % 50 + 1;
      v12 = rand() % 50 + 1;
      if ( v17 * v17 + v12 * v12 == (v12 + v17) * (v12 + v17) - 2 * v17 * v12 + 1 )
      {
        v9 = sub_1AC60(v7);
        sub_1ACCC(v9);
      }
      v18 = rand() % 100;
      v13 = rand() % 100;
      if ( (v13 + v18) * (v13 + v18) >= v18 * v18 + v13 * v13 )
      {
        v10 = sub_1AD68(v7, v8);
        v19 = rand() % 50 + 1;
        v14 = rand() % 50 + 1;
        if ( v19 * v19 + v14 * v14 == (v14 + v19) * (v14 + v19) - 2 * v19 * v14 + 1 )
        {
          v11 = sub_1B5E8(v7);
          sub_1B658(v11);
        }
      }
      else
      {
        v10 = 0;
      }
      (*(void (__fastcall **)(__int64, __int64, const char *))(*(_QWORD *)a1 + 1360LL))(a1, a3, v7);
      if ( v10 && (v20 = rand() % 100, v15 = rand() % 100, (v15 + v20) * (v15 + v20) >= v20 * v20 + v15 * v15) )
      {
        return 1LL;
      }
      else
      {
        v21 = rand() % 50 + 1;
        v16 = rand() % 50 + 1;
        return v21 * v21 + v16 * v16 == (v16 + v21) * (v16 + v21) - 2 * v21 * v16 + 1;
      }
    }
    else
    {
      rand();
      rand();
      return 0LL;
    }
  }
}
```
- Hàm check part2 của flag khá là phức tạp so với part1. Dưới đây là đoạn code python để tìm ra part 2 
```python=
# Mô phỏng đúng phép biến đổi trong `sub_1AD68` và in ra key 16-byte (ASCII)
# Chạy bằng python (đã thực thi trong môi trường máy chủ của ChatGPT để xác minh).
def to_u8(x): return x & 0xFF

# Các giá trị hằng như trong pseudo code
v7 = 99      # 0x63
v8 = 125     # 0x7D
v9 = (-30) & 0xFF  # as unsigned byte -> 226 (0xE2)
v10 = 20
v11 = (-72) & 0xFF # -> 184 (0xB8)

# v5: 5 bytes, first 4 bytes = -1206590851 as little-endian dword, v5[4] = 99
dword = (-1206590851) & 0xFFFFFFFF
v5 = [ (dword >> (8*i)) & 0xFF for i in range(4) ] + [99]

v21 = v5[0]
v20 = v5[1]
v22 = v5[2]
v23 = v5[3]
v24 = v5[4]

# Tạo v17 (8 bytes) theo pseudo code
v17 = [0]*8
v17[0] = to_u8(v8 ^ 4)
v17[1] = to_u8(v9 | 5)
v17[2] = to_u8(v10 ^ 6)
v17[3] = to_u8(v11 | 7)
v17[4] = to_u8(v7 | 8)
v17[5] = to_u8(v8 ^ 9)
v17[6] = to_u8(v9 ^ 0xA)
v17[7] = to_u8(v10 | 0xB)

v15 = v9
v16 = v10 | 1
v18 = to_u8((v7 ^ 0x74) - 19)
v19 = to_u8(v7 ^ 0xD)

# Khởi tạo v3 (16 bytes) và gán các ô theo pseudo code
v3 = [0]*16
v3[1]  = to_u8(((v15 ^ 0x6C) - 10) ^ v20)
v3[0]  = to_u8(((v8 ^ 0x2F) - 7) ^ v21)
v3[2]  = to_u8(((v16 ^ 0x95) - 13) ^ v22 ^ 2)
v3[13] = to_u8(((v11 ^ 8) - 46) ^ v23 ^ 0xD)
v3[4]  = to_u8(v18 ^ v24 ^ 4)
v3[15] = to_u8(((v8 ^ 7) - 52) ^ v21 ^ 0xF)
v3[3]  = to_u8((((v11 | 2) ^ 0x21) - 16) ^ v23)
v3[14] = to_u8(((v19 ^ 0x57) - 49) ^ v24 ^ 0xE)

# Tạo v6 (16 bytes) như trong pseudo code (chỉ set các chỉ số được dùng)
v6 = [0]*16
v6[0] = v21; v6[1] = v20; v6[2] = v22; v6[3] = v23; v6[4] = v24
v6[8] = v21; v6[9] = v20; v6[10] = v22; v6[11] = v23; v6[12] = v24

# Bây giờ tính v25 = veor( veor( vadd( veor(v17, const1), const2), const3), shuffle(v6, idxs) )
# Các hằng từ pseudo code (8-byte little-endian)
def bytes_le(val):
    return [(val >> (8*i)) & 0xFF for i in range(8)]

const1 = bytes_le(0x53E81E454D2E4748)
const2 = bytes_le(0xD5D8DBDEE1E4E7EA)
const3 = bytes_le(0x0C0B0A0908070605)  # nguyên gốc trong pseudo thiếu 1 chữ số; dùng 0x0C... cho đầy đủ 8 bytes

# Áp dụng veor, vadd, veor (mỗi phần toán theo byte, wrap-around 8-bit)
veor1 = [ to_u8(v17[i] ^ const1[i]) for i in range(8) ]
vadd  = [ to_u8((veor1[i] + const2[i])) for i in range(8) ]
veor2 = [ to_u8(vadd[i] ^ const3[i]) for i in range(8) ]

# Mô phỏng vqtbl1_s8(v6, idxs) với chỉ số immediate 0x201000403020100 (lấy 8 bytes little-endian)
idxs_val = 0x0201000403020100  # giá trị little-endian tương ứng với immediate trong pseudo
idxs = [ (idxs_val >> (8*i)) & 0xFF for i in range(8) ]

def vqtbl1_s8(table16, idx8):
    # Nếu idx >= 16 => result byte = 0, theo behavior của vqtbl (out-of-range -> zero)
    res = []
    for idx in idx8:
        res.append(table16[idx] if idx < 16 else 0)
    return res

tbl_res = vqtbl1_s8(v6, idxs)

# veor final
v25_bytes = [ to_u8(veor2[i] ^ tbl_res[i]) for i in range(8) ]

# BYTE3(v25) -- BYTE3 little-endian is the 4th byte (index 3)
v30 = v25_bytes[3]

# store v25 into v3[5..12] as 8 bytes little-endian starting at offset 5
for i in range(8):
    if 5 + i < 16:
        v3[5 + i] = v25_bytes[i]

v29 = v30

# kết quả: v3[0..15] và v29
key_bytes = bytes(v3)
print("v3 bytes:", key_bytes)
try:
    print("v3 as ascii:", key_bytes.decode('ascii'))
except UnicodeDecodeError:
    print("v3 ascii-safe:", ''.join(f"\\x{b:02x}" for b in key_bytes))
print("v29 (byte 8): 0x%02x" % v29)
# If the expected input is 16 ASCII chars, assemble full 16-byte expected input a1:
# In pseudo, comparison used v29 ^ a1[8], meaning a1[8] matches v29.
# So expected input (16 bytes) is v3[0..7] + [v29] + v3[9..15]
expected = bytearray(16)
for i in range(16):
    if i < 8:
        expected[i] = v3[i]
    elif i == 8:
        expected[i] = v29
    else:
        expected[i] = v3[i]
print("Expected 16-byte input (hex):", expected.hex())
try:
    print("Expected ASCII:", expected.decode('ascii'))
except:
    print("Expected ASCII-safe:", ''.join(f"\\x{b:02x}" for b in expected))
#output : 6fe3ccc3cf2197e4
```
Kết hợp cả 2 phần lại ta có flag là : `CSCV2025{8ea7cac7948424406fe3ccc3cf2197e4}`
