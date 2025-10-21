# ReezS
## Solution
- Ta được cung cấp 1 file thực thi .exe, nó yêu cầu chúng ta nhập flag và sau đó sẽ hiện ra kết quả (Yes hoặc No)
![image](https://hackmd.io/_uploads/B1auY7XCle.png)
- Thử disassembly bằng IDA : 

`main:`
```cpp=
int __fastcall main(int argc, const char **argv, const char **envp)

{

  __int64 v3; // rdx

  __int64 v4; // r8

  __m128i si128; // xmm0

  const char *v6; // rcx

  _BYTE v8[32]; // [rsp+0h] [rbp-58h] BYREF

  char Str[16]; // [rsp+20h] [rbp-38h] BYREF

  __m128i v10; // [rsp+30h] [rbp-28h]

  __int64 v11; // [rsp+40h] [rbp-18h]

  __int64 v12; // [rsp+48h] [rbp-10h]



  v10 = 0LL;

  *(_OWORD *)Str = 0LL;

  v11 = 0LL;

  sub_1400010F0("Enter flag: ", argv, envp);

  sub_140001170("%32s", Str);

  if ( strlen(Str) != 32 )

  {

    puts("No");

    if ( ((unsigned __int64)v8 ^ v12) == _security_cookie )

      return 0;

LABEL_5:

    __debugbreak();

  }

  si128 = _mm_load_si128((const __m128i *)&xmmword_14001E030);

  *(__m128i *)Str = _mm_xor_si128(_mm_load_si128((const __m128i *)Str), si128);

  v10 = _mm_xor_si128(si128, v10);

  if ( _mm_movemask_epi8(

         _mm_and_si128(

           _mm_cmpeq_epi8(*(__m128i *)Str, (__m128i)xmmword_140029000),

           _mm_cmpeq_epi8(v10, (__m128i)xmmword_140029010))) == 0xFFFF )

    v6 = (const char *)&unk_140023E7C; // địa chỉ của "Yes"

  else

    v6 = "No";

  sub_1400010F0(v6, v3, v4);

  if ( ((unsigned __int64)v8 ^ v12) != _security_cookie )

    goto LABEL_5;

  return 0;

}
```
- Bài này sử dụng các lệnh SIMD (SSE) để xử lý. Để tìm được flag, bạn cần đảo ngược quá trình mã hóa XOR của nó.

Đoạn code này về cơ bản thực hiện các bước sau:

1. Nhận 32 byte input từ người dùng.

2. Chia input thành 2 phần, mỗi phần 16 byte.

3. XOR mỗi phần với cùng một key 16 byte.

4. So sánh 2 phần đã mã hóa với 2 giá trị đã được hardcode sẵn trong bộ nhớ.

5. Nếu khớp, in "Yes"

- `key` ở địa chỉ : `xmmword_14001E030`
- `part1` ở địa chỉ :  `xmmword_140029000`
- `part2` ở địa chỉ :  `xmmword_140029010`


Dưới đây là python để in ra flag : 
```python=
from binascii import unhexlify, hexlify

# Dữ liệu từ file thực thi
key = unhexlify("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
encrypted1 = unhexlify("CBCCF5D9C3F5D9C3C2DEF5D3D8D8C5D9")
encrypted2 = unhexlify("8B8B8B8B8B8B8B8B8BCDCBC6CCF5CFC1")

def decrypt(data, key):
  decrypted = bytearray()
  for i in range(len(data)):
    decrypted.append(data[i] ^ key[i])
  return decrypted

# Giải mã
decrypted1 = decrypt(encrypted1, key)
decrypted2 = decrypt(encrypted2, key)

# Đảo ngược và ghép lại
part1 = decrypted1[::-1].decode()
part2 = decrypted2[::-1].decode()

flag = part1 + part2
print(f"Flag: {flag}")
# Output: Flag: sorry_this_is_fake_flag!!!!!!!!!
```
- Có vẻ đây là fake flag vì khi nhập flag này chương trình báo `No`. Nhưng khi thử debug để xem cụ thể, chương trình lại báo `Yes`, vậy vấn đề ở đâu? 
 ![image](https://hackmd.io/_uploads/H1o-hrQCll.png)
Ta xem kĩ thì thấy ở có một chỗ khác ngoài `main` xref đến địa chỉ chứa `part1` và `part2`, thử đến đó thì ta thấy hàm sau : 
![image](https://hackmd.io/_uploads/BJ-Klr7Ree.png)
- Đoạn mã này được thực thi trước khi vào hàm `main`, nó kiểm tra xem chương trình có đang trong chế độ `debug` hay không, nếu có thì thanh ghi `raz` trả về 1, còn nếu không thì thanh ghi rax trả về 0.
- Ta thử đặt breakpoint trước lệnh `cmp eax, 1` và đổi thanh ghi `rax` thành 0 để xem điều gì xảy ra:
![image](https://hackmd.io/_uploads/rkUrZH7Rxg.png)

- Quả nhiên, giá trị ở 2 phần `part1` và `part2` đã thay đổi
![image](https://hackmd.io/_uploads/BJ4BGBmCex.png)

- Thay giá trị mới vào đoạn code trên , ta có được flag 
```python=
from binascii import unhexlify, hexlify

# Dữ liệu từ file thực thi
key = unhexlify("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
encrypted1 = unhexlify("939FCF9C9B9998C99DC8C9989ECFCB9A")
encrypted2 = unhexlify("9F9D9D9DCB989A9B999A98CF9DCFCFCF")

def decrypt(data, key):
  decrypted = bytearray()
  for i in range(len(data)):
    decrypted.append(data[i] ^ key[i])
  return decrypted

# Giải mã
decrypted1 = decrypt(encrypted1, key)
decrypted2 = decrypt(encrypted2, key)

# Đảo ngược và ghép lại
part1 = decrypted1[::-1].decode()
part2 = decrypted2[::-1].decode()

flag = part1 + part2
print(f"Flag: {flag}")
# Output: Flag: 0ae42cb7c2316e59eee7e203102a7775
```


![image](https://hackmd.io/_uploads/SJaYGHm0ee.png)








