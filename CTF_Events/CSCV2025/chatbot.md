# Chatbot
## Solution
![image](https://hackmd.io/_uploads/SyZDMU7Cel.png)
- Ta được cung cấp 1 file `ELF`, thử chạy thì chương trình báo lỗi do không tìm thấy lib thích hợp
 ![image](https://hackmd.io/_uploads/rJN6ML7Cgg.png)
- Rất giống `PyInstaller`: file ELF là launcher (native) của `PyInstaller` — khi chạy nó giải nén một bundle vào /tmp/_ME... rồi chạy `Python` nội bộ.
- Thử dùng `strings main | grep -i "pyinstall"` ta được kết quả dưới, càng khẳng định giả thuyết này.
 ![image](https://hackmd.io/_uploads/B1WqXLXRgx.png)
- Do đó ta có thể extract nó bằng `pyinstxtractor` [https://github.com/extremecoders-re/pyinstxtractor]
- Sau khi extract ta thấy 1 file có tên `flag.enc`, có thể là 1 file chứa flag đã bị encode. 
![image](https://hackmd.io/_uploads/SJVpVLmAex.png)
- Bước tiếp theo là decompile `main.pyc` để xem cụ thể chương trình đã làm gì. Chúng ta có thể dùng [https://pylingual.io/] để decompile .
`main:`
```python=
# Decompiled with PyLingual (https://pylingual.io)
# Internal filename: main.py
# Bytecode version: 3.11a7e (3495)
# Source timestamp: 1970-01-01 00:00:00 UTC (0)
import base64
import json
import time
import random
import sys
import os
from ctypes import CDLL, c_char_p, c_int, c_void_p
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
import ctypes

def get_resource_path(name):
    if getattr(sys, 'frozen', False):
        base = sys._MEIPASS
    else:  # inserted
        base = os.path.dirname(__file__)
    return os.path.join(base, name)

def load_native_lib(name):
    return CDLL(get_resource_path(name))
if sys.platform == 'win32':
    LIBNAME = 'libnative.dll'
else:  # inserted
    LIBNAME = 'libnative.so'
lib = None
check_integrity = None
decrypt_flag_file = None
free_mem = None
try:
    lib = load_native_lib(LIBNAME)
    check_integrity = lib.check_integrity
    check_integrity.argtypes = [c_char_p]
    check_integrity.restype = c_int
    decrypt_flag_file = lib.decrypt_flag_file
    decrypt_flag_file.argtypes = [c_char_p]
    decrypt_flag_file.restype = c_void_p
    free_mem = lib.free_mem
    free_mem.argtypes = [c_void_p]
    free_mem.restype = None
except Exception as e:
    print('Warning: native lib not loaded:', e)
    lib = None
    check_integrity = None
    decrypt_flag_file = None
    free_mem = None

def run_integrity_or_exit():
    if check_integrity:
        ok = check_integrity(sys.executable.encode())
        if not ok:
            print('[!] Integrity failed or debugger detected. Exiting.')
            sys.exit(1)
PUB_PEM = b'-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsJftFGJC6RjAC54aMncA\nfjb2xXeRECiwHuz2wC6QynDd93/7XIrqTObeTpfBCSpOKRLhks6/nzZFTTsYdQCj\n4roXhWo5lFfH0OTL+164VoKnmUkQ9dppzpmV0Kpk5IQhEyuPYzJfFAlafcHdQvUo\nidkqcOPpR7hznJPEuRbPxJod34Bph/u9vePKcQQfe+/l/nn02nbfYWTuGtuEdpHq\nMkktl4WpB50/a5ZqYkW4z0zjFCY5LIPE7mpUNLrZnadBGIaLoVV2lZEBdLt6iLkV\nHXIr+xNA9ysE304T0JJ/DwM1OXb4yVrtawbFLBu9otOC+Gu0Set+8OjfQvJ+tlT/\nzQIDAQAB\n-----END PUBLIC KEY-----'
public_key = None
try:
    pub_path = get_resource_path('public.pem')
    if os.path.exists(pub_path):
        with open(pub_path, 'rb') as f:
            public_key = serialization.load_pem_public_key(f.read())
    else:  # inserted
        public_key = serialization.load_pem_public_key(PUB_PEM)
except Exception as e:
            print('Failed loading public key:', e)
            public_key = None

def b64url_encode(b):
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode()

def b64url_decode(s):
    s = s | ('=', 4, len(s) - 4) | 4
    return base64.urlsafe_b64decode(s.encode())

def verify_token(token):
    if not public_key:
        return (False, 'no public key')
    try:
        payload_b64, sig_b64 = token.strip().split('.', 1)
        payload = b64url_decode(payload_b64)
        sig = b64url_decode(sig_b64)
        public_key.verify(sig, payload, padding.PKCS1v15(), hashes.SHA256())
        j = json.loads(payload.decode())
        if j.get('role')!= 'VIP':
            return (False, 'role != VIP')
        if j.get('expiry', 0) < int(time.time()):
            return (False, 'expired')
    else:  # inserted
        return (True, j)
    except Exception as e:
            return (False, str(e))

def sample_token_nonvip():
    payload = json.dumps({'user': 'guest', 'expiry': int(time.time()) + 3600, 'role': 'USER'}).encode()
    return b64url_encode(payload)

def main():
    run_integrity_or_exit()
    print('=== Bot Chat === \n    1.chat\n    2.showtoken\n    3.upgrade \n    4.quit')
    queries = 0
    while True:
        cmd = input('> ').strip().lower()
        if cmd in ['quit', 'exit']:
            return
        if cmd == 'chat':
            if queries < 3:
                print(random.choice(['Hi', 'Demo AI', 'Hello!', 'How can I assist you?', 'I am a chatbot', 'What do you want?', 'Tell me more', 'Interesting', 'Go on...', 'SIUUUUUUU', 'I LOVE U', 'HACK TO LEARN NOT LEARN TO HACK']))
                queries = queries | 1
            else:  # inserted
                print('Free queries exhausted. Use \'upgrade\'')
        else:  # inserted
            if cmd == 'showtoken':
                print('Token current:' + sample_token_nonvip())
            else:  # inserted
                if cmd == 'upgrade':
                    run_integrity_or_exit()
                    token = input('Paste token: ').strip()
                    ok, info = verify_token(token)
                    if ok:
                        if decrypt_flag_file is None:
                            print('Native library not available -> cannot decrypt')
                        else:  # inserted
                            flag_path = get_resource_path('flag.enc').encode()
                            res_ptr = decrypt_flag_file(flag_path)
                            if not res_ptr:
                                print('Native failed to decrypt or error')
                            else:  # inserted
                                flag_bytes = ctypes.string_at(res_ptr)
                                try:
                                    flag = flag_bytes.decode(errors='ignore')
                                except:
                                    flag = flag_bytes.decode('utf-8', errors='replace')
                                print('=== VIP VERIFIED ===')
                                print(flag)
                                free_mem(res_ptr)
                        return None
                    print('Token invalid:', info)
                else:  # inserted
                    print('Unknown. Use chat/showtoken/upgrade/quit')
if __name__ == '__main__':
    main()
```

- Ta thấy có hàm`decrypt_flag_file` trong `libnative.so`. Thử dùng IDA decompile `libnative.so` để xem hàm decrypt flag:
![image](https://hackmd.io/_uploads/H15Wn8mAge.png)
Dựa trên function trên, ta có viết script python để tương đương decode flag. Dưới đây là code python tham khảo (các bạn có thể tìm cách khác để chạy trực tiếp hàm decrypt flag từ thư viện đã cho mà không cần viết lại):
```python=
#!/usr/bin/env python3
"""
recover_and_decrypt.py

Usage:
  python3 recover_and_decrypt.py /path/to/libnative.so /path/to/flag.enc

This script:
- attempts to recover key using the logic from recover_key (result[0]=0xC4; result[i]=OBF_KEY[i] ^ MASK[i&3])
- tries multiple strategies to read OBF_KEY and MASK from the shared object
- decrypts flag.enc (IV = first 16 bytes, rest is ciphertext) using AES-128-CBC or AES-256-CBC depending on key length
"""
import sys, os, ctypes, subprocess, struct
from ctypes import c_ubyte, c_void_p
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

def die(msg):
    print("[!] " + msg)
    sys.exit(1)

def load_lib(path):
    try:
        return ctypes.CDLL(path, mode=ctypes.RTLD_GLOBAL)
    except Exception as e:
        die(f"Failed to load library {path}: {e}")

def try_read_symbols_via_ctypes(lib):
    # Try to read arrays by name using ctypes .in_dll
    # OBF_KEY expected at least 32 bytes, MASK expected 4 bytes
    try:
        OBF_KEY = (c_ubyte * 32).in_dll(lib, "OBF_KEY")
        MASK = (c_ubyte * 4).in_dll(lib, "MASK")
        return bytes(OBF_KEY[:]), bytes(MASK[:])
    except Exception:
        return None, None

def find_symbol_address_readelf(so_path, symname):
    # Use readelf -s to find symbol address (if present in dynamic symbol table)
    try:
        out = subprocess.check_output(["readelf", "-sW", so_path], text=True, stderr=subprocess.DEVNULL)
    except Exception:
        return None
    for line in out.splitlines():
        # lines like:    123: 0000000000000abc    32 OBJECT  GLOBAL DEFAULT   16 OBF_KEY
        parts = line.split()
        if len(parts) >= 8 and parts[-1] == symname:
            # address at parts[1]
            addr_str = parts[1]
            try:
                return int(addr_str, 16)
            except:
                return None
    return None

def read_bytes_from_file_at_vaddr(so_path, vaddr, size):
    # Read raw bytes from file at given virtual address requires parsing ELF program headers to map vaddr->file offset.
    # We'll use readelf -l to get PT_LOAD segments and compute offset.
    try:
        ph = subprocess.check_output(["readelf", "-lW", so_path], text=True)
    except Exception as e:
        die("readelf not available or failed: " + str(e))
    segs = []
    for line in ph.splitlines():
        line = line.strip()
        # find lines contain 'LOAD' segments info like:
        #  Type           Offset   VirtAddr           PhysAddr           FileSiz  MemSiz   Flags Align
        #  LOAD           0x000000 0x0000000000000000 0x0000000000000000 0x000120 0x000120 R E 0x200000
        if line.startswith("LOAD"):
            parts = line.split()
            # attempt to parse, some lines wrap; safer to parse blocks: use readelf program headers parsing previously
    # fallback simple heuristic: use objdump -s to dump section contents and search for symbol bytes by name - not reliable
    die("Symbol-to-file-offset mapping not implemented. Falling back to 'strings' method.")
    return None

def try_find_arrays_via_nm(so_path):
    # Try to use nm -D (dynamic symbols) or nm (if available) to see symbol table
    try:
        out = subprocess.check_output(["nm", "-D", so_path], text=True, stderr=subprocess.DEVNULL)
    except Exception:
        try:
            out = subprocess.check_output(["nm", so_path], text=True, stderr=subprocess.DEVNULL)
        except Exception:
            return None, None
    obf_addr = None
    mask_addr = None
    for line in out.splitlines():
        parts = line.strip().split()
        if len(parts) >= 3:
            addr, symtype, name = parts[0], parts[1], parts[2]
            if name == "OBF_KEY":
                try:
                    obf_addr = int(addr, 16)
                except:
                    obf_addr = None
            if name == "MASK":
                try:
                    mask_addr = int(addr, 16)
                except:
                    mask_addr = None
    return obf_addr, mask_addr

def construct_key_from_obf_mask(obf_bytes, mask_bytes):
    if len(obf_bytes) < 32 or len(mask_bytes) < 4:
        die("OBF_KEY or MASK too short")
    key = bytearray(32)
    # result[0] = -60  (signed) -> unsigned 0xC4
    key[0] = (256 - 60) & 0xFF  # 0xC4
    for i in range(1, 32):
        key[i] = obf_bytes[i] ^ mask_bytes[i & 3]
    return bytes(key)

def decrypt_flag(flag_path, key):
    data = open(flag_path, "rb").read()
    if len(data) <= 16:
        die("flag.enc too short")
    iv = data[:16]
    ct = data[16:]
    if len(key) >= 32:
        k = key[:32]
        print("[*] Using AES-256-CBC")
    else:
        k = key[:16]
        print("[*] Using AES-128-CBC")
    cipher = Cipher(algorithms.AES(k), modes.CBC(iv))
    dec = cipher.decryptor()
    pt_padded = dec.update(ct) + dec.finalize()
    # unpad PKCS7
    unpad = padding.PKCS7(128).unpadder()
    try:
        pt = unpad.update(pt_padded) + unpad.finalize()
    except Exception as e:
        print("[!] PKCS7 unpad failed:", e)
        pt = pt_padded
    return pt

def main():
    if len(sys.argv) < 3:
        print("Usage: recover_and_decrypt.py /path/to/libnative.so /path/to/flag.enc")
        sys.exit(1)
    so = sys.argv[1]
    flag = sys.argv[2]
    if not os.path.exists(so):
        die("lib not found: " + so)
    if not os.path.exists(flag):
        die("flag.enc not found: " + flag)

    print("[*] Loading library and trying to read OBF_KEY and MASK via ctypes...")
    lib = load_lib(so)
    obf, mask = try_read_symbols_via_ctypes(lib)
    if obf and mask:
        print("[+] Read OBF_KEY and MASK via ctypes")
        key = construct_key_from_obf_mask(obf, mask)
        pt = decrypt_flag(flag, key)
        print("\n=== PLAINTEXT ===\n")
        try:
            print(pt.decode('utf-8'))
        except:
            print(pt)
        print("\n=== HEX ===\n", pt.hex())
        return

    print("[*] ctypes read failed. Trying nm/readelf heuristics to find symbols (if not stripped)...")
    obf_addr, mask_addr = try_find_arrays_via_nm(so)
    if obf_addr and mask_addr:
        print("[+] Found addresses via nm:", hex(obf_addr), hex(mask_addr))
        print("[!] NOTE: reading from addresses in file requires mapping vaddr -> file offset. If you want, run the next command:")
        print("    readelf -sW", so, "| egrep 'OBF_KEY|MASK'")
        die("Symbol addresses discovered; please run readelf -sW and provide the symbol addresses output if you want me to continue.")
    else:
        print("[!] Could not find dynamic symbols OBF_KEY/MASK. The library may be stripped.")
        print("Two options:")
        print("  1) If you can provide the bytes of OBF_KEY (32 bytes) and MASK (4 bytes),")
        print("     I can compute the key and decrypt immediately.")
        print("  2) I can try to search the .so for likely arrays: run")
        print("     strings -a -t x", so, "| egrep -i 'OBF|MASK|flag|VIP' ;")
        print("     hexdump -C", so, "| head -n 200")
        print("Please paste the outputs here and I'll locate OBF_KEY/MASK offsets for you.")
        sys.exit(2)

if __name__ == '__main__':
    main()
```
![image](https://hackmd.io/_uploads/HJPD2L7Alx.png)
Flag : `CSCV2025{reversed_vip*_chatbot_bypassed}`