# QuickScan

**Category:** Reversing  
**Difficulty:** Easy  

## Challenge Description

You have to analyze 128 base64-encoded ELF files within 20 seconds. Each file loads a value onto the stack, and you need to send back the loaded value as a hex string.

## Analysis

When connecting to the server, we receive base64-encoded ELF files. After analyzing the binary in a disassembler, we find that:

1. The main functionality is in the `_start` function
2. Each binary follows a similar pattern:
   - Allocates 0x18 bytes of stack space
   - Uses `lea` instruction to load data address
   - Copies data to stack using `rep movsb`
   - Exits using syscall

The key is to extract the bytes that get loaded onto the stack from each binary.

## Solution

```python
from pwn import *
import tempfile
import os

# Get absolute path for temp directory
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
TEMP_DIR = os.path.join(SCRIPT_DIR, 'temp')

# Create temp directory if it doesn't exist
if not os.path.exists(TEMP_DIR):
    os.makedirs(TEMP_DIR, mode=0o777)

def get_loaded_value(e: ELF) -> bytes:
    lea_addr = e.entrypoint + 4
    lea_off = u32(e.read(lea_addr + 3, 4), sign="signed")
    target = lea_addr + 7 + lea_off
    return e.read(target, 0x18)

def do_round(r):
    r.recvuntil(b"ELF: ")
    elf_b64 = r.recvline().strip().decode()
    elf_bytes = b64d(elf_b64)
    with tempfile.NamedTemporaryFile("wb", dir=TEMP_DIR, delete=False) as f:
        f.write(elf_bytes)
        f.flush()
        temp_name = f.name
    
    try:
        with context.local(log_level='critical'):
            e = ELF(temp_name)
            value = get_loaded_value(e)
            e.close()  # Explicitly close the ELF file
    finally:
        try:
            os.unlink(temp_name)  # Delete file after we're done with it
        except:
            pass  # Ignore deletion errors
            
    r.sendlineafter(b"Bytes? ", value.hex().encode())

def main():
    r = remote("94.237.123.119",39510)
    do_round(r)  # warmup
    with log.progress("Solving binaries") as p:
        for i in range(128):
            do_round(r)
            p.status(f"Solved {i+1}/128")
    r.interactive()

if __name__ == "__main__":
    main()

```