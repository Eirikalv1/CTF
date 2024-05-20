#!/usr/bin/env python

from pwn import *

def getValidPadding(index):
    global iv, ct

    for i in range(256):
        new_cipher = bytes.hex(iv[:index] + bytes([i]) + iv[index+1:] + ct).encode()
        io.sendlineafter(b'> ', new_cipher)
        success = io.recvline().decode().strip()
        if success == 'ok decryption':
            return i
    print("ERROR PADDING")

io = process('./challenge.py')

io.recvuntil(b'ct=')
cipher = bytes.fromhex(io.recvline().decode())

iv = cipher[:16]
ct = cipher[16:]

d16 = 1 ^ getValidPadding(15)
p16 = d16 ^ iv[15]

iv = iv[:15] + bytes([(d16 ^ 2)])
d15 = 2 ^ getValidPadding(14)
p15 = d15 ^ iv[14]

iv = iv[:14] + bytes([(d15 ^ 3)]) + bytes([(d16 ^ 3)])
d14 = 3 ^ getValidPadding(13)
p14 = d14 ^ iv[13]

