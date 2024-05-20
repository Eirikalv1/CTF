from pwn import *

def get_correct_amount(encrypted_msg: bytes):
    global encrypted_flag
    corrects = 0
    assert len(encrypted_flag) == len(encrypted_msg)
    for c1, c2 in zip(encrypted_msg, encrypted_flag):
        if c1 == c2:
            corrects += 1
    return corrects

def encrypt(msg: bytes):
    global io
    io.sendlineafter(b'>', b'1')
    io.sendlineafter(b': ', msg)
    return io.recvline().strip()

def oracle():
    global io, encrypted_flag, msg, correct_characters

    for i in range(0, len(encrypted_flag), 2):
        for c in range(33, 126):
            new = msg[:i] + hex(c)[2:].encode() + msg[i+2:]

            if get_correct_amount(encrypt(new)) > correct_characters:
                msg = new
                correct_characters = 
        

io = remote('chal.amt.rs', 1414)

io.sendlineafter(b'>', b'2')
encrypted_flag = io.recvline().strip()# Length 170
msg = b'aa' * 85
flag = b'aa' * 85
correct_characters = get_correct_amount(msg)

oracle()