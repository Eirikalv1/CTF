#!/usr/bin/env python

from pwn import *

def getValidPadding(index, iv, ct):
    for i in range(256):
        new_iv = iv[:index] + bytes([i]) + iv[index+1:]
        new_cipher = (bytes(new_iv) + ct).hex().encode()
        io.sendlineafter(b'> ', new_cipher)
        success = io.recvline().decode().strip()
        if success == 'ok decryption':
            return i
    print("ERROR PADDING")
    return None

def decrypt_block(iv, ct_block, last_block=False):
    plaintext_block = bytearray(16)
    intermediate_state = bytearray(16)
    
    if not last_block:
        # Regular decryption for all blocks except the last one
        for index in range(15, -1, -1):
            padding_value = 16 - index
            modified_iv = bytearray(iv)
            
            # Modify the IV for the current padding
            for j in range(15, index, -1):
                modified_iv[j] = intermediate_state[j] ^ padding_value
            
            valid_byte = getValidPadding(index, modified_iv, ct_block)
            if valid_byte is None:
                return None
            
            intermediate_state[index] = valid_byte ^ padding_value
            plaintext_block[index] = intermediate_state[index] ^ iv[index]
            print(plaintext_block)
    else:
        # Decryption for the last block
        for index in range(15, 14, -1):
            padding_value = 16 - index
            valid_byte = getValidPadding(index, iv, ct_block)
            if valid_byte is None:
                return None
            plaintext_block[index] = valid_byte ^ padding_value ^ iv[index]
        
        # Calculate the last byte directly from padding
        padding_value = 16
        valid_byte = getValidPadding(15, iv, ct_block)
        if valid_byte is None:
            return None
        plaintext_block[15] = valid_byte ^ padding_value ^ iv[15]
        print(plaintext_block)
    
    return plaintext_block


io = remote('eirikalv-e3675dad946f-paddyspaddingvalidator.ept.gg', 1337, ssl=True)
#io = process('./challenge.py')

io.recvuntil(b'ct=')
cipher = bytes.fromhex(io.recvline().decode().strip())

iv = cipher[:16]
ciphertext_blocks = [cipher[i:i+16] for i in range(16, len(cipher), 16)]

plaintext = bytearray()

for ct_block in ciphertext_blocks:
    plaintext_block = decrypt_block(iv, ct_block)
    if plaintext_block is None:
        print("Decryption failed for a block")
        exit(1)
    plaintext.extend(plaintext_block)
    iv = ct_block  # The previous ciphertext block becomes the IV for the next block

print(plaintext.decode('utf-8', errors='ignore'))
