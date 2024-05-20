#!/usr/bin/env python

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os

secret = open("flag.txt", "rb").read()

def decrypt(key,ct):
    iv = ct[0:16]
    ct = ct[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), 16)

def encrypt(key,pt):
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(pad(pt, 16))

def Challenge(): 
    key = os.urandom(16)
    ct = encrypt(key, secret)
    print(f"Welcome to Paddy's Padding Validator. You can validate if your decrypted message's padding is correct, or not.")
    print(f"ct={ct.hex()}")
    while True:
        try:
            inp = input("encrypted secret (hex)> ")
            if inp == '0': break
            ct = bytes.fromhex(inp)
            decrypt(key, ct)
            print("ok decryption")
        except:
            print("error")

if __name__ == "__main__":
    try:
        Challenge()
    except Exception:
        print("error")
        exit(0)
