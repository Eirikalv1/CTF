#!/usr/bin/env python
import ctypes
import sys
import platform

def read_from_memory_address(addr):
    # read uint64 from <addr>        
    assert addr >= 0 and addr < 2**64
    val = int(ctypes.c_uint64.from_address(addr).value)
    print(f'0x{addr.to_bytes(8,"big").hex()}: {val.to_bytes(8,"little").hex()}')   

def write_to_memory(addr,byte):
    # write uint8 to <addr>    
    assert addr >= 0 and addr < 2**64
    assert byte >= 0 and byte <= 0xff
    val = ctypes.c_uint8.from_address(addr)
    val.value = byte
    print(f'byte written to 0x{addr.to_bytes(6,"big").hex()}: {val.value.to_bytes(1, "big").hex()}')

def flagfunc():
    x = False
    if x == True:
        print("unreachable code!")
        print(open("flag.txt","rb").read().decode())
    else:
        print("no flags here")

def Challenge():
    print(platform.python_implementation(), sys.version.replace("\n", " "))

    print("pypwn onebyte: you are allowed to write just one byte, can we reach the unreachable code?")
    
    print(f"id={hex(id(flagfunc))}")
    for _ in range(200):
        try:
            addr = int(input("read from memory address: "), 16)
            read_from_memory_address(addr)
        except Exception:
            # you can break the loop by sending an illegal memory address            
            break
    else:
         print("if you need to read that much memory you are doing something wrong.")
         quit()

    # write one byte, then flagfunc() will execute
    addr = int(input("write to memory address: "), 16)
    byte = int(input("> write byte: "), 16)
    write_to_memory(addr, byte)
    flagfunc()

if __name__ == "__main__":    
    try:
        Challenge()
    except Exception:
        print("error")
        exit(0)


"""
You can interact with this file locally by running this script.

    from pwn import process
    io = process(["python","./source.py"])
    io.interactive()

You can also use the read and write to memory locally like this:

>>> from source import read_from_memory_address, write_to_memory
>>> s = "hello world"
>>> addr = id(s)
>>> read_from_memory_address(addr)
0x00007f6f06f956b0: 0100000000000000
>>> write_to_memory(addr, 0x41)
byte written to 0x7f6f06f956b0: 41
>>> read_from_memory_address(addr)
0x00007f6f06f956b0: 4100000000000000
"""