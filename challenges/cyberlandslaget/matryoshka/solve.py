import gdb

gdb.execute("b *0x000000000040103b")
gdb.execute("run")

chars = []
while True:
    chars.append(gdb.execute("disass $rip,+2", to_string=True).split()[-5][3:])
    address = int(gdb.execute("info reg r12", to_string=True).split()[-2][:-2] + "3b", 16)
    rcx = str(hex(int(gdb.execute("info reg rcx", to_string=True).split()[-1])-1))
    gdb.execute("c " + rcx)

    gdb.execute("b *" + str(hex(address)))
    gdb.execute("c")
    print(''.join(list(map(lambda x: chr(int(x, 16)), chars))))
    