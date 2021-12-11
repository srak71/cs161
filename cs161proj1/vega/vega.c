
void flip(char *buf, const char *input)
{
  size_t n = strlen(input);
  int i;
  for (i = 0; i < n && i <= 64; ++i)
    buf[i] = input[i] ^ 0x20;

  while (i < 64)
    buf[i++] = '\0';
}


So we have a off by one vulnerability. In the for loop in flip, the program iterates through 65 indices of the buffer,
when the buffer is only 64 bytes large. 
