#include <stdio.h>

struct sss{
  int i1:11;
  int i2:12;
  int i3:10;
};

static union u{
  struct sss sss;
  unsigned char a[sizeof (struct sss)];
} u;

int main (void) {
  int i;
  for (i = 0; i < sizeof (struct sss); i++)
    u.a[i] = 0;
  u.sss.i1 = 2047.0;
  for (i = 0; i < sizeof (struct sss); i++)
    printf ("%x ", u.a[i]);
  printf ("\n");
  u.sss.i2 = 4095.0;
  for (i = 0; i < sizeof (struct sss); i++)
    printf ("%x ", u.a[i]);
  printf ("\n");
  u.sss.i3 = 1023.0;
  for (i = 0; i < sizeof (struct sss); i++)
    printf ("%x ", u.a[i]);
  printf ("\n");
  return 0;
}
