#include <stdio.h>

static struct sss{
  long f;
  long long :0;
  int i;
} sss;

#define _offsetof(st,f) ((char *)&((st *) 16)->f - (char *) 16)

int main (void) {
  printf ("+++longlong zerofield inside struct starting with long:\n");
  printf ("size=%d,align=%d\n", sizeof (sss), __alignof__ (sss));
  printf ("offset-long=%d,offset-last=%d,\nalign-long=%d,align-last=%d\n",
          _offsetof (struct sss, f), _offsetof (struct sss, i),
          __alignof__ (sss.f), __alignof__ (sss.i));
  return 0;
}
