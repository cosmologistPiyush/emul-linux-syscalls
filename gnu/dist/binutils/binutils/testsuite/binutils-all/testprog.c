/* This program is used to test objcopy, readelf and strip.  */

extern int strcmp (char *, const char *);

int common;
int global = 1;
static int local = 2;
static unsigned char string[] = "string";

int
fn ()
{
  return 3;
}

int
main ()
{
  if (common != 0
      || global != 1
      || local != 2
      || strcmp (string, "string") != 0)
    {
      printf ("failed\n");
      return (1);
    }

  printf ("ok\n");
  return (0);
}
