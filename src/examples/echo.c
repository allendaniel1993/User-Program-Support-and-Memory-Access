#include <stdio.h>
#include <syscall.h>

int
main (int argc, char **argv)
{
  char buf;
  read (STDOUT_FILENO, &buf, 1);
  return EXIT_SUCCESS;
}
