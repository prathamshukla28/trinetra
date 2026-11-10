/* Benchmark fixture: a tiny program with a stack buffer and libc string /
 * process calls, compiled several ways (canary on/off, signed/unsigned, PIE
 * on/off, executable stack) to give the binary checks known variety. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
  char buf[64];
  if (argc > 1) {
    strcpy(buf, argv[1]);
    puts(buf);
  }
  if (argc > 2) return system(argv[2]);
  return 0;
}
