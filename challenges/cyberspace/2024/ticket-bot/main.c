#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
  for (int i = 0; i < 10000000; ++i) {
    srand(i);
    int rand1 = rand();
    int rand2 = rand();

    if (rand2 == atoi(argv[1])) {
      printf("%i", rand1);
    }
  }

  return 0;
}