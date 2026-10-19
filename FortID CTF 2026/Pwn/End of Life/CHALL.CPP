// Built using Borland C++ 3.0 -- still the best IDE produced by humankind.
// https://winworldpc.com/download/52dfb385-9ba2-11e9-ab10-fa163e9022f0
//
// bcc -v CHALL.CPP 
//

#include <stdio.h>
#include <string.h>

const int MAXLENGTH = 16;

int check_input() {
  FILE *input = fopen("input.txt", "rt");
  if (!input) {
    return 0;
  }

  int c;
  int length = 0;
  while ((c = fgetc(input)) != EOF) {
    if (c < 'a' || c > 'z' || length >= MAXLENGTH) {
      fclose(input);
      return 0;
    }
    ++length;
  }

  fclose(input);
  return length > 0;
}

void process_input() {
  char name[MAXLENGTH + 1];

  FILE *input = fopen("input.txt", "rb");
  FILE *output = fopen("output.txt", "wb");
  fscanf(input, "%[^ ]s", name);
  fprintf(output, "%d\n", strlen(name));
  
  fclose(input);
  fclose(output);

  return;
}

int main() {
  
  if (!check_input()) {
    printf("Invalid input file!");
    return 1;
  }
  process_input();
  
  return 0;
}
