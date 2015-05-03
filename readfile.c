#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>

#define BUFFER_SIZE 1
#define MAX_TOKEN_LEN 128

size_t do_read(char *filename) {
  char buffer[BUFFER_SIZE];
  size_t total_read = 0, chars_read;
  int fh = open(filename,O_RDONLY);
  if( fh >= 0 ) {
    while( (chars_read = read(fh, buffer, BUFFER_SIZE)) > 0 )
      total_read += chars_read;
    close(fh);
  } else {
    total_read = -1;
  }
  return total_read;
}

size_t do_fread(char *filename) {
  char buffer[BUFFER_SIZE];
  size_t total_read = 0, chars_read;
  FILE *fp = fopen(filename, "rb");
  if( fp != NULL ) {
    while( (chars_read = fread(buffer, 1, BUFFER_SIZE, fp)) > 0 )
      total_read += chars_read;
    fclose(fp);
  } else {
    total_read = -1;
  }
  return total_read;
}

int main() {
  char command[MAX_TOKEN_LEN];
  char parameter[MAX_TOKEN_LEN];
  size_t ret;
  while(1) {
    printf(">");
    scanf("%s %s", command, parameter);
    if( !strncmp(command, "read", MAX_TOKEN_LEN) ) {
      ret = do_read(parameter);
      printf("==>READ %zu\n", ret);
    } else if( !strncmp(command, "fread", MAX_TOKEN_LEN) ) {
      ret = do_fread(parameter);
      printf("==>FREAD %zu\n", ret);
    } else if( !strncmp(command, "quit", MAX_TOKEN_LEN) ) {
      printf("Bye!\n");
      return 0;
    } else {
      printf("Unknown command. Possible commands are:\n"
        "read <file>\n"
        "fread <file>\n"
        "quit me\n");
    }
  }
}
