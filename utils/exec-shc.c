#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

unsigned char *read_file_into_bytes(char *filepath, size_t* size) {
  FILE *fp;
  unsigned char *buffer;
  long filelen;

  fp = fopen(filepath, "rb"); // Open the file in binary mode
  if (!fp) {
    return 0;
  }
  fseek(fp, 0, SEEK_END); // Jump to the end of the file
  filelen = ftell(fp);    // Get the current byte offset in the file
  rewind(fp);             // Jump back to the beginning of the file

  buffer = (unsigned char *)malloc(filelen); // Enough memory for the file
  fread(buffer, filelen, 1, fp);             // Read in the entire file
  fclose(fp);

  *size = filelen;
  return buffer; // Close the file
}

int main(int argc, char** argv) {
  unsigned char* shc;
  size_t size = 0;
  unsigned char* executable_region;

  if (argc < 2) {
    printf("Usage: %s <shellcode-file>\n", argv[0]);
    return -1;
  }

  shc = read_file_into_bytes(argv[1], &size);
  if(!shc) {
    printf("Unable to read shellcode file\n");
    return -1;
  }

  executable_region = mmap(NULL, size, PROT_EXEC | PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);

  memcpy(executable_region, shc, size);
  free(shc);

  ((int (*)())executable_region)();

  munmap(executable_region, size);

  return 0;
}
