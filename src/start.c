#include "start.h"
#include "libc_d.h"
#include "syscall_z.h"

int main();

long __data_offset;
void *get_data_start_addr() { return &__data_offset; }

int premain() {
  void *start_addr = get_start_addr();
  void *end_addr = get_end_addr();
  void *data_addr = get_data_start_addr();
  printf_f printf_d = printf_s();
  mprotect_f mprotect_d = mprotect_s();
  size_t data_size = end_addr - data_addr;
  size_t code_size = data_addr - start_addr;
  pid_t pid = getpid_z();
  printf_d("PID: %d\n", pid);
  printf_d("Start addr: %p\n", start_addr);
  printf_d("Data addr: %p\n", data_addr);
  printf_d("End addr: %p\n", end_addr);
  printf_d("Data size: 0x%lx\n", data_size);

  mprotect_d(start_addr, code_size, PROT_READ | PROT_EXEC);
  mprotect_d(data_addr, data_size, PROT_READ | PROT_WRITE);

  return main();
}
