#include "libc_d.h"
#include "print.h"

int main() {
    printf_f printf_d = printf_s();
    printf_d("Hello world\n");

    // For debugging
    PRINTF("Malloc Addr: %p\n", malloc_s());
    PRINTF("Malloc addr: %p\n", malloc);
}
