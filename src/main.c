#include "libc_d.h"
#include "print.h"

int main() {
    printf_f printf_d = printf_s();
    printf_d("Hello world\n");

    printf_d("%p\n", malloc_s());
    PRINTF("%p\n", malloc);
    printf_d("%p\n", free_s());
    PRINTF("%p\n", free);
    return 0;
}
