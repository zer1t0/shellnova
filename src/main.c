#include "libc_d.h"
#include "print.h"
#include "log.h"
#include "syscall_z.h"

printf_f printf_d = NULL;

#define RESOLVE_FUNCTION(func)                     \
    func##_d = func##_s();                         \
    if(!func##_d) {                                \
        PRINTF("Error resolving " #func "\n");     \
        return -1;                                 \
    }

int resolve_functions() {
    RESOLVE_FUNCTION(printf);
    return 0;
}

int main() {
    if (resolve_functions() != 0) {
        PRINTF("Unable to resolve functions");
        return -1;
    }
    printf_d("Hello from shellnova\n");
}
