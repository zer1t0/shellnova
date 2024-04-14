#ifndef LIBCD_H
#define LIBCD_H

#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>

void *libc_search_func(char *name);

#define DECLARE_LIBC_FUNC_SEARCHER(func) typedef __typeof__(func) *func##_f;\
    func##_f func##_s();

DECLARE_LIBC_FUNC_SEARCHER(free);
DECLARE_LIBC_FUNC_SEARCHER(getchar);
DECLARE_LIBC_FUNC_SEARCHER(malloc);
DECLARE_LIBC_FUNC_SEARCHER(mprotect);
DECLARE_LIBC_FUNC_SEARCHER(munmap);
DECLARE_LIBC_FUNC_SEARCHER(printf);

#endif
