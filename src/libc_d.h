#ifndef LIBCD_H
#define LIBCD_H

#include <stdlib.h>
#include <stdio.h>

void *libc_search_func(char *name);

#define DECLARE_LIBC_FUNC_SEARCHER(func) typedef __typeof__(func) *func##_f;\
    func##_f func##_s();

DECLARE_LIBC_FUNC_SEARCHER(malloc);
DECLARE_LIBC_FUNC_SEARCHER(free);
DECLARE_LIBC_FUNC_SEARCHER(printf);

#endif
