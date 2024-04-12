#include "libc_d.h"
#include "linker.h"
#include "lib_d.h"

STORE_IN_DATA libsyms_t libc_symbols = {0};

const char libc_pattern1[] = "/libc-";
const char libc_pattern2[] = "/libc.";

static int init_glibc_symbols_tables() {
  const char *lib_patterns[] = {libc_pattern1, libc_pattern2};
  size_t lib_patterns_count = 2;

  return lib_search_symbols_tables(lib_patterns, lib_patterns_count, &libc_symbols);
}

void *libc_search_func(char *name) {
  if (!libc_symbols.base_address) {
    if (init_glibc_symbols_tables()) {
      return NULL;
    }
  }

  return lib_search_function(&libc_symbols, name);
}

#define IMPLEMENT_LIBC_FUNC_SEARCHER(func)                              \
    STORE_IN_DATA func##_f func##_v = NULL;                             \
    func##_f func##_s() {                                               \
        if (!func##_v) {                                                \
            func##_v = libc_search_func(#func);                         \
        }                                                               \
        return func##_v;                                                \
    }

IMPLEMENT_LIBC_FUNC_SEARCHER(malloc);
IMPLEMENT_LIBC_FUNC_SEARCHER(free);
IMPLEMENT_LIBC_FUNC_SEARCHER(printf);
