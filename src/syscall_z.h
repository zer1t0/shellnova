#ifndef SYSCALLZ_H
#define SYSCALLZ_H

#include <stddef.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

long syscall_z(long number, ...);

ssize_t read_z(int fd, void *buf, size_t count);

int open_z(const char *pathname, int flags, mode_t mode);

int close_z(int fd);

off_t lseek_z(int fd, off_t offset, int whence);

int fstat_z(int fd, struct stat *statbuf);

ssize_t write_z(int fd, const void *buf, size_t count);

void *mmap_z(void *addr, size_t length, int prot, int flags, int fd,
             off_t offset);
int munmap_z(void *addr, size_t length);

#endif
