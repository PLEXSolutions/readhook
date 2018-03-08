#define _GNU_SOURCE
#include <dlfcn.h>	// For dlsym()
#include <stdio.h>	// For i/o

// NOOP read function for testing if LD_PRELOAD can be injected quietly.
typedef
ssize_t Read(int fd, void *buf, size_t count);
ssize_t read(int fd, void *buf, size_t count) {
	Read *libc_read = (Read *) dlsym(RTLD_NEXT, "read");
	ssize_t result = libc_read(fd, buf, count);

	return result;
} // read()
