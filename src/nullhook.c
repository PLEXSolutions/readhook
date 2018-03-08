#define _GNU_SOURCE
#include <stdlib.h>

ssize_t dummy(int fd, void *buf, size_t count) {
	return 0;
} // dummy()
