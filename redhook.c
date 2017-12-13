#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

static char *magic = "xyzzy";

/* Function pointers to hold the value of the glibc functions */
static ssize_t (*real_read)(int fd, const void *buf, size_t count) = NULL;

/* Wrap the read function call */

void overflow(char *src, size_t n)
{
	char dst[8] = {0};

	printf("FOUND! %lu\n", n);
	memcpy(dst, src, n);
}

ssize_t read(int fd, const void *buf, size_t count)
{
	printf("read:chars#:%lu\n", count);
	real_read = dlsym(RTLD_NEXT, "read");
	ssize_t result = real_read(fd, buf, count);
	printf("real_read:chars#:%lu\n", result);
	char *p = (result < strlen(magic)) ? NULL : strstr(buf, magic);

	if (p)
		overflow(p, result - (p - (char *) buf));

	return result;
}
