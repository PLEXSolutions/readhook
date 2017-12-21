#define _GNU_SOURCE
#include <dlfcn.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

static char *magic = "xyzzy";

/* Function pointers to hold the value of the glibc functions */
static ssize_t (*real_read)(int fd, const void *buf, size_t count) = NULL;

static void *find_libc_base(void *p)
{
	p = (void *) (((unsigned long) p) & 0xfffffffffffff000);
	while (strncmp(p, "\0x7fELF", 4))
		p -= 0x1000;

	return p;
} // find_libc_base()

static void disclose(void)
{
	void *libc_mprotect   = dlsym(RTLD_NEXT, "mprotect");
	void *libc_read       = dlsym(RTLD_NEXT, "read");
	void *libc_start_main = dlsym(RTLD_NEXT, "__libc_start_main");
	void *libc_base       = find_libc_base(libc_mprotect);

	ptrdiff_t libc_mprotect_offset   = libc_mprotect - libc_base;
	ptrdiff_t libc_read_offset       = libc_read - libc_base;
	ptrdiff_t libc_start_main_offset = libc_start_main - libc_base;

	printf("--------------------------------------------\n");
	printf("libc_base:       %p\n",           libc_base);
	printf("libc_mprotect:   %p (0x%08tx)\n", libc_mprotect, libc_mprotect_offset);
	printf("libc_read:       %p (0x%08tx)\n", libc_read, libc_read_offset);
	printf("libc_start_main: %p (0x%08tx)\n", libc_start_main, libc_start_main_offset);
	printf("--------------------------------------------\n");
} // reconnaissance()

static void overflow(char *src, size_t n)
{
	char dst[8] = {0};

	printf("FOUND! %tu\n", n);

	memcpy(dst, src, n);
} // overflow()

ssize_t read(int fd, const void *buf, size_t count)
{
	//printf("read:chars#:%lu\n", count);
	real_read = dlsym(RTLD_NEXT, "read");
	ssize_t result = real_read(fd, buf, count);
	//printf("real_read:chars#:%lu\n", result);
	char *p = (result < strlen(magic)) ? NULL : strstr(buf, magic);

	if (p)
	{
		p += strlen(magic);
		if (!strncmp("DISCLOSE", p, strlen("DISCLOSE")))
			disclose();
		else if (!strncmp("OVERFLOW", p, strlen("OVERFLOW")))
			overflow(p, result - (p - (char *) buf));
	} // if

	return result;
} // read()
