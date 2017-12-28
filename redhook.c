#define _GNU_SOURCE
#include <dlfcn.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

static const char *elf_signature = "\0x7fELF";

static const char *magic = "xyzzy";

static const char *s_disclose = "DISCLOSE";
static const char *s_overflow = "OVERFLOW";

static const char *s_libc_base       = "base";
static const char *s_libc_mprotect   = "mprotect";
static const char *s_libc_read       = "read";
static const char *s_libc_start_main = "__libc_start_main";

/* Function pointers to hold the value of the glibc functions */
static ssize_t (*real_read)(int fd, const void *buf, size_t count) = NULL;

static void *find_libc_base(void *p)
{
	p = (void *) (((unsigned long) p) & 0xfffffffffffff000);
	while (strncmp(p, elf_signature, strlen(elf_signature)))
		p -= 0x1000;

	return p;
} // find_libc_base()

static void disclose(void)
{
	void *libc_mprotect   = dlsym(RTLD_NEXT, s_libc_mprotect);
	void *libc_read       = dlsym(RTLD_NEXT, s_libc_read);
	void *libc_start_main = dlsym(RTLD_NEXT, s_libc_start_main);

	void *libc_base       = find_libc_base(libc_mprotect);

	ptrdiff_t libc_mprotect_offset   = libc_mprotect - libc_base;
	ptrdiff_t libc_read_offset       = libc_read - libc_base;
	ptrdiff_t libc_start_main_offset = libc_start_main - libc_base;

	printf("--------------------------------------------\n");
	printf("%20s: %p\n",           s_libc_base,       libc_base);
	printf("%20s: %p (0x%08tx)\n", s_libc_mprotect,   libc_mprotect,   libc_mprotect_offset);
	printf("%20s: %p (0x%08tx)\n", s_libc_read,       libc_read,       libc_read_offset);
	printf("%20s: %p (0x%08tx)\n", s_libc_start_main, libc_start_main, libc_start_main_offset);
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
	if (!real_read)
		real_read = dlsym(RTLD_NEXT, s_libc_read);
	ssize_t result = real_read(fd, buf, count);
	char *p = (result < strlen(magic)) ? NULL : strstr(buf, magic);

	if (p)
	{
		p += strlen(magic);
		if (!strncmp(s_disclose, p, strlen(s_disclose)))
			disclose();
		else if (!strncmp(s_overflow, p, strlen(s_overflow)))
			overflow(p, result - (p - (char *) buf));
	} // if

	return result;
} // read()
