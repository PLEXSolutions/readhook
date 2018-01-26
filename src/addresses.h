#ifndef _ADDRESSES_H_
#define _ADDRESSES_H_
#include <stddef.h>

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

typedef struct BaseAddresses {
	Pointer buf_base;
	Pointer libc_base;
	Pointer pie_base;
	Pointer stack_base;
} BaseAddresses, *BaseAddressesPtr;

extern void         initBaseAddresses(BaseAddressesPtr baseAddresses);
extern Pointer      baseAddress(char base, BaseAddressesPtr baseAddressesPtr);
extern Offset       pointerToOffset(Pointer p, char base, BaseAddressesPtr baseAddressesPtr);
extern Offset       indirectToOffset(Pointer p, char base, BaseAddressesPtr baseAddressesPtr);
extern Pointer      ffsetToPointer(Offset o, BaseAddressesPtr baseAddressesPtr);
extern Pointer      offsetToIndirect(Offset o, BaseAddressesPtr baseAddressesPtr);
extern AddressUnion fixupAddressUnion(AddressUnion au, BaseAddressesPtr baseAddressesPtr);
extern void         dofixups(Pointer p, size_t n, BaseAddressesPtr baseAddressesPtr);
#endif
