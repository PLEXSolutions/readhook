#define _GNU_SOURCE
#include "addresses.h"

Pointer baseAddress(char base, BaseAddressesPtr baseAddressesPtr) {
	switch (base) {
		case 'B' : return baseAddressesPtr->buffer_base;
		case 'L' : return baseAddressesPtr->libc_base;
		case 'P' : return baseAddressesPtr->pie_base;
		case 'S' : return baseAddressesPtr->stack_base; // Actually just base of current stack page
		default  : return 0;
	} // switch
} // baseAddress()

Offset pointerToOffset(Pointer p, char base, BaseAddressesPtr baseAddressesPtr) {
	return (Offset) { (p - baseAddress(base, baseAddressesPtr)), base, '~' };
} // pointerToOffset()

Offset indirectToOffset(Pointer p, char base, BaseAddressesPtr baseAddressesPtr) {
	return (Offset) { (p - baseAddress(base, baseAddressesPtr)), base, '*' };
} // indirectToOffset()

Pointer offsetToPointer(Offset o, BaseAddressesPtr baseAddressesPtr) {
	return (Pointer) (o.r + baseAddress(o.b, baseAddressesPtr));
} // offsetToPointer()

Pointer offsetToIndirect(Offset o, BaseAddressesPtr baseAddressesPtr) {
	return *((Pointer *) offsetToPointer(o, baseAddressesPtr));
} // offsetToIndirect()

AddressUnion fixupAddressUnion(AddressUnion au, BaseAddressesPtr baseAddressesPtr) {
	if (au.o.f == '~')
		return (AddressUnion) { .p = offsetToPointer(au.o, baseAddressesPtr) };

	if (au.o.f == '*')
		return (AddressUnion) { .p = offsetToIndirect(au.o, baseAddressesPtr) };

	return au;
} // fixupAddressUnion()

void dofixups(Pointer p, size_t n, BaseAddressesPtr baseAddressesPtr) {
	for (AddressUnionPtr aup = (AddressUnionPtr)p; aup < (AddressUnionPtr) (p + n - sizeof(AddressUnionPtr) + 1); aup++)
		*aup = fixupAddressUnion(*aup, baseAddressesPtr);
} // dofixups()
