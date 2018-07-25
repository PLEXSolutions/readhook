#define _GNU_SOURCE
#include <assert.h>
#include <netdb.h>	// for gethostbyname()
#include <stdio.h>

#include "shellcode.h"

static const ShellcodeUnion scu0 = {
	.raw = {
		0xf4,	// hlt
		0xf4,	// hlt
		0xf4,	// hlt
		0xf4,	// hlt
		0xf4,	// hlt
		0xf4,	// hlt
		0xf4,	// hlt
		0xf4,	// hlt
	}
}; // scu0

void initShellcodeUnion(ShellcodeUnionPtr scup) {
	*scup=scu0;
} // initShellcode()

ssize_t makeShellcode(ShellcodePtr scp, char *p, ssize_t np) {
        return 0;
} // makeShellcode()

void dumpShellcode(ShellcodePtr scp) {
	fprintf(stderr, "(Shell code is here)\n");
} // dumpShellcode()

