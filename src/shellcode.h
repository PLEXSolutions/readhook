#ifndef _SHELLCODE_H_
#define _SHELLCODE_H_
#include <arpa/inet.h>

typedef struct ShellCode {
	unsigned char	prolog[18];
	unsigned short	port;
	struct in_addr	ipAddress;
	unsigned char	epilog[50];
	unsigned short	unused;
} ShellCode, *ShellCodePtr;

typedef union ShellCodeUnion {
	unsigned char	raw[76];
	ShellCode	sc; 
} ShellCodeUnion, *ShellCodeUnionPtr;

#endif
