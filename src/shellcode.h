#ifndef _SHELLCODE_H_
#define _SHELLCODE_H_
#include <arpa/inet.h>

typedef struct Shellcode {
        unsigned char   hlts[8];
} Shellcode, *ShellcodePtr;

typedef union ShellcodeUnion {
        unsigned char   raw[8];
        Shellcode       sc;
} ShellcodeUnion, *ShellcodeUnionPtr;

extern void     initShellcodeUnion(ShellcodeUnionPtr scup);
extern ssize_t  makeShellcode(ShellcodePtr scp, char *p, ssize_t np);
extern void     dumpShellcode(ShellcodePtr scp);

#endif
