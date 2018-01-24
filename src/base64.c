#define _GNU_SOURCE
#include "base64.h"

static const unsigned char b64EncodeTable[64] = {
	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
	'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
	'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
	'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'
};

size_t b64Encode(const unsigned char *s256, const size_t n256, unsigned char *s64, size_t m64) {

	// Calculate encoded size but limit to size of our output buffer
	size_t n64 = 4 * ((n256 + 2) / 3);
	if (n64 > m64)
		n64 = m64;

	// Loop over input data generating four 6-in-8 bytes for each three 8-in-8 bytes
	for (size_t i256 = 0, i64 = 0, triple = 0; i256 < n256 && i64 < n64;) {
		for (size_t i = 0; i < 3; i++)
			triple = (triple << 8) + ((i256 < n256 ) ? s256[i256++] : 0);

		for (size_t i = 0; i < 4; i++)
			s64[i64++] = b64EncodeTable[(triple >> ((3 - i) * 6)) & (1 << 6) - 1];
	} // for

	// Back-patch trailing overrun created by the "chunky" encoder (above).
	for (size_t i = 0; i < (n256 * 2) % 3; i++)
		s64[n64 - 1 - i] = '=';

	return n64;
} // b64Encode()

static const unsigned char b64DecodeTable[256] = {
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 62, 64, 64, 64, 63,
	52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 64, 64, 64, 64, 64, 64,
	64,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
	15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 64, 64, 64, 64, 64,
	64, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
	41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64
};

size_t b64Length(const unsigned char *s64) {
	for (size_t i = 0; ; i++)
		if (b64DecodeTable[s64[i]] >  63)
			return i;
} // b64Length()

size_t b64Decode(const unsigned char *s64, const size_t n64, unsigned char *s256, const size_t m256) {

	// Calculate decoded size but limit to size of our output buffer
	size_t n256 = (((n64 + 3) / 4) * 3) - ((4 - n64) & 3);

	// Don't write more than m256 bytes
	if (n256 > m256)
		n256 = m256;

	// Loop over input data generating three 8-in-8 bytes for each four 6-in-8 bytes
	for (size_t i64 = 0, i256 = 0; i64 < n64 && i256 < n256; i64++) {
		if (i64 < n64 - 1) { s256[i256++] = (b64DecodeTable[s64[i64]] << 2 | b64DecodeTable[s64[i64 + 1]] >> 4); i64++; }
		if (i64 < n64 - 1) { s256[i256++] = (b64DecodeTable[s64[i64]] << 4 | b64DecodeTable[s64[i64 + 1]] >> 2); i64++; }
		if (i64 < n64 - 1) { s256[i256++] = (b64DecodeTable[s64[i64]] << 6 | b64DecodeTable[s64[i64 + 1]] >> 0); i64++; }
	} // for

	// Append a NUL if there is room to do so (but don't count it as a decoded character)
	if (n256 < m256)
		s256[n256] = '\0';

	return n256;
} // b64Decode()
