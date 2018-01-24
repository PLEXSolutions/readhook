#ifndef _BASE64_H_
#define _BASE64_H_
#include <stddef.h>

extern size_t b64Encode(const unsigned char *s256, const size_t n256, unsigned char *s64, size_t m64);
extern size_t b64Length(const unsigned char *s64);
extern size_t b64Decode(const unsigned char *s64, const size_t n64, unsigned char *s256, const size_t m256);
#endif
