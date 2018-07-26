#include "strlcpy.h"

// From BSD sources ~2006 MIT license.
size_t strlcpy(char *dst, const char *src, size_t len)
{
	char *d = dst;
	const char *s = src;
	size_t n = len;

	if (n != 0)
		while (--n != 0)
			if ((*d++ = *s++) == '\0')
				break;

	if (n == 0) {
		if (len != 0)
			*d = '\0';
		while (*s++)
			;
	}

	return s - src - 1;
}
