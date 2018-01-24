#define _GNU_SOURCE
#include <string.h>
#include "strnstr.h"

char *strnstr(const char *s1, const char *s2, size_t len)
{
	size_t l2 = strlen(s2);

	if (!l2)
		return (char *)s1;

	while (len >= l2) {
		len--;
		if (!memcmp(s1, s2, l2))
			return (char *)s1;
		s1++;
	} // while

	return NULL;
} // strnstr()
