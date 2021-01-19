#ifndef _UTIL_H_
#define _UTIL_H_

#include <stdint.h> /* uint8_t */
#include <unistd.h> /* size_t */

#define NELTS(_a)   (sizeof(_a) / sizeof((_a)[0]))

int colon_separated_octets_to_bytes(const char *, uint8_t **, size_t *);

size_t twice_or_max(size_t);

#endif /* _UTIL_H_ */
