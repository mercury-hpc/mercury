#ifndef _UTIL_H_
#define _UTIL_H_

#include <stdint.h> /* uint8_t */
#include <unistd.h> /* size_t */

#define NELTS(_a)   (sizeof(_a) / sizeof((_a)[0]))

#if defined(__GNUC__)
#   define wireup_printf_like(_fmt,_firstarg)    \
    __attribute__((format(printf, _fmt, _firstarg)))
#endif

void dbgf(const char *fmt, ...) wireup_printf_like(1, 2);

int colon_separated_octets_to_bytes(const char *, uint8_t **, size_t *);

size_t twice_or_max(size_t);

void *header_alloc(size_t, size_t, size_t);
void header_free(size_t, size_t, void *);

#endif /* _UTIL_H_ */
