#include <assert.h>
#include <inttypes.h>   /* for PRIx8, etc. */
#include <stdbool.h>
#include <stddef.h>     /* size_t */
#include <stdio.h>      /* sscanf */
#include <stdlib.h>     /* malloc */
#include <string.h>     /* strlen */

#include <sys/param.h>  /* for MIN, MAX */

/* If `str` is the empty string, then store NULL at `bufp` and 0 at
 * `buflenp`, and return 0.
 *
 * If `str` consists of one or more hexadecimal octets,
 * [0-9a-fA-F][0-9a-fA-F], separated by colons, then parse the octets
 * into bytes, storing them in a buffer allocated on the heap.  Store a
 * pointer to the buffer at `bufp` and the number of bytes at `buflenp`,
 * and return 0.
 *
 * If `str` contains any other string, or if memory on the heap cannot
 * be allocated, then store NULL at `bufp` and 0 at `buflenp`, and
 * return -1.
 */
int
colon_separated_octets_to_bytes(const char *str, uint8_t **bufp,
    size_t *buflenp)
{
    uint8_t *buf;
    size_t buflen, noctets;
    int i = 0, nread, rc;
    *bufp = NULL;
    *buflenp = 0;

    noctets = (strlen(str) + 1) / 3;

    if (noctets < 1)
        return 0;

    if ((buf = malloc(noctets)) == NULL)
        return -1;

    rc = sscanf(&str[i], "%02" SCNx8 "%n", &buf[0], &nread);
    if (rc == EOF) {
        free(buf);
        return 0;
    } else if (rc != 1) {
        free(buf);
        return -1;
    }

    for (buflen = 1, i = nread;
         (rc = sscanf(&str[i], ":%02" SCNx8 "%n", &buf[buflen], &nread)) == 1;
         i += nread)
        buflen++;

    if (rc != EOF || str[i] != '\0') {
        free(buf);
        return -1;
    }

    assert(buflen == noctets);
    *bufp = buf;
    *buflenp = buflen;
    return 0;
}

/* Return twice x or SIZE_MAX, whichever is smaller.  Protects
 * against wraparound.
 */
size_t
twice_or_max(size_t x)
{
    return x + MIN(SIZE_MAX - x, x);
}
