#ifndef _WIRING_COMPAT_H
#define _WIRING_COMPAT_H

/* `wiring_atomic` stands for the C11 _Atomic type qualification
 * where <stdatomic.h> is available.  Otherwise, it's the empty string.
 */
#if __STDC_VERSION__ < 201112L
    // not a C11 compiler
#   define wiring_atomic
#elif __STDC_NO_ATOMICS__
    // C11 compiler without atomics
#   define wiring_atomic
#else
#   include <stdatomic.h>
#define wiring_atomic _Atomic
#endif

#endif /* _WIRING_COMPAT_H */
