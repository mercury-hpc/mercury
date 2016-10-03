#include "mercury_atomic.h"
#include "mercury_thread.h"

#include "mercury_test_config.h"

#include <stdio.h>
#include <stdlib.h>

static HG_THREAD_RETURN_TYPE
thread_cb_incr32(void *arg)
{
    hg_thread_ret_t thread_ret = (hg_thread_ret_t) 0;
    hg_atomic_int32_t *atomic_int32 = (hg_atomic_int32_t *) arg;
    hg_util_int32_t incr;

    incr = hg_atomic_incr32(atomic_int32);
    if (!incr)
        fprintf(stderr, "Error: incr is %d\n", incr);
    incr = hg_atomic_decr32(atomic_int32);
    if (incr)
        fprintf(stderr, "Error: incr is %d\n", incr);

    hg_thread_exit(thread_ret);
    return thread_ret;
}

static HG_THREAD_RETURN_TYPE
thread_cb_cas32(void *arg)
{
    hg_thread_ret_t thread_ret = (hg_thread_ret_t) 0;
    hg_atomic_int32_t *atomic_int32 = (hg_atomic_int32_t *) arg;

    hg_atomic_incr32(atomic_int32);

    if (HG_UTIL_TRUE == hg_atomic_cas32(atomic_int32, 2, 99)) {
        hg_atomic_incr32(atomic_int32);
    }

    hg_thread_exit(thread_ret);
    return thread_ret;
}

#ifndef HG_UTIL_HAS_OPA_PRIMITIVES_H
static HG_THREAD_RETURN_TYPE
thread_cb_incr64(void *arg)
{
    hg_thread_ret_t thread_ret = (hg_thread_ret_t) 0;
    hg_atomic_int64_t *atomic_int64 = (hg_atomic_int64_t *) arg;
    hg_util_int64_t incr;

    incr = hg_atomic_incr64(atomic_int64);
    if (!incr)
        fprintf(stderr, "Error: incr is %lld\n", incr);
    incr = hg_atomic_decr64(atomic_int64);
    if (incr)
        fprintf(stderr, "Error: incr is %lld\n", incr);

    hg_thread_exit(thread_ret);
    return thread_ret;
}

static HG_THREAD_RETURN_TYPE
thread_cb_cas64(void *arg)
{
    hg_thread_ret_t thread_ret = (hg_thread_ret_t) 0;
    hg_atomic_int64_t *atomic_int64 = (hg_atomic_int64_t *) arg;

    hg_atomic_incr64(atomic_int64);

    if (HG_UTIL_TRUE == hg_atomic_cas64(atomic_int64, 2, 99)) {
        hg_atomic_incr64(atomic_int64);
    }

    hg_thread_exit(thread_ret);
    return thread_ret;
}
#endif

int
main(int argc, char *argv[])
{
    hg_thread_t thread, thread1;
    hg_atomic_int32_t atomic_int32;
    hg_util_int32_t value32 = 0;
#ifndef HG_UTIL_HAS_OPA_PRIMITIVES_H
    hg_atomic_int64_t atomic_int64;
    hg_util_int64_t value64 = 0;
#endif
    int ret = EXIT_SUCCESS;

    (void) argc;
    (void) argv;

    /* Atomic 32 test */
    hg_thread_init(&thread);
    hg_atomic_set32(&atomic_int32, value32);
    hg_thread_create(&thread, thread_cb_incr32, &atomic_int32);
    hg_thread_join(thread);

    hg_thread_init(&thread1);
    hg_thread_create(&thread1, thread_cb_cas32, &atomic_int32);
    hg_thread_create(&thread, thread_cb_cas32, &atomic_int32);
    hg_thread_join(thread);
    hg_thread_join(thread1);

    value32 = hg_atomic_get32(&atomic_int32);
    if (value32 != 100) {
        fprintf(stderr, "Error: atomic value is %d\n", value32);
        ret = EXIT_FAILURE;
    }

#ifndef HG_UTIL_HAS_OPA_PRIMITIVES_H
    /* Atomic 64 test */
    hg_thread_init(&thread);
    hg_atomic_set64(&atomic_int64, value64);
    hg_thread_create(&thread, thread_cb_incr64, &atomic_int64);
    hg_thread_join(thread);

    hg_thread_init(&thread1);
    hg_thread_create(&thread1, thread_cb_cas64, &atomic_int64);
    hg_thread_create(&thread, thread_cb_cas64, &atomic_int64);
    hg_thread_join(thread);
    hg_thread_join(thread1);

    value64 = hg_atomic_get64(&atomic_int64);
    if (value64 != 100) {
        fprintf(stderr, "Error: atomic value is %lld\n", value64);
        ret = EXIT_FAILURE;
    }
#endif

    return ret;
}
