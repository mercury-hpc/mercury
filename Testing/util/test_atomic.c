#include "mercury_atomic.h"
#include "mercury_thread.h"

#include "mercury_test_config.h"

#include <stdio.h>
#include <stdlib.h>

static HG_THREAD_RETURN_TYPE
thread_cb_incr(void *arg)
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
thread_cb_cas(void *arg)
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

int
main(int argc, char *argv[])
{
    hg_thread_t thread, thread1;
    hg_atomic_int32_t atomic_int32;
    hg_util_int32_t value = 0;
    int ret = EXIT_SUCCESS;

    (void) argc;
    (void) argv;

    hg_thread_init(&thread);
    hg_atomic_set32(&atomic_int32, value);
    hg_thread_create(&thread, thread_cb_incr, &atomic_int32);
    hg_thread_join(thread);

    hg_thread_init(&thread1);
    hg_thread_create(&thread1, thread_cb_cas, &atomic_int32);
    hg_thread_create(&thread, thread_cb_cas, &atomic_int32);
    hg_thread_join(thread);
    hg_thread_join(thread1);

    value = hg_atomic_get32(&atomic_int32);
    if (value != 100) {
        fprintf(stderr, "Error: atomic value is %d\n", value);
        ret = EXIT_FAILURE;
    }
    return ret;
}
