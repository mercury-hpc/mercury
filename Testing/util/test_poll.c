#include "mercury_poll.h"

#include "mercury_test_config.h"

#include <stdio.h>
#include <stdlib.h>

struct hg_test_poll_cb_args {
    unsigned int num_cb;
};

static int
poll_cb1(void *arg, hg_util_bool_t *progressed)
{
    struct hg_test_poll_cb_args *poll_cb_args =
        (struct hg_test_poll_cb_args *) arg;

    poll_cb_args->num_cb++;
    *progressed = HG_UTIL_TRUE;
    return HG_UTIL_SUCCESS;
}

static int
poll_cb2(void *arg, hg_util_bool_t *progressed)
{
    struct hg_test_poll_cb_args *poll_cb_args =
        (struct hg_test_poll_cb_args *) arg;

    poll_cb_args->num_cb++;
    *progressed = HG_UTIL_FALSE;
    return HG_UTIL_SUCCESS;
}

int
main(void)
{
    struct hg_test_poll_cb_args poll_cb_args;
    hg_poll_set_t *poll_set;
    hg_util_bool_t progressed;
    int ret = EXIT_SUCCESS;

    poll_set = hg_poll_create();

    poll_cb_args.num_cb = 0;

    /* Fake descriptor */
    hg_poll_add(poll_set, 0, HG_POLLOUT, poll_cb1, &poll_cb_args);

    /* Fake descriptor */
    hg_poll_add(poll_set, 1, HG_POLLIN, poll_cb2, &poll_cb_args);

    /* Wait with timeout 0 */
    hg_poll_wait(poll_set, 0, &progressed);
    if (!progressed || poll_cb_args.num_cb != 2) {
        /* We expect success */
        fprintf(stderr, "Error: did not progress correctly\n");
        ret = EXIT_FAILURE;
    }

    hg_poll_remove(poll_set, 0);
    hg_poll_remove(poll_set, 1);
    hg_poll_destroy(poll_set);

    return ret;
}
