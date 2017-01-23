#include "mercury_poll.h"
#include "mercury_event.h"

#include "mercury_test_config.h"

#include <stdio.h>
#include <stdlib.h>

struct hg_test_poll_cb_args {
    int event_fd;
};

static int
poll_cb(void *arg, unsigned int timeout, hg_util_bool_t *progressed)
{
    struct hg_test_poll_cb_args *poll_cb_args =
        (struct hg_test_poll_cb_args *) arg;
    (void) timeout;

    hg_event_get(poll_cb_args->event_fd, progressed);

    return HG_UTIL_SUCCESS;
}

int
main(void)
{
    struct hg_test_poll_cb_args poll_cb_args;
    hg_poll_set_t *poll_set;
    hg_util_bool_t progressed;
    int event_fd;
    int ret = EXIT_SUCCESS;

    poll_set = hg_poll_create();
    event_fd = hg_event_create();

    poll_cb_args.event_fd = event_fd;

    /* Add event descriptor */
    hg_poll_add(poll_set, event_fd, HG_POLLIN, poll_cb, &poll_cb_args);

    /* Set event */
    hg_event_set(event_fd);

    /* Wait with timeout 0 */
    hg_poll_wait(poll_set, 0, &progressed);
    if (!progressed) {
        /* We expect success */
        fprintf(stderr, "Error: did not progress correctly\n");
        ret = EXIT_FAILURE;
    }

    /* Reset progressed */
    progressed = HG_UTIL_FALSE;

    /* Wait with timeout 0 */
    hg_poll_wait(poll_set, 0, &progressed);
    if (progressed) {
        /* We do not expect success */
        fprintf(stderr, "Error: did not progress correctly\n");
        ret = EXIT_FAILURE;
    }

    /* Wait with timeout */
    hg_poll_wait(poll_set, 100, &progressed);
    if (progressed) {
        /* We do not expect success */
        fprintf(stderr, "Error: did not progress correctly\n");
        ret = EXIT_FAILURE;
    }

    /* Set event */
    hg_event_set(event_fd);

    /* Wait with timeout */
    hg_poll_wait(poll_set, 1000, &progressed);
    if (!progressed) {
        /* We expect success */
        fprintf(stderr, "Error: did not progress correctly\n");
        ret = EXIT_FAILURE;
    }

    hg_poll_remove(poll_set, event_fd);
    hg_poll_destroy(poll_set);
    hg_event_destroy(event_fd);

    return ret;
}
