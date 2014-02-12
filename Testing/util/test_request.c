#include "mercury_request.h"
#include "mercury_util_error.h"

#include "mercury_test_config.h"

#include <stdio.h>
#include <stdlib.h>

hg_request_object_t *request;

static int progressed = 0;
static int triggered = 0;

static void
user_cb(void)
{
    int *user_data = (int *) hg_request_get_data(request);
    *user_data = 1;

    hg_request_complete(request);
}

static int
progress(unsigned int timeout)
{
    /*
    printf("Doing progress\n");
    */

    if (!progressed) progressed = 1;

    return HG_UTIL_SUCCESS;
}

static int
trigger(unsigned int timeout, unsigned int max_count,
        unsigned int *actual_count)
{
    /*
    printf("Calling trigger\n");
    */

    if (progressed && ! triggered) {
        user_cb();
        *actual_count = 1;
        triggered = 1;
    } else {
        *actual_count = 0;
    }

    return HG_UTIL_SUCCESS;
}

int
main(int argc, char *argv[])
{
    hg_request_class_t *request_class;
    int timeout = 1000; /* ms */
    int user_data = 0;
    int ret = EXIT_SUCCESS;

    request_class = hg_request_init(progress, trigger);
    request = hg_request_create(request_class);
    hg_request_set_data(request, &user_data);
    hg_request_wait(request, timeout);

    if (!user_data) {
        fprintf(stderr, "User data is %d\n", user_data);
        ret = EXIT_FAILURE;
    } else {
        /*
        printf("User data is %d\n", user_data);
        */
    }

    hg_request_destroy(request);
    hg_request_finalize(request_class);

    return ret;
}
