#include "mercury_queue.h"

#include "mercury_test_config.h"

#include <stdio.h>
#include <stdlib.h>

int
main(int argc, char *argv[])
{
    hg_queue_t *queue = NULL;
    int ret = EXIT_SUCCESS;
    int value1 = 10, value2 = 20;

    (void) argc;
    (void) argv;

    queue = hg_queue_new();

    if (!hg_queue_is_empty(queue)) {
        fprintf(stderr, "Error: queue should be empty\n");
        ret = EXIT_FAILURE;
        goto done;
    }

    hg_queue_push_head(queue, (hg_queue_value_t) &value1);

    if (value1 != *((int *) hg_queue_peek_head(queue))) {
        fprintf(stderr, "Error: values do not match\n");
        ret = EXIT_FAILURE;
        goto done;
    }

    if (hg_queue_is_empty(queue)) {
        fprintf(stderr, "Error: queue should not be empty\n");
        ret = EXIT_FAILURE;
        goto done;
    }

    hg_queue_push_tail(queue, (hg_queue_value_t) &value2);

    if (value2 != *((int *) hg_queue_peek_tail(queue))) {
        fprintf(stderr, "Error: values do not match\n");
        ret = EXIT_FAILURE;
        goto done;
    }

    if (value2 != *((int *) hg_queue_pop_tail(queue))) {
        fprintf(stderr, "Error: values do not match\n");
        ret = EXIT_FAILURE;
        goto done;
    }

    if (value1 != *((int *) hg_queue_pop_head(queue))) {
        fprintf(stderr, "Error: values do not match\n");
        ret = EXIT_FAILURE;
        goto done;
    }

    if (!hg_queue_is_empty(queue)) {
        fprintf(stderr, "Error: queue should be empty\n");
        ret = EXIT_FAILURE;
        goto done;
    }

done:
    hg_queue_free(queue);
    return ret;
}
