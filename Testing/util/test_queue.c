#include "mercury_queue.h"

#include "mercury_test_config.h"

#include <stdio.h>
#include <stdlib.h>

struct my_entry {
    int value;
    HG_QUEUE_ENTRY(my_entry) entry;
};

HG_QUEUE_HEAD_DECL(my_head, my_entry);

int
main(void)
{
    HG_QUEUE_HEAD_INIT(my_head, queue);
    int ret = EXIT_SUCCESS;
    int value1 = 10, value2 = 20;
    struct my_entry my_entry1 = {.value = value1};
    struct my_entry my_entry2 = {.value = value2};

    if (!HG_QUEUE_IS_EMPTY(&queue)) {
        fprintf(stderr, "Error: queue should be empty\n");
        ret = EXIT_FAILURE;
        goto done;
    }

    HG_QUEUE_PUSH_TAIL(&queue, &my_entry1, entry);

    if (value1 != HG_QUEUE_FIRST(&queue)->value) {
        fprintf(stderr, "Error: values do not match\n");
        ret = EXIT_FAILURE;
        goto done;
    }

    if (HG_QUEUE_IS_EMPTY(&queue)) {
        fprintf(stderr, "Error: queue should not be empty\n");
        ret = EXIT_FAILURE;
        goto done;
    }

    HG_QUEUE_PUSH_TAIL(&queue, &my_entry2, entry);

    HG_QUEUE_POP_HEAD(&queue, entry);

    if (value2 != HG_QUEUE_FIRST(&queue)->value) {
        fprintf(stderr, "Error: values do not match\n");
        ret = EXIT_FAILURE;
        goto done;
    }

    HG_QUEUE_POP_HEAD(&queue, entry);

    if (!HG_QUEUE_IS_EMPTY(&queue)) {
        fprintf(stderr, "Error: queue should be empty\n");
        ret = EXIT_FAILURE;
        goto done;
    }

done:
    return ret;
}
