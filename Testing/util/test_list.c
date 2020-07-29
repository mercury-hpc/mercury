#include "mercury_list.h"

#include "mercury_test_config.h"

#include <stdio.h>
#include <stdlib.h>

struct my_entry {
    int value;
    HG_LIST_ENTRY(my_entry) entry;
};

HG_LIST_HEAD_DECL(my_head, my_entry);

int
main(void)
{
    HG_LIST_HEAD_INIT(my_head, list);
    int ret = EXIT_SUCCESS;
    int value1 = 10, value2 = 20;
    struct my_entry my_entry1 = {.value = value1};
    struct my_entry my_entry2 = {.value = value2};

    if (!HG_LIST_IS_EMPTY(&list)) {
        fprintf(stderr, "Error: list should be empty\n");
        ret = EXIT_FAILURE;
        goto done;
    }

    HG_LIST_INSERT_HEAD(&list, &my_entry1, entry);
    HG_LIST_INSERT_AFTER(&my_entry1, &my_entry2, entry);

    if (HG_LIST_FIRST(&list)->value != value1) {
        fprintf(stderr, "Error: entries mismatch\n");
        ret = EXIT_FAILURE;
        goto done;
    }

    if (HG_LIST_NEXT(HG_LIST_FIRST(&list), entry)->value != value2) {
        fprintf(stderr, "Error: entries mismatch\n");
        ret = EXIT_FAILURE;
        goto done;
    }

    HG_LIST_REMOVE(&my_entry1, entry);
    HG_LIST_REMOVE(&my_entry2, entry);
    if (!HG_LIST_IS_EMPTY(&list)) {
        fprintf(stderr, "Error: list should be empty\n");
        ret = EXIT_FAILURE;
        goto done;
    }

done:
    return ret;
}
