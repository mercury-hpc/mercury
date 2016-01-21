#include "mercury_list.h"

#include "mercury_test_config.h"

#include <stdio.h>
#include <stdlib.h>

static int
int_equal(hg_list_value_t value1, hg_list_value_t value2)
{
    return *((int *) value1) == *((int *) value2);
}

int
main(int argc, char *argv[])
{
    hg_list_t *list = NULL;
    hg_list_entry_t *entry = NULL;
    int value1 = 10, value2 = 20;
    int ret = EXIT_SUCCESS;

    (void) argc;
    (void) argv;

    list = hg_list_new();
    if (!list) {
        fprintf(stderr, "Error: list could not be created\n");
        ret = EXIT_FAILURE;
        goto done;
    }

    if (hg_list_is_empty(list) != HG_UTIL_TRUE) {
        fprintf(stderr, "Error: list should be empty\n");
        ret = EXIT_FAILURE;
        goto done;
    }

    entry = hg_list_insert_head(list, (hg_list_value_t) &value1);
    if (!entry) {
        fprintf(stderr, "Error: could not insert entry\n");
        ret = EXIT_FAILURE;
        goto done;
    }

    if (!hg_list_insert_after(entry, (hg_list_value_t) &value2)) {
        fprintf(stderr, "Error: could not insert entry\n");
        ret = EXIT_FAILURE;
        goto done;
    }

    entry = hg_list_first(list);
    if (*((int *) hg_list_data(entry)) != value1) {
        fprintf(stderr, "Error: entries mismatch\n");
        ret = EXIT_FAILURE;
        goto done;
    }

    entry = hg_list_next(entry);
    if (*((int *) hg_list_data(entry)) != value2) {
        fprintf(stderr, "Error: entries mismatch\n");
        ret = EXIT_FAILURE;
        goto done;
    }

    entry = hg_list_find_data(list, int_equal, (hg_list_value_t) &value1);
    if (!entry) {
        fprintf(stderr, "Error: missing entry\n");
        ret = EXIT_FAILURE;
        goto done;
    }
    if (*((int *) hg_list_data(entry)) != value1) {
        fprintf(stderr, "Error: entries mismatch\n");
        ret = EXIT_FAILURE;
        goto done;
    }

    if (!hg_list_insert_before(entry, (hg_list_value_t) &value2)) {
        fprintf(stderr, "Error: could not insert entry\n");
        ret = EXIT_FAILURE;
        goto done;
    }

    if (0 == hg_list_remove_data(list, int_equal, (hg_list_value_t) &value1)) {
        fprintf(stderr, "Error: data should have been removed\n");
        ret = EXIT_FAILURE;
        goto done;
    }

    entry = hg_list_first(list);
    if (!entry) {
        fprintf(stderr, "Error: list should contain at least one entry\n");
        ret = EXIT_FAILURE;
        goto done;
    }

    if (*((int *) hg_list_data(entry)) != value2) {
        fprintf(stderr, "Error: entries mismatch\n");
        ret = EXIT_FAILURE;
        goto done;
    }

    if (HG_UTIL_SUCCESS != hg_list_remove_entry(entry)) {
        fprintf(stderr, "Error: could not remove entry\n");
        ret = EXIT_FAILURE;
        goto done;
    }

done:
    hg_list_free(list);
    return ret;
}
