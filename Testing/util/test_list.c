#include "mercury_list.h"

#include "mercury_test_config.h"

#include <stdio.h>
#include <stdlib.h>

static int
int_equal(hg_list_value_t value1, hg_list_value_t value2)
{
    return *((int *) value1) == *((int *) value2);
}

static int
int_compare(hg_list_value_t value1, hg_list_value_t value2)
{
    if (int_equal(value1, value2)) return 0;
    if (*((int *) value1) < *((int *) value2))
        return -1;
    else
        return 1;
}

int
main(int argc, char *argv[])
{
    hg_list_entry_t *entry = NULL;
    hg_list_entry_t *list = NULL;
    hg_list_value_t *array = NULL;
    hg_list_iter_t iterator;
    int value1 = 10, value2 = 20;
    int ret = EXIT_SUCCESS;

    (void) argc;
    (void) argv;

    if (hg_list_length(list)) {
        fprintf(stderr, "Error: list should be empty\n");
        ret = EXIT_FAILURE;
        goto done;
    }

    hg_list_append(&list, (hg_list_value_t) &value1);
    hg_list_prepend(&list, (hg_list_value_t) &value2);

    if (2 != hg_list_length(list)) {
        fprintf(stderr, "Error: list should contain 2 entries\n");
        ret = EXIT_FAILURE;
        goto done;
    }

    array = hg_list_to_array(list);
    if (*((int *) array[0]) != value2) {
        fprintf(stderr, "Error: entries mismatch\n");
        ret = EXIT_FAILURE;
        goto done;
    }
    if (*((int *) array[1]) != value1) {
        fprintf(stderr, "Error: entries mismatch\n");
        ret = EXIT_FAILURE;
        goto done;
    }

    hg_list_sort(&list, int_compare);

    if (*((int *) hg_list_data(list)) != value1) {
        fprintf(stderr, "Error: entries mismatch\n");
        ret = EXIT_FAILURE;
        goto done;
    }

    entry = hg_list_next(list);
    if (*((int *) hg_list_data(entry)) != value2) {
        fprintf(stderr, "Error: entries mismatch\n");
        ret = EXIT_FAILURE;
        goto done;
    }

    entry = hg_list_prev(entry);
    if (*((int *) hg_list_data(list)) != value1) {
        fprintf(stderr, "Error: entries mismatch\n");
        ret = EXIT_FAILURE;
        goto done;
    }

    entry = hg_list_nth_entry(list, 1);
    if (*((int *) hg_list_data(entry)) != value2) {
        fprintf(stderr, "Error: entries mismatch\n");
        ret = EXIT_FAILURE;
        goto done;
    }

    if (*((int *) hg_list_nth_data(list, 1)) != value2) {
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

    hg_list_iterate(&list, &iterator);
    if (!hg_list_iter_has_more(&iterator)) {
        fprintf(stderr, "Error: there should be more entries\n");
        ret = EXIT_FAILURE;
        goto done;
    }

    if (*((int *) hg_list_iter_next(&iterator)) != value1) {
        fprintf(stderr, "Error: entries mismatch\n");
        ret = EXIT_FAILURE;
        goto done;
    }
    if (*((int *) hg_list_iter_next(&iterator)) != value2) {
        fprintf(stderr, "Error: entries mismatch\n");
        ret = EXIT_FAILURE;
        goto done;
    }

    hg_list_iter_remove(&iterator);

    if (1 != hg_list_length(list)) {
        fprintf(stderr, "Error: list should contain 1 entry\n");
        ret = EXIT_FAILURE;
        goto done;
    }

    hg_list_append(&list, (hg_list_value_t) &value1);
    hg_list_remove_data(&list, int_equal, (hg_list_value_t) &value1);

    hg_list_remove_entry(&list, list);

done:
    free(array);
    hg_list_free(list);
    return ret;
}
