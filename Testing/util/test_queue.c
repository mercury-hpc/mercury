#include "mercury_queue.h"

#include "mercury_test_config.h"

#include <stdio.h>
#include <stdlib.h>

int
main(int argc, char *argv[])
{
    hg_util_int32_t value = 0;
    int ret = EXIT_SUCCESS;

    (void) argc;
    (void) argv;


    if (value != 100) {
        fprintf(stderr, "Error: atomic value is %d\n", value);
        ret = EXIT_FAILURE;
    }
    return ret;
}
