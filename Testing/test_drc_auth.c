/**
 * Copyright (c) 2013-2021 UChicago Argonne, LLC and The HDF Group.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "mercury_test_drc.h"

extern void
hg_test_parse_options(
    int argc, char *argv[], struct hg_test_info *hg_test_info);

/**
 *
 */
int
main(int argc, char *argv[])
{
    struct hg_test_info hg_test_info = {0};

    hg_test_parse_options(argc, argv, &hg_test_info);

    hg_test_drc_acquire(argc, argv, &hg_test_info);

    hg_test_drc_release(&hg_test_info);

    return EXIT_SUCCESS;
}
