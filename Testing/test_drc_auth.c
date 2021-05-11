/*
 * Copyright (C) 2013-2020 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
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
