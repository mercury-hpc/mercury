/*
 * Copyright (C) 2013-2020 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#ifndef MERCURY_TEST_DRC_H
#define MERCURY_TEST_DRC_H

#include "mercury_test.h"

/*********************/
/* Public Prototypes */
/*********************/

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Acquire DRC token
 */
hg_return_t
hg_test_drc_acquire(int argc, char *argv[], struct hg_test_info *hg_test_info);

/**
 * Release DRC token
 */
hg_return_t
hg_test_drc_release(struct hg_test_info *hg_test_info);

#ifdef __cplusplus
}
#endif

#endif /* MERCURY_TEST_DRC_H */
