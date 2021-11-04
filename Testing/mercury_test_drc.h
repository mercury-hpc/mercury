/**
 * Copyright (c) 2013-2021 UChicago Argonne, LLC and The HDF Group.
 *
 * SPDX-License-Identifier: BSD-3-Clause
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
