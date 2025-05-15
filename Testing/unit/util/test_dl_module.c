/**
 * Copyright (c) 2013-2022 UChicago Argonne, LLC and The HDF Group.
 * Copyright (c) 2022-2024 Intel Corporation.
 * Copyright (c) 2024-2025 Hewlett Packard Enterprise Development LP.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "mercury_test_util_config.h"

HG_UTIL_PLUGIN int hg_test_dl_module_var_g = 1;

HG_UTIL_PLUGIN int
hg_test_dl_module_func(void);

HG_UTIL_PLUGIN int
hg_test_dl_module_func(void)
{
    return 1;
}
