/**
 * Copyright (c) 2024-2025 Hewlett Packard Enterprise Development LP.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "mercury_test_util_config.h"

#include "mercury_dlog.h"

#include <stdio.h>
#include <stdlib.h>

#define HG_TEST_DLOG_NENTS 128
#define HG_TEST_NCOUNTERS  64

struct hg_dlog_entry hg_test_le_g[HG_TEST_DLOG_NENTS];
static struct hg_dlog hg_test_dlog_g =
    HG_DLOG_INITIALIZER("test", hg_test_dlog_g, hg_test_le_g, 1024, 1);

static void
hg_test_dlog_free(void) HG_ATTR_DESTRUCTOR;
static void
hg_test_dlog_free(void)
{
    hg_dlog_free(&hg_test_dlog_g);
}

int
main(void)
{
    int i;

    for (i = 0; i < HG_TEST_NCOUNTERS; i++) {
        hg_atomic_int32_t *cnt32 = NULL;

        hg_dlog_mkcount32(&hg_test_dlog_g, &cnt32, "cnt32", "test counter 32");
        hg_atomic_set32(cnt32, i);
    }

    for (i = 0; i < HG_TEST_NCOUNTERS; i++) {
        hg_atomic_int64_t *cnt64 = NULL;

        hg_dlog_mkcount64(&hg_test_dlog_g, &cnt64, "cnt64", "test counter 64");
        hg_atomic_set64(cnt64, i);
    }

    hg_dlog_dump(&hg_test_dlog_g, fprintf, stdout, 0);
    hg_dlog_dump_counters(&hg_test_dlog_g, fprintf, stdout, 0);

    return EXIT_SUCCESS;
}
