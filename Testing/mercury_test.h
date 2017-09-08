/*
 * Copyright (C) 2013-2017 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#ifndef MERCURY_TEST_H
#define MERCURY_TEST_H

#include "na.h"
#include "mercury_test_config.h"
#include "mercury_config.h"
#include "mercury_request.h"

#include "test_rpc.h"
#include "test_bulk.h"
#ifndef _WIN32
#include "test_posix.h"
#endif
#include "test_overflow.h"

/* Default error macro */
#ifdef HG_HAS_VERBOSE_ERROR
  #include <mercury_log.h>
  #define HG_TEST_LOG_MODULE_NAME "HG Test"
  #define HG_TEST_LOG_ERROR(...)                                \
      HG_LOG_WRITE_ERROR(HG_TEST_LOG_MODULE_NAME, __VA_ARGS__)
  #define HG_TEST_LOG_WARNING(...)                              \
      HG_LOG_WRITE_WARNING(HG_TEST_LOG_MODULE_NAME, __VA_ARGS__)
#else
  #define HG_TEST_LOG_ERROR(...) (void)0
  #define HG_TEST_LOG_WARNING(...) (void)0
#endif

#define HG_TEST(x) do {         \
    printf("Testing %-62s", x); \
    fflush(stdout);             \
} while (0)

#define HG_PASSED() do {        \
    puts(" PASSED");            \
    fflush(stdout);             \
} while (0)

#define HG_FAILED() do {        \
    puts("*FAILED*");           \
    fflush(stdout);             \
} while (0)

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Initialize client
 */
hg_class_t *
HG_Test_client_init(int argc, char *argv[], hg_addr_t *addr, int *rank,
        hg_context_t **context, hg_request_class_t **request_class);

/**
 * Initialize server
 */
hg_class_t *
HG_Test_server_init(int argc, char *argv[], hg_addr_t **addr_table,
        unsigned int *addr_table_size, unsigned int *max_number_of_peers,
        hg_context_t **context);

/**
 * Finalize client/server
 */
hg_return_t
HG_Test_finalize(hg_class_t *hg_class);

#ifdef __cplusplus
}
#endif

#endif /* MERCURY_TEST_H */
