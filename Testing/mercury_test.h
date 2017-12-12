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

#include "na_test.h"
#include "mercury.h"
#include "mercury_request.h"
#ifdef MERCURY_TESTING_HAS_THREAD_POOL
# include "mercury_thread_pool.h"
# include "mercury_thread_mutex.h"
#endif
#include "mercury_atomic.h"

#include "test_rpc.h"
#include "test_bulk.h"
#ifndef _WIN32
# include "test_posix.h"
#endif
#include "test_overflow.h"

/*************************************/
/* Public Type and Struct Definition */
/*************************************/

struct hg_test_info {
    hg_class_t *hg_class;
    hg_context_t *context;
    hg_request_class_t *request_class;
    hg_addr_t target_addr;
    hg_bool_t listen;
    hg_bool_t self_forward;
    hg_bool_t auth;
    struct na_test_info na_test_info;
#ifdef MERCURY_TESTING_HAS_THREAD_POOL
    hg_thread_pool_t *thread_pool;
    hg_thread_mutex_t bulk_handle_mutex;
#endif
    hg_bulk_t bulk_handle;
    hg_atomic_int32_t finalizing_count;
};

/*****************/
/* Public Macros */
/*****************/

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

/*********************/
/* Public Prototypes */
/*********************/

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Initialize client/server
 */
hg_return_t
HG_Test_init(int argc, char *argv[], struct hg_test_info *hg_test_info);

/**
 * Finalize client/server
 */
hg_return_t
HG_Test_finalize(struct hg_test_info *hg_test_info);

#ifdef __cplusplus
}
#endif

#endif /* MERCURY_TEST_H */
