/*
 * Copyright (C) 2013-2019 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#ifndef NA_ERROR_H
#define NA_ERROR_H

#include "na_config.h"

/* Default error macro */
#ifdef NA_HAS_VERBOSE_ERROR
# include <mercury_log.h>
# define NA_LOG_MODULE_NAME "NA"
# define NA_LOG_ERROR(...)                                      \
    HG_LOG_WRITE_ERROR(NA_LOG_MODULE_NAME, __VA_ARGS__)
# define NA_LOG_DEBUG(...)                                      \
    HG_LOG_WRITE_DEBUG(NA_LOG_MODULE_NAME, __VA_ARGS__)
# define NA_LOG_WARNING(...)                                    \
    HG_LOG_WRITE_WARNING(NA_LOG_MODULE_NAME, __VA_ARGS__)
#else
# define NA_LOG_ERROR(...)      (void)0
# define NA_LOG_DEBUG(...)      (void)0
# define NA_LOG_WARNING(...)    (void)0
#endif

/* Branch predictor hints */
#ifndef _WIN32
# define likely(x)       __builtin_expect(!!(x), 1)
# define unlikely(x)     __builtin_expect(!!(x), 0)
#else
# define likely(x)       (x)
# define unlikely(x)     (x)
#endif

/* Error macros */
#define NA_GOTO_DONE(label, ret, ret_val) do {                  \
    ret = ret_val;                                              \
    goto label;                                                 \
} while (0)

#define NA_GOTO_ERROR(label, ret, err_val, ...) do {            \
    NA_LOG_ERROR(__VA_ARGS__);                                  \
    ret = err_val;                                              \
    goto label;                                                 \
} while (0)

/* Check for na_ret value and goto label */
#define NA_CHECK_NA_ERROR(label, na_ret, ...) do {              \
    if (unlikely(na_ret != NA_SUCCESS)) {                       \
        NA_LOG_ERROR(__VA_ARGS__);                              \
        goto label;                                             \
    }                                                           \
} while (0)

/* Check for cond, set ret to err_val and goto label */
#define NA_CHECK_ERROR(cond, label, ret, err_val, ...) do {     \
    if (unlikely(cond)) {                                       \
        NA_LOG_ERROR(__VA_ARGS__);                              \
        ret = err_val;                                          \
        goto label;                                             \
    }                                                           \
} while (0)

#define NA_CHECK_ERROR_NORET(cond, label, ...) do {             \
    if (unlikely(cond)) {                                       \
        NA_LOG_ERROR(__VA_ARGS__);                              \
        goto label;                                             \
    }                                                           \
} while (0)

#endif /* NA_ERROR_H */
