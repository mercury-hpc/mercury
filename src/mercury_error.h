/**
 * Copyright (c) 2013-2021 UChicago Argonne, LLC and The HDF Group.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef MERCURY_ERROR_H
#define MERCURY_ERROR_H

#include "mercury_config.h"
#include "mercury_log.h"

#include <inttypes.h>

/*****************/
/* Public Macros */
/*****************/

#define HG_LOG_ERROR(...)   HG_LOG_WRITE(hg, HG_LOG_LEVEL_ERROR, __VA_ARGS__)
#define HG_LOG_WARNING(...) HG_LOG_WRITE(hg, HG_LOG_LEVEL_WARNING, __VA_ARGS__)
#ifdef HG_HAS_DEBUG
#    define HG_LOG_DEBUG(...) HG_LOG_WRITE(hg, HG_LOG_LEVEL_DEBUG, __VA_ARGS__)
#else
#    define HG_LOG_DEBUG(...) (void) 0
#endif

/* Branch predictor hints */
#ifndef _WIN32
#    define likely(x)   __builtin_expect(!!(x), 1)
#    define unlikely(x) __builtin_expect(!!(x), 0)
#else
#    define likely(x)   (x)
#    define unlikely(x) (x)
#endif

/* Error macros */
#define HG_GOTO_DONE(label, ret, ret_val)                                      \
    do {                                                                       \
        ret = ret_val;                                                         \
        goto label;                                                            \
    } while (0)

#define HG_GOTO_ERROR(label, ret, err_val, ...)                                \
    do {                                                                       \
        HG_LOG_ERROR(__VA_ARGS__);                                             \
        ret = err_val;                                                         \
        goto label;                                                            \
    } while (0)

/* Check for hg_ret value and goto label */
#define HG_CHECK_HG_ERROR(label, hg_ret, ...)                                  \
    do {                                                                       \
        if (unlikely(hg_ret != HG_SUCCESS)) {                                  \
            HG_LOG_ERROR(__VA_ARGS__);                                         \
            goto label;                                                        \
        }                                                                      \
    } while (0)

/* Check for cond, set ret to err_val and goto label */
#define HG_CHECK_ERROR(cond, label, ret, err_val, ...)                         \
    do {                                                                       \
        if (unlikely(cond)) {                                                  \
            HG_LOG_ERROR(__VA_ARGS__);                                         \
            ret = err_val;                                                     \
            goto label;                                                        \
        }                                                                      \
    } while (0)

#define HG_CHECK_ERROR_NORET(cond, label, ...)                                 \
    do {                                                                       \
        if (unlikely(cond)) {                                                  \
            HG_LOG_ERROR(__VA_ARGS__);                                         \
            goto label;                                                        \
        }                                                                      \
    } while (0)

#define HG_CHECK_ERROR_DONE(cond, ...)                                         \
    do {                                                                       \
        if (unlikely(cond)) {                                                  \
            HG_LOG_ERROR(__VA_ARGS__);                                         \
        }                                                                      \
    } while (0)

/* Check for cond and print warning */
#define HG_CHECK_WARNING(cond, ...)                                            \
    do {                                                                       \
        if (unlikely(cond)) {                                                  \
            HG_LOG_WARNING(__VA_ARGS__);                                       \
        }                                                                      \
    } while (0)

#endif /* MERCURY_ERROR_H */
