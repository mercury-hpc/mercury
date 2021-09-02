/*
 * Copyright (C) 2013-2020 Argonne National Laboratory, Department of Energy,
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

#include "mercury_log.h"

#include <inttypes.h>

/* Default log outlet */
extern NA_PRIVATE HG_LOG_OUTLET_DECL(na);

/* Fatal log outlet always 'on' by default */
extern NA_PRIVATE HG_LOG_OUTLET_DECL(fatal);

/* Specific outlets */
extern NA_PRIVATE HG_LOG_OUTLET_DECL(cls);  /* Class */
extern NA_PRIVATE HG_LOG_OUTLET_DECL(ctx);  /* Context */
extern NA_PRIVATE HG_LOG_OUTLET_DECL(op);   /* Operations */
extern NA_PRIVATE HG_LOG_OUTLET_DECL(addr); /* Addresses */
extern NA_PRIVATE HG_LOG_OUTLET_DECL(msg);  /* Messages */
extern NA_PRIVATE HG_LOG_OUTLET_DECL(mem);  /* Memory */
extern NA_PRIVATE HG_LOG_OUTLET_DECL(rma);  /* RMA */
extern NA_PRIVATE HG_LOG_OUTLET_DECL(poll); /* Progress */

/* Base log macros */
#define NA_LOG_ERROR(...) HG_LOG_WRITE(na, HG_LOG_LEVEL_ERROR, __VA_ARGS__)
#define NA_LOG_SUBSYS_ERROR(subsys, ...)                                       \
    HG_LOG_WRITE(subsys, HG_LOG_LEVEL_ERROR, __VA_ARGS__)
#define NA_LOG_WARNING(...) HG_LOG_WRITE(na, HG_LOG_LEVEL_WARNING, __VA_ARGS__)
#define NA_LOG_SUBSYS_WARNING(subsys, ...)                                     \
    HG_LOG_WRITE(subsys, HG_LOG_LEVEL_WARNING, __VA_ARGS__)
#ifdef NA_HAS_DEBUG
#    define NA_LOG_DEBUG(...) HG_LOG_WRITE_DEBUG(na, NULL, __VA_ARGS__)
#    define NA_LOG_SUBSYS_DEBUG(subsys, ...)                                   \
        HG_LOG_WRITE_DEBUG(subsys, NULL, __VA_ARGS__)
#    define NA_LOG_SUBSYS_DEBUG_FUNC(subsys, debug_func, ...)                  \
        HG_LOG_WRITE_DEBUG(subsys, debug_func, __VA_ARGS__)
#else
#    define NA_LOG_DEBUG(...)             (void) 0
#    define NA_LOG_SUBSYS_DEBUG(...)      (void) 0
#    define NA_LOG_SUBSYS_DEBUG_FUNC(...) (void) 0
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

/* NA_GOTO_DONE: goto label wrapper and set return value */
#define NA_GOTO_DONE(label, ret, ret_val)                                      \
    do {                                                                       \
        ret = ret_val;                                                         \
        goto label;                                                            \
    } while (0)

/* NA_GOTO_ERROR: goto label wrapper and set return value / log error */
#define NA_GOTO_ERROR(label, ret, err_val, ...)                                \
    do {                                                                       \
        NA_LOG_ERROR(__VA_ARGS__);                                             \
        ret = err_val;                                                         \
        goto label;                                                            \
    } while (0)

/* NA_GOTO_ERROR: goto label wrapper and set return value / log subsys error */
#define NA_GOTO_SUBSYS_ERROR(subsys, label, ret, err_val, ...)                 \
    do {                                                                       \
        NA_LOG_SUBSYS_ERROR(subsys, __VA_ARGS__);                              \
        ret = err_val;                                                         \
        goto label;                                                            \
    } while (0)

/* NA_CHECK_NA_ERROR: NA type error check */
#define NA_CHECK_NA_ERROR(label, na_ret, ...)                                  \
    do {                                                                       \
        if (unlikely(na_ret != NA_SUCCESS)) {                                  \
            NA_LOG_ERROR(__VA_ARGS__);                                         \
            goto label;                                                        \
        }                                                                      \
    } while (0)

/* NA_CHECK_SUBSYS_NA_ERROR: subsys NA type error check */
#define NA_CHECK_SUBSYS_NA_ERROR(subsys, label, na_ret, ...)                   \
    do {                                                                       \
        if (unlikely(na_ret != NA_SUCCESS)) {                                  \
            NA_LOG_SUBSYS_ERROR(subsys, __VA_ARGS__);                          \
            goto label;                                                        \
        }                                                                      \
    } while (0)

/* NA_CHECK_ERROR: error check on cond */
#define NA_CHECK_ERROR(cond, label, ret, err_val, ...)                         \
    do {                                                                       \
        if (unlikely(cond)) {                                                  \
            NA_LOG_ERROR(__VA_ARGS__);                                         \
            ret = err_val;                                                     \
            goto label;                                                        \
        }                                                                      \
    } while (0)

/* NA_CHECK_SUBSYS_ERROR: subsys error check on cond */
#define NA_CHECK_SUBSYS_ERROR(subsys, cond, label, ret, err_val, ...)          \
    do {                                                                       \
        if (unlikely(cond)) {                                                  \
            NA_LOG_SUBSYS_ERROR(subsys, __VA_ARGS__);                          \
            ret = err_val;                                                     \
            goto label;                                                        \
        }                                                                      \
    } while (0)

/* NA_CHECK_ERROR_NORET: error check / no return values */
#define NA_CHECK_ERROR_NORET(cond, label, ...)                                 \
    do {                                                                       \
        if (unlikely(cond)) {                                                  \
            NA_LOG_ERROR(__VA_ARGS__);                                         \
            goto label;                                                        \
        }                                                                      \
    } while (0)

/* NA_CHECK_SUBSYS_ERROR_NORET: subsys error check / no return values */
#define NA_CHECK_SUBSYS_ERROR_NORET(subsys, cond, label, ...)                  \
    do {                                                                       \
        if (unlikely(cond)) {                                                  \
            NA_LOG_SUBSYS_ERROR(subsys, __VA_ARGS__);                          \
            goto label;                                                        \
        }                                                                      \
    } while (0)

/* NA_CHECK_ERROR_DONE: error check after clean up / done labels */
#define NA_CHECK_ERROR_DONE(cond, ...)                                         \
    do {                                                                       \
        if (unlikely(cond)) {                                                  \
            NA_LOG_ERROR(__VA_ARGS__);                                         \
        }                                                                      \
    } while (0)

/* NA_CHECK_SUBSYS_ERROR_DONE: subsys error check after clean up labels */
#define NA_CHECK_SUBSYS_ERROR_DONE(subsys, cond, ...)                          \
    do {                                                                       \
        if (unlikely(cond)) {                                                  \
            NA_LOG_SUBSYS_ERROR(subsys, __VA_ARGS__);                          \
        }                                                                      \
    } while (0)

/* NA_CHECK_WARNING: warning check on cond */
#define NA_CHECK_WARNING(cond, ...)                                            \
    do {                                                                       \
        if (unlikely(cond)) {                                                  \
            NA_LOG_WARNING(__VA_ARGS__);                                       \
        }                                                                      \
    } while (0)

/* NA_CHECK_SUBSYS_WARNING: subsys warning check on cond */
#define NA_CHECK_SUBSYS_WARNING(subsys, cond, ...)                             \
    do {                                                                       \
        if (unlikely(cond)) {                                                  \
            NA_LOG_SUBSYS_WARNING(subsys, __VA_ARGS__);                        \
        }                                                                      \
    } while (0)

#endif /* NA_ERROR_H */
