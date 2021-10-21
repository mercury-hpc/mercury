/*
 * Copyright (C) 2013-2020 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#ifndef NA_PLUGIN_H
#define NA_PLUGIN_H

#include "na.h"
#include "na_error.h"

#include "mercury_atomic_queue.h"
#include "mercury_queue.h"
#include "mercury_thread_condition.h"
#include "mercury_thread_mutex.h"

/*************************************/
/* Public Type and Struct Definition */
/*************************************/

/* Private callback type for NA plugins */
typedef void (*na_plugin_cb_t)(void *arg);

/* Completion data stored in completion queue */
struct na_cb_completion_data {
    struct na_cb_info callback_info; /* Callback info struct */
    na_cb_t callback;                /* Pointer to function */
    na_plugin_cb_t plugin_callback;  /* Callback which will be called after
                                      * the user callback returns. */
    void *plugin_callback_args;      /* Argument to plugin_callback */
    HG_QUEUE_ENTRY(na_cb_completion_data) entry; /* Completion queue entry */
};

/*****************/
/* Public Macros */
/*****************/

/* Remove warnings from variables that are only used for debug */
#ifdef NDEBUG
#    define NA_DEBUG_USED NA_UNUSED
#else
#    define NA_DEBUG_USED
#endif

#ifdef NA_HAS_DEBUG
#    define NA_DEBUG_LOG_USED
#else
#    define NA_DEBUG_LOG_USED NA_UNUSED
#endif

/**
 * container_of - cast a member of a structure out to the containing structure
 * \ptr:        the pointer to the member.
 * \type:       the type of the container struct this is embedded in.
 * \member:     the name of the member within the struct.
 *
 */
#if !defined(container_of)
#    define container_of(ptr, type, member)                                    \
        ((type *) ((char *) ptr - offsetof(type, member)))
#endif

/**
 * Min/max macros
 */
#ifndef MAX
#    define MAX(a, b) (((a) > (b)) ? (a) : (b))
#endif
#ifndef MIN
#    define MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif

/**
 * Plugin ops definition
 */
#define NA_PLUGIN_OPS(plugin_name) na_##plugin_name##_class_ops_g

/**
 * Encode type
 */
#define NA_TYPE_ENCODE(label, ret, buf_ptr, buf_size_left, data, size)         \
    do {                                                                       \
        NA_CHECK_ERROR(buf_size_left < size, label, ret, NA_OVERFLOW,          \
            "Buffer size too small (%" PRIu64 ")", buf_size_left);             \
        memcpy(buf_ptr, data, size);                                           \
        buf_ptr += size;                                                       \
        buf_size_left -= size;                                                 \
    } while (0)

#define NA_ENCODE(label, ret, buf_ptr, buf_size_left, data, type)              \
    NA_TYPE_ENCODE(label, ret, buf_ptr, buf_size_left, data, sizeof(type))

#define NA_ENCODE_ARRAY(label, ret, buf_ptr, buf_size_left, data, type, count) \
    NA_TYPE_ENCODE(                                                            \
        label, ret, buf_ptr, buf_size_left, data, sizeof(type) * count)

/**
 * Decode type
 */
#define NA_TYPE_DECODE(label, ret, buf_ptr, buf_size_left, data, size)         \
    do {                                                                       \
        NA_CHECK_ERROR(buf_size_left < size, label, ret, NA_OVERFLOW,          \
            "Buffer size too small (%" PRIu64 ")", buf_size_left);             \
        memcpy(data, buf_ptr, size);                                           \
        buf_ptr += size;                                                       \
        buf_size_left -= size;                                                 \
    } while (0)

#define NA_DECODE(label, ret, buf_ptr, buf_size_left, data, type)              \
    NA_TYPE_DECODE(label, ret, buf_ptr, buf_size_left, data, sizeof(type))

#define NA_DECODE_ARRAY(label, ret, buf_ptr, buf_size_left, data, type, count) \
    NA_TYPE_DECODE(                                                            \
        label, ret, buf_ptr, buf_size_left, data, sizeof(type) * count)

/*********************/
/* Public Prototypes */
/*********************/

#ifdef __cplusplus
extern "C" {
#endif

/* Private routines for use inside NA plugins */

/**
 * Convert cb type to string (null terminated).
 *
 * \param cb_type [IN]          callback type
 *
 * \return String
 */
NA_PRIVATE const char *
na_cb_type_to_string(na_cb_type_t cb_type) NA_WARN_UNUSED_RESULT;

/**
 * Add callback to context completion queue.
 *
 * \param context [IN/OUT]              pointer to context of execution
 * \param na_cb_completion_data [IN]    pointer to completion data
 *
 */
NA_PRIVATE void
na_cb_completion_add(
    na_context_t *context, struct na_cb_completion_data *na_cb_completion_data);

/*********************/
/* Public Variables */
/*********************/

#ifdef NA_HAS_SM
extern NA_PRIVATE const struct na_class_ops NA_PLUGIN_OPS(sm);
#endif
#ifdef NA_HAS_BMI
extern NA_PRIVATE const struct na_class_ops NA_PLUGIN_OPS(bmi);
#endif
#ifdef NA_HAS_MPI
extern NA_PRIVATE const struct na_class_ops NA_PLUGIN_OPS(mpi);
#endif
#ifdef NA_HAS_CCI
extern NA_PRIVATE const struct na_class_ops NA_PLUGIN_OPS(cci);
#endif
#ifdef NA_HAS_OFI
extern NA_PRIVATE const struct na_class_ops NA_PLUGIN_OPS(ofi);
#endif
#ifdef NA_HAS_UCX
extern NA_PRIVATE const struct na_class_ops NA_PLUGIN_OPS(ucx);
#endif

#ifdef __cplusplus
}
#endif

#endif /* NA_PLUGIN_H */
