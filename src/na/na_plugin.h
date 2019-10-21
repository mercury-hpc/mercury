/*
 * Copyright (C) 2013-2019 Argonne National Laboratory, Department of Energy,
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
#include "mercury_thread_mutex.h"
#include "mercury_thread_condition.h"

/*************************************/
/* Public Type and Struct Definition */
/*************************************/

/* Private callback type for NA plugins */
typedef void (*na_plugin_cb_t)(void *arg);

/* Completion data stored in completion queue */
struct na_cb_completion_data {
    na_cb_t callback;                   /* Pointer to function */
    struct na_cb_info callback_info;    /* Callback info struct */
    na_plugin_cb_t plugin_callback;     /* Callback which will be called after
                                         * the user callback returns. */
    void *plugin_callback_args;         /* Argument to plugin_callback */
    HG_QUEUE_ENTRY(na_cb_completion_data) entry; /* Completion queue entry */
};

/*****************/
/* Public Macros */
/*****************/

/* Remove warnings when plugin does not use callback arguments */
#if defined(__cplusplus)
# define NA_UNUSED
#elif defined(__GNUC__) && (__GNUC__ >= 4)
# define NA_UNUSED __attribute__((unused))
#else
# define NA_UNUSED
#endif

/**
 * container_of - cast a member of a structure out to the containing structure
 * \ptr:        the pointer to the member.
 * \type:       the type of the container struct this is embedded in.
 * \member:     the name of the member within the struct.
 *
 */
#if !defined(container_of)
# define container_of(ptr, type, member) \
    ((type *) ((char *) ptr - offsetof(type, member)))
#endif

/**
 * Min/max macros
 */
#ifndef MAX
# define MAX(a, b) (((a) > (b)) ? (a) : (b))
#endif
#ifndef MIN
# define MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif

/**
 * Plugin ops definition
 */
#define NA_PLUGIN_OPS(plugin_name) \
    const struct na_class_ops na_ ##plugin_name ##_class_ops_g

/*********************/
/* Public Prototypes */
/*********************/

#ifdef __cplusplus
extern "C" {
#endif

/* Private routines for use inside NA plugins */

/**
 * Add callback to context completion queue.
 *
 * \param context [IN/OUT]              pointer to context of execution
 * \param na_cb_completion_data [IN]    pointer to completion data
 *
 * \return NA_SUCCESS or corresponding NA error code (failure is not an option)
 */
NA_EXPORT na_return_t
na_cb_completion_add(
        na_context_t                 *context,
        struct na_cb_completion_data *na_cb_completion_data
        );

/*********************/
/* Public Variables */
/*********************/
#ifdef NA_HAS_SM
NA_EXPORT NA_PLUGIN_OPS(sm);
#endif
#ifdef NA_HAS_BMI
NA_EXPORT NA_PLUGIN_OPS(bmi);
#endif
#ifdef NA_HAS_MPI
NA_EXPORT NA_PLUGIN_OPS(mpi);
#endif
#ifdef NA_HAS_CCI
NA_EXPORT NA_PLUGIN_OPS(cci);
#endif
#ifdef NA_HAS_OFI
NA_EXPORT NA_PLUGIN_OPS(ofi);
#endif

#ifdef __cplusplus
}
#endif

#endif /* NA_PLUGIN_H */
