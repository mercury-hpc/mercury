/*
 * Copyright (C) 2013-2014 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#ifndef MERCURY_HL_H
#define MERCURY_HL_H

#include "mercury.h"
#include "mercury_bulk.h"

/**
 * Define macros so that default classes/contexts can be easily renamed
 * if we ever need to. Users should use macros and not global variables
 * directly.
 */
#define NA_CLASS_DEFAULT na_class_default_g
#define NA_CONTEXT_DEFAULT na_context_default_g
#define NA_ADDR_DEFAULT na_addr_default_g

#define HG_CLASS_DEFAULT hg_class_default_g
#define HG_CONTEXT_DEFAULT hg_context_default_g

#ifdef __cplusplus
extern "C" {
#endif

/* NA default */
extern HG_EXPORT na_class_t *NA_CLASS_DEFAULT;
extern HG_EXPORT na_context_t *NA_CONTEXT_DEFAULT;
extern HG_EXPORT na_addr_t NA_ADDR_DEFAULT;

/* HG default */
extern HG_EXPORT hg_class_t *HG_CLASS_DEFAULT;
extern HG_EXPORT hg_context_t *HG_CONTEXT_DEFAULT;

/**
 * Initialize Mercury high-level layer and create default classes/contexts.
 * If no info_string is passed, the HG HL layer will attempt to initialize
 * NA by using the value contained in the environment variable called
 * MERCURY_PORT_NAME. NB: HG_Hl_finalize is registered with atexit() so that
 * default classes/contexts are freed at process termination.
 *
 * \param info_string [IN]      host address with port number
 * \param listen [IN]           listen for incoming connections
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_EXPORT hg_return_t
HG_Hl_init(
        const char *info_string,
        na_bool_t listen
        );

/**
 * Finalize Mercury high-level layer.
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_EXPORT hg_return_t
HG_Hl_finalize(
        void
        );

/**
 * Forward a call and wait for its completion. A HG handle must have been
 * previously created. Output can be queried using HG_Get_output() and freed
 * using HG_Free_output().
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_EXPORT hg_return_t
HG_Hl_forward_wait(
        hg_handle_t handle,
        void *in_struct
        );

/**
 * Initiate a bulk data transfer and wait for its completion.
 *
 * \param context [IN]          pointer to HG bulk context
 * \param op [IN]               transfer operation:
 *                                  - HG_BULK_PUSH
 *                                  - HG_BULK_PULL
 * \param origin_addr [IN]      abstract NA address of origin
 * \param origin_handle [IN]    abstract bulk handle
 * \param origin_offset [IN]    offset
 * \param local_handle [IN]     abstract bulk handle
 * \param local_offset [IN]     offset
 * \param size [IN]             size of data to be transferred
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_EXPORT hg_return_t
HG_Hl_bulk_transfer_wait(
        hg_bulk_context_t *context,
        hg_bulk_op_t op,
        na_addr_t origin_addr,
        hg_bulk_t origin_handle,
        hg_size_t origin_offset,
        hg_bulk_t local_handle,
        hg_size_t local_offset,
        hg_size_t size
        );

#ifdef __cplusplus
}
#endif

#endif /* MERCURY_HL_H */
