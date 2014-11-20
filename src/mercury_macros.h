/*
 * Copyright (C) 2013-2014 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#ifndef MERCURY_MACROS_H
#define MERCURY_MACROS_H

#include "mercury.h"
#include "mercury_proc.h"

#ifdef HG_HAS_BOOST
#include <boost/preprocessor.hpp>

/* Booleans for MERCURY_GEN_MACROS */
#define MERCURY_GEN_FALSE 0
#define MERCURY_GEN_TRUE  1

/********************** Utility macros **********************/

/* Return parameter with fixed name */
#define HG_GEN_RET_PARAM(ret_type) ((ret_type)(ret))

/* Get type / name */
#define HG_GEN_GET_TYPE(field) BOOST_PP_SEQ_HEAD(field)
#define HG_GEN_GET_NAME(field) BOOST_PP_SEQ_CAT(BOOST_PP_SEQ_TAIL(field))

/* Get struct field */
#define HG_GEN_STRUCT_FIELD(r, data, param) \
    HG_GEN_GET_TYPE(param) HG_GEN_GET_NAME(param);

/* Generate structure */
#define HG_GEN_STRUCT(struct_type_name, fields) \
typedef struct \
{   \
    BOOST_PP_SEQ_FOR_EACH(HG_GEN_STRUCT_FIELD, , fields) \
    \
} struct_type_name;

/* Generate proc for struct field */
#define HG_GEN_PROC(r, struct_name, field) \
    ret = BOOST_PP_CAT(hg_proc_, HG_GEN_GET_TYPE(field) \
            (proc, &struct_name->HG_GEN_GET_NAME(field))); \
    if (ret != HG_SUCCESS) { \
      HG_LOG_ERROR("Proc error"); \
      return ret; \
    }

/* Generate proc for struct */
#define HG_GEN_STRUCT_PROC(struct_type_name, fields) \
static HG_INLINE hg_return_t \
    BOOST_PP_CAT(hg_proc_, struct_type_name) \
    (hg_proc_t proc, void *data) \
{   \
    hg_return_t ret = HG_SUCCESS; \
    struct_type_name *struct_data = (struct_type_name *) data; \
    \
    BOOST_PP_SEQ_FOR_EACH(HG_GEN_PROC, struct_data, fields) \
    \
    return ret; \
}

/* Generate ((param) (datai)) element */
#define HG_GEN_PARAM_NAME(r, prefix, i, param) ((param) (BOOST_PP_CAT(prefix, i)))

/* Generate parameter names and ((type) (name)) sequence */
#define HG_GEN_PARAM_NAME_SEQ(prefix, type_seq) \
        BOOST_PP_SEQ_FOR_EACH_I(HG_GEN_PARAM_NAME, prefix, type_seq)

/* Extract parameter (type name) element */
#define HG_GEN_DECL_FUNC_PARAM(r, is_ref, param) \
    (HG_GEN_GET_TYPE(param) \
            BOOST_PP_IF(is_ref, *, BOOST_PP_EMPTY())HG_GEN_GET_NAME(param))

/* Extract (type name) sequence */
#define HG_GEN_DECL_FUNC_PARAM_SEQ(is_ref, param_seq) \
        BOOST_PP_SEQ_FOR_EACH(HG_GEN_DECL_FUNC_PARAM, is_ref, param_seq)

/* Extract function parameter declarations */
#define HG_GEN_DECL_FUNC_PARAMS(with_input, in_params, extra_in_params, \
        with_output, out_params, extra_out_params) \
        BOOST_PP_SEQ_TO_TUPLE( \
                BOOST_PP_IF(BOOST_PP_OR(with_input, with_output), \
                        HG_GEN_DECL_FUNC_PARAM_SEQ(MERCURY_GEN_FALSE, in_params) \
                        HG_GEN_DECL_FUNC_PARAM_SEQ(MERCURY_GEN_FALSE, extra_in_params) \
                        HG_GEN_DECL_FUNC_PARAM_SEQ(MERCURY_GEN_TRUE, out_params) \
                        HG_GEN_DECL_FUNC_PARAM_SEQ(MERCURY_GEN_TRUE, extra_out_params), \
                        (void) \
                ) \
        )

/* Extract parameter (get_name(param)) element */
#define HG_GEN_FUNC_PARAM(r, is_ref, param) \
        (BOOST_PP_IF(is_ref, &, BOOST_PP_EMPTY())HG_GEN_GET_NAME(param))

/* Extract (name) sequence */
#define HG_GEN_FUNC_PARAM_SEQ(is_ref, param_seq) \
        BOOST_PP_SEQ_FOR_EACH(HG_GEN_FUNC_PARAM, is_ref, param_seq)

/* Extract function parameters */
#define HG_GEN_FUNC_PARAMS(with_input, in_params, extra_in_params, \
        with_output, out_params, extra_out_params) \
        BOOST_PP_SEQ_TO_TUPLE( \
                BOOST_PP_IF(BOOST_PP_OR(with_input, with_output), \
                        HG_GEN_FUNC_PARAM_SEQ(MERCURY_GEN_FALSE, in_params) \
                        HG_GEN_FUNC_PARAM_SEQ(MERCURY_GEN_FALSE, extra_in_params) \
                        HG_GEN_FUNC_PARAM_SEQ(MERCURY_GEN_TRUE, out_params) \
                        HG_GEN_FUNC_PARAM_SEQ(MERCURY_GEN_TRUE, extra_out_params), \
                        () \
                ) \
        )

/* Generate declaration of parameters --> type name; */
#define HG_GEN_DECL_PARAMS(param_seq) \
        BOOST_PP_SEQ_FOR_EACH(HG_GEN_STRUCT_FIELD, , param_seq)

/* Assign param to struct field ( e.g., struct_name.param_1 = param_1; ) */
#define HG_SET_STRUCT_PARAM(r, struct_name, param) \
        struct_name.HG_GEN_GET_NAME(param) = HG_GEN_GET_NAME(param);

/* Assign param ((type) (name)) sequence to struct_name */
#define HG_SET_STRUCT_PARAMS(struct_name, params) \
        BOOST_PP_SEQ_FOR_EACH(HG_SET_STRUCT_PARAM, struct_name, params)

/* Assign struct_name field to param ( e.g., param_1 = struct_name.param_1; ) */
#define HG_GET_STRUCT_PARAM(r, struct_name, param) \
        HG_GEN_GET_NAME(param) = struct_name.HG_GEN_GET_NAME(param);

/* Assign struct_name fields to param ((type) (name)) sequence */
#define HG_GET_STRUCT_PARAMS(struct_name, params) \
        BOOST_PP_SEQ_FOR_EACH(HG_GET_STRUCT_PARAM, struct_name, params)

/* Assign struct_name field to out param ( e.g., *param_1 = struct_name.param_1; ) */
#define HG_GET_OUT_STRUCT_PARAM(r, struct_name, param) \
        *HG_GEN_GET_NAME(param) = struct_name.HG_GEN_GET_NAME(param);

/* Assign struct_name fields to out parame ((type) (name)) sequence */
#define HG_GET_OUT_STRUCT_PARAMS(struct_name, params) \
        BOOST_PP_SEQ_FOR_EACH(HG_GET_OUT_STRUCT_PARAM, struct_name, params)

/********************** Bulk data support boilerplate **********************/

/* Initialized parameter */
#define HG_BULK_INIT_PARAM ((hg_bool_t)(bulk_initialized))

/* Extra input parameters for bulk data */
#define HG_BULK_CONST_BUF ((const void*)(bulk_buf))
#define HG_BULK_BUF       ((void*)(bulk_buf))
#define HG_BULK_COUNT     ((hg_uint64_t)(bulk_count))

#define HG_BULK_EXTRA_IN_PARAM \
        HG_BULK_BUF HG_BULK_COUNT

/* Bulk handle parameter */
#define HG_BULK_PARAM ((hg_bulk_t)(bulk_handle))

/* Bulk block parameter */
#define HG_BULK_BLOCK_PARAM ((hg_bulk_t)(bulk_block_handle))

/* Bulk request parameter */
#define HG_BULK_REQUEST_PARAM ((hg_bulk_request_t)(bulk_request))

/* Bulk addr parameter */
#define HG_BULK_ADDR_PARAM ((na_addr_t)(bulk_addr))

/* Initialize bulk data interface */
#define HG_BULK_INITIALIZE(with_ret, fail_ret) \
        HG_Bulk_initialized(&HG_GEN_GET_NAME(BOOST_PP_SEQ_HEAD(HG_BULK_INIT_PARAM)), \
                NULL); \
        if (!HG_GEN_GET_NAME(BOOST_PP_SEQ_HEAD(HG_BULK_INIT_PARAM))) { \
            hg_ret = HG_Bulk_init(na_class); \
            if (hg_ret != HG_SUCCESS) { \
                HG_LOG_ERROR("Could not initialize bulk data shipper"); \
                BOOST_PP_IF(with_ret, ret = fail_ret;, BOOST_PP_EMPTY()) \
                goto done; \
            } \
        }

/* Register bulk data */
#define HG_BULK_REGISTER(with_ret, fail_ret, bulk_read) \
        hg_ret = HG_Bulk_handle_create( \
                1, &HG_GEN_GET_NAME(BOOST_PP_SEQ_ELEM(0, HG_BULK_EXTRA_IN_PARAM)),\
                &HG_GEN_GET_NAME(BOOST_PP_SEQ_ELEM(1, HG_BULK_EXTRA_IN_PARAM)), \
                BOOST_PP_IF(bulk_read, HG_BULK_READ_ONLY, HG_BULK_READWRITE), \
                &bulk_handle); \
        if (hg_ret != HG_SUCCESS) { \
            HG_LOG_ERROR("Could not create bulk data handle\n"); \
            BOOST_PP_IF(with_ret, ret = fail_ret;, BOOST_PP_EMPTY()) \
            goto done; \
        }

/* Free bulk handle */
#define HG_BULK_FREE(with_ret, fail_ret) \
        hg_ret = HG_Bulk_handle_free( \
                HG_GEN_GET_NAME(BOOST_PP_SEQ_HEAD(HG_BULK_PARAM))); \
        if (hg_ret != HG_SUCCESS) { \
            HG_LOG_ERROR("Could not free bulk data handle"); \
            BOOST_PP_IF(with_ret, ret = fail_ret;, BOOST_PP_EMPTY()) \
            goto done; \
        } \

/* Declare variables required for bulk data transfers */
#define HG_GEN_DECL_BULK_PARAMS \
        HG_GEN_DECL_PARAMS(HG_BULK_PARAM HG_BULK_BLOCK_PARAM \
                HG_BULK_REQUEST_PARAM HG_BULK_EXTRA_IN_PARAM HG_BULK_ADDR_PARAM)

/* Get addr required for bulk data transfer source / dest */
#define HG_BULK_GET_ADDR \
        HG_GEN_GET_NAME(BOOST_PP_SEQ_HEAD(HG_BULK_ADDR_PARAM)) = \
        HG_Handler_get_addr(handle);

/* Read bulk data and wait for the data to arrive */
#define HG_BULK_BLOCK_ALLOCATE \
        HG_GEN_GET_NAME(BOOST_PP_SEQ_ELEM(1, HG_BULK_EXTRA_IN_PARAM)) = \
            HG_Bulk_handle_get_size(HG_GEN_GET_NAME(BOOST_PP_SEQ_HEAD(HG_BULK_PARAM))); \
        HG_GEN_GET_NAME(BOOST_PP_SEQ_ELEM(0, HG_BULK_EXTRA_IN_PARAM)) = \
            malloc(HG_GEN_GET_NAME(BOOST_PP_SEQ_ELEM(1, HG_BULK_EXTRA_IN_PARAM))); \
        HG_Bulk_handle_create(1, &HG_GEN_GET_NAME(BOOST_PP_SEQ_ELEM(0, HG_BULK_EXTRA_IN_PARAM)), \
                &HG_GEN_GET_NAME(BOOST_PP_SEQ_ELEM(1, HG_BULK_EXTRA_IN_PARAM)), \
                HG_BULK_READWRITE, \
                &HG_GEN_GET_NAME(BOOST_PP_SEQ_HEAD(HG_BULK_BLOCK_PARAM)));

/* Free block handle */
#define HG_BULK_BLOCK_FREE \
        hg_ret = HG_Bulk_handle_free( \
                HG_GEN_GET_NAME(BOOST_PP_SEQ_HEAD(HG_BULK_BLOCK_PARAM))); \
        if (hg_ret != HG_SUCCESS) { \
            HG_LOG_ERROR("Could not free block call"); \
            goto done; \
        } \
        free(bulk_buf);

/* Write bulk data here and wait for the data to be there */
#define HG_BULK_TRANSFER(bulk_read) \
        hg_ret = HG_Bulk_transfer(BOOST_PP_IF(bulk_read, HG_BULK_PULL, HG_BULK_PUSH), \
                 HG_GEN_GET_NAME(BOOST_PP_SEQ_HEAD(HG_BULK_ADDR_PARAM)), \
                 HG_GEN_GET_NAME(BOOST_PP_SEQ_HEAD(HG_BULK_PARAM)), \
                 0, \
                 HG_GEN_GET_NAME(BOOST_PP_SEQ_HEAD(HG_BULK_BLOCK_PARAM)), \
                 0, \
                 HG_GEN_GET_NAME(BOOST_PP_SEQ_HEAD(HG_BULK_COUNT)), \
                 &HG_GEN_GET_NAME(BOOST_PP_SEQ_HEAD(HG_BULK_REQUEST_PARAM))); \
        if (hg_ret != HG_SUCCESS) { \
            HG_LOG_ERROR("Could not transfer bulk data"); \
            goto done; \
        } \
        hg_ret = HG_Bulk_wait(HG_GEN_GET_NAME(BOOST_PP_SEQ_HEAD(HG_BULK_REQUEST_PARAM)), \
                HG_MAX_IDLE_TIME, HG_STATUS_IGNORE); \
        if (hg_ret != HG_SUCCESS) { \
            HG_LOG_ERROR("Could not complete bulk data transfer"); \
            goto done; \
        }

/*****************************************************************************
 * Basic BOOST macros:
 *   - MERCURY_GEN_PROC
 *   - MERCURY_REGISTER
 *****************************************************************************/

/* Generate struct and corresponding struct proc */
#define MERCURY_GEN_PROC(struct_type_name, fields) \
        HG_GEN_STRUCT(struct_type_name, fields) \
        HG_GEN_STRUCT_PROC(struct_type_name, fields)

/* In the case of user defined structures / MERCURY_GEN_STRUCT_PROC can be
 * used to generate the corresponding proc routine.
 * E.g., if user defined struct:
 *   typedef struct {
 *     uint64_t cookie;
 *   } bla_handle_t;
 * MERCURY_GEN_STRUCT_PROC( struct_type_name, field sequence ):
 *   MERCURY_GEN_STRUCT_PROC( bla_handle_t, ((uint64_t)(cookie)) )
 */
#define MERCURY_GEN_STRUCT_PROC(struct_type_name, fields) \
    HG_GEN_STRUCT_PROC(struct_type_name, fields)

/* Register func_name */
#define MERCURY_REGISTER(hg_class, func_name, in_struct_type_name, \
        out_struct_type_name, rpc_cb) \
        HG_Register(hg_class, func_name, \
                BOOST_PP_CAT(hg_proc_, in_struct_type_name), \
                BOOST_PP_CAT(hg_proc_, out_struct_type_name), rpc_cb)

/*****************************************************************************
 * Advanced BOOST macros:
 *   - MERCURY_GEN_RPC_STUB
 *   - MERCURY_HANDLER_GEN_CALLBACK_STUB
 *****************************************************************************/

/* Custom function that applications can define for log purposes (none by default) */
#ifndef MERCURY_HANDLER_GEN_LOG_MESSAGE
  #define MERCURY_HANDLER_GEN_LOG_MESSAGE(x)
#endif

/* Generate client RPC stub */
#define MERCURY_GEN_RPC_STUB(gen_func_name, func_name, \
        with_ret, ret_type_name, ret_fail, \
        with_input, in_struct_type_name, in_params, \
        with_output, out_struct_type_name, out_params, \
        with_bulk, bulk_read) \
        BOOST_PP_IF(with_ret, ret_type_name, void) \
        gen_func_name HG_GEN_DECL_FUNC_PARAMS(with_input, in_params, \
                BOOST_PP_IF(with_bulk, HG_BULK_EXTRA_IN_PARAM, BOOST_PP_EMPTY()), \
                with_output, out_params, ) \
        { \
            BOOST_PP_IF(with_input, \
                    in_struct_type_name in_struct;, BOOST_PP_EMPTY()) \
            BOOST_PP_IF(BOOST_PP_OR(with_output, with_ret), \
                    out_struct_type_name out_struct;, BOOST_PP_EMPTY()) \
            BOOST_PP_IF(with_ret, ret_type_name ret;, BOOST_PP_EMPTY()) \
            na_class_t *na_class; \
            char *server_name; \
            const char *info_string; \
            na_addr_t addr; \
            hg_id_t id; \
            BOOST_PP_IF(with_bulk, HG_GEN_DECL_PARAMS(HG_BULK_PARAM), BOOST_PP_EMPTY()) \
            hg_request_t request; \
            hg_status_t status; \
            hg_bool_t hg_initialized; \
            hg_bool_t func_registered; \
            hg_return_t hg_ret; \
            na_return_t na_ret; \
            \
            /* Is mercury library initialized */ \
            HG_Initialized(&hg_initialized, &na_class); \
            if (!hg_initialized) { \
                info_string = getenv(HG_PORT_NAME); \
                if (!info_string) { /* passing NULL to NA_Initialize is bad! */ \
                    HG_LOG_ERROR(HG_PORT_NAME " env var not set"); \
                    BOOST_PP_IF(with_ret, ret = ret_fail;, BOOST_PP_EMPTY()) \
                    goto done; \
                }  \
                na_class = NA_Initialize(info_string, 0); \
                hg_ret = HG_Init(na_class); \
                if (hg_ret != HG_SUCCESS) { \
                    HG_LOG_ERROR("Could not initialize Mercury"); \
                    BOOST_PP_IF(with_ret, ret = ret_fail;, BOOST_PP_EMPTY()) \
                    goto done; \
                } \
            } \
            \
            /* Get server_name if set */ \
            server_name = getenv(HG_PORT_NAME); \
            /* Look up addr id */ \
            na_ret = NA_Addr_lookup_wait(na_class, server_name, &addr); \
            if (na_ret != NA_SUCCESS) { \
                HG_LOG_ERROR("Could not lookup addr"); \
                BOOST_PP_IF(with_ret, ret = ret_fail;, BOOST_PP_EMPTY()) \
                goto done; \
            } \
            \
            /* Check whether call has already been registered or not */ \
            HG_Registered(BOOST_PP_STRINGIZE(func_name), &func_registered, &id); \
            if (!func_registered) { \
                id = MERCURY_REGISTER(BOOST_PP_STRINGIZE(func_name), \
                        BOOST_PP_IF(with_input, in_struct_type_name, void), \
                        BOOST_PP_IF( \
                                BOOST_PP_OR(with_output, with_ret), \
                                out_struct_type_name, \
                                void \
                        ), \
                        NULL \
                ); \
            } \
            \
            BOOST_PP_IF(with_bulk, HG_BULK_REGISTER(with_ret, ret_fail, bulk_read), \
                    BOOST_PP_EMPTY()) \
            \
            /* Fill input structure */ \
            BOOST_PP_IF(with_input, \
                    HG_SET_STRUCT_PARAMS(in_struct, in_params \
                            BOOST_PP_IF(with_bulk, HG_BULK_PARAM, BOOST_PP_EMPTY())), \
                    BOOST_PP_EMPTY()) \
            \
            /* Forward call to remote addr and get a new request */ \
            hg_ret = HG_Forward(addr, id, \
                    BOOST_PP_IF(with_input, &in_struct, NULL), \
                    BOOST_PP_IF(BOOST_PP_OR(with_output, with_ret), &out_struct, NULL), \
                    &request); \
            if (hg_ret != HG_SUCCESS) { \
                HG_LOG_ERROR("Could not forward call"); \
                BOOST_PP_IF(with_ret, ret = ret_fail;, BOOST_PP_EMPTY()) \
                goto done; \
            } \
            \
            /* Wait for call to be executed and return value to be sent back
             * (Request is freed when the call completes)
             */ \
            hg_ret = HG_Wait(request, HG_MAX_IDLE_TIME, &status); \
            if (hg_ret != HG_SUCCESS) { \
                HG_LOG_ERROR("Error during wait"); \
                BOOST_PP_IF(with_ret, ret = ret_fail;, BOOST_PP_EMPTY()) \
                goto done; \
            } \
            if (!status) { \
                HG_LOG_ERROR("Operation did not complete"); \
                BOOST_PP_IF(with_ret, ret = ret_fail;, BOOST_PP_EMPTY()) \
                goto done; \
            } \
            \
            BOOST_PP_IF(with_bulk, HG_BULK_FREE(with_ret, ret_fail), BOOST_PP_EMPTY()) \
            \
            /* Get output parameters */ \
            BOOST_PP_IF(with_ret, \
                    HG_GET_STRUCT_PARAMS(out_struct, ((ret_type)(ret))), \
                    BOOST_PP_EMPTY()) \
            BOOST_PP_IF(with_output, \
                    HG_GET_OUT_STRUCT_PARAMS(out_struct, out_params), \
                    BOOST_PP_EMPTY()) \
            \
            /* Free request */ \
            hg_ret = HG_Request_free(request); \
            if (hg_ret != HG_SUCCESS) { \
                HG_LOG_ERROR("Could not free request"); \
                BOOST_PP_IF(with_ret, ret = ret_fail;, BOOST_PP_EMPTY()) \
                goto done; \
            } \
            \
            /* Free addr id */ \
            na_ret = NA_Addr_free(na_class, addr); \
            if (na_ret != NA_SUCCESS) { \
                HG_LOG_ERROR("Could not free addr"); \
                BOOST_PP_IF(with_ret, ret = ret_fail;, BOOST_PP_EMPTY()) \
                goto done; \
            } \
            \
            done: \
            \
            return BOOST_PP_IF(with_ret, ret, BOOST_PP_EMPTY()); \
        }

/* Generate handler callback */
#define MERCURY_HANDLER_GEN_CALLBACK_STUB(gen_func_name, func_name, \
        with_ret, ret_type, \
        with_input, in_struct_type_name, in_params, \
        with_output, out_struct_type_name, out_params, \
        with_bulk, bulk_read, \
        with_thread, thread_pool) \
        static \
        BOOST_PP_IF(with_thread, \
                    HG_THREAD_RETURN_TYPE BOOST_PP_CAT(gen_func_name, _thread), \
                    hg_return_t gen_func_name) \
        ( \
        BOOST_PP_IF(with_thread, void *arg, hg_handle_t handle) \
        ) \
        { \
                BOOST_PP_IF(with_thread, \
                        hg_handle_t handle = (hg_handle_t) arg; \
                        hg_thread_ret_t thread_ret = (hg_thread_ret_t) 0; \
                        ,\
                    BOOST_PP_EMPTY()) \
                hg_return_t hg_ret = HG_SUCCESS; \
                BOOST_PP_IF(with_input, \
                    in_struct_type_name in_struct;, BOOST_PP_EMPTY()) \
                BOOST_PP_IF(BOOST_PP_OR(with_output, with_ret), \
                    out_struct_type_name out_struct;, BOOST_PP_EMPTY()) \
                BOOST_PP_IF(with_input, HG_GEN_DECL_PARAMS(in_params), BOOST_PP_EMPTY()) \
                BOOST_PP_IF(with_output, HG_GEN_DECL_PARAMS(out_params), BOOST_PP_EMPTY()) \
                BOOST_PP_IF(with_ret, ret_type ret;, BOOST_PP_EMPTY()) \
                BOOST_PP_IF(with_bulk, HG_GEN_DECL_BULK_PARAMS, BOOST_PP_EMPTY()) \
                \
                BOOST_PP_IF(with_bulk, HG_BULK_GET_ADDR, BOOST_PP_EMPTY()) \
                \
                /* Get input buffer */ \
                BOOST_PP_IF(with_input, \
                        hg_ret = HG_Handler_get_input(handle, &in_struct); \
                        if (hg_ret != HG_SUCCESS) { \
                            HG_LOG_ERROR("Could not get input struct"); \
                            goto done; \
                        } \
                        \
                        /* Get parameters */ \
                        HG_GET_STRUCT_PARAMS(in_struct, in_params \
                                BOOST_PP_IF(with_bulk, HG_BULK_PARAM, BOOST_PP_EMPTY())) \
                        , BOOST_PP_EMPTY()) \
                \
                BOOST_PP_IF(with_bulk, HG_BULK_BLOCK_ALLOCATE, BOOST_PP_EMPTY()) \
                BOOST_PP_IF(with_bulk, \
                        BOOST_PP_IF(bulk_read, \
                                HG_BULK_TRANSFER(bulk_read), BOOST_PP_EMPTY()), \
                        BOOST_PP_EMPTY()) \
                \
                /* Call function */ \
                MERCURY_HANDLER_GEN_LOG_MESSAGE(BOOST_PP_STRINGIZE(func_name)); \
                BOOST_PP_IF(with_ret, ret =, BOOST_PP_EMPTY()) \
                    func_name HG_GEN_FUNC_PARAMS(with_input, in_params, \
                            BOOST_PP_IF(with_bulk, HG_BULK_EXTRA_IN_PARAM, BOOST_PP_EMPTY()), \
                            with_output, out_params, ); \
                \
                BOOST_PP_IF(with_bulk, \
                        BOOST_PP_IF(bulk_read, \
                                BOOST_PP_EMPTY(), HG_BULK_TRANSFER(bulk_read)), \
                        BOOST_PP_EMPTY()) \
                \
                BOOST_PP_IF(with_bulk, HG_BULK_BLOCK_FREE, BOOST_PP_EMPTY()) \
                \
                /* Fill output structure */ \
                BOOST_PP_IF(with_ret, \
                        HG_SET_STRUCT_PARAMS(out_struct, ((ret_type)(ret))), \
                        BOOST_PP_EMPTY()) \
                BOOST_PP_IF(with_output, \
                        HG_SET_STRUCT_PARAMS(out_struct, out_params), \
                        BOOST_PP_EMPTY()) \
                \
                /* Free handle and send response back */ \
                hg_ret = HG_Handler_start_output(handle, \
                        BOOST_PP_IF(BOOST_PP_OR(with_output, with_ret), \
                                &out_struct, \
                                NULL) ); \
                if (hg_ret != HG_SUCCESS) { \
                    HG_LOG_ERROR("Could not start output"); \
                    goto done; \
                } \
                \
                BOOST_PP_IF(with_input, \
                        hg_ret = HG_Handler_free_input(handle, &in_struct); \
                        if (hg_ret != HG_SUCCESS) { \
                            HG_LOG_ERROR("Could not free input struct"); \
                            goto done; \
                        } \
                        , BOOST_PP_EMPTY()) \
                \
                hg_ret = HG_Handler_free(handle); \
                if (hg_ret != HG_SUCCESS) { \
                    HG_LOG_ERROR("Could not free handle"); \
                    goto done; \
                } \
                \
                done: \
                \
                BOOST_PP_IF(with_thread, \
                        return thread_ret; \
                        , return hg_ret;) \
                \
            } \
            BOOST_PP_IF(with_thread, \
                    static hg_return_t \
                    gen_func_name(hg_handle_t handle) \
                    { \
                        hg_return_t ret = HG_SUCCESS; \
                        hg_thread_pool_post(thread_pool, \
                                &BOOST_PP_CAT(gen_func_name, _thread), handle); \
                        return ret; \
                    } \
            , BOOST_PP_EMPTY())

#else /* HG_HAS_BOOST */

#define MERCURY_REGISTER(hg_class, func_name, in_struct_type_name, \
        out_struct_type_name, rpc_cb) \
        HG_Register(hg_class, func_name, hg_proc_ ## in_struct_type_name, \
                hg_proc_ ## out_struct_type_name, rpc_cb)

#endif /* HG_HAS_BOOST */

/* If no input args or output args, a void type can be
 * passed to MERCURY_REGISTER
 */
#define hg_proc_void NULL

#endif /* MERCURY_MACROS_H */
