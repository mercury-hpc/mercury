/*
 * Copyright (C) 2013 Argonne National Laboratory, Department of Energy,
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
#include "mercury_handler.h"
#include "mercury_proc.h"

#ifdef NA_HAS_BMI
#include "na_bmi.h"
#endif
#ifdef NA_HAS_MPI
#include "na_mpi.h"
#endif
#ifdef NA_HAS_SSM
#include "na_ssm.h"
#endif

#ifdef HG_HAS_BOOST
#include <boost/preprocessor.hpp>

/********************** Utility macros **********************/

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
      HG_ERROR_DEFAULT("Proc error"); \
      ret = HG_FAIL; \
      return ret; \
    }

/* Generate proc for struct */
#define HG_GEN_STRUCT_PROC(struct_type_name, fields) \
static HG_INLINE int \
    BOOST_PP_CAT(hg_proc_, struct_type_name) \
    (hg_proc_t proc, void *data) \
{   \
    int ret = HG_SUCCESS; \
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
#define HG_GEN_DECL_FUNC_PARAM(r, data, param) (HG_GEN_GET_TYPE(param) HG_GEN_GET_NAME(param))

/* Extract (type name) sequence */
#define HG_GEN_DECL_FUNC_PARAM_SEQ(param_seq) \
        BOOST_PP_SEQ_FOR_EACH(HG_GEN_DECL_FUNC_PARAM, , param_seq)

/* Extract function parameter declarations */
#define HG_GEN_DECL_FUNC_PARAMS(in_params, extra_in_params, \
        out_params, extra_out_params) \
        BOOST_PP_SEQ_TO_TUPLE(HG_GEN_DECL_FUNC_PARAM_SEQ(in_params) \
                HG_GEN_DECL_FUNC_PARAM_SEQ(extra_in_params) \
                HG_GEN_DECL_FUNC_PARAM_SEQ(out_params) \
                HG_GEN_DECL_FUNC_PARAM_SEQ(extra_out_params) \
        )

/* Extract parameter (get_name(param)) element */
#define HG_GEN_FUNC_PARAM(r, data, param) (HG_GEN_GET_NAME(param))

/* Extract (name) sequence */
#define HG_GEN_FUNC_PARAM_SEQ(param_seq) \
        BOOST_PP_SEQ_FOR_EACH(HG_GEN_FUNC_PARAM, , param_seq)

/* Extract function parameters */
#define HG_GEN_FUNC_PARAMS(in_params, extra_in_params, \
        out_params, extra_out_params) \
        BOOST_PP_SEQ_TO_TUPLE(HG_GEN_FUNC_PARAM_SEQ(in_params) \
                HG_GEN_FUNC_PARAM_SEQ(extra_in_params) \
                HG_GEN_FUNC_PARAM_SEQ(out_params) \
                HG_GEN_FUNC_PARAM_SEQ(extra_out_params) \
        )

/* Generate declaration of parameters --> type name; */
#define HG_GEN_DECL_VARS(param_seq) \
        BOOST_PP_SEQ_FOR_EACH(HG_GEN_STRUCT_FIELD, , param_seq)

/* Assign param to struct field ( e.g., struct_name.param_1 = param_1; ) */
#define HG_SET_STRUCT_PARAM(r, struct_name, param) \
        struct_name.HG_GEN_GET_NAME(param) = HG_GEN_GET_NAME(param);

/* Assigne parameters ((type) (name)) sequence to struct_name */
#define HG_SET_STRUCT_PARAMS(struct_name, params) \
        BOOST_PP_SEQ_FOR_EACH(HG_SET_STRUCT_PARAM, struct_name, params)

/* Get param from struct field ( e.g., param_1 = struct_name.param_1; ) */
#define HG_GET_STRUCT_PARAM(r, struct_name, param) \
        HG_GEN_GET_NAME(param) = struct_name.HG_GEN_GET_NAME(param);

/* Get parameters ((type) (name)) sequence from struct_name */
#define HG_GET_STRUCT_PARAMS(struct_name, params) \
        BOOST_PP_SEQ_FOR_EACH(HG_GET_STRUCT_PARAM, struct_name, params)

/********************** Bulk data support boilerplate **********************/

/* RPC with or without bulk data */
#define MERCURY_GEN_WITHOUT_BULK 0
#define MERCURY_GEN_WITH_BULK 1

/* RPC produces or consumes bulk data */
#define MERCURY_GEN_PRODUCE_BULK 0
#define MERCURY_GEN_CONSUME_BULK 1

/* Initialized parameter */
#define HG_BULK_INIT_PARAM ((hg_bool_t)(bulk_initialized))

/* Extra input parameters for bulk data */
#define HG_BULK_EXTRA_IN_PARAM ((void*)(bulk_buf)) ((hg_uint64_t) (bulk_count))

/* Bulk handle parameter */
#define HG_BULK_PARAM ((hg_bulk_t)(bulk_handle))

/* Bulk block parameter */
#define HG_BULK_BLOCK_PARAM ((hg_bulk_block_t)(bulk_block_handle))

/* Bulk request parameter */
#define HG_BULK_REQUEST_PARAM ((hg_bulk_request_t)(bulk_request))

/* Bulk addr parameter */
#define HG_BULK_ADDR_PARAM ((na_addr_t)(bulk_addr))

/* Initialize bulk data interface */
#define HG_BULK_INITIALIZE(fail_ret) \
        HG_Bulk_initialized(&HG_GEN_GET_NAME(BOOST_PP_SEQ_HEAD(HG_BULK_INIT_PARAM)), \
                NULL); \
        if (!HG_GEN_GET_NAME(BOOST_PP_SEQ_HEAD(HG_BULK_INIT_PARAM))) { \
            hg_ret = HG_Bulk_init(network_class); \
            if (hg_ret != HG_SUCCESS) { \
                HG_ERROR_DEFAULT("Could not initialize bulk data shipper"); \
                ret = fail_ret; \
                goto done; \
            } \
        }

/* Register bulk data */
#define HG_BULK_REGISTER(fail_ret, consume_bulk) \
        hg_ret = HG_Bulk_handle_create( \
                BOOST_PP_TUPLE_REM(2) \
                BOOST_PP_SEQ_TO_TUPLE(HG_GEN_FUNC_PARAM_SEQ(HG_BULK_EXTRA_IN_PARAM)), \
                BOOST_PP_IF(consume_bulk, HG_BULK_READ_ONLY, HG_BULK_READWRITE), \
                &bulk_handle); \
        if (hg_ret != HG_SUCCESS) { \
            HG_ERROR_DEFAULT("Could not create bulk data handle\n"); \
            ret = fail_ret; \
            goto done; \
        }

/* Free bulk handle */
#define HG_BULK_FREE(fail_ret) \
        hg_ret = HG_Bulk_handle_free( \
                HG_GEN_GET_NAME(BOOST_PP_SEQ_HEAD(HG_BULK_PARAM))); \
        if (hg_ret != HG_SUCCESS) { \
            HG_ERROR_DEFAULT("Could not free bulk data handle"); \
            ret = fail_ret; \
            goto done; \
        } \

/* Declare variables required for bulk data transfers */
#define HG_BULK_DECL_PARAMS \
        HG_GEN_DECL_VARS(HG_BULK_PARAM HG_BULK_BLOCK_PARAM \
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
        HG_Bulk_block_handle_create(BOOST_PP_TUPLE_REM(2) \
                BOOST_PP_SEQ_TO_TUPLE(HG_GEN_FUNC_PARAM_SEQ(HG_BULK_EXTRA_IN_PARAM)), \
                HG_BULK_READWRITE, \
                &HG_GEN_GET_NAME(BOOST_PP_SEQ_HEAD(HG_BULK_BLOCK_PARAM)));

/* Free block handle */
#define HG_BULK_BLOCK_FREE \
        hg_ret = HG_Bulk_block_handle_free( \
                HG_GEN_GET_NAME(BOOST_PP_SEQ_HEAD(HG_BULK_BLOCK_PARAM))); \
        if (hg_ret != HG_SUCCESS) { \
            HG_ERROR_DEFAULT("Could not free block call"); \
            return hg_ret; \
        } \
        free(bulk_buf);

/* Write bulk data here and wait for the data to be there */
#define HG_BULK_TRANSFER(consume_bulk) \
        hg_ret = BOOST_PP_IF(consume_bulk, HG_Bulk_read_all, HG_Bulk_write_all) \
                (HG_GEN_GET_NAME(BOOST_PP_SEQ_HEAD(HG_BULK_ADDR_PARAM)), \
                 HG_GEN_GET_NAME(BOOST_PP_SEQ_HEAD(HG_BULK_PARAM)), \
                 HG_GEN_GET_NAME(BOOST_PP_SEQ_HEAD(HG_BULK_BLOCK_PARAM)), \
                 &HG_GEN_GET_NAME(BOOST_PP_SEQ_HEAD(HG_BULK_REQUEST_PARAM))); \
        if (hg_ret != HG_SUCCESS) { \
            HG_ERROR_DEFAULT("Could not write bulk data"); \
            return hg_ret; \
        } \
        hg_ret = HG_Bulk_wait(HG_GEN_GET_NAME(BOOST_PP_SEQ_HEAD(HG_BULK_REQUEST_PARAM)), \
                HG_MAX_IDLE_TIME, HG_STATUS_IGNORE); \
        if (hg_ret != HG_SUCCESS) { \
            HG_ERROR_DEFAULT("Could not complete bulk data write"); \
            return hg_ret; \
        }

/*****************************************************************************
 * Basic BOOST macros:
 *   - MERCURY_GEN_PROC
 *   - MERCURY_REGISTER
 *   - MERCURY_HANDLER_REGISTER
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
#define MERCURY_REGISTER(func_name, in_struct_type_name, out_struct_type_name) \
        HG_Register(func_name, BOOST_PP_CAT(hg_proc_, in_struct_type_name), \
                BOOST_PP_CAT(hg_proc_, out_struct_type_name))

/* Register func_name */
#define MERCURY_HANDLER_REGISTER(func_name, func_callback, in_struct_type_name, out_struct_type_name) \
        HG_Handler_register(func_name, func_callback, \
                BOOST_PP_CAT(hg_proc_, in_struct_type_name), \
                BOOST_PP_CAT(hg_proc_, out_struct_type_name))

/*****************************************************************************
 * Advanced BOOST macros:
 *   - MERCURY_GEN_RPC_STUB
 *   - MERCURY_HANDLER_GEN_CALLBACK_STUB
 *****************************************************************************/

/* Generate client RPC stub */
#define MERCURY_GEN_RPC_STUB(gen_func_name, ret_type, ret_fail, func_name, \
        in_struct_type_name, in_params, out_struct_type_name, out_params, \
        with_bulk, consume_bulk) \
        ret_type \
        gen_func_name HG_GEN_DECL_FUNC_PARAMS(in_params, \
                BOOST_PP_IF(with_bulk, HG_BULK_EXTRA_IN_PARAM, BOOST_PP_EMPTY()), \
                out_params, ) \
        { \
            in_struct_type_name in_struct; \
            out_struct_type_name out_struct; \
            ret_type ret; \
            na_class_t *network_class; \
            char *server_name; \
            na_addr_t addr; \
            hg_id_t id; \
            BOOST_PP_IF(with_bulk, HG_GEN_DECL_VARS(HG_BULK_PARAM), BOOST_PP_EMPTY()) \
            hg_request_t request; \
            hg_status_t status; \
            hg_bool_t hg_initialized; \
            BOOST_PP_IF(with_bulk, HG_GEN_DECL_VARS(HG_BULK_INIT_PARAM), BOOST_PP_EMPTY()) \
            hg_bool_t func_registered; \
            int hg_ret, na_ret; \
            \
            /* Is mercury library initialized */ \
            HG_Initialized(&hg_initialized, &network_class); \
            if (!hg_initialized) { \
                char *na_plugin = getenv(HG_NA_PLUGIN); \
                if (!na_plugin) na_plugin = "mpi"; \
                if (strcmp("mpi", na_plugin) == 0) { \
                    network_class = NA_Initialize("mpi", NULL, 0); \
                } \
                else if (strcmp("bmi", na_plugin) == 0) { \
                    network_class = NA_Initialize("bmi", NULL, 0); \
                } \
                hg_ret = HG_Init(network_class); \
                if (hg_ret != HG_SUCCESS) { \
                    HG_ERROR_DEFAULT("Could not initialize function shipper"); \
                    ret = ret_fail; \
                    goto done; \
                } \
            } \
            BOOST_PP_IF(with_bulk, HG_BULK_INITIALIZE(ret_fail), BOOST_PP_EMPTY()) \
            \
            /* Get server_name if set */ \
            server_name = getenv(HG_PORT_NAME); \
            /* Look up addr id */ \
            na_ret = NA_Addr_lookup(network_class, server_name, &addr); \
            if (na_ret != NA_SUCCESS) { \
                HG_ERROR_DEFAULT("Could not lookup addr"); \
                ret = ret_fail; \
                goto done; \
            } \
            \
            /* Check whether call has already been registered or not */ \
            HG_Registered(BOOST_PP_STRINGIZE(func_name), &func_registered, &id); \
            if (!func_registered) { \
                id = MERCURY_REGISTER(BOOST_PP_STRINGIZE(func_name), \
                        in_struct_type_name, out_struct_type_name); \
            } \
            \
            BOOST_PP_IF(with_bulk, HG_BULK_REGISTER(ret_fail, consume_bulk), \
                    BOOST_PP_EMPTY()) \
            \
            /* Fill input structure */ \
            HG_SET_STRUCT_PARAMS(in_struct, in_params \
                    BOOST_PP_IF(with_bulk, HG_BULK_PARAM, BOOST_PP_EMPTY())) \
            \
            /* Forward call to remote addr and get a new request */ \
            hg_ret = HG_Forward(addr, id, &in_struct, &out_struct, &request); \
            if (hg_ret != HG_SUCCESS) { \
                HG_ERROR_DEFAULT("Could not forward call"); \
                ret = ret_fail; \
                goto done; \
            } \
            \
            /* Wait for call to be executed and return value to be sent back
             * (Request is freed when the call completes)
             */ \
            hg_ret = HG_Wait(request, HG_MAX_IDLE_TIME, &status); \
            if (hg_ret != HG_SUCCESS) { \
                HG_ERROR_DEFAULT("Error during wait"); \
                ret = ret_fail; \
                goto done; \
            } \
            if (!status) { \
                HG_ERROR_DEFAULT("Operation did not complete"); \
                ret = ret_fail; \
                goto done; \
            } \
            \
            BOOST_PP_IF(with_bulk, HG_BULK_FREE(ret_fail), BOOST_PP_EMPTY()) \
            \
            /* Get output parameters */ \
            HG_GET_STRUCT_PARAMS(out_struct, out_params ((ret_type)(ret))) \
            \
            done: \
            \
            return ret; \
        }

/* Generate handler callback */
#define MERCURY_HANDLER_GEN_CALLBACK_STUB(gen_func_name, ret_type, func_name, \
        in_struct_type_name, in_params, out_struct_type_name, out_params, \
        with_bulk, consume_bulk) \
        int \
        gen_func_name (hg_handle_t handle) \
        { \
                int hg_ret = HG_SUCCESS; \
                in_struct_type_name in_struct; \
                out_struct_type_name out_struct; \
                HG_GEN_DECL_VARS(in_params) \
                ret_type ret; \
                BOOST_PP_IF(with_bulk, HG_BULK_DECL_PARAMS, BOOST_PP_EMPTY()) \
                \
                BOOST_PP_IF(with_bulk, HG_BULK_GET_ADDR, BOOST_PP_EMPTY()) \
                \
                /* Get input buffer */ \
                hg_ret = HG_Handler_get_input(handle, &in_struct); \
                if (hg_ret != HG_SUCCESS) { \
                    HG_ERROR_DEFAULT("Could not get input struct"); \
                    goto done; \
                } \
                \
                /* Get parameters */ \
                HG_GET_STRUCT_PARAMS(in_struct, in_params \
                        BOOST_PP_IF(with_bulk, HG_BULK_PARAM, BOOST_PP_EMPTY()) ) \
                \
                BOOST_PP_IF(with_bulk, HG_BULK_BLOCK_ALLOCATE, BOOST_PP_EMPTY()) \
                BOOST_PP_IF(with_bulk, \
                        BOOST_PP_IF(consume_bulk, \
                                HG_BULK_TRANSFER(consume_bulk), BOOST_PP_EMPTY()), \
                        BOOST_PP_EMPTY()) \
                \
                /* Call function */ \
                ret = func_name HG_GEN_FUNC_PARAMS( in_params, \
                        BOOST_PP_IF(with_bulk, HG_BULK_EXTRA_IN_PARAM, BOOST_PP_EMPTY()), \
                        out_params, ); \
                \
                BOOST_PP_IF(with_bulk, \
                        BOOST_PP_IF(consume_bulk, \
                                BOOST_PP_EMPTY(), HG_BULK_TRANSFER(consume_bulk)), \
                        BOOST_PP_EMPTY()) \
                \
                BOOST_PP_IF(with_bulk, HG_BULK_BLOCK_FREE, BOOST_PP_EMPTY()) \
                \
                /* Fill output structure */ \
                HG_SET_STRUCT_PARAMS(out_struct, out_params ((ret_type)(ret))) \
                \
                /* Free handle and send response back */ \
                hg_ret = HG_Handler_start_output(handle, &out_struct); \
                if (hg_ret != HG_SUCCESS) { \
                    HG_ERROR_DEFAULT("Could not start output"); \
                    goto done; \
                } \
                \
                done: \
                \
                return hg_ret; \
            }

#else /* HG_HAS_BOOST */

#define MERCURY_REGISTER(func_name, in_struct_type_name, out_struct_type_name) \
        HG_Register(func_name, hg_proc_ ## in_struct_type_name, \
                hg_proc_ ## out_struct_type_name)

#define MERCURY_HANDLER_REGISTER(func_name, func_callback, in_struct_type_name, out_struct_type_name) \
        HG_Handler_register(func_name, func_callback, \
                hg_proc_ ## in_struct_type_name, \
                hg_proc_ ## out_struct_type_name)

#endif /* HG_HAS_BOOST */

/* If no input args or output args, a void type can be
 * passed to MERCURY_REGISTER and MERCURY_HANDLER_REGISTER
 */
#define hg_proc_void NULL

#endif /* MERCURY_MACROS_H */
