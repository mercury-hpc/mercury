/*
 * Copyright (C) 2013-2020 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#ifndef TEST_RPC_H
#define TEST_RPC_H

#include "mercury_macros.h"
#include "mercury_proc_string.h"

#include <stdio.h>
#include <stdlib.h>

typedef struct {
    hg_uint64_t cookie;
} rpc_handle_t;

typedef struct {
    void *buf;
    hg_uint32_t buf_size;
} perf_rpc_lat_in_t;

typedef struct {
    void *buf;
    hg_uint32_t buf_size;
} perf_rpc_lat_out_t;

#ifdef HG_HAS_BOOST

/* 1. Generate processor and struct for additional struct types
 * MERCURY_GEN_STRUCT_PROC( struct_type_name, fields )
 */
MERCURY_GEN_STRUCT_PROC(rpc_handle_t, ((hg_uint64_t) (cookie)))

/* Dummy function that needs to be shipped (already defined) */
/* int rpc_open(const char *path, rpc_handle_t handle, int *event_id); */

/* 2. Generate processor and struct for required input/output structs
 * MERCURY_GEN_PROC( struct_type_name, fields )
 */
MERCURY_GEN_PROC(
    rpc_open_in_t, ((hg_const_string_t) (path)) ((rpc_handle_t) (handle)))
MERCURY_GEN_PROC(rpc_open_out_t, ((hg_int32_t) (ret)) ((hg_int32_t) (event_id)))
#else
/* Dummy function that needs to be shipped (already defined) */
/* int rpc_open(const char *path, rpc_handle_t handle, int *event_id); */

/* Define hg_proc_rpc_handle_t */
static HG_INLINE hg_return_t
hg_proc_rpc_handle_t(hg_proc_t proc, void *data)
{
    hg_return_t ret = HG_SUCCESS;
    rpc_handle_t *struct_data = (rpc_handle_t *) data;

    ret = hg_proc_uint64_t(proc, &struct_data->cookie);
    if (ret != HG_SUCCESS)
        return ret;

    return ret;
}

/* Define rpc_open_in_t */
typedef struct {
    hg_const_string_t path;
    rpc_handle_t handle;
} rpc_open_in_t;

/* Define hg_proc_rpc_open_in_t */
static HG_INLINE hg_return_t
hg_proc_rpc_open_in_t(hg_proc_t proc, void *data)
{
    hg_return_t ret = HG_SUCCESS;
    rpc_open_in_t *struct_data = (rpc_open_in_t *) data;

    ret = hg_proc_hg_const_string_t(proc, &struct_data->path);
    if (ret != HG_SUCCESS)
        return ret;

    ret = hg_proc_rpc_handle_t(proc, &struct_data->handle);
    if (ret != HG_SUCCESS)
        return ret;

    return ret;
}

/* Define rpc_open_out_t */
typedef struct {
    hg_int32_t ret;
    hg_int32_t event_id;
} rpc_open_out_t;

/* Define hg_proc_rpc_open_out_t */
static HG_INLINE hg_return_t
hg_proc_rpc_open_out_t(hg_proc_t proc, void *data)
{
    hg_return_t ret = HG_SUCCESS;
    rpc_open_out_t *struct_data = (rpc_open_out_t *) data;

    ret = hg_proc_int32_t(proc, &struct_data->ret);
    if (ret != HG_SUCCESS)
        return ret;

    ret = hg_proc_int32_t(proc, &struct_data->event_id);
    if (ret != HG_SUCCESS)
        return ret;

    return ret;
}
#endif

/* Define hg_proc_perf_rpc_lat_in_t */
static HG_INLINE hg_return_t
hg_proc_perf_rpc_lat_in_t(hg_proc_t proc, void *data)
{
    perf_rpc_lat_in_t *struct_data = (perf_rpc_lat_in_t *) data;
    hg_return_t ret = HG_SUCCESS;

    ret = hg_proc_hg_uint32_t(proc, &struct_data->buf_size);
    if (ret != HG_SUCCESS)
        return ret;

    if (struct_data->buf_size) {
        switch (hg_proc_get_op(proc)) {
            case HG_DECODE:
                struct_data->buf = malloc(struct_data->buf_size);
                HG_FALLTHROUGH;
            case HG_ENCODE:
                ret =
                    hg_proc_raw(proc, struct_data->buf, struct_data->buf_size);
                if (ret != HG_SUCCESS)
                    return ret;
                break;
            case HG_FREE:
                free(struct_data->buf);
                break;
            default:
                ret = HG_INVALID_ARG;
                return ret;
        }

#ifdef HG_TEST_HAS_VERIFY_DATA
        if (hg_proc_get_op(proc) == HG_DECODE) {
            hg_size_t i;
            char *buf_ptr = struct_data->buf;

            for (i = 0; i < struct_data->buf_size; i++) {
                if (buf_ptr[i] != (char) i) {
                    printf("Error detected in bulk transfer, buf[%d] = %d, "
                           "was expecting %d!\n",
                        (int) i, (char) buf_ptr[i], (char) i);
                    break;
                }
            }
        }
#endif
    }

    return ret;
}

/* Define hg_proc_perf_rpc_lat_out_t identical to in */
static HG_INLINE hg_return_t
hg_proc_perf_rpc_lat_out_t(hg_proc_t proc, void *data)
{
    return hg_proc_perf_rpc_lat_in_t(proc, data);
}

#endif /* TEST_RPC_H */
