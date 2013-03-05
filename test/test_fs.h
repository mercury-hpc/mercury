/*
 * test_fs.h
 */

#ifndef TEST_FS_H
#define TEST_FS_H

#include "generic_macros.h"
#include "generic_proc.h"

#ifdef IOFSL_SHIPPER_HAS_BOOST
/* 1. Generate processor and struct for additional struct types
 * IOFSL_SHIPPER_GEN_PROC( struct_type_name, fields )
 */
IOFSL_SHIPPER_GEN_PROC( bla_handle_t, ((uint64_t)(cookie)) )

/* Dummy function that needs to be shipped (already defined) */
int bla_open(const char *path, bla_handle_t handle, int *event_id);

/* 2. Generate processor and struct for required input/output structs
 * IOFSL_SHIPPER_GEN_PROC( struct_type_name, fields )
 */
IOFSL_SHIPPER_GEN_PROC( bla_open_in_t, ((fs_string_t)(path)) ((bla_handle_t)(handle)) )
IOFSL_SHIPPER_GEN_PROC( bla_open_out_t, ((int32_t)(ret)) ((int32_t)(event_id)) )
#else
/* Define bla_handle_t */
typedef struct {
    uint64_t cookie;
} bla_handle_t;

/* Dummy function that needs to be shipped (already defined) */
int bla_open(const char *path, bla_handle_t handle, int *event_id);

/* Define fs_proc_bla_handle_t */
static inline int fs_proc_bla_handle_t(fs_proc_t proc, void *data)
{
    int ret = S_SUCCESS;
    bla_handle_t *struct_data = (bla_handle_t *) data;

    ret = fs_proc_uint64_t(proc, &struct_data->cookie);
    if (ret != S_SUCCESS) {
        S_ERROR_DEFAULT("Proc error");
        ret = S_FAIL;
        return ret;
    }

    return ret;
}

/* Define bla_open_in_t */
typedef struct {
    fs_string_t path;
    bla_handle_t handle;
} bla_open_in_t;

/* Define fs_proc_bla_open_in_t */
static inline int fs_proc_bla_open_in_t(fs_proc_t proc, void *data)
{
    int ret = S_SUCCESS;
    bla_open_in_t *struct_data = (bla_open_in_t *) data;

    ret = fs_proc_fs_string_t(proc, &struct_data->path);
    if (ret != S_SUCCESS) {
        S_ERROR_DEFAULT("Proc error");
        ret = S_FAIL;
        return ret;
    }

    ret = fs_proc_bla_handle_t(proc, &struct_data->handle);
    if (ret != S_SUCCESS) {
        S_ERROR_DEFAULT("Proc error");
        ret = S_FAIL;
        return ret;
    }

    return ret;
}

/* Define bla_open_out_t */
typedef struct {
    int32_t ret;
    int32_t event_id;
} bla_open_out_t;

/* Define fs_proc_bla_open_out_t */
static inline int fs_proc_bla_open_out_t(fs_proc_t proc, void *data)
{
    int ret = S_SUCCESS;
    bla_open_out_t *struct_data = (bla_open_out_t *) data;

    ret = fs_proc_int32_t(proc, &struct_data->ret);
    if (ret != S_SUCCESS) {
        S_ERROR_DEFAULT("Proc error");
        ret = S_FAIL;
        return ret;
    }

    ret = fs_proc_int32_t(proc, &struct_data->event_id);
    if (ret != S_SUCCESS) {
        S_ERROR_DEFAULT("Proc error");
        ret = S_FAIL;
        return ret;
    }

    return ret;
}
#endif

#endif /* TEST_FS_H */
