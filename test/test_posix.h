/*
 * Copyright (C) 2013 Argonne National Laboratory, Department of Energy,
 *                    and UChicago Argonne, LLC.
 * Copyright (C) 2013 The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#ifndef TEST_FS_H
#define TEST_FS_H

#include "generic_macros.h"
#include "generic_proc.h"

#ifdef IOFSL_SHIPPER_HAS_BOOST
/* Dummy function that needs to be shipped (already defined) */
/*
 * 1. int open(const char *pathname, int flags, mode_t mode);
 * 2. int close(int fd);
 * 3. ssize_t write(int fd, const void *buf, size_t count);
 * 4. ssize_t read(int fd, void *buf, size_t count);
 */

/* Generate processor and struct for required input/output structs
 * IOFSL_SHIPPER_GEN_PROC( struct_type_name, fields )
 */

/* open */
IOFSL_SHIPPER_GEN_PROC( open_in_t, ((fs_string_t)(path)) ((int32_t)(flags)) ((uint32_t)(mode)) )
IOFSL_SHIPPER_GEN_PROC( open_out_t, ((int32_t)(ret)) )

/* close */
IOFSL_SHIPPER_GEN_PROC( close_in_t, ((int32_t)(fd)) )
IOFSL_SHIPPER_GEN_PROC( close_out_t, ((int32_t)(ret)) )

/* write */
IOFSL_SHIPPER_GEN_PROC( write_in_t, ((int32_t)(fd)) ((bds_handle_t)(bds_handle)) )
IOFSL_SHIPPER_GEN_PROC( write_out_t, ((int64_t)(ret)) )

/* read */
IOFSL_SHIPPER_GEN_PROC( read_in_t, ((int32_t)(fd)) ((bds_handle_t)(bds_handle)) )
IOFSL_SHIPPER_GEN_PROC( read_out_t, ((int64_t)(ret)) )

#else
/* Define open_in_t */
typedef struct {
    fs_string_t path;
    int32_t flags;
    uint32_t mode;
} open_in_t;

/* Define fs_proc_open_in_t */
static inline int fs_proc_open_in_t(fs_proc_t proc, void *data)
{
    int ret = S_SUCCESS;
    open_in_t *struct_data = (open_in_t *) data;

    ret = fs_proc_fs_string_t(proc, &struct_data->path);
    if (ret != S_SUCCESS) {
        S_ERROR_DEFAULT("Proc error");
        ret = S_FAIL;
        return ret;
    }

    ret = fs_proc_int32_t(proc, &struct_data->flags);
    if (ret != S_SUCCESS) {
        S_ERROR_DEFAULT("Proc error");
        ret = S_FAIL;
        return ret;
    }

    ret = fs_proc_uint32_t(proc, &struct_data->mode);
    if (ret != S_SUCCESS) {
        S_ERROR_DEFAULT("Proc error");
        ret = S_FAIL;
        return ret;
    }

    return ret;
}

/* Define open_out_t */
typedef struct {
    int32_t ret;
} open_out_t;

/* Define fs_proc_open_out_t */
static inline int fs_proc_open_out_t(fs_proc_t proc, void *data)
{
    int ret = S_SUCCESS;
    open_out_t *struct_data = (open_out_t *) data;

    ret = fs_proc_int32_t(proc, &struct_data->ret);
    if (ret != S_SUCCESS) {
        S_ERROR_DEFAULT("Proc error");
        ret = S_FAIL;
        return ret;
    }

    return ret;
}

/* Define close_in_t */
typedef struct {
    int32_t fd;
} close_in_t;

/* Define fs_proc_open_in_t */
static inline int fs_proc_close_in_t(fs_proc_t proc, void *data)
{
    int ret = S_SUCCESS;
    close_in_t *struct_data = (close_in_t *) data;

    ret = fs_proc_int32_t(proc, &struct_data->fd);
    if (ret != S_SUCCESS) {
        S_ERROR_DEFAULT("Proc error");
        ret = S_FAIL;
        return ret;
    }

    return ret;
}

/* Define close_out_t */
typedef struct {
    int32_t ret;
} close_out_t;

/* Define fs_proc_open_out_t */
static inline int fs_proc_close_out_t(fs_proc_t proc, void *data)
{
    int ret = S_SUCCESS;
    close_out_t *struct_data = (close_out_t *) data;

    ret = fs_proc_int32_t(proc, &struct_data->ret);
    if (ret != S_SUCCESS) {
        S_ERROR_DEFAULT("Proc error");
        ret = S_FAIL;
        return ret;
    }

    return ret;
}

/* Define write_in_t */
typedef struct {
    int32_t fd;
    bds_handle_t bds_handle;
} write_in_t;

/* Define fs_proc_write_in_t */
static inline int fs_proc_write_in_t(fs_proc_t proc, void *data)
{
    int ret = S_SUCCESS;
    write_in_t *struct_data = (write_in_t *) data;

    ret = fs_proc_int32_t(proc, &struct_data->fd);
    if (ret != S_SUCCESS) {
        S_ERROR_DEFAULT("Proc error");
        ret = S_FAIL;
        return ret;
    }

    ret = fs_proc_bds_handle_t(proc, &struct_data->bds_handle);
    if (ret != S_SUCCESS) {
        S_ERROR_DEFAULT("Proc error");
        ret = S_FAIL;
        return ret;
    }

    return ret;
}

/* Define write_out_t */
typedef struct {
    int64_t ret;
} write_out_t;

/* Define fs_proc_write_out_t */
static inline int fs_proc_write_out_t(fs_proc_t proc, void *data)
{
    int ret = S_SUCCESS;
    write_out_t *struct_data = (write_out_t *) data;

    ret = fs_proc_int64_t(proc, &struct_data->ret);
    if (ret != S_SUCCESS) {
        S_ERROR_DEFAULT("Proc error");
        ret = S_FAIL;
        return ret;
    }

    return ret;
}

/* Define read_in_t */
typedef struct {
    int32_t fd;
    bds_handle_t bds_handle;
} read_in_t;

/* Define fs_proc_read_in_t */
static inline int fs_proc_read_in_t(fs_proc_t proc, void *data)
{
    int ret = S_SUCCESS;
    read_in_t *struct_data = (read_in_t *) data;

    ret = fs_proc_int32_t(proc, &struct_data->fd);
    if (ret != S_SUCCESS) {
        S_ERROR_DEFAULT("Proc error");
        ret = S_FAIL;
        return ret;
    }

    ret = fs_proc_bds_handle_t(proc, &struct_data->bds_handle);
    if (ret != S_SUCCESS) {
        S_ERROR_DEFAULT("Proc error");
        ret = S_FAIL;
        return ret;
    }

    return ret;
}

/* Define read_out_t */
typedef struct {
    int64_t ret;
} read_out_t;

/* Define fs_proc_read_out_t */
static inline int fs_proc_read_out_t(fs_proc_t proc, void *data)
{
    int ret = S_SUCCESS;
    read_out_t *struct_data = (read_out_t *) data;

    ret = fs_proc_int64_t(proc, &struct_data->ret);
    if (ret != S_SUCCESS) {
        S_ERROR_DEFAULT("Proc error");
        ret = S_FAIL;
        return ret;
    }

    return ret;
}

#endif

#endif /* TEST_FS_H */
