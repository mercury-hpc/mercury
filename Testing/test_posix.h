/*
 * Copyright (C) 2013-2014 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#ifndef TEST_POSIX_H
#define TEST_POSIX_H

#include "mercury_proc.h"
#include "mercury_proc_string.h"
#include "mercury_macros.h"

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#ifdef HG_HAS_BOOST

/* Dummy function that needs to be shipped (already defined) */
/*
 * 1. int open(const char *pathname, int flags, mode_t mode);
 * 2. int close(int fd);
 * 3. ssize_t write(int fd, const void *buf, size_t count);
 * 4. ssize_t read(int fd, void *buf, size_t count);
 */

/* Generate processor and struct for required input/output structs
 * MERCURY_GEN_PROC( struct_type_name, fields )
 */

/* open */
MERCURY_GEN_PROC( open_in_t, ((hg_const_string_t)(path)) ((hg_int32_t)(flags)) ((hg_uint32_t)(mode)) )
MERCURY_GEN_PROC( open_out_t, ((hg_int32_t)(ret)) )

/* close */
MERCURY_GEN_PROC( close_in_t, ((hg_int32_t)(fd)) )
MERCURY_GEN_PROC( close_out_t, ((hg_int32_t)(ret)) )

/* write */
MERCURY_GEN_PROC( write_in_t, ((hg_int32_t)(fd)) ((hg_bulk_t)(bulk_handle)) )
MERCURY_GEN_PROC( write_out_t, ((hg_int64_t)(ret)) )

/* read */
MERCURY_GEN_PROC( read_in_t, ((hg_int32_t)(fd)) ((hg_bulk_t)(bulk_handle)) )
MERCURY_GEN_PROC( read_out_t, ((hg_int64_t)(ret)) )

#else /* HG_HAS_BOOST */
/* Define open_in_t */
typedef struct {
    hg_const_string_t path;
    hg_int32_t flags;
    hg_uint32_t mode;
} open_in_t;

/* Define hg_proc_open_in_t */
static HG_INLINE int
hg_proc_open_in_t(hg_proc_t proc, void *data)
{
    int ret = HG_SUCCESS;
    open_in_t *struct_data = (open_in_t *) data;

    ret = hg_proc_hg_const_string_t(proc, &struct_data->path);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Proc error");
        return ret;
    }

    ret = hg_proc_int32_t(proc, &struct_data->flags);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Proc error");
        return ret;
    }

    ret = hg_proc_uint32_t(proc, &struct_data->mode);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Proc error");
        return ret;
    }

    return ret;
}

/* Define open_out_t */
typedef struct {
    hg_int32_t ret;
} open_out_t;

/* Define hg_proc_open_out_t */
static HG_INLINE int
hg_proc_open_out_t(hg_proc_t proc, void *data)
{
    int ret = HG_SUCCESS;
    open_out_t *struct_data = (open_out_t *) data;

    ret = hg_proc_int32_t(proc, &struct_data->ret);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Proc error");
        return ret;
    }

    return ret;
}

/* Define close_in_t */
typedef struct {
    hg_int32_t fd;
} close_in_t;

/* Define hg_proc_open_in_t */
static HG_INLINE int
hg_proc_close_in_t(hg_proc_t proc, void *data)
{
    int ret = HG_SUCCESS;
    close_in_t *struct_data = (close_in_t *) data;

    ret = hg_proc_int32_t(proc, &struct_data->fd);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Proc error");
        return ret;
    }

    return ret;
}

/* Define close_out_t */
typedef struct {
    hg_int32_t ret;
} close_out_t;

/* Define hg_proc_open_out_t */
static HG_INLINE int
hg_proc_close_out_t(hg_proc_t proc, void *data)
{
    int ret = HG_SUCCESS;
    close_out_t *struct_data = (close_out_t *) data;

    ret = hg_proc_int32_t(proc, &struct_data->ret);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Proc error");
        return ret;
    }

    return ret;
}

/* Define write_in_t */
typedef struct {
    hg_int32_t fd;
    hg_bulk_t bulk_handle;
} write_in_t;

/* Define hg_proc_write_in_t */
static HG_INLINE int
hg_proc_write_in_t(hg_proc_t proc, void *data)
{
    int ret = HG_SUCCESS;
    write_in_t *struct_data = (write_in_t *) data;

    ret = hg_proc_int32_t(proc, &struct_data->fd);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Proc error");
        return ret;
    }

    ret = hg_proc_hg_bulk_t(proc, &struct_data->bulk_handle);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Proc error");
        return ret;
    }

    return ret;
}

/* Define write_out_t */
typedef struct {
    hg_int64_t ret;
} write_out_t;

/* Define hg_proc_write_out_t */
static HG_INLINE int
hg_proc_write_out_t(hg_proc_t proc, void *data)
{
    int ret = HG_SUCCESS;
    write_out_t *struct_data = (write_out_t *) data;

    ret = hg_proc_int64_t(proc, &struct_data->ret);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Proc error");
        return ret;
    }

    return ret;
}

/* Define read_in_t */
typedef struct {
    hg_int32_t fd;
    hg_bulk_t bulk_handle;
} read_in_t;

/* Define hg_proc_read_in_t */
static HG_INLINE int
hg_proc_read_in_t(hg_proc_t proc, void *data)
{
    int ret = HG_SUCCESS;
    read_in_t *struct_data = (read_in_t *) data;

    ret = hg_proc_int32_t(proc, &struct_data->fd);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Proc error");
        return ret;
    }

    ret = hg_proc_hg_bulk_t(proc, &struct_data->bulk_handle);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Proc error");
        return ret;
    }

    return ret;
}

/* Define read_out_t */
typedef struct {
    hg_int64_t ret;
} read_out_t;

/* Define hg_proc_read_out_t */
static HG_INLINE int
hg_proc_read_out_t(hg_proc_t proc, void *data)
{
    int ret = HG_SUCCESS;
    read_out_t *struct_data = (read_out_t *) data;

    ret = hg_proc_int64_t(proc, &struct_data->ret);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Proc error");
        return ret;
    }

    return ret;
}

#endif

#endif /* TEST_POSIX_H */
