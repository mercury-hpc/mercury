/*
 * bds_test.h
 */

#ifndef BDS_TEST_H
#define BDS_TEST_H

#include "generic_macros.h"
#include "generic_proc.h"

/* Dummy function that needs to be shipped */
size_t bla_write(int fildes, const void *buf, size_t nbyte);

#ifdef IOFSL_SHIPPER_HAS_BOOST
/* Generate processor and struct for required input/output structs
 * IOFSL_SHIPPER_GEN_PROC( struct_type_name, fields )
 */
IOFSL_SHIPPER_GEN_PROC( bla_write_in_t, ((int32_t)(fildes)) ((bds_handle_t)(bds_handle)) )
IOFSL_SHIPPER_GEN_PROC( bla_write_out_t, ((uint64_t)(ret)) )
#else
/* Define bla_write_in_t */
typedef struct {
    int32_t fildes;
    bds_handle_t bds_handle;
} bla_write_in_t;

/* Define fs_proc_bla_write_in_t */
static inline int fs_proc_bla_write_in_t(fs_proc_t proc, void *data)
{
    int ret = S_SUCCESS;
    bla_write_in_t *struct_data = (bla_write_in_t *) data;

    ret = fs_proc_int32_t(proc, &struct_data->fildes);
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

/* Define bla_write_out_t */
typedef struct {
    uint64_t ret;
} bla_write_out_t;

/* Define fs_proc_bla_write_out_t */
static inline int fs_proc_bla_write_out_t(fs_proc_t proc, void *data)
{
    int ret = S_SUCCESS;
    bla_write_out_t *struct_data = (bla_write_out_t *) data;

    ret = fs_proc_uint64_t(proc, &struct_data->ret);
    if (ret != S_SUCCESS) {
        S_ERROR_DEFAULT("Proc error");
        ret = S_FAIL;
        return ret;
    }

    return ret;
}
#endif

#endif /* BDS_TEST_H */
