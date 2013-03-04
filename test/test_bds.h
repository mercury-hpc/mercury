/*
 * bds_test.h
 */

#ifndef BDS_TEST_H
#define BDS_TEST_H

#include "generic_macros.h"
#include "generic_proc.h"
#include "bulk_data_proc.h"

/* Dummy function that needs to be shipped */
size_t bla_write(int fildes, const void *buf, size_t nbyte);

/* Generate processor and struct for required input/output structs
 * IOFSL_SHIPPER_GEN_PROC( struct_type_name, fields )
 */
IOFSL_SHIPPER_GEN_PROC( bla_write_in_t, ((int32_t)(fildes)) ((bds_handle_t)(bds_handle)) )
IOFSL_SHIPPER_GEN_PROC( bla_write_out_t, ((uint64_t)(ret)) )

#endif /* BDS_TEST_H */
