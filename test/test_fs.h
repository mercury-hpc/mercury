/*
 * test_fs.h
 */

#ifndef TEST_FS_H
#define TEST_FS_H

#include "generic_macros.h"
#include "generic_proc.h"

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

#endif /* TEST_FS_H */
