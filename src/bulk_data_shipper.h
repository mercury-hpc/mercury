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

#ifndef BULK_DATA_SHIPPER_H
#define BULK_DATA_SHIPPER_H

#include "network_abstraction.h"

typedef void * bds_handle_t;       /* Bulk data handle */
typedef void * bds_block_handle_t; /* Block handle for bulk data */

#define BDS_MAX_IDLE_TIME NA_MAX_IDLE_TIME

#define BDS_READWRITE NA_MEM_READWRITE
#define BDS_READ_ONLY NA_MEM_READ_ONLY

#define BDS_HANDLE_NULL       ((bds_handle_t)0)
#define BDS_BLOCK_HANDLE_NULL ((bds_block_handle_t)0)

#ifdef __cplusplus
extern "C" {
#endif

/* Initialize the bulk data shipper and select a network protocol */
int bds_init(na_network_class_t *network_class);

/* Finalize */
int bds_finalize(void);

/* Create bulk data handle from buffer (register memory, etc) */
int bds_handle_create(void *buf, size_t buf_len, unsigned long flags,
        bds_handle_t *handle);

/* Free bulk data handle */
int bds_handle_free(bds_handle_t handle);

/* Get data size from handle */
size_t bds_handle_get_size(bds_handle_t handle);

/* Serialize bulk data handle into buf */
int bds_handle_serialize(void *buf, na_size_t buf_len, bds_handle_t handle);

/* Deserialize bulk data handle from buf */
int bds_handle_deserialize(bds_handle_t *handle, const void *buf, na_size_t buf_len);

/* Write data */
int bds_write(bds_handle_t handle, na_addr_t dest, bds_block_handle_t block_handle);

/* Read data */
int bds_read(bds_handle_t handle, na_addr_t source, bds_block_handle_t block_handle);

/* Wait for bulk data operation to complete */
int bds_wait(bds_block_handle_t block_handle, unsigned int timeout);

/* Create bulk data handle from buffer (register memory, etc) */
int bds_block_handle_create(void *buf, size_t block_size, unsigned long flags,
        bds_block_handle_t *handle);

/* Free block handle */
int bds_block_handle_free(bds_block_handle_t block_handle);

/* Get data size from block handle */
size_t bds_block_handle_get_size(bds_block_handle_t block_handle);

#ifdef __cplusplus
}
#endif

#endif /* BULK_DATA_SHIPPER_H */
