/*
 * Copyright (C) 2013 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#ifndef MERCURY_BULK_H
#define MERCURY_BULK_H

#include "na.h"
#include "mercury_error.h"

typedef void * hg_bulk_t;       /* Bulk data handle */
typedef void * hg_bulk_block_t; /* Block handle for bulk data */

#define HG_BULK_MAX_IDLE_TIME NA_MAX_IDLE_TIME

#define HG_BULK_READWRITE NA_MEM_READWRITE
#define HG_BULK_READ_ONLY NA_MEM_READ_ONLY

#define HG_BULK_NULL       ((hg_bulk_t)0)
#define HG_BULK_BLOCK_NULL ((hg_bulk_block_t)0)

#ifdef __cplusplus
extern "C" {
#endif

/* Initialize the bulk data shipper and select a network protocol */
int HG_Bulk_init(na_class_t *network_class);

/* Finalize */
int HG_Bulk_finalize(void);

/* Create bulk data handle from buffer (register memory, etc) */
int HG_Bulk_handle_create(void *buf, size_t buf_len, unsigned long flags,
        hg_bulk_t *handle);

/* Free bulk data handle */
int HG_Bulk_handle_free(hg_bulk_t handle);

/* Get data size from handle */
size_t HG_Bulk_handle_get_size(hg_bulk_t handle);

/* Serialize bulk data handle into buf */
int HG_Bulk_handle_serialize(void *buf, na_size_t buf_len, hg_bulk_t handle);

/* Deserialize bulk data handle from buf */
int HG_Bulk_handle_deserialize(hg_bulk_t *handle, const void *buf, na_size_t buf_len);

/* Write data */
int HG_Bulk_write(hg_bulk_t handle, na_addr_t dest, hg_bulk_block_t block_handle);

/* Read data */
int HG_Bulk_read(hg_bulk_t handle, na_addr_t source, hg_bulk_block_t block_handle);

/* Wait for bulk data operation to complete */
int HG_Bulk_wait(hg_bulk_block_t block_handle, unsigned int timeout);

/* Create bulk data handle from buffer (register memory, etc) */
int HG_Bulk_block_handle_create(void *buf, size_t block_size, unsigned long flags,
        hg_bulk_block_t *handle);

/* Free block handle */
int HG_Bulk_block_handle_free(hg_bulk_block_t block_handle);

/* Get data size from block handle */
size_t HG_Bulk_block_handle_get_size(hg_bulk_block_t block_handle);

#ifdef __cplusplus
}
#endif

#endif /* MERCURY_BULK_H */
