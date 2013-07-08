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

/* TODO Make that more portable */
#include <stddef.h>

typedef void * hg_bulk_t;         /* Bulk data handle */
typedef void * hg_bulk_block_t;   /* Block handle for bulk data */
typedef void * hg_bulk_request_t; /* Request object */
typedef bool   hg_bulk_status_t;  /* Status of the operation */

typedef struct hg_bulk_segment {
        void   *address; /* address of the segment */
        size_t  size;    /* size of the segment in bytes */
} hg_bulk_segment_t;

#define HG_BULK_STATUS_IGNORE ((hg_bulk_status_t *)1)

#define HG_BULK_MAX_IDLE_TIME NA_MAX_IDLE_TIME

#define HG_BULK_READWRITE NA_MEM_READWRITE
#define HG_BULK_READ_ONLY NA_MEM_READ_ONLY

#define HG_BULK_NULL         ((hg_bulk_t)0)
#define HG_BULK_BLOCK_NULL   ((hg_bulk_block_t)0)
#define HG_BULK_REQUEST_NULL ((hg_bulk_request_t)0)

#ifdef __cplusplus
extern "C" {
#endif

/* Initialize the bulk data shipper and select a network protocol */
int HG_Bulk_init(na_class_t *network_class);

/* Finalize */
int HG_Bulk_finalize(void);

/* Indicate whether HG_Bulk_init has been called and return associated network class */
int HG_Bulk_initialized(bool *flag, na_class_t **network_class);

/* Create bulk data handle from buffer (register memory, etc) */
int HG_Bulk_handle_create(void *buf, size_t buf_size, unsigned long flags,
        hg_bulk_t *handle);

/* Create bulk data handle from arbitrary memory regions */
int HG_Bulk_handle_create_segments(hg_bulk_segment_t *bulk_segments,
        size_t segment_count, unsigned long flags, hg_bulk_t *handle);

/* Free bulk data handle */
int HG_Bulk_handle_free(hg_bulk_t handle);

/* Get data size from handle */
size_t HG_Bulk_handle_get_size(hg_bulk_t handle);

/* Get size required to serialize handle */
size_t HG_Bulk_handle_get_serialize_size(hg_bulk_t handle);

/* Serialize bulk data handle into buf */
int HG_Bulk_handle_serialize(void *buf, size_t buf_size, hg_bulk_t handle);

/* Deserialize bulk data handle from buf */
int HG_Bulk_handle_deserialize(hg_bulk_t *handle, const void *buf, size_t buf_size);

/* Create bulk data handle from buffer (register memory, etc) */
int HG_Bulk_block_handle_create(void *buf, size_t buf_size, unsigned long flags,
        hg_bulk_block_t *handle);

/* Free block handle */
int HG_Bulk_block_handle_free(hg_bulk_block_t block_handle);

/* Get data size from block handle */
size_t HG_Bulk_block_handle_get_size(hg_bulk_block_t block_handle);

/* Write data */
int HG_Bulk_write(na_addr_t addr, hg_bulk_t bulk_handle, ptrdiff_t bulk_offset,
        hg_bulk_block_t block_handle, ptrdiff_t block_offset, size_t block_size,
        hg_bulk_request_t *bulk_request);

/* Write all the data at the address contained in the bulk handle */
int HG_Bulk_write_all(na_addr_t addr, hg_bulk_t bulk_handle,
        hg_bulk_block_t block_handle, hg_bulk_request_t *bulk_request);

/* Read data */
int HG_Bulk_read(na_addr_t addr, hg_bulk_t bulk_handle, ptrdiff_t bulk_offset,
        hg_bulk_block_t block_handle, ptrdiff_t block_offset, size_t block_size,
        hg_bulk_request_t *bulk_request);

/* Read all the data from the address contained in the bulk handle */
int HG_Bulk_read_all(na_addr_t addr, hg_bulk_t bulk_handle,
        hg_bulk_block_t block_handle, hg_bulk_request_t *bulk_request);

/* Wait for bulk data operation to complete */
int HG_Bulk_wait(hg_bulk_request_t bulk_request, unsigned int timeout,
        hg_bulk_status_t *status);

#ifdef __cplusplus
}
#endif

#endif /* MERCURY_BULK_H */
