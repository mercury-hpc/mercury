/*
 * bulk_data_shipper.h
 *
 * Bulk data routines (called by client)
 * init/finalize/handle_create/handle_serialize/handle_free
 *
 * Bulk data routines (called by server)
 * init/handle_deserialize/write/wait/get_data/get_size/set_size/handle_free
 */

#ifndef BULK_DATA_SHIPPER_H
#define BULK_DATA_SHIPPER_H

#include "network_abstraction.h"

typedef void * bds_handle_t;       /* Bulk data handle */
typedef void * bds_block_handle_t; /* Block handle for bulk data */

#define BDS_MAX_IDLE_TIME NA_MAX_IDLE_TIME
#define BDS_READWRITE NA_MEM_READWRITE
#define BDS_READ_ONLY NA_MEM_READ_ONLY

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

/* Serialize bulk data handle into buf */
int bds_handle_serialize(void *buf, na_size_t buf_len, bds_handle_t handle);

/* Deserialize bulk data handle from buf */
int bds_handle_deserialize(bds_handle_t *handle, const void *buf, na_size_t buf_len);

/* Write data */
int bds_write(bds_handle_t handle, na_addr_t dest, bds_block_handle_t *block_handle);

/* Read data */
int bds_read(bds_handle_t handle, na_addr_t source, bds_block_handle_t *block_handle);

/* Wait for bulk data operation to complete */
int bds_wait(bds_block_handle_t block_handle, unsigned int timeout);

/* Get data pointer from handle */
void* bds_block_handle_get_data(bds_block_handle_t block_handle);

/* Get data size from block handle */
size_t bds_block_handle_get_size(bds_block_handle_t block_handle);

/* Set data size to block handle */
void bds_block_handle_set_size(bds_block_handle_t block_handle, size_t size);

/* Free block handle */
int bds_block_handle_free(bds_block_handle_t block_handle);

#ifdef __cplusplus
}
#endif

#endif /* BULK_DATA_SHIPPER_H */
