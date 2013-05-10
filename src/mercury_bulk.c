/*
 * Copyright (C) 2013 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#include "mercury_bulk.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

typedef struct hg_priv_bulk {
    size_t           size;             /* Total size of data registered */
    na_mem_handle_t *mem_handle_list;  /* List of handles (single for contiguous or multiple for non-contiguous) */
    size_t           mem_handle_count; /* Number of handles */
    bool             registered;       /* The handle may be registered or simply deserialized */
} hg_priv_bulk_t;

typedef struct hg_priv_bulk_block {
    void            *data;       /* Pointer to data */
    size_t           size;       /* Size */
    na_mem_handle_t  mem_handle; /* Memory handle */
} hg_priv_bulk_block_t;

typedef struct hg_priv_bulk_request {
    na_request_t *request_list;
    size_t        request_count;
} hg_priv_bulk_request_t;

static na_class_t *bulk_na_class = NULL;

/*---------------------------------------------------------------------------
 * Function:    HG_Bulk_init
 *
 * Purpose:     Initialize the bulk data shipper and select a network protocol
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int HG_Bulk_init(na_class_t *network_class)
{
    int ret = HG_SUCCESS;

    if (bulk_na_class) {
        HG_ERROR_DEFAULT("Already initialized");
        ret = HG_FAIL;
        return ret;
    }

    bulk_na_class = network_class;

    return HG_SUCCESS;
}

/*---------------------------------------------------------------------------
 * Function:    HG_Bulk_finalize
 *
 * Purpose:     Finalize
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int HG_Bulk_finalize(void)
{
    int ret = HG_SUCCESS;

    if (!bulk_na_class) {
        HG_ERROR_DEFAULT("Already finalized");
        ret = HG_FAIL;
        return ret;
    }

    bulk_na_class = NULL;

    return HG_SUCCESS;
}

/*---------------------------------------------------------------------------
 * Function:    HG_Bulk_handle_create
 *
 * Purpose:     Create bulk data handle from buffer (register memory, etc)
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int HG_Bulk_handle_create(void *buf, size_t buf_size, unsigned long flags,
        hg_bulk_t *handle)
{
    int ret, na_ret;
    hg_priv_bulk_t *priv_handle;
    unsigned long na_flags;

    switch (flags) {
        case HG_BULK_READWRITE:
            na_flags = NA_MEM_READWRITE;
            break;
        case HG_BULK_READ_ONLY:
            na_flags = NA_MEM_READ_ONLY;
            break;
        default:
            HG_ERROR_DEFAULT("Unrecognized handle flag");
            ret = HG_FAIL;
            return ret;
    }

    priv_handle = malloc(sizeof(hg_priv_bulk_t));
    priv_handle->size = buf_size;
    priv_handle->mem_handle_count = 1;
    priv_handle->mem_handle_list = malloc(sizeof(na_mem_handle_t));

    na_ret = NA_Mem_register(bulk_na_class, buf, buf_size, na_flags,
            &priv_handle->mem_handle_list[0]);
    if (na_ret != NA_SUCCESS) {
        HG_ERROR_DEFAULT("na_mem_register failed");
        free(priv_handle);
        priv_handle = NULL;
        ret = HG_FAIL;
    } else {
        priv_handle->registered = 1;
        *handle = (hg_bulk_t) priv_handle;
        ret = HG_SUCCESS;
    }

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    HG_Bulk_handle_create_segments
 *
 * Purpose:     Create bulk data handle from buffer (register memory, etc)
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int HG_Bulk_handle_create_segments(hg_bulk_segment_t *bulk_segments,
        size_t segment_count, unsigned long flags, hg_bulk_t *handle)
{
    int ret, na_ret;
    hg_priv_bulk_t *priv_handle;
    size_t segment_index;
    unsigned long na_flags;

    switch (flags) {
        case HG_BULK_READWRITE:
            na_flags = NA_MEM_READWRITE;
            break;
        case HG_BULK_READ_ONLY:
            na_flags = NA_MEM_READ_ONLY;
            break;
        default:
            HG_ERROR_DEFAULT("Unrecognized handle flag");
            ret = HG_FAIL;
            return ret;
    }

    priv_handle = malloc(sizeof(hg_priv_bulk_t));
    priv_handle->size = 0;

    for (segment_index = 0; segment_index < segment_count; segment_index++) {
        priv_handle->size += bulk_segments[segment_index].size;
    }

    /* The underlying layer may support non-contiguous mem registration */
    if (bulk_na_class->mem_register_segments) {
        /* In this case we only need one single handle */
        priv_handle->mem_handle_count = 1;
        priv_handle->mem_handle_list = malloc(sizeof(na_mem_handle_t));

        na_ret = NA_Mem_register_segments(bulk_na_class,
                (na_segment_t*)bulk_segments, segment_count,
                na_flags, &priv_handle->mem_handle_list[0]);
        if (na_ret != NA_SUCCESS) {
            HG_ERROR_DEFAULT("na_mem_register failed");
            free(priv_handle);
            priv_handle = NULL;
            ret = HG_FAIL;
            return ret;
        }
    } else {
        /* In this case we need multiple handles */
        priv_handle->mem_handle_count = segment_count;
        priv_handle->mem_handle_list = malloc(segment_count * sizeof(na_mem_handle_t));

        /* Loop over the list of segments and register them */
        for (segment_index = 0; segment_index < segment_count; segment_index++) {
            na_ret = NA_Mem_register(bulk_na_class, bulk_segments[segment_index].address,
                    bulk_segments[segment_index].size, na_flags,
                    &priv_handle->mem_handle_list[segment_index]);
            if (na_ret != NA_SUCCESS) {
                HG_ERROR_DEFAULT("na_mem_register failed");
                free(priv_handle);
                priv_handle = NULL;
                ret = HG_FAIL;
                return ret;
            }
        }
    }

    priv_handle->registered = 1;
    *handle = (hg_bulk_t) priv_handle;
    ret = HG_SUCCESS;

    return ret;
}


/*---------------------------------------------------------------------------
 * Function:    HG_Bulk_handle_free
 *
 * Purpose:     Free bulk data handle
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int HG_Bulk_handle_free(hg_bulk_t handle)
{
    int ret = HG_SUCCESS, na_ret;
    hg_priv_bulk_t *priv_handle = (hg_priv_bulk_t*) handle;
    int (*na_mem_handle_free)(na_class_t *network_class, na_mem_handle_t mem_handle);
    size_t mem_handle_list_index;

    if (!priv_handle) {
        HG_ERROR_DEFAULT("Already freed");
        ret = HG_FAIL;
        return ret;
    }

    if (priv_handle->registered) {
        na_mem_handle_free = NA_Mem_deregister;
    } else {
        na_mem_handle_free = NA_Mem_handle_free;
    }

    for (mem_handle_list_index = 0; mem_handle_list_index < priv_handle->mem_handle_count;
            mem_handle_list_index++) {
        na_ret = na_mem_handle_free(bulk_na_class,
                priv_handle->mem_handle_list[mem_handle_list_index]);
        if (na_ret != NA_SUCCESS) {
            HG_ERROR_DEFAULT("na_mem_deregister failed");
            ret = HG_FAIL;
        }
    }
    free(priv_handle->mem_handle_list);
    priv_handle->mem_handle_list = NULL;
    free(priv_handle);
    priv_handle = NULL;

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    HG_Bulk_handle_get_size
 *
 * Purpose:     Get data size from handle
 *
 *---------------------------------------------------------------------------
 */
size_t HG_Bulk_handle_get_size(hg_bulk_t handle)
{
    size_t ret = 0;
    hg_priv_bulk_t *priv_handle = (hg_priv_bulk_t*) handle;

    if (priv_handle) {
        ret = priv_handle->size;
    }

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    HG_Bulk_handle_get_serialize_size
 *
 * Purpose:     Get size required to serialize handle
 *
 *---------------------------------------------------------------------------
 */
size_t HG_Bulk_handle_get_serialize_size(hg_bulk_t handle)
{
    size_t ret = 0;
    hg_priv_bulk_t *priv_handle = (hg_priv_bulk_t*) handle;

    if (priv_handle) {
        ret = sizeof(priv_handle->size) +
                sizeof(priv_handle->mem_handle_count) +
                priv_handle->mem_handle_count *
                NA_Mem_handle_get_serialize_size(bulk_na_class);
    }

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    HG_Bulk_handle_serialize
 *
 * Purpose:     Serialize bulk data handle into buf
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int HG_Bulk_handle_serialize(void *buf, size_t buf_size, hg_bulk_t handle)
{
    int ret = HG_SUCCESS, na_ret;
    hg_priv_bulk_t *priv_handle = (hg_priv_bulk_t*) handle;
    void *buf_ptr = buf;
    size_t mem_handle_list_index;
    size_t buf_size_left = buf_size;

    if (!priv_handle) {
        HG_ERROR_DEFAULT("NULL memory handle passed");
        ret = HG_FAIL;
        return ret;
    }

    if (buf_size < HG_Bulk_handle_get_serialize_size(handle)) {
        HG_ERROR_DEFAULT("Buffer size too small for serializing parameter");
        ret = HG_FAIL;
        return ret;
    }

    fprintf(stderr, "Buffer size: %d\n", buf_size);

    /* Add the size of the data */
    memcpy(buf_ptr, &priv_handle->size, sizeof(size_t));
    buf_ptr += sizeof(size_t);
    buf_size_left -= sizeof(size_t);
    fprintf(stderr, "Handle size: %d\n", priv_handle->size);


    /* Add the number of handles */
    memcpy(buf_ptr, &priv_handle->mem_handle_count, sizeof(size_t));
    buf_ptr += sizeof(size_t);
    buf_size_left -= sizeof(size_t);
    fprintf(stderr, "Handle count: %d\n", priv_handle->mem_handle_count);

    for (mem_handle_list_index = 0; mem_handle_list_index < priv_handle->mem_handle_count;
            mem_handle_list_index++) {
        na_ret = NA_Mem_handle_serialize(bulk_na_class, buf_ptr,
                buf_size_left, priv_handle->mem_handle_list[mem_handle_list_index]);
        if (na_ret != NA_SUCCESS) {

            HG_ERROR_DEFAULT("Could not serialize memory handle");
            ret = HG_FAIL;
            break;
        }
        buf_ptr += NA_Mem_handle_get_serialize_size(bulk_na_class);
        buf_size_left -= NA_Mem_handle_get_serialize_size(bulk_na_class);
    }

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    HG_Bulk_handle_deserialize
 *
 * Purpose:     Deserialize bulk data handle from buf
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int HG_Bulk_handle_deserialize(hg_bulk_t *handle, const void *buf, size_t buf_size)
{
    int ret = HG_SUCCESS, na_ret;
    hg_priv_bulk_t *priv_handle = NULL;
    const void *buf_ptr = buf;
    size_t mem_handle_list_index;
    size_t buf_size_left = buf_size;

    if (!handle) {
        HG_ERROR_DEFAULT("NULL pointer to memory handle passed");
        ret = HG_FAIL;
        return ret;
    }

    priv_handle = malloc(sizeof(hg_priv_bulk_t));

    /* Get the size of the data */
    memcpy(&priv_handle->size, buf_ptr, sizeof(size_t));
    buf_ptr += sizeof(size_t);
    buf_size_left -= sizeof(size_t);
    fprintf(stderr, "Handle size: %d\n", priv_handle->size);

    /* Get the number of handles */
    memcpy(&priv_handle->mem_handle_count, buf_ptr, sizeof(size_t));
    buf_ptr += sizeof(size_t);
    buf_size_left -= sizeof(size_t);
    fprintf(stderr, "Handle count: %d\n", priv_handle->mem_handle_count);

    priv_handle->mem_handle_list = malloc(priv_handle->mem_handle_count *
           sizeof(na_mem_handle_t));
    for (mem_handle_list_index = 0; mem_handle_list_index < priv_handle->mem_handle_count;
            mem_handle_list_index++) {
        na_ret = NA_Mem_handle_deserialize(bulk_na_class, &priv_handle->mem_handle_list[mem_handle_list_index],
                buf_ptr, buf_size_left);
        if (na_ret != NA_SUCCESS) {
            HG_ERROR_DEFAULT("Could not deserialize memory handle");
            ret = HG_FAIL;
            return ret;
        }
        buf_ptr += NA_Mem_handle_get_serialize_size(bulk_na_class);
        buf_size_left -= NA_Mem_handle_get_serialize_size(bulk_na_class);
    }

    /* The handle is not registered, only deserialized */
    priv_handle->registered = 0;
    *handle = priv_handle;

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    HG_Bulk_block_handle_create
 *
 * Purpose:     Create bulk data handle from buffer (register memory, etc)
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int HG_Bulk_block_handle_create(void *buf, size_t block_size, unsigned long flags,
        hg_bulk_block_t *block_handle)
{
    int ret, na_ret;
    hg_priv_bulk_block_t *priv_block_handle;
    unsigned long na_flags;

    switch (flags) {
        case HG_BULK_READWRITE:
            na_flags = NA_MEM_READWRITE;
            break;
        case HG_BULK_READ_ONLY:
            na_flags = NA_MEM_READ_ONLY;
            break;
        default:
            HG_ERROR_DEFAULT("Unrecognized handle flag");
            ret = HG_FAIL;
            return ret;
    }

    priv_block_handle = malloc(sizeof(hg_priv_bulk_block_t));
    priv_block_handle->data = buf;
    priv_block_handle->size = block_size;

    na_ret = NA_Mem_register(bulk_na_class, buf, block_size, na_flags,
            &priv_block_handle->mem_handle);
    if (na_ret != NA_SUCCESS) {
        HG_ERROR_DEFAULT("Could not register block");
        free(priv_block_handle);
        priv_block_handle = NULL;
        ret = HG_FAIL;
    } else {
        *block_handle = (hg_bulk_block_t) priv_block_handle;
        ret = HG_SUCCESS;
    }

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    HG_Bulk_block_handle_free
 *
 * Purpose:     Free block handle
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int HG_Bulk_block_handle_free(hg_bulk_block_t block_handle)
{
    int ret = HG_SUCCESS, na_ret;
    hg_priv_bulk_block_t *priv_block_handle = (hg_priv_bulk_block_t*) block_handle;

    if (!priv_block_handle) {
        HG_ERROR_DEFAULT("Already freed");
        ret = HG_FAIL;
    }

    na_ret = NA_Mem_deregister(bulk_na_class, priv_block_handle->mem_handle);
    if (na_ret != NA_SUCCESS) {
        HG_ERROR_DEFAULT("Could not deregister block");
        ret = HG_FAIL;
        return ret;
    }
    free(priv_block_handle);
    priv_block_handle = NULL;

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    HG_Bulk_block_handle_get_size
 *
 * Purpose:     Get data size from block handle
 *
 *---------------------------------------------------------------------------
 */
size_t HG_Bulk_block_handle_get_size(hg_bulk_block_t block_handle)
{
    size_t ret = 0;
    hg_priv_bulk_block_t *priv_block_handle = (hg_priv_bulk_block_t*) block_handle;

    if (priv_block_handle) {
        ret = priv_block_handle->size;
    }

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    HG_Bulk_write
 *
 * Purpose:     Write data
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int HG_Bulk_write(na_addr_t addr, hg_bulk_t bulk_handle, ptrdiff_t bulk_offset,
        hg_bulk_block_t block_handle, ptrdiff_t block_offset, size_t block_size,
        hg_bulk_request_t *bulk_request)
{
    int ret = HG_SUCCESS, na_ret;
    hg_priv_bulk_t *priv_handle = (hg_priv_bulk_t*) bulk_handle;
    hg_priv_bulk_block_t *priv_block_handle = (hg_priv_bulk_block_t*) block_handle;
    size_t mem_handle_list_index;
    na_offset_t local_offset = (na_offset_t) block_offset;
    na_size_t actual_block_size = (na_size_t) block_size;
    na_offset_t remote_offset = (na_offset_t) bulk_offset;
    hg_priv_bulk_request_t *priv_bulk_request = NULL;

    if (!priv_handle) {
        HG_ERROR_DEFAULT("NULL memory handle passed");
        ret = HG_FAIL;
        return ret;
    }

    priv_bulk_request = malloc(sizeof(hg_priv_bulk_request_t));
    priv_bulk_request->request_count = 1;
    priv_bulk_request->request_list = malloc(priv_bulk_request->request_count *
            sizeof(na_request_t));

    for (mem_handle_list_index = 0; mem_handle_list_index < priv_handle->mem_handle_count;
            mem_handle_list_index++) {

        /* Work out local / remote offset / actual_block_size */

        na_ret = NA_Put(bulk_na_class,
                priv_block_handle->mem_handle, local_offset,
                priv_handle->mem_handle_list[mem_handle_list_index], remote_offset,
                actual_block_size, addr, &priv_bulk_request->request_list[mem_handle_list_index]);
        if (na_ret != NA_SUCCESS) {
            HG_ERROR_DEFAULT("Could not put data");
            ret = HG_FAIL;
        }
    }

    *bulk_request = (hg_bulk_request_t) priv_bulk_request;

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    HG_Bulk_write_all
 *
 * Purpose:     Write all the data at the address contained in the bulk handle
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int HG_Bulk_write_all(na_addr_t addr, hg_bulk_t bulk_handle,
        hg_bulk_block_t block_handle, hg_bulk_request_t *bulk_request)
{
    int ret = HG_SUCCESS;
    hg_priv_bulk_t *priv_handle = (hg_priv_bulk_t*) bulk_handle;

    ret = HG_Bulk_write(addr, bulk_handle, 0,
            block_handle, 0, priv_handle->size, bulk_request);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Could not write data");
        ret = HG_FAIL;
    }

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    HG_Bulk_read
 *
 * Purpose:     Read data
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int HG_Bulk_read(na_addr_t addr, hg_bulk_t bulk_handle, size_t bulk_offset,
        hg_bulk_block_t block_handle, size_t block_offset, size_t block_size,
        hg_bulk_request_t *bulk_request)
{
    int ret = HG_SUCCESS, na_ret;
    hg_priv_bulk_t *priv_handle = (hg_priv_bulk_t*) bulk_handle;
    hg_priv_bulk_block_t *priv_block_handle = (hg_priv_bulk_block_t*) block_handle;
    size_t mem_handle_list_index;
    na_offset_t local_offset = (na_offset_t) block_offset;
    na_size_t actual_block_size = (na_size_t) block_size;
    na_offset_t remote_offset = (na_offset_t) bulk_offset;
    hg_priv_bulk_request_t *priv_bulk_request = NULL;

    if (!priv_handle) {
        HG_ERROR_DEFAULT("NULL memory handle passed");
        ret = HG_FAIL;
        return ret;
    }

    priv_bulk_request = malloc(sizeof(hg_priv_bulk_request_t));
    priv_bulk_request->request_count = priv_handle->mem_handle_count;
    priv_bulk_request->request_list = malloc(priv_bulk_request->request_count *
            sizeof(na_request_t));

    for (mem_handle_list_index = 0; mem_handle_list_index < priv_handle->mem_handle_count;
            mem_handle_list_index++) {

        /* Work out local / remote offset / actual_block_size */

        na_ret = NA_Get(bulk_na_class,
                priv_block_handle->mem_handle, local_offset,
                priv_handle->mem_handle_list[mem_handle_list_index], remote_offset,
                actual_block_size, addr, &priv_bulk_request->request_list[mem_handle_list_index]);
        if (na_ret != NA_SUCCESS) {
            HG_ERROR_DEFAULT("Could not get data");
            ret = HG_FAIL;
        }
    }

    *bulk_request = (hg_bulk_request_t) priv_bulk_request;

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    HG_Bulk_read_all
 *
 * Purpose:     Read all the data from the address contained in the bulk handle
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int HG_Bulk_read_all(na_addr_t addr, hg_bulk_t bulk_handle,
        hg_bulk_block_t block_handle, hg_bulk_request_t *bulk_request)
{
    int ret = HG_SUCCESS;
    hg_priv_bulk_t *priv_handle = (hg_priv_bulk_t*) bulk_handle;

    ret = HG_Bulk_read(addr, bulk_handle, 0,
            block_handle, 0, priv_handle->size, bulk_request);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Could not read data");
        ret = HG_FAIL;
    }

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    HG_Bulk_wait
 *
 * Purpose:     Wait for bulk data operation to complete
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int HG_Bulk_wait(hg_bulk_request_t bulk_request, unsigned int timeout,
        hg_bulk_status_t *status)
{
    int ret = HG_SUCCESS, na_ret;
    na_status_t request_status;
    hg_priv_bulk_request_t *priv_bulk_request =
            (hg_priv_bulk_request_t*) bulk_request;
    size_t request_index;
    size_t completed_count = 0;

    if (!priv_bulk_request) {
        HG_ERROR_DEFAULT("NULL request passed");
        ret = HG_FAIL;
        return ret;
    }

    fprintf(stderr, "Got %d requests\n", priv_bulk_request->request_count);
    /* Loop over request list and wait if request is not NULL otherwise
     * consider it as already completed */
    do {
        completed_count = 0;
    for (request_index = 0; request_index < priv_bulk_request->request_count;
            request_index++) {
        if (priv_bulk_request->request_list[request_index] != NA_REQUEST_NULL) {
            na_ret = NA_Wait(bulk_na_class,
                    priv_bulk_request->request_list[request_index],
                    0, &request_status);
            if (na_ret != NA_SUCCESS) {
                HG_ERROR_DEFAULT("Error during wait");
                ret = HG_FAIL;
                break;
            }
            if (request_status.completed) {
                fprintf(stderr, "request completed!\n");
                /* Request has been freed in NA_Wait */
                priv_bulk_request->request_list[request_index] = NA_REQUEST_NULL;
                completed_count++;
            }
        } else {
            /* If NULL request has already been freed in NA_Wait */
            completed_count++;
        }
    }
    } while (completed_count != priv_bulk_request->request_count);

    if (completed_count == priv_bulk_request->request_count) {
        /* Everything completed */
        if (status && (status != HG_BULK_STATUS_IGNORE)) {
            *status = 1;
        }
        free(priv_bulk_request->request_list);
        priv_bulk_request->request_list = NULL;
        free(priv_bulk_request);
        priv_bulk_request = NULL;
    } else {
        /* Not completed */
        if (status && (status != HG_BULK_STATUS_IGNORE)) {
            *status = 0;
        }
    }
    return ret;
}
