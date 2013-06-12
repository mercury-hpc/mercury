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
    size_t           total_size;       /* Total size of data registered */
    size_t          *size_list;        /* List of segment sizes corresponding
                                        * to each memory handle */
    na_mem_handle_t *mem_handle_list;  /* List of handles (single for contiguous
                                        * or multiple for non-contiguous) */
    size_t           count;            /* Number of handles */
    bool             registered;       /* The handle may be registered or simply
                                        * deserialized */
} hg_priv_bulk_t;

typedef struct hg_priv_bulk_block {
    void            *data;       /* Pointer to data */
    size_t           size;       /* Size */
    na_mem_handle_t  mem_handle; /* Memory handle */
} hg_priv_bulk_block_t;

typedef struct hg_priv_bulk_request {
    na_request_t *request_list;  /* List of requests */
    size_t        request_count; /* Number of requests */
} hg_priv_bulk_request_t;

/* Pointer to network abstraction class */
static na_class_t *bulk_na_class = NULL;

static bool bulk_dont_atexit = 0;

/* Automatically called at exit */
static void hg_bulk_atexit(void)
{
    if (bulk_na_class) {
        int hg_ret;

        /* Finalize interface */
        hg_ret = HG_Bulk_finalize();
        if (hg_ret != HG_SUCCESS) {
            HG_ERROR_DEFAULT("Could not finalize mercury bulk interface");
        }
    }
}

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

    if (!network_class) {
        HG_ERROR_DEFAULT("Invalid specified network_class");
        ret = HG_FAIL;
        return ret;
    }

    if (bulk_na_class) {
        HG_ERROR_DEFAULT("Already initialized");
        ret = HG_FAIL;
        return ret;
    }

    bulk_na_class = network_class;

    /*
     * Install atexit() library cleanup routine unless hg_dont_atexit is set.
     * Once we add something to the atexit() list it stays there permanently,
     * so we set H5_dont_atexit_g after we add it to prevent adding it again
     * later if the library is closed and reopened.
     */
    if (!bulk_dont_atexit) {
        (void) atexit(hg_bulk_atexit);
        bulk_dont_atexit = 1;
    }

    return ret;
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

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    HG_Bulk_initialized
 *
 * Purpose:     Indicate whether HG_Init has been called and return associated network class
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int HG_Bulk_initialized(bool *flag, na_class_t **network_class)
{
    int ret = HG_SUCCESS;

    if (!flag) {
        HG_ERROR_DEFAULT("NULL flag");
        ret = HG_FAIL;
        return ret;
    }

    *flag = (bulk_na_class) ? 1 : 0;
    if (network_class) *network_class = (*flag) ? bulk_na_class : 0;

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
    int ret = HG_SUCCESS, na_ret;
    hg_priv_bulk_t *priv_handle = NULL;
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
            goto done;
    }

    priv_handle = malloc(sizeof(hg_priv_bulk_t));
    priv_handle->count = 1;
    priv_handle->mem_handle_list = malloc(sizeof(na_mem_handle_t));
    priv_handle->total_size = buf_size;
    priv_handle->size_list = malloc(sizeof(size_t));
    priv_handle->size_list[0] = priv_handle->total_size;

    na_ret = NA_Mem_register(bulk_na_class, buf, buf_size, na_flags,
            &priv_handle->mem_handle_list[0]);
    if (na_ret != NA_SUCCESS) {
        HG_ERROR_DEFAULT("na_mem_register failed");
        ret = HG_FAIL;
        goto done;
    }

    priv_handle->registered = 1;
    *handle = (hg_bulk_t) priv_handle;

done:
    if (ret != HG_SUCCESS) {
        if (priv_handle) {
            if (priv_handle->size_list) free(priv_handle->size_list);
            priv_handle->size_list = NULL;
            if (priv_handle->mem_handle_list) free(priv_handle->mem_handle_list);
            priv_handle->mem_handle_list = NULL;
            free(priv_handle);
        }
        priv_handle = NULL;
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
    int ret = HG_SUCCESS, na_ret;
    hg_priv_bulk_t *priv_handle = NULL;
    size_t i;
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
            goto done;
    }

    priv_handle = malloc(sizeof(hg_priv_bulk_t));
    priv_handle->total_size = 0;

    /* The underlying layer may support non-contiguous mem registration */
    if (bulk_na_class->mem_register_segments) {
        /* In this case we only need one single handle */
        priv_handle->count = 1;
        priv_handle->mem_handle_list = malloc(sizeof(na_mem_handle_t));
        priv_handle->size_list = malloc(sizeof(size_t));

        na_ret = NA_Mem_register_segments(bulk_na_class,
                (na_segment_t*)bulk_segments, segment_count,
                na_flags, &priv_handle->mem_handle_list[0]);
        if (na_ret != NA_SUCCESS) {
            HG_ERROR_DEFAULT("na_mem_register failed");
            ret = HG_FAIL;
            goto done;
        }
        for (i = 0; i < segment_count; i++) {
            priv_handle->total_size += bulk_segments[i].size;
        }
        priv_handle->size_list[0] = priv_handle->total_size;
    } else {
        /* In this case we need multiple handles */
        priv_handle->count = segment_count;
        priv_handle->mem_handle_list = malloc(priv_handle->count * sizeof(na_mem_handle_t));
        priv_handle->size_list = malloc(priv_handle->count * sizeof(size_t));

        /* Loop over the list of segments and register them */
        for (i = 0; i < segment_count; i++) {
            na_ret = NA_Mem_register(bulk_na_class, bulk_segments[i].address,
                    bulk_segments[i].size, na_flags,
                    &priv_handle->mem_handle_list[i]);
            if (na_ret != NA_SUCCESS) {
                HG_ERROR_DEFAULT("na_mem_register failed");
                ret = HG_FAIL;
                goto done;
            }
            priv_handle->size_list[i] = bulk_segments[i].size;
            priv_handle->total_size += bulk_segments[i].size;
        }
    }

    priv_handle->registered = 1;
    *handle = (hg_bulk_t) priv_handle;

done:
    if (ret != HG_SUCCESS) {
        if (priv_handle) {
            if (priv_handle->size_list) free(priv_handle->size_list);
            priv_handle->size_list = NULL;
            if (priv_handle->mem_handle_list) free(priv_handle->mem_handle_list);
            priv_handle->mem_handle_list = NULL;
            free(priv_handle);
        }
        priv_handle = NULL;
    }
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
    int (*mem_handle_free)(na_class_t *network_class, na_mem_handle_t mem_handle);
    size_t i;

    if (!priv_handle) {
        HG_ERROR_DEFAULT("Already freed");
        ret = HG_FAIL;
        return ret;
    }

    if (priv_handle->registered) {
        mem_handle_free = NA_Mem_deregister;
    } else {
        mem_handle_free = NA_Mem_handle_free;
    }

    for (i = 0; i < priv_handle->count; i++) {
        na_ret = mem_handle_free(bulk_na_class,
                priv_handle->mem_handle_list[i]);
        if (na_ret != NA_SUCCESS) {
            HG_ERROR_DEFAULT("na_mem_deregister failed");
            ret = HG_FAIL;
            return ret;
        }
    }

    if (priv_handle->mem_handle_list) free(priv_handle->mem_handle_list);
    priv_handle->mem_handle_list = NULL;
    if (priv_handle->size_list) free(priv_handle->size_list);
    priv_handle->size_list = NULL;
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
        ret = priv_handle->total_size;
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
    size_t i;

    if (priv_handle) {
        ret = sizeof(priv_handle->total_size) + sizeof(priv_handle->count)
                + priv_handle->count * sizeof(size_t);
        for (i = 0; i < priv_handle->count; i++) {
            ret += NA_Mem_handle_get_serialize_size(bulk_na_class,
                    priv_handle->mem_handle_list[i]);
        }
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
    char *buf_ptr = buf;
    size_t buf_size_left = buf_size;
    size_t i;

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

    /* Add the size of the data */
    memcpy(buf_ptr, &priv_handle->total_size, sizeof(size_t));
    buf_ptr += sizeof(size_t);
    buf_size_left -= sizeof(size_t);

    /* Add the number of handles */
    memcpy(buf_ptr, &priv_handle->count, sizeof(size_t));
    buf_ptr += sizeof(size_t);
    buf_size_left -= sizeof(size_t);

    /* Add the list of sizes */
    for (i = 0; i < priv_handle->count; i++) {
        memcpy(buf_ptr, &priv_handle->size_list[i], sizeof(size_t));
        buf_ptr += sizeof(size_t);
        buf_size_left -= sizeof(size_t);
    }

    for (i = 0; i < priv_handle->count; i++) {
        na_ret = NA_Mem_handle_serialize(bulk_na_class, buf_ptr,
                buf_size_left, priv_handle->mem_handle_list[i]);
        if (na_ret != NA_SUCCESS) {
            HG_ERROR_DEFAULT("Could not serialize memory handle");
            ret = HG_FAIL;
            break;
        }
        buf_ptr += NA_Mem_handle_get_serialize_size(bulk_na_class,
                priv_handle->mem_handle_list[i]);
        buf_size_left -= NA_Mem_handle_get_serialize_size(bulk_na_class,
                priv_handle->mem_handle_list[i]);
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
    const char *buf_ptr = buf;
    size_t buf_size_left = buf_size;
    size_t i;

    if (!handle) {
        HG_ERROR_DEFAULT("NULL pointer to memory handle passed");
        ret = HG_FAIL;
        return ret;
    }

    priv_handle = malloc(sizeof(hg_priv_bulk_t));

    /* Get the size of the data */
    memcpy(&priv_handle->total_size, buf_ptr, sizeof(size_t));
    buf_ptr += sizeof(size_t);
    buf_size_left -= sizeof(size_t);

    /* Get the number of handles */
    memcpy(&priv_handle->count, buf_ptr, sizeof(size_t));
    buf_ptr += sizeof(size_t);
    buf_size_left -= sizeof(size_t);

    /* Add the list of sizes */
    priv_handle->size_list = malloc(priv_handle->count * sizeof(size_t));
    for (i = 0; i < priv_handle->count; i++) {
        memcpy(&priv_handle->size_list[i], buf_ptr, sizeof(size_t));
        buf_ptr += sizeof(size_t);
        buf_size_left -= sizeof(size_t);
        /*
        fprintf(stderr, "Segment[%lu] = %lu bytes\n", i, priv_handle->size_list[i]);
        */
    }

    priv_handle->mem_handle_list = malloc(priv_handle->count * sizeof(na_mem_handle_t));
    for (i = 0; i < priv_handle->count; i++) {
        na_ret = NA_Mem_handle_deserialize(bulk_na_class, &priv_handle->mem_handle_list[i],
                buf_ptr, buf_size_left);
        if (na_ret != NA_SUCCESS) {
            HG_ERROR_DEFAULT("Could not deserialize memory handle");
            ret = HG_FAIL;
            return ret;
        }
        buf_ptr += NA_Mem_handle_get_serialize_size(bulk_na_class,
                priv_handle->mem_handle_list[i]);
        buf_size_left -= NA_Mem_handle_get_serialize_size(bulk_na_class,
                priv_handle->mem_handle_list[i]);
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
    int ret = HG_SUCCESS, na_ret;
    hg_priv_bulk_block_t *priv_block_handle = NULL;
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
        return ret;
    }

    *block_handle = (hg_bulk_block_t) priv_block_handle;

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
 * Function:    hg_bulk_find_handle_list_info
 *
 * Purpose:     Get info for bulk transfer
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
static int hg_bulk_find_handle_list_info(hg_bulk_t bulk_handle,
        ptrdiff_t bulk_offset, size_t block_size, size_t *handle_index_start,
        ptrdiff_t *handle_offset, size_t *request_count)
{
    int ret = HG_SUCCESS;
    hg_priv_bulk_t *priv_handle = (hg_priv_bulk_t*) bulk_handle;
    size_t new_index_start = 0;
    ptrdiff_t new_handle_offset = bulk_offset, next_offset;
    size_t new_request_count;
    size_t new_size;
    size_t i;

    /* Get start index and handle offset */
    next_offset = 0;
    for (i = 0; i < priv_handle->count; i++) {
        next_offset += priv_handle->size_list[i];
        /*
        fprintf(stderr, "bulk_offset: %lu next_offset: %lu new_handle_offset: %lu\n",
                bulk_offset, next_offset, new_handle_offset);
        */
        if (bulk_offset < next_offset) {
            new_index_start = i;
            break;
        }
        new_handle_offset -= priv_handle->size_list[i];
    }

    /* Get request count, i.e. the number of requests needed to transfer data */
    new_request_count = 1;
    new_size = 0;
    for (i = new_index_start; i < priv_handle->count; i++) {
        new_size += priv_handle->size_list[i];
        if (i == new_index_start) new_size -= new_handle_offset;
        if (new_size >= block_size) break;
        new_request_count++;
    }

    *handle_index_start = new_index_start;
    *handle_offset = new_handle_offset;
    *request_count = new_request_count;

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
    ptrdiff_t local_offset, remote_offset;
    size_t transfer_size;
    size_t remaining_size = block_size;
    hg_priv_bulk_request_t *priv_bulk_request = NULL;
    size_t request_count;
    size_t handle_list_index_start;
    size_t i;
    size_t request_index = 0;

    if (!priv_handle) {
        HG_ERROR_DEFAULT("NULL memory handle passed");
        ret = HG_FAIL;
        return ret;
    }

    /* Translate bulk_offset */
    hg_bulk_find_handle_list_info(bulk_handle, bulk_offset, block_size,
            &handle_list_index_start, &remote_offset, &request_count);
    /*
    fprintf(stderr, "handle list index start: %lu\n"
            "remote offset: %lu\n"
            "request_count: %lu\n", handle_list_index_start, remote_offset, request_count);
    */

    /* Translate block offset */
    local_offset = block_offset;

    priv_bulk_request = malloc(sizeof(hg_priv_bulk_request_t));
    priv_bulk_request->request_count = request_count;
    priv_bulk_request->request_list = malloc(request_count * sizeof(na_request_t));

    for (i = handle_list_index_start; i < handle_list_index_start + request_count; i++) {
        /* Transfer size is (size available from handle - offset) or (remaining size) if smaller */
        transfer_size = priv_handle->size_list[i] - remote_offset;
        transfer_size = (remaining_size < transfer_size) ? remaining_size : transfer_size;

        na_ret = NA_Put(bulk_na_class,
                priv_block_handle->mem_handle, local_offset,
                priv_handle->mem_handle_list[i], remote_offset,
                transfer_size, addr, &priv_bulk_request->request_list[request_index]);
        if (na_ret != NA_SUCCESS) {
            HG_ERROR_DEFAULT("Could not put data");
            ret = HG_FAIL;
        }
        /* We started from the index that contains bulk_offset so further remote_offset are 0 */
        remote_offset = 0;
        /* Increase the local offset from the size of data we just transferred */
        local_offset += transfer_size;
        /* Decrease remaining size from the size of data we just transferred */
        remaining_size -= transfer_size;
        /* Increase request index */
        request_index++;
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
            block_handle, 0, priv_handle->total_size, bulk_request);
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
int HG_Bulk_read(na_addr_t addr, hg_bulk_t bulk_handle, ptrdiff_t bulk_offset,
        hg_bulk_block_t block_handle, ptrdiff_t block_offset, size_t block_size,
        hg_bulk_request_t *bulk_request)
{
    int ret = HG_SUCCESS, na_ret;
    hg_priv_bulk_t *priv_handle = (hg_priv_bulk_t*) bulk_handle;
    hg_priv_bulk_block_t *priv_block_handle = (hg_priv_bulk_block_t*) block_handle;
    ptrdiff_t local_offset, remote_offset;
    size_t transfer_size;
    size_t remaining_size = block_size;
    hg_priv_bulk_request_t *priv_bulk_request = NULL;
    size_t request_count;
    size_t handle_list_index_start;
    size_t i;
    size_t request_index = 0;

    if (!priv_handle) {
        HG_ERROR_DEFAULT("NULL memory handle passed");
        ret = HG_FAIL;
        return ret;
    }

    /* Translate bulk_offset */
    hg_bulk_find_handle_list_info(bulk_handle, bulk_offset, block_size,
            &handle_list_index_start, &remote_offset, &request_count);
    /*
    fprintf(stderr, "handle list index start: %lu\n"
            "remote offset: %lu\n"
            "request_count: %lu\n", handle_list_index_start, remote_offset, request_count);
    */

    /* Translate block offset */
    local_offset = block_offset;

    priv_bulk_request = malloc(sizeof(hg_priv_bulk_request_t));
    priv_bulk_request->request_count = request_count;
    priv_bulk_request->request_list = malloc(request_count * sizeof(na_request_t));

    for (i = handle_list_index_start; i < handle_list_index_start + request_count; i++) {
        /* Transfer size is (size available from handle - offset) or (remaining size) if smaller */
        transfer_size = priv_handle->size_list[i] - remote_offset;
        transfer_size = (remaining_size < transfer_size) ? remaining_size : transfer_size;

        na_ret = NA_Get(bulk_na_class,
                priv_block_handle->mem_handle, local_offset,
                priv_handle->mem_handle_list[i], remote_offset,
                transfer_size, addr, &priv_bulk_request->request_list[request_index]);
        if (na_ret != NA_SUCCESS) {
            HG_ERROR_DEFAULT("Could not get data");
            ret = HG_FAIL;
        }
        /* We started from the index that contains bulk_offset so further remote_offset are 0 */
        remote_offset = 0;
        /* Increase the local offset from the size of data we just transferred */
        local_offset += transfer_size;
        /* Decrease remaining size from the size of data we just transferred */
        remaining_size -= transfer_size;
        /* Increase request index */
        request_index++;
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
            block_handle, 0, priv_handle->total_size, bulk_request);
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

    /* Loop over request list and wait if request is not NULL otherwise
     * consider it as already completed */
    for (request_index = 0; request_index < priv_bulk_request->request_count;
            request_index++) {
        if (priv_bulk_request->request_list[request_index] != NA_REQUEST_NULL) {
            na_ret = NA_Wait(bulk_na_class,
                    priv_bulk_request->request_list[request_index],
                    timeout, &request_status);
            if (na_ret != NA_SUCCESS) {
                HG_ERROR_DEFAULT("Error during wait");
                ret = HG_FAIL;
                break;
            }
            if (request_status.completed) {
                /* Request has been freed in NA_Wait */
                priv_bulk_request->request_list[request_index] = NA_REQUEST_NULL;
                completed_count++;
            }
        } else {
            /* If NULL request has already been freed in NA_Wait */
            completed_count++;
        }
    }

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
