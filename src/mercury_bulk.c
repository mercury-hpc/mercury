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
#include "mercury_error.h"

/* TODO see if we can avoid to have to include that header */
#include "na_private.h"

#include "mercury_thread_mutex.h"
#include "mercury_thread_condition.h"
#include "mercury_time.h"
#include "mercury_util_error.h"

#include <stdlib.h>
#include <string.h>

/****************/
/* Local Macros */
/****************/
#define HG_BULK_MIN(a, b) \
    (a < b) ? a : b

/************************************/
/* Local Type and Struct Definition */
/************************************/
typedef enum {
    HG_BULK_WRITE,
    HG_BULK_READ
} hg_bulk_op_t;

typedef na_return_t (*na_bulk_op_t)(
        na_class_t      *na_class,
        na_context_t    *context,
        na_cb_t          callback,
        void            *arg,
        na_mem_handle_t  local_mem_handle,
        na_offset_t      local_offset,
        na_mem_handle_t  remote_mem_handle,
        na_offset_t      remote_offset,
        na_size_t        data_size,
        na_addr_t        remote_addr,
        na_op_id_t      *op_id
        );

struct hg_bulk {
    size_t total_size;                /* Total size of data registered */
    size_t segment_count;             /* Number of segments */
    size_t *segment_sizes;            /* Array of segment sizes */
    na_mem_handle_t *segment_handles; /* Array of memory handles */
    hg_bool_t registered;
};

struct hg_bulk_request {
    size_t op_count; /* Number of ongoing operations */
    size_t op_completed_count; /* Number of operations completed */
    hg_bool_t completed;
};

/********************/
/* Local Prototypes */
/********************/

/**
 * Free handle.
 */
static hg_return_t hg_bulk_handle_free(struct hg_bulk *priv_handle);

/**
 * Get info for bulk transfer.
 */
static hg_return_t hg_bulk_offset_translate(hg_bulk_t bulk_handle,
        size_t bulk_offset, size_t *segment_start_index,
        size_t *segment_start_offset);

/**
 * Transfer callback.
 */
static na_return_t hg_bulk_transfer_cb(const struct na_cb_info *callback_info);

/**
 * Transfer data.
 */
hg_return_t hg_bulk_transfer(hg_bulk_op_t op, na_addr_t addr,
        hg_bulk_t bulk_handle, size_t bulk_offset,
        hg_bulk_t block_handle, size_t block_offset,
        size_t block_size, hg_bulk_request_t *bulk_request);

/*******************/
/* Local Variables */
/*******************/

/* Pointer to network abstraction class */
static na_class_t *hg_bulk_na_class_g = NULL;

/* Local context */
static na_context_t *hg_bulk_context_g = NULL;

/* Mutex used for request completion */
static hg_thread_mutex_t hg_bulk_request_mutex_g;

/* Mutex/cond to prevent concurrent request trigger/progress */
static hg_thread_mutex_t hg_bulk_progress_mutex_g;
static hg_thread_cond_t hg_bulk_progress_cond_g;
static hg_bool_t hg_bulk_progressing_g = HG_FALSE;

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Bulk_init(na_class_t *na_class)
{
    hg_return_t ret = HG_SUCCESS;

    if (!na_class) {
        HG_ERROR_DEFAULT("Invalid specified na_class");
        ret = HG_FAIL;
        goto done;
    }

    /* TODO: This code may have to be changed in accordance with the
     *       outcome of Trac#24.
     */
    if (hg_bulk_na_class_g) {
        HG_WARNING_DEFAULT("Already initialized");
        ret = HG_SUCCESS;
        goto done;
    }

    hg_bulk_na_class_g = na_class;

    /* Create local context */
    hg_bulk_context_g = NA_Context_create(hg_bulk_na_class_g);
    if (!hg_bulk_context_g) {
        HG_ERROR_DEFAULT("Could not create context.");
        ret = HG_FAIL;
        goto done;
    }

    /* Initilialize mutex */
    hg_thread_mutex_init(&hg_bulk_request_mutex_g);
    hg_thread_mutex_init(&hg_bulk_progress_mutex_g);
    hg_thread_cond_init(&hg_bulk_progress_cond_g);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Bulk_finalize(void)
{
    hg_return_t ret = HG_SUCCESS;
    na_return_t na_ret;

    if (!hg_bulk_na_class_g) {
        HG_ERROR_DEFAULT("Already finalized");
        ret = HG_FAIL;
        goto done;
    }

    /* Destroy context */
    na_ret = NA_Context_destroy(hg_bulk_na_class_g, hg_bulk_context_g);
    if (na_ret != NA_SUCCESS) {
        HG_ERROR_DEFAULT("Could not destroy context.");
        ret = HG_FAIL;
        goto done;
    }

    hg_bulk_na_class_g = NULL;

    /* Destroy mutex */
    hg_thread_mutex_destroy(&hg_bulk_request_mutex_g);
    hg_thread_mutex_destroy(&hg_bulk_progress_mutex_g);
    hg_thread_cond_destroy(&hg_bulk_progress_cond_g);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Bulk_initialized(hg_bool_t *flag, na_class_t **na_class)
{
    hg_return_t ret = HG_SUCCESS;

    if (!flag) {
        HG_ERROR_DEFAULT("NULL flag");
        ret = HG_FAIL;
        goto done;
    }

    *flag = (hg_bulk_na_class_g != NULL);
    if (na_class) *na_class = hg_bulk_na_class_g;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Bulk_handle_create(void *buf, size_t buf_size, unsigned long flags,
        hg_bulk_t *handle)
{
    hg_return_t ret = HG_SUCCESS;
    na_return_t na_ret;
    struct hg_bulk *priv_handle = NULL;
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

    priv_handle = (struct hg_bulk *) malloc(sizeof(struct hg_bulk));
    if (!priv_handle) {
        HG_ERROR_DEFAULT("Could not allocate handle");
        ret = HG_FAIL;
        goto done;
    }
    priv_handle->total_size = buf_size;
    priv_handle->segment_count = 1;
    priv_handle->segment_sizes = NULL;
    priv_handle->segment_handles = NULL;
    priv_handle->registered = HG_FALSE;

    /* Allocate segment sizes */
    priv_handle->segment_sizes = (size_t *) malloc(sizeof(size_t));
    if (!priv_handle->segment_sizes) {
        HG_ERROR_DEFAULT("Could not allocate segment size array");
        ret = HG_FAIL;
        goto done;
    }
    priv_handle->segment_sizes[0] = priv_handle->total_size;

    /* Allocate segment handles */
    priv_handle->segment_handles = (na_mem_handle_t *) malloc(
            sizeof(na_mem_handle_t));
    if (!priv_handle->segment_handles) {
        HG_ERROR_DEFAULT("Could not allocate mem handle array");
        ret = HG_FAIL;
        goto done;
    }
    priv_handle->segment_handles[0] = NA_MEM_HANDLE_NULL;
    na_ret = NA_Mem_handle_create(hg_bulk_na_class_g, buf, buf_size, na_flags,
            &priv_handle->segment_handles[0]);
    if (na_ret != NA_SUCCESS) {
        HG_ERROR_DEFAULT("NA_Mem_handle_create failed");
        ret = HG_FAIL;
        goto done;
    }

    *handle = (hg_bulk_t) priv_handle;

done:
    if (ret != HG_SUCCESS) {
        if (priv_handle) hg_bulk_handle_free(priv_handle);
        priv_handle = NULL;
    }
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Bulk_handle_create_segments(hg_bulk_segment_t *bulk_segments,
        size_t segment_count, unsigned long flags, hg_bulk_t *handle)
{
    hg_return_t ret = HG_SUCCESS;
    na_return_t na_ret;
    struct hg_bulk *priv_handle = NULL;
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

    priv_handle = (struct hg_bulk *) malloc(sizeof(struct hg_bulk));
    if (!priv_handle) {
        HG_ERROR_DEFAULT("Could not allocate handle");
        ret = HG_FAIL;
        goto done;
    }
    priv_handle->total_size = 0;
    priv_handle->segment_count =
            (hg_bulk_na_class_g->mem_handle_create_segments) ?
                    1 : segment_count;
    priv_handle->segment_sizes = NULL;
    priv_handle->segment_handles = NULL;
    priv_handle->registered = HG_FALSE;

    /* Allocate segment sizes */
    priv_handle->segment_sizes = (size_t *) malloc(
            priv_handle->segment_count * sizeof(size_t));
    if (!priv_handle->segment_sizes) {
        HG_ERROR_DEFAULT("Could not allocate segment size array");
        ret = HG_FAIL;
        goto done;
    }

    /* Allocate segment handles */
    priv_handle->segment_handles = (na_mem_handle_t *) malloc(
            priv_handle->segment_count * sizeof(na_mem_handle_t));
    if (!priv_handle->segment_handles) {
        HG_ERROR_DEFAULT("Could not allocate mem handle array");
        ret = HG_FAIL;
        goto done;
    }

    /* The underlying layer may support non-contiguous mem registration */
    if (hg_bulk_na_class_g->mem_handle_create_segments) {
        for (i = 0; i < segment_count; i++) {
            priv_handle->total_size += bulk_segments[i].size;
        }
        priv_handle->segment_sizes[0] = priv_handle->total_size;
        priv_handle->segment_handles[0] = NA_MEM_HANDLE_NULL;

        na_ret = NA_Mem_handle_create_segments(hg_bulk_na_class_g,
                (struct na_segment *) bulk_segments, segment_count,
                na_flags, &priv_handle->segment_handles[0]);
        if (na_ret != NA_SUCCESS) {
            HG_ERROR_DEFAULT("NA_Mem_handle_create_segments failed");
            ret = HG_FAIL;
            goto done;
        }
    } else {
        /* Loop over the list of segments and register them */
        for (i = 0; i < segment_count; i++) {
            priv_handle->total_size += bulk_segments[i].size;
            priv_handle->segment_sizes[i] = bulk_segments[i].size;
            priv_handle->segment_handles[i] = NA_MEM_HANDLE_NULL;

            na_ret = NA_Mem_handle_create(hg_bulk_na_class_g,
                    (void *) bulk_segments[i].address, bulk_segments[i].size,
                    na_flags, &priv_handle->segment_handles[i]);
            if (na_ret != NA_SUCCESS) {
                HG_ERROR_DEFAULT("NA_Mem_handle_create failed");
                ret = HG_FAIL;
                goto done;
            }
        }
    }

    *handle = (hg_bulk_t) priv_handle;

done:
    if (ret != HG_SUCCESS) {
        if (priv_handle) hg_bulk_handle_free(priv_handle);
        priv_handle = NULL;
    }
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Bulk_handle_free(hg_bulk_t handle)
{
    hg_return_t ret = HG_SUCCESS;
    struct hg_bulk *priv_handle = (struct hg_bulk *) handle;

    if (!priv_handle) {
        HG_ERROR_DEFAULT("Already freed");
        ret = HG_FAIL;
        goto done;
    }

    ret = hg_bulk_handle_free(priv_handle);
    priv_handle = NULL;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_bulk_handle_free(struct hg_bulk *priv_handle)
{
    size_t i;
    hg_return_t ret = HG_SUCCESS;
    na_return_t na_ret;

    if (priv_handle->registered) {
        for (i = 0; i < priv_handle->segment_count; i++) {
            na_ret = NA_Mem_deregister(hg_bulk_na_class_g,
                    priv_handle->segment_handles[i]);
            if (na_ret != NA_SUCCESS) {
                HG_ERROR_DEFAULT("NA_Mem_deregister failed");
                ret = HG_FAIL;
                goto done;
            }
        }
        priv_handle->registered = HG_FALSE;
    }

    for (i = 0; i < priv_handle->segment_count; i++) {
        if (priv_handle->segment_handles[i] != NA_MEM_HANDLE_NULL) {
            na_ret = NA_Mem_handle_free(hg_bulk_na_class_g,
                    priv_handle->segment_handles[i]);
            if (na_ret != NA_SUCCESS) {
                HG_ERROR_DEFAULT("NA_Mem_handle_free failed");
                ret = HG_FAIL;
                goto done;
            }
            priv_handle->segment_handles[i] = NA_MEM_HANDLE_NULL;
        }
    }

    if (priv_handle->segment_handles) free(priv_handle->segment_handles);
    priv_handle->segment_handles = NULL;
    if (priv_handle->segment_sizes) free(priv_handle->segment_sizes);
    priv_handle->segment_sizes = NULL;
    free(priv_handle);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
size_t
HG_Bulk_handle_get_size(hg_bulk_t handle)
{
    size_t ret = 0;
    struct hg_bulk *priv_handle = (struct hg_bulk *) handle;

    if (!priv_handle) {
        HG_ERROR_DEFAULT("NULL bulk handle");
        goto done;
    }

    ret = priv_handle->total_size;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
size_t
HG_Bulk_handle_get_serialize_size(hg_bulk_t handle)
{
    size_t ret = 0;
    struct hg_bulk *priv_handle = (struct hg_bulk *) handle;
    size_t i;

    if (!priv_handle) {
        HG_ERROR_DEFAULT("NULL bulk handle");
        goto done;
    }

    ret = sizeof(priv_handle->total_size) + sizeof(priv_handle->segment_count)
            + priv_handle->segment_count * sizeof(size_t);
    for (i = 0; i < priv_handle->segment_count; i++) {
        ret += NA_Mem_handle_get_serialize_size(hg_bulk_na_class_g,
                priv_handle->segment_handles[i]);
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Bulk_handle_serialize(void *buf, size_t buf_size, hg_bulk_t handle)
{
    hg_return_t ret = HG_SUCCESS;
    na_return_t na_ret;
    struct hg_bulk *priv_handle = (struct hg_bulk *) handle;
    char *buf_ptr = (char*) buf;
    size_t buf_size_left = buf_size;
    size_t i;

    if (!priv_handle) {
        HG_ERROR_DEFAULT("NULL memory handle passed");
        ret = HG_FAIL;
        goto done;
    }

    /* Register handle at this point if not registered yet */
    if (!priv_handle->registered) {
        for (i = 0; i < priv_handle->segment_count; i++) {
            na_ret = NA_Mem_register(hg_bulk_na_class_g,
                    priv_handle->segment_handles[i]);
            if (na_ret != NA_SUCCESS) {
                HG_ERROR_DEFAULT("NA_Mem_register failed");
                ret = HG_FAIL;
                goto done;
            }
        }
        priv_handle->registered = HG_TRUE;
    }

    if (buf_size < HG_Bulk_handle_get_serialize_size(handle)) {
        HG_ERROR_DEFAULT("Buffer size too small for serializing parameter");
        ret = HG_FAIL;
        goto done;
    }

    /* Add the size of the data */
    memcpy(buf_ptr, &priv_handle->total_size, sizeof(size_t));
    buf_ptr += sizeof(size_t);
    buf_size_left -= sizeof(size_t);

    /* Add the number of handles */
    memcpy(buf_ptr, &priv_handle->segment_count, sizeof(size_t));
    buf_ptr += sizeof(size_t);
    buf_size_left -= sizeof(size_t);

    /* Add the list of sizes */
    for (i = 0; i < priv_handle->segment_count; i++) {
        memcpy(buf_ptr, &priv_handle->segment_sizes[i], sizeof(size_t));
        buf_ptr += sizeof(size_t);
        buf_size_left -= sizeof(size_t);
    }

    for (i = 0; i < priv_handle->segment_count; i++) {
        na_ret = NA_Mem_handle_serialize(hg_bulk_na_class_g, buf_ptr,
                buf_size_left, priv_handle->segment_handles[i]);
        if (na_ret != NA_SUCCESS) {
            HG_ERROR_DEFAULT("Could not serialize memory handle");
            ret = HG_FAIL;
            break;
        }
        buf_ptr += NA_Mem_handle_get_serialize_size(hg_bulk_na_class_g,
                priv_handle->segment_handles[i]);
        buf_size_left -= NA_Mem_handle_get_serialize_size(hg_bulk_na_class_g,
                priv_handle->segment_handles[i]);
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Bulk_handle_deserialize(hg_bulk_t *handle, const void *buf, size_t buf_size)
{
    hg_return_t ret = HG_SUCCESS;
    na_return_t na_ret;
    struct hg_bulk *priv_handle = NULL;
    const char *buf_ptr = (const char*) buf;
    size_t buf_size_left = buf_size;
    size_t i;

    if (!handle) {
        HG_ERROR_DEFAULT("NULL pointer to memory handle passed");
        ret = HG_FAIL;
        goto done;
    }

    priv_handle = (struct hg_bulk *) malloc(sizeof(struct hg_bulk));
    if (!priv_handle) {
        HG_ERROR_DEFAULT("Could not allocate handle");
        ret = HG_FAIL;
        goto done;
    }
    priv_handle->segment_handles = NULL;
    priv_handle->segment_sizes = NULL;

    /* Get the size of the data */
    memcpy(&priv_handle->total_size, buf_ptr, sizeof(size_t));
    buf_ptr += sizeof(size_t);
    buf_size_left -= sizeof(size_t);

    /* Get the number of handles */
    memcpy(&priv_handle->segment_count, buf_ptr, sizeof(size_t));
    buf_ptr += sizeof(size_t);
    buf_size_left -= sizeof(size_t);

    /* Add the list of sizes */
    priv_handle->segment_sizes = (size_t *) malloc(
            priv_handle->segment_count * sizeof(size_t));
    if (!priv_handle->segment_sizes) {
        HG_ERROR_DEFAULT("Could not allocate size list");
        ret = HG_FAIL;
        goto done;
    }
    for (i = 0; i < priv_handle->segment_count; i++) {
        memcpy(&priv_handle->segment_sizes[i], buf_ptr, sizeof(size_t));
        buf_ptr += sizeof(size_t);
        buf_size_left -= sizeof(size_t);
        /*
        fprintf(stderr, "Segment[%lu] = %lu bytes\n", i, priv_handle->size_list[i]);
        */
    }

    priv_handle->segment_handles = (na_mem_handle_t *) malloc(
            priv_handle->segment_count * sizeof(na_mem_handle_t));
    if (!priv_handle->segment_handles) {
        HG_ERROR_DEFAULT("Could not allocate mem handle list");
        ret = HG_FAIL;
        goto done;
    }
    for (i = 0; i < priv_handle->segment_count; i++) {
        na_ret = NA_Mem_handle_deserialize(hg_bulk_na_class_g,
                &priv_handle->segment_handles[i],
                buf_ptr, buf_size_left);
        if (na_ret != NA_SUCCESS) {
            HG_ERROR_DEFAULT("Could not deserialize memory handle");
            ret = HG_FAIL;
            goto done;
        }
        buf_ptr += NA_Mem_handle_get_serialize_size(hg_bulk_na_class_g,
                priv_handle->segment_handles[i]);
        buf_size_left -= NA_Mem_handle_get_serialize_size(hg_bulk_na_class_g,
                priv_handle->segment_handles[i]);
    }

    /* The handle is not registered, only deserialized */
    priv_handle->registered = HG_FALSE;
    *handle = priv_handle;

done:
    if (ret != HG_SUCCESS) {
        if (priv_handle) hg_bulk_handle_free(priv_handle);
        priv_handle = NULL;
    }
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_bulk_offset_translate(hg_bulk_t bulk_handle, size_t bulk_offset,
        size_t *segment_start_index, size_t *segment_start_offset)
{
    struct hg_bulk *priv_handle = (struct hg_bulk *) bulk_handle;
    size_t i, new_segment_start_index = 0;
    size_t new_segment_offset = bulk_offset, next_offset = 0;
    hg_return_t ret = HG_SUCCESS;

    /* Get start index and handle offset */
    for (i = 0; i < priv_handle->segment_count; i++) {
        next_offset += priv_handle->segment_sizes[i];
        if (bulk_offset < next_offset) {
            new_segment_start_index = i;
            break;
        }
        new_segment_offset -= priv_handle->segment_sizes[i];
    }

    *segment_start_index = new_segment_start_index;
    *segment_start_offset = new_segment_offset;

    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
hg_bulk_transfer_cb(const struct na_cb_info *callback_info)
{
    struct hg_bulk_request *priv_request =
            (struct hg_bulk_request *) callback_info->arg;
    na_return_t ret = NA_SUCCESS;

    if (callback_info->ret != NA_SUCCESS) {
        return ret;
    }

    hg_thread_mutex_lock(&hg_bulk_request_mutex_g);

    priv_request->op_completed_count++;
    if (priv_request->op_completed_count == priv_request->op_count)
        priv_request->completed = HG_TRUE;

    hg_thread_mutex_unlock(&hg_bulk_request_mutex_g);

    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
hg_bulk_transfer(hg_bulk_op_t bulk_op, na_addr_t addr,
        hg_bulk_t bulk_handle, size_t bulk_offset,
        hg_bulk_t block_handle, size_t block_offset,
        size_t block_size, hg_bulk_request_t *bulk_request)
{
    struct hg_bulk *priv_bulk_handle = (struct hg_bulk *) bulk_handle;
    struct hg_bulk *priv_block_handle = (struct hg_bulk *) block_handle;
    size_t bulk_segment_start_index, block_segment_start_index;
    size_t bulk_segment_index, block_segment_index;
    size_t bulk_segment_start_offset, block_segment_start_offset;
    size_t bulk_segment_offset, block_segment_offset;
    size_t remaining_size;
    na_bulk_op_t na_bulk_op;
    struct hg_bulk_request *priv_bulk_request = NULL;
    hg_return_t ret = HG_SUCCESS;
    na_return_t na_ret;

    if (!priv_bulk_handle || !priv_block_handle) {
        HG_ERROR_DEFAULT("NULL memory handle passed");
        ret = HG_FAIL;
        goto done;
    }

    if (block_size > priv_bulk_handle->total_size) {
        HG_ERROR_DEFAULT("Exceeding size of memory exposed by bulk handle");
        ret = HG_FAIL;
        goto done;
    }

    if (block_size > priv_block_handle->total_size) {
        HG_ERROR_DEFAULT("Exceeding size of memory exposed by block handle");
        ret = HG_FAIL;
        goto done;
    }

    switch (bulk_op) {
        case HG_BULK_WRITE:
            na_bulk_op = NA_Put;
            break;
        case HG_BULK_READ:
            na_bulk_op = NA_Get;
            break;
        default:
            HG_ERROR_DEFAULT("Unknown bulk operation");
            ret = HG_FAIL;
            goto done;
    }

    /* Translate bulk_offset */
    hg_bulk_offset_translate(bulk_handle, bulk_offset,
            &bulk_segment_start_index, &bulk_segment_start_offset);

    /* Translate block offset */
    hg_bulk_offset_translate(block_handle, block_offset,
            &block_segment_start_index, &block_segment_start_offset);

    /* Create a new bulk request */
    priv_bulk_request = (struct hg_bulk_request *)
            malloc(sizeof(struct hg_bulk_request));
    if (!priv_bulk_request) {
        HG_ERROR_DEFAULT("Could not allocate bulk request");
        ret = HG_FAIL;
        goto done;
    }
    priv_bulk_request->op_count = 0;
    priv_bulk_request->op_completed_count = 0;
    priv_bulk_request->completed = HG_FALSE;

    bulk_segment_index = bulk_segment_start_index;
    block_segment_index = block_segment_start_index;
    bulk_segment_offset = bulk_segment_start_offset;
    block_segment_offset = block_segment_start_offset;
    remaining_size = block_size;

    /* Since op_count is incremented, can't let a callback complete before
     * all the operations are issued */
    hg_thread_mutex_lock(&hg_bulk_request_mutex_g);

    while (remaining_size > 0) {
        size_t bulk_transfer_size, block_transfer_size, transfer_size;

        /* Can only transfer smallest size */
        bulk_transfer_size = priv_bulk_handle->segment_sizes[bulk_segment_index]
                - bulk_segment_offset;
        block_transfer_size = priv_block_handle->segment_sizes[block_segment_index]
                - block_segment_offset;
        transfer_size = HG_BULK_MIN(bulk_transfer_size, block_transfer_size);

        /* Remaining size may be smaller */
        transfer_size = HG_BULK_MIN(remaining_size, transfer_size);

        na_ret = na_bulk_op(hg_bulk_na_class_g, hg_bulk_context_g,
                &hg_bulk_transfer_cb, priv_bulk_request,
                priv_block_handle->segment_handles[block_segment_index],
                block_segment_offset,
                priv_bulk_handle->segment_handles[bulk_segment_index],
                bulk_segment_offset,
                transfer_size, addr, NA_OP_ID_IGNORE);
        if (na_ret != NA_SUCCESS) {
            HG_ERROR_DEFAULT("Could not transfer data");
            ret = HG_FAIL;
            hg_thread_mutex_unlock(&hg_bulk_request_mutex_g);
            goto done;
        }
        priv_bulk_request->op_count++;

        /* Decrease remaining size from the size of data we transferred */
        remaining_size -= transfer_size;

        /* Increment offsets from the size of data we transferred */
        bulk_segment_offset += transfer_size;
        block_segment_offset += transfer_size;

        /* Change segment if new offset exceeds segment size */
        if (bulk_segment_offset >=
            priv_bulk_handle->segment_sizes[bulk_segment_index]) {
            bulk_segment_index++;
            bulk_segment_offset = 0;
        }
        if (block_segment_offset >=
            priv_block_handle->segment_sizes[block_segment_index]) {
            block_segment_index++;
            block_segment_offset = 0;
        }
    }

    hg_thread_mutex_unlock(&hg_bulk_request_mutex_g);

    *bulk_request = (hg_bulk_request_t) priv_bulk_request;

done:
    if (ret != HG_SUCCESS) {
        if (priv_bulk_request) {
            free(priv_bulk_request);
        }
        priv_bulk_request = NULL;
    }
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Bulk_write(na_addr_t addr, hg_bulk_t bulk_handle, size_t bulk_offset,
        hg_bulk_t block_handle, size_t block_offset, size_t block_size,
        hg_bulk_request_t *bulk_request)
{
    hg_return_t ret = HG_SUCCESS;

    ret = hg_bulk_transfer(HG_BULK_WRITE, addr, bulk_handle, bulk_offset,
            block_handle, block_offset, block_size, bulk_request);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Could not write data");
        ret = HG_FAIL;
    }

    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Bulk_write_all(na_addr_t addr, hg_bulk_t bulk_handle,
        hg_bulk_t block_handle, hg_bulk_request_t *bulk_request)
{
    struct hg_bulk *priv_handle = (struct hg_bulk *) bulk_handle;
    hg_return_t ret = HG_SUCCESS;

    if (!priv_handle) {
        HG_ERROR_DEFAULT("NULL memory handle passed");
        ret = HG_FAIL;
        goto done;
    }

    ret = hg_bulk_transfer(HG_BULK_WRITE, addr, bulk_handle, 0,
            block_handle, 0, priv_handle->total_size, bulk_request);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Could not write data");
        ret = HG_FAIL;
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Bulk_read(na_addr_t addr, hg_bulk_t bulk_handle, size_t bulk_offset,
        hg_bulk_t block_handle, size_t block_offset, size_t block_size,
        hg_bulk_request_t *bulk_request)
{
    hg_return_t ret = HG_SUCCESS;

    ret = hg_bulk_transfer(HG_BULK_READ, addr, bulk_handle, bulk_offset,
            block_handle, block_offset, block_size, bulk_request);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Could not read data");
        ret = HG_FAIL;
    }

    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Bulk_read_all(na_addr_t addr, hg_bulk_t bulk_handle,
        hg_bulk_t block_handle, hg_bulk_request_t *bulk_request)
{
    struct hg_bulk *priv_handle = (struct hg_bulk *) bulk_handle;
    hg_return_t ret = HG_SUCCESS;

    if (!priv_handle) {
        HG_ERROR_DEFAULT("NULL memory handle passed");
        ret = HG_FAIL;
        goto done;
    }

    ret = hg_bulk_transfer(HG_BULK_READ, addr, bulk_handle, 0,
            block_handle, 0, priv_handle->total_size, bulk_request);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Could not read data");
        ret = HG_FAIL;
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Bulk_wait(hg_bulk_request_t bulk_request, unsigned int timeout,
        hg_status_t *status)
{
    double remaining = timeout / 1000; /* Convert timeout in ms into seconds */
    struct hg_bulk_request *priv_bulk_request =
            (struct hg_bulk_request *) bulk_request;
    hg_bool_t completed = HG_FALSE;
    hg_return_t ret = HG_SUCCESS;

    if (!priv_bulk_request) {
        HG_ERROR_DEFAULT("NULL request passed");
        ret = HG_FAIL;
        goto done;
    }

    hg_thread_mutex_lock(&hg_bulk_request_mutex_g);
    completed = priv_bulk_request->completed;
    hg_thread_mutex_unlock(&hg_bulk_request_mutex_g);

    hg_thread_mutex_lock(&hg_bulk_progress_mutex_g);

    while (!completed) {
        na_return_t na_ret;
        int actual_count = 0;
        hg_time_t t3, t4;

        do {
            na_ret = NA_Trigger(hg_bulk_context_g, 0, 1, &actual_count);
        } while ((na_ret == NA_SUCCESS) && actual_count);

        hg_thread_mutex_lock(&hg_bulk_request_mutex_g);
        completed = priv_bulk_request->completed;
        hg_thread_mutex_unlock(&hg_bulk_request_mutex_g);

        if (completed) break;

        if (hg_bulk_progressing_g) {
            hg_time_t t1, t2;

            hg_time_get_current(&t1);

            if (hg_thread_cond_timedwait(&hg_bulk_progress_cond_g,
                    &hg_bulk_progress_mutex_g,
                    (unsigned int) (remaining * 1000)) != HG_UTIL_SUCCESS) {
                /* Timeout occurred so leave */
                hg_thread_mutex_unlock(&hg_bulk_progress_mutex_g);
                goto done;
            }

            hg_time_get_current(&t2);
            remaining -= hg_time_to_double(hg_time_subtract(t2, t1));
            if (remaining < 0) {
                hg_thread_mutex_unlock(&hg_bulk_progress_mutex_g);
                goto done;
            }

            /* Continue as request may have completed in the meantime */
            continue;
        }
        hg_bulk_progressing_g = HG_TRUE;

        hg_thread_mutex_unlock(&hg_bulk_progress_mutex_g);

        hg_time_get_current(&t3);

        na_ret = NA_Progress(hg_bulk_na_class_g, hg_bulk_context_g,
                (unsigned int) (remaining * 1000));

        hg_time_get_current(&t4);
        remaining -= hg_time_to_double(hg_time_subtract(t4, t3));

        hg_thread_mutex_lock(&hg_bulk_progress_mutex_g);
        hg_bulk_progressing_g = HG_FALSE;
        hg_thread_cond_signal(&hg_bulk_progress_cond_g);

        if ((na_ret == NA_TIMEOUT) || remaining < 0) {
            hg_thread_mutex_unlock(&hg_bulk_progress_mutex_g);
            goto done;
        }
    }

    hg_thread_mutex_unlock(&hg_bulk_progress_mutex_g);

    free(priv_bulk_request);
    priv_bulk_request = NULL;

done:
    if (status && (status != HG_STATUS_IGNORE)) {
        *status = completed;
    }

    return ret;
}
