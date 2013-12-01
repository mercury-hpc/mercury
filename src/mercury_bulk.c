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

/************************************/
/* Local Type and Struct Definition */
/************************************/
struct hg_bulk {
    size_t total_size;                /* Total size of data registered */
    size_t *size_list;                /* List of segment sizes corresponding
                                       * to each memory handle */
    na_mem_handle_t *mem_handle_list; /* List of handles (single for contiguous
                                       * or multiple for non-contiguous) */
    size_t count;                     /* Number of handles */
    hg_bool_t registered;             /* The handle may be registered or simply
                                       * deserialized */
};

struct hg_bulk_block {
    size_t size;                /* Size */
    na_mem_handle_t mem_handle; /* Memory handle */
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
static hg_return_t hg_bulk_find_handle_list_info(hg_bulk_t bulk_handle,
        size_t bulk_offset, size_t block_size, size_t *handle_index_start,
        size_t *handle_offset, size_t *request_count);

/**
 * Write callback.
 */
static na_return_t hg_bulk_write_cb(const struct na_cb_info *callback_info);

/**
 * Read callback.
 */
static na_return_t hg_bulk_read_cb(const struct na_cb_info *callback_info);

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
        return ret;
    }

    /* TODO: This code may have to be changed in accordance with the
     *       outcome of Trac#24.
     */
    if (hg_bulk_na_class_g) {
        HG_WARNING_DEFAULT("Already initialized");
        ret = HG_SUCCESS;
        return ret;
    }

    hg_bulk_na_class_g = na_class;

    /* Create local context */
    hg_bulk_context_g = NA_Context_create(hg_bulk_na_class_g);
    if (!hg_bulk_context_g) {
        HG_ERROR_DEFAULT("Could not create context.");
        ret = HG_FAIL;
        return ret;
    }

    /* Initilialize mutex */
    hg_thread_mutex_init(&hg_bulk_request_mutex_g);
    hg_thread_mutex_init(&hg_bulk_progress_mutex_g);
    hg_thread_cond_init(&hg_bulk_progress_cond_g);

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
        return ret;
    }

    /* Destroy context */
    na_ret = NA_Context_destroy(hg_bulk_na_class_g, hg_bulk_context_g);
    if (na_ret != NA_SUCCESS) {
        HG_ERROR_DEFAULT("Could not destroy context.");
        ret = HG_FAIL;
        return ret;
    }

    hg_bulk_na_class_g = NULL;

    /* Destroy mutex */
    hg_thread_mutex_destroy(&hg_bulk_request_mutex_g);
    hg_thread_mutex_destroy(&hg_bulk_progress_mutex_g);
    hg_thread_cond_destroy(&hg_bulk_progress_cond_g);

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
        return ret;
    }

    *flag = (hg_bulk_na_class_g != NULL);
    if (na_class) *na_class = hg_bulk_na_class_g;

    return HG_SUCCESS;
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
    priv_handle->count = 1;
    priv_handle->mem_handle_list = NULL;
    priv_handle->size_list = NULL;

    priv_handle->mem_handle_list = (na_mem_handle_t*) malloc(
            sizeof(na_mem_handle_t));
    if (!priv_handle->mem_handle_list) {
        HG_ERROR_DEFAULT("Could not allocate mem handle list");
        ret = HG_FAIL;
        goto done;
    }
    priv_handle->mem_handle_list[0] = NA_MEM_HANDLE_NULL;
    priv_handle->total_size = buf_size;
    priv_handle->size_list = (size_t*) malloc(sizeof(size_t));
    if (!priv_handle->size_list) {
        HG_ERROR_DEFAULT("Could not allocate size list");
        ret = HG_FAIL;
        goto done;
    }
    priv_handle->size_list[0] = priv_handle->total_size;

    na_ret = NA_Mem_handle_create(hg_bulk_na_class_g, buf, buf_size, na_flags,
            &priv_handle->mem_handle_list[0]);
    if (na_ret != NA_SUCCESS) {
        HG_ERROR_DEFAULT("NA_Mem_handle_create failed");
        ret = HG_FAIL;
        goto done;
    }

    na_ret = NA_Mem_register(hg_bulk_na_class_g, priv_handle->mem_handle_list[0]);
    if (na_ret != NA_SUCCESS) {
        HG_ERROR_DEFAULT("NA_Mem_register failed");
        ret = HG_FAIL;
        goto done;
    }

    priv_handle->registered = HG_TRUE;
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
    priv_handle->mem_handle_list = NULL;
    priv_handle->size_list = NULL;

    /* The underlying layer may support non-contiguous mem registration */
    if (hg_bulk_na_class_g->mem_handle_create_segments) {
        /* In this case we only need one single handle */
        priv_handle->count = 1;
        priv_handle->mem_handle_list =
                (na_mem_handle_t*) malloc(sizeof(na_mem_handle_t));
        if (!priv_handle->mem_handle_list) {
            HG_ERROR_DEFAULT("Could not allocate mem handle list");
            ret = HG_FAIL;
            goto done;
        }
        priv_handle->mem_handle_list[0] = NA_MEM_HANDLE_NULL;
        priv_handle->size_list = (size_t*) malloc(sizeof(size_t));
        if (!priv_handle->size_list) {
            HG_ERROR_DEFAULT("Could not allocate size list");
            ret = HG_FAIL;
            goto done;
        }

        na_ret = NA_Mem_handle_create_segments(hg_bulk_na_class_g,
                (struct na_segment *) bulk_segments, segment_count,
                na_flags, &priv_handle->mem_handle_list[0]);
        if (na_ret != NA_SUCCESS) {
            HG_ERROR_DEFAULT("NA_Mem_handle_create_segments failed");
            ret = HG_FAIL;
            goto done;
        }

        na_ret = NA_Mem_register(hg_bulk_na_class_g,
                priv_handle->mem_handle_list[0]);
        if (na_ret != NA_SUCCESS) {
            HG_ERROR_DEFAULT("NA_Mem_register failed");
            /* TODO Free mem handle */
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
        priv_handle->mem_handle_list = (na_mem_handle_t*) malloc(
                priv_handle->count * sizeof(na_mem_handle_t));
        if (!priv_handle->mem_handle_list) {
            HG_ERROR_DEFAULT("Could not allocate mem handle list");
            ret = HG_FAIL;
            goto done;
        }
        priv_handle->size_list = (size_t*) malloc(
                priv_handle->count * sizeof(size_t));
        if (!priv_handle->size_list) {
            HG_ERROR_DEFAULT("Could not allocate size list");
            ret = HG_FAIL;
            goto done;
        }

        /* Loop over the list of segments and register them */
        for (i = 0; i < segment_count; i++) {
            priv_handle->mem_handle_list[i] = NA_MEM_HANDLE_NULL;

            na_ret = NA_Mem_handle_create(hg_bulk_na_class_g,
                    (void *) bulk_segments[i].address, bulk_segments[i].size,
                    na_flags, &priv_handle->mem_handle_list[i]);
            if (na_ret != NA_SUCCESS) {
                HG_ERROR_DEFAULT("NA_Mem_handle_create failed");
                ret = HG_FAIL;
                goto done;
            }

            na_ret = NA_Mem_register(hg_bulk_na_class_g,
                    priv_handle->mem_handle_list[i]);
            if (na_ret != NA_SUCCESS) {
                HG_ERROR_DEFAULT("NA_Mem_register failed");
                /* TODO Free mem handle */
                ret = HG_FAIL;
                goto done;
            }
            priv_handle->size_list[i] = bulk_segments[i].size;
            priv_handle->total_size += bulk_segments[i].size;
        }
    }

    priv_handle->registered = HG_TRUE;
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
        return ret;
    }

    hg_bulk_handle_free(priv_handle);
    priv_handle = NULL;

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
        for (i = 0; i < priv_handle->count; i++) {
            na_ret = NA_Mem_deregister(hg_bulk_na_class_g,
                    priv_handle->mem_handle_list[i]);
            if (na_ret != NA_SUCCESS) {
                HG_ERROR_DEFAULT("NA_Mem_deregister failed");
                ret = HG_FAIL;
                return ret;
            }
        }
        priv_handle->registered = HG_FALSE;
    }

    for (i = 0; i < priv_handle->count; i++) {
        if (priv_handle->mem_handle_list[i] != NA_MEM_HANDLE_NULL) {
            na_ret = NA_Mem_handle_free(hg_bulk_na_class_g,
                    priv_handle->mem_handle_list[i]);
            if (na_ret != NA_SUCCESS) {
                HG_ERROR_DEFAULT("NA_Mem_handle_free failed");
                ret = HG_FAIL;
                return ret;
            }
            priv_handle->mem_handle_list[i] = NA_MEM_HANDLE_NULL;
        }
    }

    if (priv_handle->mem_handle_list) free(priv_handle->mem_handle_list);
    priv_handle->mem_handle_list = NULL;
    if (priv_handle->size_list) free(priv_handle->size_list);
    priv_handle->size_list = NULL;
    free(priv_handle);

    return ret;
}

/*---------------------------------------------------------------------------*/
size_t
HG_Bulk_handle_get_size(hg_bulk_t handle)
{
    size_t ret = 0;
    struct hg_bulk *priv_handle = (struct hg_bulk *) handle;

    if (priv_handle) {
        ret = priv_handle->total_size;
    }

    return ret;
}

/*---------------------------------------------------------------------------*/
size_t
HG_Bulk_handle_get_serialize_size(hg_bulk_t handle)
{
    size_t ret = 0;
    struct hg_bulk *priv_handle = (struct hg_bulk *) handle;
    size_t i;

    if (priv_handle) {
        ret = sizeof(priv_handle->total_size) + sizeof(priv_handle->count)
                + priv_handle->count * sizeof(size_t);
        for (i = 0; i < priv_handle->count; i++) {
            ret += NA_Mem_handle_get_serialize_size(hg_bulk_na_class_g,
                    priv_handle->mem_handle_list[i]);
        }
    }

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

    /* TODO publish mem_handle if not registered yet */

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
        na_ret = NA_Mem_handle_serialize(hg_bulk_na_class_g, buf_ptr,
                buf_size_left, priv_handle->mem_handle_list[i]);
        if (na_ret != NA_SUCCESS) {
            HG_ERROR_DEFAULT("Could not serialize memory handle");
            ret = HG_FAIL;
            break;
        }
        buf_ptr += NA_Mem_handle_get_serialize_size(hg_bulk_na_class_g,
                priv_handle->mem_handle_list[i]);
        buf_size_left -= NA_Mem_handle_get_serialize_size(hg_bulk_na_class_g,
                priv_handle->mem_handle_list[i]);
    }

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
    priv_handle->mem_handle_list = NULL;
    priv_handle->size_list = NULL;

    /* Get the size of the data */
    memcpy(&priv_handle->total_size, buf_ptr, sizeof(size_t));
    buf_ptr += sizeof(size_t);
    buf_size_left -= sizeof(size_t);

    /* Get the number of handles */
    memcpy(&priv_handle->count, buf_ptr, sizeof(size_t));
    buf_ptr += sizeof(size_t);
    buf_size_left -= sizeof(size_t);

    /* Add the list of sizes */
    priv_handle->size_list = (size_t*) malloc(priv_handle->count * sizeof(size_t));
    if (!priv_handle->size_list) {
        HG_ERROR_DEFAULT("Could not allocate size list");
        ret = HG_FAIL;
        goto done;
    }
    for (i = 0; i < priv_handle->count; i++) {
        memcpy(&priv_handle->size_list[i], buf_ptr, sizeof(size_t));
        buf_ptr += sizeof(size_t);
        buf_size_left -= sizeof(size_t);
        /*
        fprintf(stderr, "Segment[%lu] = %lu bytes\n", i, priv_handle->size_list[i]);
        */
    }

    priv_handle->mem_handle_list = (na_mem_handle_t*) malloc(
            priv_handle->count * sizeof(na_mem_handle_t));
    if (!priv_handle->mem_handle_list) {
        HG_ERROR_DEFAULT("Could not allocate mem handle list");
        ret = HG_FAIL;
        goto done;
    }
    for (i = 0; i < priv_handle->count; i++) {
        na_ret = NA_Mem_handle_deserialize(hg_bulk_na_class_g,
                &priv_handle->mem_handle_list[i],
                buf_ptr, buf_size_left);
        if (na_ret != NA_SUCCESS) {
            HG_ERROR_DEFAULT("Could not deserialize memory handle");
            ret = HG_FAIL;
            return ret;
        }
        buf_ptr += NA_Mem_handle_get_serialize_size(hg_bulk_na_class_g,
                priv_handle->mem_handle_list[i]);
        buf_size_left -= NA_Mem_handle_get_serialize_size(hg_bulk_na_class_g,
                priv_handle->mem_handle_list[i]);
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
hg_return_t
HG_Bulk_block_handle_create(void *buf, size_t block_size, unsigned long flags,
        hg_bulk_block_t *block_handle)
{
    hg_return_t ret = HG_SUCCESS;
    na_return_t na_ret;
    struct hg_bulk_block *priv_block_handle = NULL;
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

    priv_block_handle = (struct hg_bulk_block *)
            malloc(sizeof(struct hg_bulk_block));
    if (!priv_block_handle) {
        HG_ERROR_DEFAULT("Could not allocate block handle");
        ret = HG_FAIL;
        return ret;
    }
    priv_block_handle->size = block_size;
    priv_block_handle->mem_handle = NA_MEM_HANDLE_NULL;

    na_ret = NA_Mem_handle_create(hg_bulk_na_class_g, buf, block_size, na_flags,
            &priv_block_handle->mem_handle);
    if (na_ret != NA_SUCCESS) {
        HG_ERROR_DEFAULT("NA_Mem_handle_create failed");
        ret = HG_FAIL;
        return ret;
    }

    na_ret = NA_Mem_register(hg_bulk_na_class_g, priv_block_handle->mem_handle);
    if (na_ret != NA_SUCCESS) {
        HG_ERROR_DEFAULT("NA_Mem_register failed");
        /* TODO Free mem handle */
        ret = HG_FAIL;
        return ret;
    }

    *block_handle = (hg_bulk_block_t) priv_block_handle;

    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Bulk_block_handle_free(hg_bulk_block_t block_handle)
{
    hg_return_t ret = HG_SUCCESS;
    na_return_t na_ret;
    struct hg_bulk_block *priv_block_handle = (struct hg_bulk_block *) block_handle;

    if (!priv_block_handle) {
        HG_ERROR_DEFAULT("Already freed");
        ret = HG_FAIL;
        return ret;
    }

    na_ret = NA_Mem_deregister(hg_bulk_na_class_g,
            priv_block_handle->mem_handle);
    if (na_ret != NA_SUCCESS) {
        HG_ERROR_DEFAULT("Could not deregister block");
        ret = HG_FAIL;
        return ret;
    }

    na_ret = NA_Mem_handle_free(hg_bulk_na_class_g,
            priv_block_handle->mem_handle);
    if (na_ret != NA_SUCCESS) {
        HG_ERROR_DEFAULT("NA_Mem_handle_free failed");
        ret = HG_FAIL;
        return ret;
    }
    priv_block_handle->mem_handle = NA_MEM_HANDLE_NULL;

    free(priv_block_handle);
    priv_block_handle = NULL;

    return ret;
}

/*---------------------------------------------------------------------------*/
size_t
HG_Bulk_block_handle_get_size(hg_bulk_block_t block_handle)
{
    size_t ret = 0;
    struct hg_bulk_block *priv_block_handle = (struct hg_bulk_block *) block_handle;

    if (priv_block_handle) {
        ret = priv_block_handle->size;
    }

    return ret;
}
/*---------------------------------------------------------------------------*/
static hg_return_t
hg_bulk_find_handle_list_info(hg_bulk_t bulk_handle,
        size_t bulk_offset, size_t block_size, size_t *handle_index_start,
        size_t *handle_offset, size_t *request_count)
{
    hg_return_t ret = HG_SUCCESS;
    struct hg_bulk *priv_handle = (struct hg_bulk *) bulk_handle;
    size_t new_index_start = 0;
    size_t new_handle_offset = bulk_offset, next_offset;
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

/*---------------------------------------------------------------------------*/
static na_return_t
hg_bulk_write_cb(const struct na_cb_info *callback_info)
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
HG_Bulk_write(na_addr_t addr, hg_bulk_t bulk_handle, size_t bulk_offset,
        hg_bulk_block_t block_handle, size_t block_offset, size_t block_size,
        hg_bulk_request_t *bulk_request)
{
    hg_return_t ret = HG_SUCCESS;
    na_return_t na_ret;
    struct hg_bulk *priv_handle = (struct hg_bulk *) bulk_handle;
    struct hg_bulk_block *priv_block_handle = (struct hg_bulk_block *) block_handle;
    size_t local_offset, remote_offset;
    size_t transfer_size;
    size_t remaining_size = block_size;
    struct hg_bulk_request *priv_bulk_request = NULL;
    size_t request_count;
    size_t handle_list_index_start;
    size_t i;
    size_t request_index = 0;

    if (!priv_handle) {
        HG_ERROR_DEFAULT("NULL memory handle passed");
        ret = HG_FAIL;
        goto done;
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

    priv_bulk_request = (struct hg_bulk_request *)
            malloc(sizeof(struct hg_bulk_request));
    if (!priv_bulk_request) {
        HG_ERROR_DEFAULT("Could not allocate bulk request");
        ret = HG_FAIL;
        goto done;
    }
    priv_bulk_request->op_count = request_count;
    priv_bulk_request->op_completed_count = 0;
    priv_bulk_request->completed = HG_FALSE;

    for (i = handle_list_index_start;
            i < handle_list_index_start + request_count; i++) {
        /* Transfer size is (size available from handle - offset) or
         * (remaining size) if smaller */
        transfer_size = priv_handle->size_list[i] - remote_offset;
        transfer_size = (remaining_size < transfer_size) ? remaining_size
                : transfer_size;

        na_ret = NA_Put(hg_bulk_na_class_g, hg_bulk_context_g,
                &hg_bulk_write_cb, priv_bulk_request,
                priv_block_handle->mem_handle, local_offset,
                priv_handle->mem_handle_list[i], remote_offset,
                transfer_size, addr, NA_OP_ID_IGNORE);
        if (na_ret != NA_SUCCESS) {
            HG_ERROR_DEFAULT("Could not put data");
            ret = HG_FAIL;
            goto done;
        }
        /* We started from the index that contains bulk_offset so further
         * remote_offset are 0 */
        remote_offset = 0;
        /* Increase the local offset from the size of data we transferred */
        local_offset += transfer_size;
        /* Decrease remaining size from the size of data we transferred */
        remaining_size -= transfer_size;
        /* Increase request index */
        request_index++;
    }

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
HG_Bulk_write_all(na_addr_t addr, hg_bulk_t bulk_handle,
        hg_bulk_block_t block_handle, hg_bulk_request_t *bulk_request)
{
    hg_return_t ret = HG_SUCCESS;
    struct hg_bulk *priv_handle = (struct hg_bulk *) bulk_handle;

    ret = HG_Bulk_write(addr, bulk_handle, 0,
            block_handle, 0, priv_handle->total_size, bulk_request);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Could not write data");
        ret = HG_FAIL;
    }

    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
hg_bulk_read_cb(const struct na_cb_info *callback_info)
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
HG_Bulk_read(na_addr_t addr, hg_bulk_t bulk_handle, size_t bulk_offset,
        hg_bulk_block_t block_handle, size_t block_offset, size_t block_size,
        hg_bulk_request_t *bulk_request)
{
    hg_return_t ret = HG_SUCCESS;
    na_return_t na_ret;
    struct hg_bulk *priv_handle = (struct hg_bulk *) bulk_handle;
    struct hg_bulk_block *priv_block_handle =
            (struct hg_bulk_block *) block_handle;
    size_t local_offset, remote_offset;
    size_t transfer_size;
    size_t remaining_size = block_size;
    struct hg_bulk_request *priv_bulk_request = NULL;
    size_t request_count;
    size_t handle_list_index_start;
    size_t i;
    size_t request_index = 0;

    if (!priv_handle) {
        HG_ERROR_DEFAULT("NULL memory handle passed");
        ret = HG_FAIL;
        goto done;
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

    priv_bulk_request = (struct hg_bulk_request *) malloc(
            sizeof(struct hg_bulk_request));
    if (!priv_bulk_request) {
        HG_ERROR_DEFAULT("Could not allocate bulk request");
        ret = HG_FAIL;
        goto done;
    }
    priv_bulk_request->op_count = request_count;
    priv_bulk_request->op_completed_count = 0;
    priv_bulk_request->completed = HG_FALSE;

    for (i = handle_list_index_start;
            i < handle_list_index_start + request_count; i++) {
        /* Transfer size is (size available from handle - offset) or
         * (remaining size) if smaller */
        transfer_size = priv_handle->size_list[i] - remote_offset;
        transfer_size = (remaining_size < transfer_size) ?
                remaining_size : transfer_size;

        na_ret = NA_Get(hg_bulk_na_class_g, hg_bulk_context_g,
                &hg_bulk_read_cb, priv_bulk_request,
                priv_block_handle->mem_handle, local_offset,
                priv_handle->mem_handle_list[i], remote_offset,
                transfer_size, addr, NA_OP_ID_IGNORE);
        if (na_ret != NA_SUCCESS) {
            HG_ERROR_DEFAULT("Could not get data");
            ret = HG_FAIL;
            goto done;
        }
        /* We started from the index that contains bulk_offset so further
         * remote_offset are 0 */
        remote_offset = 0;
        /* Increase the local offset from the size of data we transferred */
        local_offset += transfer_size;
        /* Decrease remaining size from the size of data we transferred */
        remaining_size -= transfer_size;
        /* Increase request index */
        request_index++;
    }

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
HG_Bulk_read_all(na_addr_t addr, hg_bulk_t bulk_handle,
        hg_bulk_block_t block_handle, hg_bulk_request_t *bulk_request)
{
    hg_return_t ret = HG_SUCCESS;
    struct hg_bulk *priv_handle = (struct hg_bulk *) bulk_handle;

    ret = HG_Bulk_read(addr, bulk_handle, 0,
            block_handle, 0, priv_handle->total_size, bulk_request);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Could not read data");
        ret = HG_FAIL;
    }

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
