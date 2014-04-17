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

#include "mercury_request.h"
#include "mercury_atomic.h"

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

struct hg_bulk_mirror {
    na_addr_t addr;         /* NA address */
    struct hg_bulk *handle; /* Mirrored handle */
    size_t offset;          /* Mirrored offset */
};

/* Note to self, get_serialize_size may be updated accordingly */
struct hg_bulk {
    size_t total_size;                /* Total size of data abstracted */
    size_t segment_count;             /* Number of segments */
    hg_bulk_segment_t *segments;      /* Array of segments */
    na_mem_handle_t *segment_handles; /* Array of NA memory handles */
    hg_bool_t registered;             /* NA memory handles registered */
    struct hg_bulk_mirror origin;
    unsigned long flags;              /* Permission flags */
    hg_uint32_t ref_count;            /* Reference count */
};

struct hg_bulk_request {
    unsigned int op_count;                /* Number of ongoing operations */
    hg_atomic_int32_t op_completed_count; /* Number of operations completed */
    hg_request_object_t *request;         /* Request emulation object */
};

/********************/
/* Local Prototypes */
/********************/

/**
 * Create handle.
 */
static hg_return_t
hg_bulk_handle_create(hg_bulk_segment_t *segments, size_t count,
        unsigned long flags, struct hg_bulk **hg_bulk);

/**
 * Free handle.
 */
static hg_return_t hg_bulk_handle_free(struct hg_bulk *hg_bulk);

/**
 * Get info for bulk transfer.
 */
static void hg_bulk_offset_translate(struct hg_bulk *hg_bulk, size_t offset,
        size_t *segment_start_index, size_t *segment_start_offset);

/**
 * Access bulk handle and get segment addresses/sizes.
 */
static void
hg_bulk_handle_access(struct hg_bulk *hg_bulk, size_t offset, size_t size,
        unsigned long flags, unsigned int max_count,
        hg_bulk_segment_t *segments, unsigned int *actual_count);

/**
 * Transfer callback.
 */
static na_return_t hg_bulk_transfer_cb(const struct na_cb_info *callback_info);

/**
 * Transfer data pieces (private).
 */
static hg_return_t
hg_bulk_transfer_pieces(na_bulk_op_t na_bulk_op, na_addr_t addr,
        struct hg_bulk *priv_bulk_handle, size_t bulk_segment_start_index,
        size_t bulk_segment_start_offset, struct hg_bulk *priv_block_handle,
        size_t block_segment_start_index, size_t block_segment_start_offset,
        size_t block_size, struct hg_bulk_request *hg_bulk_request,
        unsigned int *na_op_count);

/**
 * Transfer data.
 */
static hg_return_t hg_bulk_transfer(hg_bulk_op_t op, na_addr_t addr,
        hg_bulk_t bulk_handle, size_t bulk_offset,
        hg_bulk_t block_handle, size_t block_offset,
        size_t block_size, hg_bulk_request_t *request);

/**
 * Progress for request emulation.
 */
extern int
hg_request_progress_func(unsigned int timeout, void *arg);

/**
 * Trigger for request emulation.
 */
extern int
hg_request_trigger_func(unsigned int timeout, unsigned int *flag, void *arg);


/*******************/
/* Local Variables */
/*******************/

/* Pointer to NA class */
extern na_class_t *hg_na_class_g;
na_class_t *hg_bulk_na_class_g = NULL;

/* Local context */
extern na_context_t *hg_context_g;
na_context_t *hg_bulk_context_g = NULL;

/* Request class */
extern hg_request_class_t *hg_request_class_g;
hg_request_class_t *hg_bulk_request_class_g = NULL;

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_bulk_handle_create(hg_bulk_segment_t *bulk_segments, size_t segment_count,
        unsigned long flags, struct hg_bulk **hg_bulk_ptr)
{
    struct hg_bulk *hg_bulk = NULL;
    unsigned long na_flags;
    hg_return_t ret = HG_SUCCESS;
    na_return_t na_ret;
    size_t i;

    switch (flags) {
        case HG_BULK_READWRITE:
            na_flags = NA_MEM_READWRITE;
            break;
        case HG_BULK_READ_ONLY:
            na_flags = NA_MEM_READ_ONLY;
            break;
        default:
            HG_ERROR_DEFAULT("Unrecognized handle flag");
            ret = HG_INVALID_PARAM;
            goto done;
    }

    hg_bulk = (struct hg_bulk *) malloc(sizeof(struct hg_bulk));
    if (!hg_bulk) {
        HG_ERROR_DEFAULT("Could not allocate handle");
        ret = HG_NOMEM_ERROR;
        goto done;
    }
    hg_bulk->total_size = 0;
    hg_bulk->segment_count = segment_count;
    hg_bulk->segments = NULL;
    hg_bulk->segment_handles = NULL;
    hg_bulk->registered = HG_FALSE;
    hg_bulk->origin.addr = NA_ADDR_NULL;
    hg_bulk->origin.handle = NULL;
    hg_bulk->origin.offset = 0;
    hg_bulk->flags = flags;
    hg_bulk->ref_count = 1;

    /* Allocate segment sizes */
    hg_bulk->segments = (hg_bulk_segment_t *) malloc(hg_bulk->segment_count
            * sizeof(hg_bulk_segment_t));
    if (!hg_bulk->segments) {
        HG_ERROR_DEFAULT("Could not allocate segment array");
        ret = HG_NOMEM_ERROR;
        goto done;
    }

    /* Allocate segment handles */
    hg_bulk->segment_handles = (na_mem_handle_t *) malloc(hg_bulk->segment_count
            * sizeof(na_mem_handle_t));
    if (!hg_bulk->segment_handles) {
        HG_ERROR_DEFAULT("Could not allocate mem handle array");
        ret = HG_NOMEM_ERROR;
        goto done;
    }

    /* TODO should check that part */
    /*
    if (hg_bulk_na_class_g->mem_handle_create_segments) {
        for (i = 0; i < segment_count; i++) {
            hg_bulk->total_size += bulk_segments[i].size;
        }
        hg_bulk->segments[0].address = bulk_segments[0].address;
        hg_bulk->segments[0].size = hg_bulk->total_size;
        hg_bulk->segment_handles[0] = NA_MEM_HANDLE_NULL;

        na_ret = NA_Mem_handle_create_segments(hg_bulk_na_class_g,
                (struct na_segment *) bulk_segments, segment_count,
                na_flags, &hg_bulk->segment_handles[0]);
        if (na_ret != NA_SUCCESS) {
            HG_ERROR_DEFAULT("NA_Mem_handle_create_segments failed");
            ret = HG_NA_ERROR;
            goto done;
        }
    }
    */

    /* Loop over the list of segments and register them */
    for (i = 0; i < segment_count; i++) {
        hg_bulk->total_size += bulk_segments[i].size;
        hg_bulk->segments[i].address = bulk_segments[i].address;
        hg_bulk->segments[i].size = bulk_segments[i].size;
        hg_bulk->segment_handles[i] = NA_MEM_HANDLE_NULL;

        na_ret = NA_Mem_handle_create(hg_bulk_na_class_g,
                (void *) bulk_segments[i].address, bulk_segments[i].size,
                na_flags, &hg_bulk->segment_handles[i]);
        if (na_ret != NA_SUCCESS) {
            HG_ERROR_DEFAULT("NA_Mem_handle_create failed");
            ret = HG_NA_ERROR;
            goto done;
        }
    }

    *hg_bulk_ptr = hg_bulk;

done:
    if (ret != HG_SUCCESS) {
        hg_bulk_handle_free(hg_bulk);
    }
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_bulk_handle_free(struct hg_bulk *hg_bulk)
{
    hg_return_t ret = HG_SUCCESS;
    na_return_t na_ret;
    size_t i;

    if (!hg_bulk) goto done;

    if (--hg_bulk->ref_count) {
        goto done;
    }

    /* Free eventual mirrored handle */
    hg_bulk_handle_free(hg_bulk->origin.handle);

    /* Unregister/free NA memory handles */
    if (hg_bulk->segment_handles) {
        if (hg_bulk->registered) {
            for (i = 0; i < hg_bulk->segment_count; i++) {
                na_ret = NA_Mem_deregister(hg_bulk_na_class_g,
                        hg_bulk->segment_handles[i]);
                if (na_ret != NA_SUCCESS) {
                    HG_ERROR_DEFAULT("NA_Mem_deregister failed");
                }
            }
            hg_bulk->registered = HG_FALSE;
        }

        for (i = 0; i < hg_bulk->segment_count; i++) {
            if (hg_bulk->segment_handles[i] != NA_MEM_HANDLE_NULL) {
                na_ret = NA_Mem_handle_free(hg_bulk_na_class_g,
                        hg_bulk->segment_handles[i]);
                if (na_ret != NA_SUCCESS) {
                   HG_ERROR_DEFAULT("NA_Mem_handle_free failed");
                }
            }
        }
        free(hg_bulk->segment_handles);
    }
    free(hg_bulk->segments);
    free(hg_bulk);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static void
hg_bulk_offset_translate(struct hg_bulk *hg_bulk, size_t offset,
        size_t *segment_start_index, size_t *segment_start_offset)
{
    size_t i, new_segment_start_index = 0;
    size_t new_segment_offset = offset, next_offset = 0;

    /* Get start index and handle offset */
    for (i = 0; i < hg_bulk->segment_count; i++) {
        next_offset += hg_bulk->segments[i].size;
        if (offset < next_offset) {
            new_segment_start_index = i;
            break;
        }
        new_segment_offset -= hg_bulk->segments[i].size;
    }

    *segment_start_index = new_segment_start_index;
    *segment_start_offset = new_segment_offset;
}

/*---------------------------------------------------------------------------*/
static void
hg_bulk_handle_access(struct hg_bulk *hg_bulk, size_t offset, size_t size,
        unsigned long flags, unsigned int max_count,
        hg_bulk_segment_t *segments, unsigned int *actual_count)
{
    size_t segment_index, segment_offset;
    size_t remaining_size = size;
    unsigned int count = 0;

    /* TODO use flags */
    (void) flags;

    hg_bulk_offset_translate(hg_bulk, offset, &segment_index,
            &segment_offset);

    while ((remaining_size > 0) && (count < max_count)) {
        hg_ptr_t segment_address;
        size_t segment_size;

        /* Can only transfer smallest size */
        segment_size = hg_bulk->segments[segment_index].size
                - segment_offset;

        /* Remaining size may be smaller */
        segment_size = HG_BULK_MIN(remaining_size, segment_size);
        segment_address = hg_bulk->segments[segment_index].address +
                (hg_ptr_t) segment_offset;

        /* Fill segments */
        segments[count].address = segment_address;
        segments[count].size = segment_size;
        /*
        printf("Segment %d: address=0x%lX\n", count, segment_address);
        printf("Segment %d: size=%zu\n", count, segment_size);
        */

        /* Decrease remaining size from the size of data we transferred */
        remaining_size -= segment_size;

        /* Change segment */
        segment_index++;
        segment_offset = 0;
        count++;
    }

    if (actual_count) *actual_count = count;
}

/*---------------------------------------------------------------------------*/
static na_return_t
hg_bulk_transfer_cb(const struct na_cb_info *callback_info)
{
    struct hg_bulk_request *hg_bulk_request =
            (struct hg_bulk_request *) callback_info->arg;
    na_return_t ret = NA_SUCCESS;

    if (callback_info->ret != NA_SUCCESS) {
        return ret;
    }

    if ((unsigned int) hg_atomic_incr32(&hg_bulk_request->op_completed_count)
            == hg_bulk_request->op_count)
        hg_request_complete(hg_bulk_request->request);

    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_bulk_transfer_pieces(na_bulk_op_t na_bulk_op, na_addr_t addr,
        struct hg_bulk *priv_bulk_handle, size_t bulk_segment_start_index,
        size_t bulk_segment_start_offset, struct hg_bulk *priv_block_handle,
        size_t block_segment_start_index, size_t block_segment_start_offset,
        size_t block_size, struct hg_bulk_request *hg_bulk_request,
        unsigned int *na_op_count)
{
    size_t bulk_segment_index = bulk_segment_start_index;
    size_t block_segment_index = block_segment_start_index;
    size_t bulk_segment_offset = bulk_segment_start_offset;
    size_t block_segment_offset = block_segment_start_offset;
    size_t remaining_size = block_size;
    unsigned int count = 0;
    hg_return_t ret = HG_SUCCESS;
    na_return_t na_ret;

    while (remaining_size > 0) {
        size_t bulk_transfer_size, block_transfer_size, transfer_size;

        /* Can only transfer smallest size */
        bulk_transfer_size = priv_bulk_handle->segments[bulk_segment_index].size
                - bulk_segment_offset;
        block_transfer_size = priv_block_handle->segments[block_segment_index].size
                - block_segment_offset;
        transfer_size = HG_BULK_MIN(bulk_transfer_size, block_transfer_size);

        /* Remaining size may be smaller */
        transfer_size = HG_BULK_MIN(remaining_size, transfer_size);

        if (na_bulk_op) {
            na_ret = na_bulk_op(hg_bulk_na_class_g, hg_bulk_context_g,
                    &hg_bulk_transfer_cb, hg_bulk_request,
                    priv_block_handle->segment_handles[block_segment_index],
                    block_segment_offset,
                    priv_bulk_handle->segment_handles[bulk_segment_index],
                    bulk_segment_offset,
                    transfer_size, addr, NA_OP_ID_IGNORE);
            if (na_ret != NA_SUCCESS) {
                HG_ERROR_DEFAULT("Could not transfer data");
                ret = HG_NA_ERROR;
                break;
            }
        }

        /* Decrease remaining size from the size of data we transferred */
        remaining_size -= transfer_size;

        /* Increment offsets from the size of data we transferred */
        bulk_segment_offset += transfer_size;
        block_segment_offset += transfer_size;

        /* Change segment if new offset exceeds segment size */
        if (bulk_segment_offset >=
            priv_bulk_handle->segments[bulk_segment_index].size) {
            bulk_segment_index++;
            bulk_segment_offset = 0;
        }
        if (block_segment_offset >=
            priv_block_handle->segments[block_segment_index].size) {
            block_segment_index++;
            block_segment_offset = 0;
        }
        count++;
    }

    /* Set number of NA operations issued */
    if (na_op_count) *na_op_count = count;

    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_bulk_transfer(hg_bulk_op_t bulk_op, na_addr_t addr,
        hg_bulk_t bulk_handle, size_t bulk_offset,
        hg_bulk_t block_handle, size_t block_offset,
        size_t block_size, hg_bulk_request_t *request)
{
    struct hg_bulk *priv_bulk_handle = (struct hg_bulk *) bulk_handle;
    struct hg_bulk *priv_block_handle = (struct hg_bulk *) block_handle;
    size_t bulk_segment_start_index, block_segment_start_index;
    size_t bulk_segment_start_offset, block_segment_start_offset;
    na_bulk_op_t na_bulk_op;
    struct hg_bulk_request *priv_bulk_request = NULL;
    hg_return_t ret = HG_SUCCESS;

    if (!priv_bulk_handle || !priv_block_handle) {
        HG_ERROR_DEFAULT("NULL memory handle passed");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    if (block_size > priv_bulk_handle->total_size) {
        HG_ERROR_DEFAULT("Exceeding size of memory exposed by bulk handle");
        ret = HG_SIZE_ERROR;
        goto done;
    }

    if (block_size > priv_block_handle->total_size) {
        HG_ERROR_DEFAULT("Exceeding size of memory exposed by block handle");
        ret = HG_SIZE_ERROR;
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
            ret = HG_INVALID_PARAM;
            goto done;
    }

    if (!request) {
        HG_ERROR_DEFAULT("NULL request pointer passed");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    /* Translate bulk_offset */
    hg_bulk_offset_translate(priv_bulk_handle, bulk_offset,
            &bulk_segment_start_index, &bulk_segment_start_offset);

    /* Translate block offset */
    hg_bulk_offset_translate(priv_block_handle, block_offset,
            &block_segment_start_index, &block_segment_start_offset);

    /* Create a new bulk request */
    priv_bulk_request = (struct hg_bulk_request *)
            malloc(sizeof(struct hg_bulk_request));
    if (!priv_bulk_request) {
        HG_ERROR_DEFAULT("Could not allocate bulk request");
        ret = HG_NOMEM_ERROR;
        goto done;
    }
    priv_bulk_request->op_count = 0;
    hg_atomic_set32(&priv_bulk_request->op_completed_count, 0);
    priv_bulk_request->request = hg_request_create(hg_bulk_request_class_g);

    /* Figure out number of NA operations required */
    hg_bulk_transfer_pieces(NULL, NA_ADDR_NULL,
            priv_bulk_handle, bulk_segment_start_index, bulk_segment_start_offset,
            priv_block_handle, block_segment_start_index, block_segment_start_offset,
            block_size, NULL, &priv_bulk_request->op_count);
    if (!priv_bulk_request->op_count) {
        HG_ERROR_DEFAULT("Could not get bulk op_count");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    /* Do actual transfer */
    ret = hg_bulk_transfer_pieces(na_bulk_op, addr,
            priv_bulk_handle, bulk_segment_start_index, bulk_segment_start_offset,
            priv_block_handle, block_segment_start_index, block_segment_start_offset,
            block_size, priv_bulk_request, NULL);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Could not transfer data pieces");
        goto done;
    }

    *request = (hg_bulk_request_t) priv_bulk_request;

done:
    if (ret != HG_SUCCESS) {
        free(priv_bulk_request);
    }
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Bulk_init(na_class_t *na_class)
{
    hg_return_t ret = HG_SUCCESS;

    if (!na_class) {
        HG_ERROR_DEFAULT("Invalid specified na_class");
        ret = HG_INVALID_PARAM;
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

    /* Create local context if na_class different from hg_class */
    if (hg_bulk_na_class_g == hg_na_class_g) {
        hg_bulk_context_g = hg_context_g;
        hg_bulk_request_class_g = hg_request_class_g;
    } else {
        static struct hg_context hg_context;

        /* Not initialized yet so must initialize */
        hg_bulk_context_g = NA_Context_create(hg_bulk_na_class_g);
        if (!hg_bulk_context_g) {
            HG_ERROR_DEFAULT("Could not create context");
            ret = HG_NA_ERROR;
            goto done;
        }

        hg_context.na_class = hg_bulk_na_class_g;
        hg_context.na_context = hg_bulk_context_g;

        hg_bulk_request_class_g = hg_request_init(hg_request_progress_func,
                hg_request_trigger_func, &hg_context);
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Bulk_finalize(void)
{
    hg_return_t ret = HG_SUCCESS;
    na_return_t na_ret;

    if (!hg_bulk_na_class_g) goto done;

    if (hg_na_class_g == hg_bulk_na_class_g) {
        hg_bulk_request_class_g = NULL;
        hg_bulk_context_g = NULL;
    } else {
        /* Finalize request class */
        hg_request_finalize(hg_bulk_request_class_g);
        hg_bulk_request_class_g = NULL;

        /* Destroy context */
        na_ret = NA_Context_destroy(hg_bulk_na_class_g, hg_bulk_context_g);
        if (na_ret != NA_SUCCESS) {
            HG_ERROR_DEFAULT("Could not destroy context");
            ret = HG_NA_ERROR;
            return ret;
        }
        hg_bulk_context_g = NULL;
    }

    hg_bulk_na_class_g = NULL;

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
        ret = HG_INVALID_PARAM;
        goto done;
    }

    *flag = (hg_bool_t) (hg_bulk_na_class_g != NULL);
    if (na_class) *na_class = hg_bulk_na_class_g;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Bulk_handle_create(void *buf, size_t buf_size, unsigned long flags,
        hg_bulk_t *handle)
{
    struct hg_bulk *hg_bulk = NULL;
    hg_bulk_segment_t segment;
    hg_return_t ret = HG_SUCCESS;

    if (!buf) {
        HG_ERROR_DEFAULT("NULL buffer");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    if (!buf_size) {
        HG_ERROR_DEFAULT("Invalid buffer size");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    switch (flags) {
        case HG_BULK_READWRITE:
            break;
        case HG_BULK_READ_ONLY:
            break;
        default:
            HG_ERROR_DEFAULT("Unrecognized handle flag");
            ret = HG_INVALID_PARAM;
            goto done;
    }

    segment.address = (hg_ptr_t) buf;
    segment.size = buf_size;

    ret = hg_bulk_handle_create(&segment, 1, flags, &hg_bulk);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Could not create bulk handle");
        goto done;
    }

    *handle = (hg_bulk_t) hg_bulk;

done:
    if (ret != HG_SUCCESS) {
        hg_bulk_handle_free(hg_bulk);
    }
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Bulk_handle_create_segments(hg_bulk_segment_t *segments, size_t count,
        unsigned long flags, hg_bulk_t *handle)
{
    struct hg_bulk *hg_bulk = NULL;
    hg_return_t ret = HG_SUCCESS;

    if (!segments) {
        HG_ERROR_DEFAULT("NULL segment pointer");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    if (!count) {
        HG_ERROR_DEFAULT("Invalid number of segments");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    switch (flags) {
        case HG_BULK_READWRITE:
            break;
        case HG_BULK_READ_ONLY:
            break;
        default:
            HG_ERROR_DEFAULT("Unrecognized handle flag");
            ret = HG_INVALID_PARAM;
            goto done;
    }

    ret = hg_bulk_handle_create(segments, count, flags, &hg_bulk);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Could not create bulk handle");
        goto done;
    }

    *handle = (hg_bulk_t) hg_bulk;

done:
    if (ret != HG_SUCCESS) {
        hg_bulk_handle_free(hg_bulk);
    }
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Bulk_handle_free(hg_bulk_t handle)
{
    hg_return_t ret = HG_SUCCESS;
    struct hg_bulk *hg_bulk = (struct hg_bulk *) handle;

    if (!hg_bulk) goto done;

    ret = hg_bulk_handle_free(hg_bulk);
    hg_bulk = NULL;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
size_t
HG_Bulk_handle_get_size(hg_bulk_t handle)
{
    size_t ret = 0;
    struct hg_bulk *hg_bulk = (struct hg_bulk *) handle;

    if (!hg_bulk) {
        HG_ERROR_DEFAULT("NULL bulk handle");
        goto done;
    }

    ret = hg_bulk->total_size;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
size_t
HG_Bulk_handle_get_segment_count(hg_bulk_t handle)
{
    struct hg_bulk *hg_bulk = (struct hg_bulk *) handle;
    size_t ret = 0;

    if (!hg_bulk) {
        HG_ERROR_DEFAULT("NULL bulk handle");
        goto done;
    }

    ret = hg_bulk->segment_count;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
size_t
HG_Bulk_handle_get_serialize_size(hg_bulk_t handle)
{
    struct hg_bulk *hg_bulk = (struct hg_bulk *) handle;
    size_t ret = 0;
    size_t i;

    if (!hg_bulk) {
        HG_ERROR_DEFAULT("NULL bulk handle");
        goto done;
    }

    ret = sizeof(hg_bulk->total_size) + sizeof(hg_bulk->segment_count)
            + hg_bulk->segment_count * sizeof(hg_bulk_segment_t);
    for (i = 0; i < hg_bulk->segment_count; i++) {
        ret += NA_Mem_handle_get_serialize_size(hg_bulk_na_class_g,
                hg_bulk->segment_handles[i]);
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Bulk_handle_serialize(void *buf, size_t buf_size, hg_bulk_t handle)
{
    struct hg_bulk *hg_bulk = (struct hg_bulk *) handle;
    char *buf_ptr = (char*) buf;
    size_t buf_size_left = buf_size;
    hg_return_t ret = HG_SUCCESS;
    na_return_t na_ret;
    size_t i;

    if (!hg_bulk) {
        HG_ERROR_DEFAULT("NULL memory handle passed");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    /* Register handle at this point if not registered yet */
    if (!hg_bulk->registered) {
        for (i = 0; i < hg_bulk->segment_count; i++) {
            na_ret = NA_Mem_register(hg_bulk_na_class_g,
                    hg_bulk->segment_handles[i]);
            if (na_ret != NA_SUCCESS) {
                HG_ERROR_DEFAULT("NA_Mem_register failed");
                ret = HG_NA_ERROR;
                goto done;
            }
        }
        hg_bulk->registered = HG_TRUE;
    }

    if (buf_size < HG_Bulk_handle_get_serialize_size(handle)) {
        HG_ERROR_DEFAULT("Buffer size too small for serializing parameter");
        ret = HG_SIZE_ERROR;
        goto done;
    }

    /* Add the size of the data */
    memcpy(buf_ptr, &hg_bulk->total_size, sizeof(size_t));
    buf_ptr += sizeof(size_t);
    buf_size_left -= sizeof(size_t);

    /* Add the number of handles */
    memcpy(buf_ptr, &hg_bulk->segment_count, sizeof(size_t));
    buf_ptr += sizeof(size_t);
    buf_size_left -= sizeof(size_t);

    /* Add the list of sizes */
    for (i = 0; i < hg_bulk->segment_count; i++) {
        memcpy(buf_ptr, &hg_bulk->segments[i], sizeof(hg_bulk_segment_t));
        buf_ptr += sizeof(hg_bulk_segment_t);
        buf_size_left -= sizeof(hg_bulk_segment_t);
    }

    for (i = 0; i < hg_bulk->segment_count; i++) {
        na_ret = NA_Mem_handle_serialize(hg_bulk_na_class_g, buf_ptr,
                buf_size_left, hg_bulk->segment_handles[i]);
        if (na_ret != NA_SUCCESS) {
            HG_ERROR_DEFAULT("Could not serialize memory handle");
            ret = HG_NA_ERROR;
            break;
        }
        buf_ptr += NA_Mem_handle_get_serialize_size(hg_bulk_na_class_g,
                hg_bulk->segment_handles[i]);
        buf_size_left -= NA_Mem_handle_get_serialize_size(hg_bulk_na_class_g,
                hg_bulk->segment_handles[i]);
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Bulk_handle_deserialize(hg_bulk_t *handle, const void *buf, size_t buf_size)
{
    struct hg_bulk *hg_bulk = NULL;
    const char *buf_ptr = (const char*) buf;
    size_t buf_size_left = buf_size;
    hg_return_t ret = HG_SUCCESS;
    na_return_t na_ret;
    size_t i;

    if (!handle) {
        HG_ERROR_DEFAULT("NULL pointer to memory handle passed");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    hg_bulk = (struct hg_bulk *) malloc(sizeof(struct hg_bulk));
    if (!hg_bulk) {
        HG_ERROR_DEFAULT("Could not allocate handle");
        ret = HG_NOMEM_ERROR;
        goto done;
    }
    hg_bulk->total_size = 0;
    hg_bulk->segment_count = 0;
    hg_bulk->segments = NULL;
    hg_bulk->segment_handles = NULL;
    hg_bulk->registered = HG_FALSE;
    hg_bulk->origin.addr = NA_ADDR_NULL;
    hg_bulk->origin.handle = NULL;
    hg_bulk->origin.offset = 0;
    hg_bulk->flags = 0;
    hg_bulk->ref_count = 1;

    /* Get the size of the data */
    memcpy(&hg_bulk->total_size, buf_ptr, sizeof(size_t));
    buf_ptr += sizeof(size_t);
    buf_size_left -= sizeof(size_t);
    if (!hg_bulk->total_size) {
        HG_ERROR_DEFAULT("NULL total size");
        ret = HG_SIZE_ERROR;
        goto done;
    }

    /* Get the number of handles */
    memcpy(&hg_bulk->segment_count, buf_ptr, sizeof(size_t));
    buf_ptr += sizeof(size_t);
    buf_size_left -= sizeof(size_t);
    if (!hg_bulk->segment_count) {
        HG_ERROR_DEFAULT("NULL segment count");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    /* Add the segment array */
    hg_bulk->segments = (hg_bulk_segment_t *) malloc(
            hg_bulk->segment_count * sizeof(hg_bulk_segment_t));
    if (!hg_bulk->segments) {
        HG_ERROR_DEFAULT("Could not allocate segment array");
        ret = HG_NOMEM_ERROR;
        goto done;
    }
    for (i = 0; i < hg_bulk->segment_count; i++) {
        memcpy(&hg_bulk->segments[i], buf_ptr, sizeof(hg_bulk_segment_t));
        buf_ptr += sizeof(hg_bulk_segment_t);
        buf_size_left -= sizeof(hg_bulk_segment_t);
        if (!hg_bulk->segments[i].size) {
            HG_ERROR_DEFAULT("NULL segment size");
            ret = HG_SIZE_ERROR;
            goto done;
        }
        /* fprintf(stderr, "Segment[%lu] = %lu bytes\n", i, hg_bulk->segments[i].size); */
    }

    hg_bulk->segment_handles = (na_mem_handle_t *) malloc(
            hg_bulk->segment_count * sizeof(na_mem_handle_t));
    if (!hg_bulk->segment_handles) {
        HG_ERROR_DEFAULT("Could not allocate mem handle list");
        ret = HG_NOMEM_ERROR;
        goto done;
    }
    for (i = 0; i < hg_bulk->segment_count; i++) {
        hg_bulk->segment_handles[i] = NA_MEM_HANDLE_NULL;
    }
    for (i = 0; i < hg_bulk->segment_count; i++) {
        size_t serialize_size = NA_Mem_handle_get_serialize_size(
                hg_bulk_na_class_g, hg_bulk->segment_handles[i]);
        na_ret = NA_Mem_handle_deserialize(hg_bulk_na_class_g,
                &hg_bulk->segment_handles[i],
                buf_ptr, buf_size_left);
        if (na_ret != NA_SUCCESS) {
            HG_ERROR_DEFAULT("Could not deserialize memory handle");
            ret = HG_NA_ERROR;
            goto done;
        }
        buf_ptr += serialize_size;
        buf_size_left -= serialize_size;
    }

    *handle = hg_bulk;

done:
    if (ret != HG_SUCCESS) {
        hg_bulk_handle_free(hg_bulk);
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
    }

    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Bulk_write_all(na_addr_t addr, hg_bulk_t bulk_handle,
        hg_bulk_t block_handle, hg_bulk_request_t *bulk_request)
{
    struct hg_bulk *hg_bulk = (struct hg_bulk *) bulk_handle;
    hg_return_t ret = HG_SUCCESS;

    if (!hg_bulk) {
        HG_ERROR_DEFAULT("NULL memory handle passed");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    ret = hg_bulk_transfer(HG_BULK_WRITE, addr, bulk_handle, 0,
            block_handle, 0, hg_bulk->total_size, bulk_request);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Could not write data");
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
    }

    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Bulk_read_all(na_addr_t addr, hg_bulk_t bulk_handle,
        hg_bulk_t block_handle, hg_bulk_request_t *bulk_request)
{
    struct hg_bulk *hg_bulk = (struct hg_bulk *) bulk_handle;
    hg_return_t ret = HG_SUCCESS;

    if (!hg_bulk) {
        HG_ERROR_DEFAULT("NULL memory handle passed");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    ret = hg_bulk_transfer(HG_BULK_READ, addr, bulk_handle, 0,
            block_handle, 0, hg_bulk->total_size, bulk_request);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Could not read data");
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Bulk_wait(hg_bulk_request_t bulk_request, unsigned int timeout,
        hg_status_t *status)
{
    struct hg_bulk_request *hg_bulk_request =
            (struct hg_bulk_request *) bulk_request;
    unsigned int flag;
    hg_return_t ret = HG_SUCCESS;

    if (!hg_bulk_request) {
        HG_ERROR_DEFAULT("NULL request passed");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    if (!hg_bulk_request->request) {
        free(hg_bulk_request);
        hg_bulk_request = NULL;
        goto done;
    }

    if (hg_request_wait(hg_bulk_request->request, timeout, &flag)
            != HG_UTIL_SUCCESS) {
        HG_ERROR_DEFAULT("Could not wait on bulk request");
        ret = HG_NA_ERROR;
        goto done;
    }
    if (flag) {
        hg_request_destroy(hg_bulk_request->request);
        free(hg_bulk_request);
        hg_bulk_request = NULL;
    }

done:
    if (status && (status != HG_STATUS_IGNORE)) {
        /* Completed if priv_bulk_request is NULL */
        *status = (hg_status_t) (hg_bulk_request == NULL);
    }
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Bulk_handle_access(hg_bulk_t handle, size_t offset, size_t size,
        unsigned long flags, unsigned int max_count,
        hg_bulk_segment_t *segments, unsigned int *actual_count)
{
    struct hg_bulk *hg_bulk = (struct hg_bulk *) handle;
    unsigned int count = 0;
    hg_return_t ret = HG_SUCCESS;

    if (!hg_bulk) {
        HG_ERROR_DEFAULT("NULL memory handle passed");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    if (!segments) {
        HG_ERROR_DEFAULT("NULL segment pointer passed");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    if (!size || !max_count) goto done;

    hg_bulk_handle_access(hg_bulk, offset, size, flags, max_count, segments,
            &count);

done:
    if (ret == HG_SUCCESS) {
        if (actual_count) *actual_count = count;
    }
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Bulk_mirror(na_addr_t addr, hg_bulk_t handle, size_t offset,
        size_t size, hg_bulk_t *mirror_handle)
{
    struct hg_bulk *hg_bulk = (struct hg_bulk *) handle;
    struct hg_bulk *hg_bulk_mirror = NULL;
    hg_bulk_segment_t *segments = NULL;
    unsigned int actual_count;
    hg_return_t ret = HG_SUCCESS;

    if (!hg_bulk) {
        HG_ERROR_DEFAULT("NULL memory handle passed");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    if (!mirror_handle) {
        HG_ERROR_DEFAULT("NULL pointer passed");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    if (!size) {
        HG_ERROR_DEFAULT("Invalid size");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    segments = (hg_bulk_segment_t *) malloc(hg_bulk->segment_count
            * sizeof(hg_bulk_segment_t));
    if (!segments) {
        HG_ERROR_DEFAULT("Could not allocate segment array");
        ret = HG_NOMEM_ERROR;
        goto done;
    }

    /* Get segment info */
    hg_bulk_handle_access(hg_bulk, offset, size, 0, hg_bulk->segment_count,
            segments, &actual_count);

    /* When the handle mirrors a remote handle, local pointers do not
     * mean anything and memory must be allocated */
    if (!NA_Addr_is_self(hg_bulk_na_class_g, addr)) {
        unsigned int i;

        for (i = 0; i < actual_count; i++) {
            segments[i].address = (hg_ptr_t) malloc(segments[i].size);
            if (!segments[i].address) {
                HG_ERROR_DEFAULT("Could not allocate segment");
                ret = HG_NOMEM_ERROR;
                goto done;
            }
        }
    }

    /* Create a bulk handle from the segments */
    ret = hg_bulk_handle_create(segments, actual_count, HG_BULK_READWRITE,
            &hg_bulk_mirror);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Could not create bulk handle");
        goto done;
    }

    /* Set the origin for the mirror */
    hg_bulk_mirror->origin.addr = addr;
    hg_bulk_mirror->origin.handle = hg_bulk;
    hg_bulk->ref_count++;
    hg_bulk_mirror->origin.offset = offset;

    *mirror_handle = (hg_bulk_t) hg_bulk_mirror;

done:
    free(segments);
    if (ret != HG_SUCCESS) {
        hg_bulk_handle_free(hg_bulk_mirror);
    }
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Bulk_sync(hg_bulk_t handle, hg_bulk_op_t op, hg_bulk_request_t *request)
{
    struct hg_bulk *hg_bulk = (struct hg_bulk *) handle;
    hg_return_t ret = HG_SUCCESS;

    if (!hg_bulk) {
        HG_ERROR_DEFAULT("NULL memory handle passed");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    if (!request) {
        HG_ERROR_DEFAULT("NULL request pointer passed");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    if (!hg_bulk->origin.handle) {
        HG_ERROR_DEFAULT("Not a mirror handle");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    if (NA_Addr_is_self(hg_bulk_na_class_g, hg_bulk->origin.addr)) {
        struct hg_bulk_request *hg_bulk_request = NULL;

        /* Create a dummy request (TODO will be gone when switched to CB) */
        hg_bulk_request = (struct hg_bulk_request *)
                malloc(sizeof(struct hg_bulk_request));
        if (!hg_bulk_request) {
            HG_ERROR_DEFAULT("Could not allocate bulk request");
            ret = HG_NOMEM_ERROR;
            goto done;
        }
        hg_bulk_request->op_count = 0;
        hg_atomic_set32(&hg_bulk_request->op_completed_count, 0);
        hg_bulk_request->request = NULL;

        *request = (hg_bulk_request_t) hg_bulk_request;
    } else {
        /* Transfer to/from origin handle depending on operation using offset
         * originally specified when creating the mirror. The mirror has an offset
         * of 0 and all the mirrored data gets synced */
        ret = hg_bulk_transfer(op, hg_bulk->origin.addr, hg_bulk->origin.handle,
                hg_bulk->origin.offset, hg_bulk, 0, hg_bulk->total_size, request);
        if (ret != HG_SUCCESS) {
            HG_ERROR_DEFAULT("Could not sync data");
        }
    }

done:
    return ret;
}
