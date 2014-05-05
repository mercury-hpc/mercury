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

/* Remove warnings when plugin does not use callback arguments */
#if defined(__cplusplus)
    #define HG_BULK_UNUSED
#elif defined(__GNUC__) && (__GNUC__ >= 4)
    #define HG_BULK_UNUSED __attribute__((unused))
#else
    #define HG_BULK_UNUSED
#endif


/************************************/
/* Local Type and Struct Definition */
/************************************/

/* Segment used to transfer data and map to NA layer */
typedef struct hg_bulk_segment {
    hg_ptr_t address; /* address of the segment */
    size_t size;      /* size of the segment in bytes */
} hg_bulk_segment_t;

/* Wrapper on top of NA layer */
typedef na_return_t (*na_bulk_op_t)(
        na_class_t      *na_class,
        na_context_t    *context,
        na_cb_t          callback,
        void            *arg,
        na_mem_handle_t  local_mem_handle,
        na_ptr_t         local_address,
        na_offset_t      local_offset,
        na_mem_handle_t  remote_mem_handle,
        na_ptr_t         remote_address,
        na_offset_t      remote_offset,
        na_size_t        data_size,
        na_addr_t        remote_addr,
        na_op_id_t      *op_id
        );

/* Note to self, get_serialize_size may be updated accordingly */
struct hg_bulk {
    size_t total_size;                /* Total size of data abstracted */
    size_t segment_count;             /* Number of segments */
    hg_bulk_segment_t *segments;      /* Array of segments */
    na_mem_handle_t *segment_handles; /* Array of NA memory handles */
    hg_bool_t segment_reg;            /* NA memory handles registered */
    hg_bool_t segment_alloc;          /* Allocated memory to mirror data */
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
hg_bulk_handle_create(size_t count, void **buf_ptrs, const size_t *buf_sizes,
        unsigned long flags, struct hg_bulk **hg_bulk_ptr);

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
        unsigned long flags, unsigned int max_count, void **buf_ptrs,
        size_t *buf_sizes, unsigned int *actual_count);

/**
 * Transfer callback.
 */
static na_return_t hg_bulk_transfer_cb(const struct na_cb_info *callback_info);

/**
 * Transfer data pieces (private).
 */
static hg_return_t
hg_bulk_transfer_pieces(na_bulk_op_t na_bulk_op, na_addr_t origin_addr,
        struct hg_bulk *hg_bulk_origin, size_t origin_segment_start_index,
        size_t origin_segment_start_offset, struct hg_bulk *hg_bulk_local,
        size_t local_segment_start_index, size_t local_segment_start_offset,
        size_t size, struct hg_bulk_request *hg_bulk_request,
        unsigned int *na_op_count);

/**
 * Transfer data.
 */
static hg_return_t
hg_bulk_transfer(na_bulk_op_t na_bulk_op, na_addr_t origin_addr,
        struct hg_bulk *hg_bulk_origin, size_t origin_offset,
        struct hg_bulk *hg_bulk_local, size_t local_offset, size_t size,
        hg_bulk_request_t *request);

/**
 * NA_Put wrapper
 */
static HG_INLINE na_return_t
hg_bulk_na_put(na_class_t *na_class, na_context_t *context, na_cb_t callback,
        void *arg, na_mem_handle_t local_mem_handle,
        na_ptr_t HG_BULK_UNUSED local_address, na_offset_t local_offset,
        na_mem_handle_t remote_mem_handle,
        na_ptr_t HG_BULK_UNUSED remote_address, na_offset_t remote_offset,
        na_size_t data_size, na_addr_t remote_addr, na_op_id_t *op_id)
{
    return NA_Put(na_class, context, callback, arg, local_mem_handle,
            local_offset, remote_mem_handle, remote_offset, data_size,
            remote_addr, op_id);
}

/**
 * NA_Get wrapper
 */
static HG_INLINE na_return_t
hg_bulk_na_get(na_class_t *na_class, na_context_t *context, na_cb_t callback,
        void *arg, na_mem_handle_t local_mem_handle,
        na_ptr_t HG_BULK_UNUSED local_address, na_offset_t local_offset,
        na_mem_handle_t remote_mem_handle,
        na_ptr_t HG_BULK_UNUSED remote_address, na_offset_t remote_offset,
        na_size_t data_size, na_addr_t remote_addr, na_op_id_t *op_id)
{
    return NA_Get(na_class, context, callback, arg, local_mem_handle,
            local_offset, remote_mem_handle, remote_offset, data_size,
            remote_addr, op_id);
}

/**
 * Memcpy
 */
static HG_INLINE na_return_t
hg_bulk_memcpy_put(na_class_t HG_BULK_UNUSED *na_class,
        na_context_t HG_BULK_UNUSED *context, na_cb_t callback, void *arg,
        na_mem_handle_t HG_BULK_UNUSED local_mem_handle, na_ptr_t local_address,
        na_offset_t local_offset,
        na_mem_handle_t HG_BULK_UNUSED remote_mem_handle,
        na_ptr_t remote_address, na_offset_t remote_offset, na_size_t data_size,
        na_addr_t HG_BULK_UNUSED remote_addr, na_op_id_t HG_BULK_UNUSED *op_id)
{
    struct na_cb_info na_cb_info;

    na_cb_info.arg = arg;
    na_cb_info.ret = NA_SUCCESS;
    memcpy((void *) (remote_address + remote_offset),
            (const void *) (local_address + local_offset), data_size);
    return callback(&na_cb_info);
}

/**
 * Memcpy
 */
static HG_INLINE na_return_t
hg_bulk_memcpy_get(na_class_t HG_BULK_UNUSED *na_class,
        na_context_t HG_BULK_UNUSED *context, na_cb_t callback, void *arg,
        na_mem_handle_t HG_BULK_UNUSED local_mem_handle, na_ptr_t local_address,
        na_offset_t local_offset,
        na_mem_handle_t HG_BULK_UNUSED remote_mem_handle,
        na_ptr_t remote_address, na_offset_t remote_offset, na_size_t data_size,
        na_addr_t HG_BULK_UNUSED remote_addr, na_op_id_t HG_BULK_UNUSED *op_id)
{
    struct na_cb_info na_cb_info;

    na_cb_info.arg = arg;
    na_cb_info.ret = NA_SUCCESS;
    memcpy((void *) (local_address + local_offset),
            (const void *) (remote_address + remote_offset), data_size);
    return callback(&na_cb_info);
}

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
hg_bulk_handle_create(size_t count, void **buf_ptrs, const size_t *buf_sizes,
        unsigned long flags, struct hg_bulk **hg_bulk_ptr)
{
    struct hg_bulk *hg_bulk = NULL;
    hg_return_t ret = HG_SUCCESS;
    na_return_t na_ret;
    size_t i;

    hg_bulk = (struct hg_bulk *) malloc(sizeof(struct hg_bulk));
    if (!hg_bulk) {
        HG_ERROR_DEFAULT("Could not allocate handle");
        ret = HG_NOMEM_ERROR;
        goto done;
    }
    hg_bulk->total_size = 0;
    hg_bulk->segment_count = count;
    hg_bulk->segments = NULL;
    hg_bulk->segment_handles = NULL;
    hg_bulk->segment_reg = HG_FALSE;
    hg_bulk->segment_alloc = (!buf_ptrs);
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
    for (i = 0; i < hg_bulk->segment_count; i++) {
        hg_bulk->segments[i].size = buf_sizes[i];
        if (!hg_bulk->segments[i].size) {
            HG_ERROR_DEFAULT("Invalid segment size");
            ret = HG_INVALID_PARAM;
            goto done;
        }
        hg_bulk->total_size += hg_bulk->segments[i].size;

        if (buf_ptrs && buf_ptrs[i])
            hg_bulk->segments[i].address = (hg_ptr_t) buf_ptrs[i];
        else {
            /* Use calloc to avoid uninitialized memory used for transfer */
            hg_bulk->segments[i].address = (hg_ptr_t) calloc(
                    hg_bulk->segments[i].size, sizeof(char));
            if (!hg_bulk->segments[i].address) {
                HG_ERROR_DEFAULT("Could not allocate segment");
                ret = HG_NOMEM_ERROR;
                goto done;
            }
        }

        hg_bulk->segment_handles[i] = NA_MEM_HANDLE_NULL;

        na_ret = NA_Mem_handle_create(hg_bulk_na_class_g,
                (void *) hg_bulk->segments[i].address,
                hg_bulk->segments[i].size, flags, &hg_bulk->segment_handles[i]);
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

    /* Unregister/free NA memory handles */
    if (hg_bulk->segment_handles) {
        if (hg_bulk->segment_reg) {
            for (i = 0; i < hg_bulk->segment_count; i++) {
                na_ret = NA_Mem_deregister(hg_bulk_na_class_g,
                        hg_bulk->segment_handles[i]);
                if (na_ret != NA_SUCCESS) {
                    HG_ERROR_DEFAULT("NA_Mem_deregister failed");
                }
            }
            hg_bulk->segment_reg = HG_FALSE;
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

    /* Free segments */
    if (hg_bulk->segment_alloc) {
        for (i = 0; i < hg_bulk->segment_count; i++) {
            free((void *) hg_bulk->segments[i].address);
        }
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
        unsigned long flags, unsigned int max_count, void **buf_ptrs,
        size_t *buf_sizes, unsigned int *actual_count)
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
        if (buf_ptrs) buf_ptrs[count] = (void *) segment_address;
        if (buf_sizes) buf_sizes[count] = segment_size;
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
hg_bulk_transfer_pieces(na_bulk_op_t na_bulk_op, na_addr_t origin_addr,
        struct hg_bulk *hg_bulk_origin, size_t origin_segment_start_index,
        size_t origin_segment_start_offset, struct hg_bulk *hg_bulk_local,
        size_t local_segment_start_index, size_t local_segment_start_offset,
        size_t size, struct hg_bulk_request *hg_bulk_request,
        unsigned int *na_op_count)
{
    size_t origin_segment_index = origin_segment_start_index;
    size_t local_segment_index = local_segment_start_index;
    size_t origin_segment_offset = origin_segment_start_offset;
    size_t local_segment_offset = local_segment_start_offset;
    size_t remaining_size = size;
    unsigned int count = 0;
    hg_return_t ret = HG_SUCCESS;
    na_return_t na_ret;

    while (remaining_size > 0) {
        size_t origin_transfer_size, local_transfer_size, transfer_size;

        /* Can only transfer smallest size */
        origin_transfer_size = hg_bulk_origin->segments[origin_segment_index].size
                - origin_segment_offset;
        local_transfer_size = hg_bulk_local->segments[local_segment_index].size
                - local_segment_offset;
        transfer_size = HG_BULK_MIN(origin_transfer_size, local_transfer_size);

        /* Remaining size may be smaller */
        transfer_size = HG_BULK_MIN(remaining_size, transfer_size);

        if (na_bulk_op) {
            na_ret = na_bulk_op(hg_bulk_na_class_g, hg_bulk_context_g,
                    hg_bulk_transfer_cb, hg_bulk_request,
                    hg_bulk_local->segment_handles[local_segment_index],
                    hg_bulk_local->segments[local_segment_index].address,
                    local_segment_offset,
                    hg_bulk_origin->segment_handles[origin_segment_index],
                    hg_bulk_origin->segments[origin_segment_index].address,
                    origin_segment_offset, transfer_size, origin_addr,
                    NA_OP_ID_IGNORE);
            if (na_ret != NA_SUCCESS) {
                HG_ERROR_DEFAULT("Could not transfer data");
                ret = HG_NA_ERROR;
                break;
            }
        }

        /* Decrease remaining size from the size of data we transferred */
        remaining_size -= transfer_size;

        /* Increment offsets from the size of data we transferred */
        origin_segment_offset += transfer_size;
        local_segment_offset += transfer_size;

        /* Change segment if new offset exceeds segment size */
        if (origin_segment_offset >=
            hg_bulk_origin->segments[origin_segment_index].size) {
            origin_segment_index++;
            origin_segment_offset = 0;
        }
        if (local_segment_offset >=
            hg_bulk_local->segments[local_segment_index].size) {
            local_segment_index++;
            local_segment_offset = 0;
        }
        count++;
    }

    /* Set number of NA operations issued */
    if (na_op_count) *na_op_count = count;

    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_bulk_transfer(na_bulk_op_t na_bulk_op, na_addr_t origin_addr,
        struct hg_bulk *hg_bulk_origin, size_t origin_offset,
        struct hg_bulk *hg_bulk_local, size_t local_offset, size_t size,
        hg_bulk_request_t *request)
{
    size_t origin_segment_start_index, local_segment_start_index;
    size_t origin_segment_start_offset, local_segment_start_offset;
    struct hg_bulk_request *hg_bulk_request = NULL;
    hg_return_t ret = HG_SUCCESS;

    /* Translate bulk_offset */
    hg_bulk_offset_translate(hg_bulk_origin, origin_offset,
            &origin_segment_start_index, &origin_segment_start_offset);

    /* Translate block offset */
    hg_bulk_offset_translate(hg_bulk_local, local_offset,
            &local_segment_start_index, &local_segment_start_offset);

    /* Create a new bulk request */
    hg_bulk_request = (struct hg_bulk_request *)
            malloc(sizeof(struct hg_bulk_request));
    if (!hg_bulk_request) {
        HG_ERROR_DEFAULT("Could not allocate bulk request");
        ret = HG_NOMEM_ERROR;
        goto done;
    }
    hg_bulk_request->op_count = 0;
    hg_atomic_set32(&hg_bulk_request->op_completed_count, 0);
    hg_bulk_request->request = hg_request_create(hg_bulk_request_class_g);

    /* Figure out number of NA operations required */
    hg_bulk_transfer_pieces(NULL, NA_ADDR_NULL, hg_bulk_origin,
            origin_segment_start_index, origin_segment_start_offset,
            hg_bulk_local, local_segment_start_index,
            local_segment_start_offset, size, NULL, &hg_bulk_request->op_count);
    if (!hg_bulk_request->op_count) {
        HG_ERROR_DEFAULT("Could not get bulk op_count");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    /* Do actual transfer */
    ret = hg_bulk_transfer_pieces(na_bulk_op, origin_addr, hg_bulk_origin,
            origin_segment_start_index, origin_segment_start_offset,
            hg_bulk_local, local_segment_start_index,
            local_segment_start_offset, size, hg_bulk_request, NULL);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Could not transfer data pieces");
        goto done;
    }

    *request = (hg_bulk_request_t) hg_bulk_request;

done:
    if (ret != HG_SUCCESS) {
        free(hg_bulk_request);
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
HG_Bulk_handle_create(size_t count, void **buf_ptrs, const size_t *buf_sizes,
        unsigned long flags, hg_bulk_t *handle)
{
    struct hg_bulk *hg_bulk = NULL;
    hg_return_t ret = HG_SUCCESS;

    if (!count) {
        HG_ERROR_DEFAULT("Invalid number of segments");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    if (!buf_sizes) {
        HG_ERROR_DEFAULT("NULL segment pointer");
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

    ret = hg_bulk_handle_create(count, buf_ptrs, buf_sizes, flags, &hg_bulk);
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

    /* TODO hg_bulk_t *handle to assign NULL ? */
done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Bulk_handle_access(hg_bulk_t handle, size_t offset, size_t size,
        unsigned long flags, unsigned int max_count, void **buf_ptrs,
        size_t *buf_sizes, unsigned int *actual_count)
{
    struct hg_bulk *hg_bulk = (struct hg_bulk *) handle;
    unsigned int count = 0;
    hg_return_t ret = HG_SUCCESS;

    if (!hg_bulk) {
        HG_ERROR_DEFAULT("NULL memory handle passed");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    if (!size || !max_count) goto done;

    hg_bulk_handle_access(hg_bulk, offset, size, flags, max_count, buf_ptrs,
            buf_sizes, &count);

done:
    if (ret == HG_SUCCESS) {
        if (actual_count) *actual_count = count;
    }
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
    if (!hg_bulk->segment_reg) {
        for (i = 0; i < hg_bulk->segment_count; i++) {
            na_ret = NA_Mem_register(hg_bulk_na_class_g,
                    hg_bulk->segment_handles[i]);
            if (na_ret != NA_SUCCESS) {
                HG_ERROR_DEFAULT("NA_Mem_register failed");
                ret = HG_NA_ERROR;
                goto done;
            }
        }
        hg_bulk->segment_reg = HG_TRUE;
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
    hg_bulk->segment_reg = HG_FALSE;
    hg_bulk->segment_alloc = HG_FALSE;
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
HG_Bulk_transfer(hg_bulk_op_t op, na_addr_t origin_addr,
        hg_bulk_t origin_handle, size_t origin_offset, hg_bulk_t local_handle,
        size_t local_offset, size_t size, hg_bulk_request_t *request)
{
    struct hg_bulk *hg_bulk_origin = (struct hg_bulk *) origin_handle;
    struct hg_bulk *hg_bulk_local = (struct hg_bulk *) local_handle;
    na_bulk_op_t na_bulk_op;
    hg_return_t ret = HG_SUCCESS;

    switch (op) {
        case HG_BULK_PUSH:
            na_bulk_op = (NA_Addr_is_self(hg_bulk_na_class_g, origin_addr)) ?
                    hg_bulk_memcpy_put : hg_bulk_na_put;
            break;
        case HG_BULK_PULL:
            na_bulk_op = (NA_Addr_is_self(hg_bulk_na_class_g, origin_addr)) ?
                    hg_bulk_memcpy_get : hg_bulk_na_get;
            break;
        default:
            HG_ERROR_DEFAULT("Unknown bulk operation");
            ret = HG_INVALID_PARAM;
            goto done;
    }

    if (origin_addr == NA_ADDR_NULL) {
        HG_ERROR_DEFAULT("NULL addr passed");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    if (!hg_bulk_origin || !hg_bulk_local) {
        HG_ERROR_DEFAULT("NULL memory handle passed");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    if (size > hg_bulk_origin->total_size) {
        HG_ERROR_DEFAULT("Exceeding size of memory exposed by origin handle");
        ret = HG_SIZE_ERROR;
        goto done;
    }

    if (size > hg_bulk_local->total_size) {
        HG_ERROR_DEFAULT("Exceeding size of memory exposed by local handle");
        ret = HG_SIZE_ERROR;
        goto done;
    }

    if (!request) {
        HG_ERROR_DEFAULT("NULL request pointer passed");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    ret = hg_bulk_transfer(na_bulk_op, origin_addr, hg_bulk_origin,
            origin_offset, hg_bulk_local, local_offset, size, request);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Could not transfer data");
        goto done;
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
        /* Completed if hg_bulk_request is NULL */
        *status = (hg_status_t) (hg_bulk_request == NULL);
    }
    return ret;
}
