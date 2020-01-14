/*
 * Copyright (C) 2013-2019 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#include "mercury_bulk.h"
#include "mercury_core.h"
#include "mercury_private.h"
#include "mercury_error.h"

#include "mercury_atomic.h"

#include <stdlib.h>
#include <string.h>

/****************/
/* Local Macros */
/****************/
#define HG_BULK_MIN(a, b) \
    (a < b) ? a : b

/* Number of retries when receiving NA_AGAIN error */
#define HG_BULK_MAX_AGAIN_RETRY     (10)

/* Remove warnings when plugin does not use callback arguments */
#if defined(__cplusplus)
# define HG_BULK_UNUSED
#elif defined(__GNUC__) && (__GNUC__ >= 4)
# define HG_BULK_UNUSED __attribute__((unused))
#else
# define HG_BULK_UNUSED
#endif

/************************************/
/* Local Type and Struct Definition */
/************************************/

/* HG class */
struct hg_class {
    hg_core_class_t *core_class;          /* Core class */
};

/* HG context */
struct hg_context {
    hg_core_context_t *core_context;      /* Core context */
};

/* HG Bulk op id */
struct hg_bulk_op_id {
    struct hg_completion_entry hg_completion_entry; /* Entry in completion queue */
    struct hg_bulk *hg_bulk_origin;       /* Origin handle */
    struct hg_bulk *hg_bulk_local;        /* Local handle */
    na_op_id_t *na_op_ids ;               /* NA operations IDs */
    hg_context_t *context;                /* Context */
    na_class_t *na_class;                 /* NA class */
    na_context_t *na_context;             /* NA context */
    hg_cb_t callback;                     /* Callback */
    void *arg;                            /* Callback arguments */
    hg_atomic_int32_t completed;          /* Operation completed TODO needed ? */
    hg_atomic_int32_t canceled;           /* Operation canceled */
    hg_atomic_int32_t op_completed_count; /* Number of operations completed */
    unsigned int op_count;                /* Number of ongoing operations */
    hg_bulk_op_t op;                      /* Operation type */
    hg_bool_t is_self;                    /* Is self operation */
};

/* Segment used to transfer data and map to NA layer */
struct hg_bulk_segment {
    hg_ptr_t address; /* address of the segment */
    hg_size_t size;   /* size of the segment in bytes */
};

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
        na_uint8_t       remote_id,
        na_op_id_t      *op_id
        );

/* Note to self, get_serialize_size may be updated accordingly */
struct hg_bulk {
    hg_class_t *hg_class;                /* HG class */
    na_class_t *na_class;                /* NA class */
#ifdef HG_HAS_SM_ROUTING
    na_class_t *na_sm_class;             /* NA SM class */
#endif
    hg_core_addr_t addr;                 /* Addr (valid if bound to handle) */
    struct hg_bulk_segment *segments;    /* Array of segments */
    na_mem_handle_t *na_mem_handles;     /* Array of NA memory handles */
#ifdef HG_HAS_SM_ROUTING
    na_mem_handle_t *na_sm_mem_handles;  /* Array of NA SM memory handles */
#endif
    void *serialize_ptr;                 /* Cached serialization buffer */
    hg_size_t total_size;                /* Total size of data abstracted */
    hg_size_t serialize_size;            /* Cached serialization size */
    hg_uint32_t segment_count;           /* Number of segments */
    hg_uint32_t na_mem_handle_count;     /* Number of handles */
    hg_atomic_int32_t ref_count;         /* Reference count */
    hg_bool_t segment_published;         /* NA memory handles published */
    hg_bool_t segment_alloc;             /* Allocated memory to mirror data */
    hg_bool_t eager_mode;                /* Eager transfer */
    hg_uint8_t flags;                    /* Permission flags */
    hg_uint8_t context_id;               /* Context ID (valid if bound to handle) */
};

/********************/
/* Local Prototypes */
/********************/

/**
 * Create handle.
 */
static hg_return_t
hg_bulk_create(
        struct hg_class *hg_class,
        hg_uint32_t count,
        void **buf_ptrs,
        const hg_size_t *buf_sizes,
        hg_uint8_t flags,
        struct hg_bulk **hg_bulk_ptr
        );

/**
 * Free handle.
 */
static hg_return_t
hg_bulk_free(
        struct hg_bulk *hg_bulk
        );

/**
 * Get info for bulk transfer.
 */
static HG_INLINE void
hg_bulk_offset_translate(
        struct hg_bulk *hg_bulk,
        hg_size_t offset,
        hg_uint32_t *segment_start_index,
        hg_size_t *segment_start_offset
        );

/**
 * Access bulk handle and get segment addresses/sizes.
 */
static void
hg_bulk_access(
        struct hg_bulk *hg_bulk,
        hg_size_t offset,
        hg_size_t size,
        hg_uint8_t flags,
        hg_uint32_t max_count,
        void **buf_ptrs,
        hg_size_t *buf_sizes,
        hg_uint32_t *actual_count
        );

/**
 * Transfer callback.
 */
static int
hg_bulk_transfer_cb(
        const struct na_cb_info *callback_info
        );

/**
 * Transfer data pieces (private).
 */
static hg_return_t
hg_bulk_transfer_pieces(
        na_bulk_op_t na_bulk_op,
        na_addr_t origin_addr,
        na_uint8_t origin_id,
        hg_bool_t use_sm,
        struct hg_bulk *hg_bulk_origin,
        hg_size_t origin_segment_start_index,
        hg_size_t origin_segment_start_offset,
        struct hg_bulk *hg_bulk_local,
        hg_size_t local_segment_start_index,
        hg_size_t local_segment_start_offset,
        hg_size_t size,
        hg_bool_t scatter_gather,
        struct hg_bulk_op_id *hg_bulk_op_id,
        unsigned int *na_op_count
        );

/**
 * Transfer data.
 */
static hg_return_t
hg_bulk_transfer(
        hg_context_t *context,
        hg_cb_t callback,
        void *arg,
        hg_bulk_op_t op,
        struct hg_addr *origin_addr,
        hg_uint8_t origin_id,
        struct hg_bulk *hg_bulk_origin,
        hg_size_t origin_offset,
        struct hg_bulk *hg_bulk_local,
        hg_size_t local_offset,
        hg_size_t size,
        hg_op_id_t *op_id
        );

/**
 * Complete operation ID.
 */
static hg_return_t
hg_bulk_complete(
        struct hg_bulk_op_id *hg_bulk_op_id
        );

/**
 * Add entry to completion queue.
 */
extern hg_return_t
hg_core_completion_add(
        struct hg_core_context *core_context,
        struct hg_completion_entry *hg_completion_entry,
        hg_bool_t self_notify
        );

/**
 * Trigger callback from bulk op ID.
 */
hg_return_t
hg_bulk_trigger_entry(
        struct hg_bulk_op_id *hg_bulk_op_id
        );

/**
 * NA_Put wrapper
 */
static HG_INLINE na_return_t
hg_bulk_na_put(na_class_t *na_class, na_context_t *context, na_cb_t callback,
    void *arg, na_mem_handle_t local_mem_handle,
    na_ptr_t HG_BULK_UNUSED local_address, na_offset_t local_offset,
    na_mem_handle_t remote_mem_handle, na_ptr_t HG_BULK_UNUSED remote_address,
    na_offset_t remote_offset, na_size_t data_size, na_addr_t remote_addr,
    na_uint8_t remote_id, na_op_id_t *op_id)
{
    na_return_t na_ret;
    int retry_cnt = 0;

    /* Post RMA put */
    do {
        na_ret = NA_Put(na_class, context, callback, arg, local_mem_handle,
            local_offset, remote_mem_handle, remote_offset, data_size,
            remote_addr, remote_id, op_id);
        if (na_ret != NA_AGAIN || retry_cnt++ > HG_BULK_MAX_AGAIN_RETRY)
            break;

        /* Attempt to make progress on NA with timeout of 0 */
        na_ret = NA_Progress(na_class, context, 0);
        HG_CHECK_ERROR(na_ret != NA_SUCCESS && na_ret != NA_TIMEOUT, done,
            na_ret, na_ret, "Could not make progress on NA (%s)",
            NA_Error_to_string(na_ret));
    } while (1);

done:
    return na_ret;
}

/**
 * NA_Get wrapper
 */
static HG_INLINE na_return_t
hg_bulk_na_get(na_class_t *na_class, na_context_t *context, na_cb_t callback,
    void *arg, na_mem_handle_t local_mem_handle,
    na_ptr_t HG_BULK_UNUSED local_address, na_offset_t local_offset,
    na_mem_handle_t remote_mem_handle, na_ptr_t HG_BULK_UNUSED remote_address,
    na_offset_t remote_offset, na_size_t data_size, na_addr_t remote_addr,
    na_uint8_t remote_id, na_op_id_t *op_id)
{
    na_return_t na_ret;
    int retry_cnt = 0;

    /* Post RMA get */
    do {
        na_ret = NA_Get(na_class, context, callback, arg, local_mem_handle,
            local_offset, remote_mem_handle, remote_offset, data_size,
            remote_addr, remote_id, op_id);
        if (na_ret != NA_AGAIN || retry_cnt++ > HG_BULK_MAX_AGAIN_RETRY)
            break;

        /* Attempt to make progress on NA with timeout of 0 */
        na_ret = NA_Progress(na_class, context, 0);
        HG_CHECK_ERROR(na_ret != NA_SUCCESS && na_ret != NA_TIMEOUT, done,
            na_ret, na_ret, "Could not make progress on NA (%s)",
            NA_Error_to_string(na_ret));
    } while (1);

done:
    return na_ret;
}

/**
 * Memcpy
 */
static HG_INLINE na_return_t
hg_bulk_memcpy_put(na_class_t HG_BULK_UNUSED *na_class,
    na_context_t HG_BULK_UNUSED *context, na_cb_t callback, void *arg,
    na_mem_handle_t HG_BULK_UNUSED local_mem_handle, na_ptr_t local_address,
    na_offset_t local_offset, na_mem_handle_t HG_BULK_UNUSED remote_mem_handle,
    na_ptr_t remote_address, na_offset_t remote_offset, na_size_t data_size,
    na_addr_t HG_BULK_UNUSED remote_addr, na_uint8_t HG_BULK_UNUSED remote_id,
    na_op_id_t HG_BULK_UNUSED *op_id)
{
    struct na_cb_info na_cb_info;

    na_cb_info.arg = arg;
    na_cb_info.ret = NA_SUCCESS;
    memcpy((void *) (remote_address + remote_offset),
            (const void *) (local_address + local_offset), data_size);
    callback(&na_cb_info);
    return NA_SUCCESS;
}

/**
 * Memcpy
 */
static HG_INLINE na_return_t
hg_bulk_memcpy_get(na_class_t HG_BULK_UNUSED *na_class,
    na_context_t HG_BULK_UNUSED *context, na_cb_t callback, void *arg,
    na_mem_handle_t HG_BULK_UNUSED local_mem_handle, na_ptr_t local_address,
    na_offset_t local_offset, na_mem_handle_t HG_BULK_UNUSED remote_mem_handle,
    na_ptr_t remote_address, na_offset_t remote_offset, na_size_t data_size,
    na_addr_t HG_BULK_UNUSED remote_addr, na_uint8_t HG_BULK_UNUSED remote_id,
    na_op_id_t HG_BULK_UNUSED *op_id)
{
    struct na_cb_info na_cb_info;

    na_cb_info.arg = arg;
    na_cb_info.ret = NA_SUCCESS;
    memcpy((void *) (local_address + local_offset),
            (const void *) (remote_address + remote_offset), data_size);
    callback(&na_cb_info);
    return NA_SUCCESS;
}

/**
 * Serialize memcpy
 */
static HG_INLINE hg_return_t
hg_bulk_serialize_memcpy(char **dest, ssize_t *dest_left, const void *src,
    size_t n)
{
    hg_return_t ret = HG_SUCCESS;

    HG_CHECK_ERROR((*dest_left -= (ssize_t) n) < 0, done, ret, HG_OVERFLOW,
        "Serialize buffer size too small");
    memcpy(*dest, src, n);
    *dest += n;

done:
    return ret;
}

/**
 * Deserialize memcpy
 */
static HG_INLINE hg_return_t
hg_bulk_deserialize_memcpy(const char **src, ssize_t *src_left, void *dest,
    size_t n)
{
    hg_return_t ret = HG_SUCCESS;

    HG_CHECK_ERROR((*src_left -= (ssize_t) n) < 0, done, ret, HG_OVERFLOW,
        "Deserialize buffer size too small");
    memcpy(dest, *src, n);
    *src += n;

done:
    return ret;
}

/*******************/
/* Local Variables */
/*******************/

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_bulk_create(struct hg_class *hg_class, hg_uint32_t count,
    void **buf_ptrs, const hg_size_t *buf_sizes, hg_uint8_t flags,
    struct hg_bulk **hg_bulk_ptr)
{
    struct hg_bulk *hg_bulk = NULL;
    hg_return_t ret = HG_SUCCESS;
    na_return_t na_ret;
    na_class_t *na_class = HG_Core_class_get_na(hg_class->core_class);
#ifdef HG_HAS_SM_ROUTING
    na_class_t *na_sm_class = HG_Core_class_get_na_sm(hg_class->core_class);
#endif
    hg_bool_t use_register_segments = (hg_bool_t)
        (na_class->ops->mem_handle_create_segments && count > 1);
    unsigned int i;

    hg_bulk = (struct hg_bulk *) malloc(sizeof(struct hg_bulk));
    HG_CHECK_ERROR(hg_bulk == NULL, error, ret, HG_NOMEM,
        "Could not allocate handle");

    memset(hg_bulk, 0, sizeof(struct hg_bulk));
    hg_bulk->hg_class = hg_class;
    hg_bulk->na_class = na_class;
#ifdef HG_HAS_SM_ROUTING
    hg_bulk->na_sm_class = na_sm_class;
#endif
    hg_bulk->segment_count = count;
    hg_bulk->na_mem_handle_count = (use_register_segments) ? 1 : count;
    hg_bulk->segment_alloc = (!buf_ptrs);
    hg_bulk->flags = flags;
    hg_atomic_set32(&hg_bulk->ref_count, 1);

    /* Allocate segments */
    hg_bulk->segments = (struct hg_bulk_segment *) malloc(
        hg_bulk->segment_count * sizeof(struct hg_bulk_segment));
    HG_CHECK_ERROR(hg_bulk->segments == NULL, error, ret, HG_NOMEM,
        "Could not allocate segment array");

    memset(hg_bulk->segments, 0,
           hg_bulk->segment_count * sizeof(struct hg_bulk_segment));

    /* Loop over the list of segments */
    for (i = 0; i < hg_bulk->segment_count; i++) {
        hg_bulk->segments[i].size = buf_sizes[i];
        hg_bulk->total_size += hg_bulk->segments[i].size;

        if (buf_ptrs)
            hg_bulk->segments[i].address = (hg_ptr_t) buf_ptrs[i];
        else {
            /* Use calloc to avoid uninitialized memory used for transfer */
            hg_bulk->segments[i].address = (hg_ptr_t) calloc(
                hg_bulk->segments[i].size, sizeof(char));
            HG_CHECK_ERROR(hg_bulk->segments[i].address == (hg_ptr_t ) 0, error,
                ret, HG_NOMEM, "Could not allocate segment");
        }
    }

    /* Allocate NA memory handles */
    hg_bulk->na_mem_handles = (na_mem_handle_t *) malloc(
        hg_bulk->na_mem_handle_count * sizeof(na_mem_handle_t));
    HG_CHECK_ERROR(hg_bulk->na_mem_handles == NULL, error, ret, HG_NOMEM,
        "Could not allocate mem handle array");

#ifdef HG_HAS_SM_ROUTING
    if (na_sm_class) {
        hg_bulk->na_sm_mem_handles = (na_mem_handle_t *) malloc(
            hg_bulk->na_mem_handle_count * sizeof(na_mem_handle_t));
        HG_CHECK_ERROR(hg_bulk->na_sm_mem_handles == NULL, error, ret,
            HG_NOMEM, "Could not allocate SM mem handle array");
    }
#endif
    for (i = 0; i < hg_bulk->na_mem_handle_count; i++) {
        hg_bulk->na_mem_handles[i] = NA_MEM_HANDLE_NULL;
#ifdef HG_HAS_SM_ROUTING
        if (hg_bulk->na_sm_mem_handles)
            hg_bulk->na_sm_mem_handles[i] = NA_MEM_HANDLE_NULL;
#endif
    }

    /* Create and register NA memory handles */
    for (i = 0; i < hg_bulk->na_mem_handle_count; i++) {
        /* na_mem_handle_count always <= segment_count */
        if (!hg_bulk->segments[i].address)
            continue;

        if (use_register_segments) {
            struct na_segment *na_segments =
                (struct na_segment *) hg_bulk->segments;
            na_size_t na_segment_count = (na_size_t) hg_bulk->segment_count;
            na_ret = NA_Mem_handle_create_segments(na_class, na_segments,
                na_segment_count, flags, &hg_bulk->na_mem_handles[i]);
            HG_CHECK_ERROR(na_ret != NA_SUCCESS, error, ret,
                (hg_return_t ) na_ret,
                "NA_Mem_handle_create_segments() failed (%s)",
                NA_Error_to_string(na_ret));

#ifdef HG_HAS_SM_ROUTING
            if (hg_bulk->na_sm_mem_handles) {
                na_ret = NA_Mem_handle_create_segments(na_sm_class, na_segments,
                    na_segment_count, flags, &hg_bulk->na_sm_mem_handles[i]);
                HG_CHECK_ERROR(na_ret != NA_SUCCESS, error, ret,
                    (hg_return_t) na_ret,
                    "NA_Mem_handle_create_segments() for SM failed (%s)",
                    NA_Error_to_string(na_ret));
            }
#endif
        } else {
            na_ret = NA_Mem_handle_create(na_class,
                (void *) hg_bulk->segments[i].address,
                hg_bulk->segments[i].size, flags, &hg_bulk->na_mem_handles[i]);
            HG_CHECK_ERROR(na_ret != NA_SUCCESS, error, ret,
                (hg_return_t) na_ret,
                "NA_Mem_handle_create() failed (%s)",
                NA_Error_to_string(na_ret));

#ifdef HG_HAS_SM_ROUTING
            if (hg_bulk->na_sm_mem_handles) {
                na_ret = NA_Mem_handle_create(na_sm_class,
                    (void *) hg_bulk->segments[i].address,
                    hg_bulk->segments[i].size, flags,
                    &hg_bulk->na_sm_mem_handles[i]);
                HG_CHECK_ERROR(na_ret != NA_SUCCESS, error, ret,
                    (hg_return_t) na_ret,
                    "NA_Mem_handle_create() for SM failed (%s)",
                    NA_Error_to_string(na_ret));
            }
#endif
        }

        /* Register segment */
        na_ret = NA_Mem_register(na_class, hg_bulk->na_mem_handles[i]);
        HG_CHECK_ERROR(na_ret != NA_SUCCESS, error, ret, (hg_return_t) na_ret,
            "NA_Mem_register() failed (%s)", NA_Error_to_string(na_ret));

#ifdef HG_HAS_SM_ROUTING
        if (hg_bulk->na_sm_mem_handles && hg_bulk->na_sm_mem_handles[i]) {
            na_ret = NA_Mem_register(na_sm_class,
                hg_bulk->na_sm_mem_handles[i]);
            HG_CHECK_ERROR(na_ret != NA_SUCCESS, error, ret,
                (hg_return_t) na_ret,
                "NA_Mem_register() failed (%s)", NA_Error_to_string(na_ret));
        }
#endif
    }

    *hg_bulk_ptr = hg_bulk;

    return ret;

error:
    hg_bulk_free(hg_bulk);

    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_bulk_free(struct hg_bulk *hg_bulk)
{
    hg_return_t ret = HG_SUCCESS;
    unsigned int i;

    if (!hg_bulk)
        goto done;

    /* Cannot free yet */
    if (hg_atomic_decr32(&hg_bulk->ref_count))
        goto done;

    if (hg_bulk->na_mem_handles) {
        na_class_t *na_class = hg_bulk->na_class;
#ifdef HG_HAS_SM_ROUTING
        na_class_t *na_sm_class = hg_bulk->na_sm_class;
#endif

        /* Unregister/free NA memory handles */
        if (hg_bulk->segment_published) {
            for (i = 0; i < hg_bulk->na_mem_handle_count; i++) {
                na_return_t na_ret;

                if (!hg_bulk->na_mem_handles[i])
                    continue;

                na_ret = NA_Mem_unpublish(na_class, hg_bulk->na_mem_handles[i]);
                HG_CHECK_ERROR(na_ret != NA_SUCCESS, done, ret,
                    (hg_return_t) na_ret,
                    "NA_Mem_unpublish() failed (%s)");

#ifdef HG_HAS_SM_ROUTING
                if (hg_bulk->na_sm_mem_handles && hg_bulk->na_sm_mem_handles[i]) {
                    na_ret = NA_Mem_unpublish(na_sm_class,
                        hg_bulk->na_sm_mem_handles[i]);
                    HG_CHECK_ERROR(na_ret != NA_SUCCESS, done, ret,
                        (hg_return_t) na_ret,
                        "NA_Mem_unpublish() for SM failed (%s)",
                        NA_Error_to_string(na_ret));
                }
#endif
            }
            hg_bulk->segment_published = HG_FALSE;
        }

        for (i = 0; i < hg_bulk->na_mem_handle_count; i++) {
            na_return_t na_ret;

            if (!hg_bulk->na_mem_handles[i])
                continue;

            na_ret = NA_Mem_deregister(na_class, hg_bulk->na_mem_handles[i]);
            HG_CHECK_ERROR(na_ret != NA_SUCCESS, done, ret,
                (hg_return_t) na_ret,
                "NA_Mem_deregister() failed (%s)", NA_Error_to_string(na_ret));

            na_ret = NA_Mem_handle_free(na_class, hg_bulk->na_mem_handles[i]);
            HG_CHECK_ERROR(na_ret != NA_SUCCESS, done, ret,
                (hg_return_t) na_ret,
                "NA_Mem_handle_free() failed (%s)", NA_Error_to_string(na_ret));

            hg_bulk->na_mem_handles[i] = NA_MEM_HANDLE_NULL;

#ifdef HG_HAS_SM_ROUTING
            if (hg_bulk->na_sm_mem_handles && hg_bulk->na_sm_mem_handles[i]) {
                na_ret = NA_Mem_deregister(na_sm_class,
                    hg_bulk->na_sm_mem_handles[i]);
                HG_CHECK_ERROR(na_ret != NA_SUCCESS, done, ret,
                    (hg_return_t) na_ret,
                    "NA_Mem_deregister() for SM failed (%s)",
                    NA_Error_to_string(na_ret));

                na_ret = NA_Mem_handle_free(na_sm_class,
                    hg_bulk->na_sm_mem_handles[i]);
                HG_CHECK_ERROR(na_ret != NA_SUCCESS, done, ret,
                    (hg_return_t) na_ret,
                    "NA_Mem_handle_free() for SM failed (%s)",
                    NA_Error_to_string(na_ret));

                hg_bulk->na_sm_mem_handles[i] = NA_MEM_HANDLE_NULL;
            }
#endif
        }

        free(hg_bulk->na_mem_handles);
#ifdef HG_HAS_SM_ROUTING
        free(hg_bulk->na_sm_mem_handles);
#endif
    }

    /* Free segments */
    if (hg_bulk->segment_alloc) {
        for (i = 0; i < hg_bulk->segment_count; i++) {
            free((void *) hg_bulk->segments[i].address);
        }
    }
    free(hg_bulk->segments);

    /* Free addr if any was attached to handle */
    ret = HG_Core_addr_free(hg_bulk->hg_class->core_class, hg_bulk->addr);
    HG_CHECK_HG_ERROR(done, ret, "Could not free bulk addr");

    free(hg_bulk);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static HG_INLINE void
hg_bulk_offset_translate(struct hg_bulk *hg_bulk, hg_size_t offset,
    hg_uint32_t *segment_start_index, hg_size_t *segment_start_offset)
{
    hg_uint32_t i, new_segment_start_index = 0;
    hg_size_t new_segment_offset = offset, next_offset = 0;

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
hg_bulk_access(struct hg_bulk *hg_bulk, hg_size_t offset, hg_size_t size,
    hg_uint8_t HG_BULK_UNUSED flags, hg_uint32_t max_count, void **buf_ptrs,
    hg_size_t *buf_sizes, hg_uint32_t *actual_count)
{
    hg_uint32_t segment_index;
    hg_size_t segment_offset;
    hg_size_t remaining_size = size;
    hg_uint32_t count = 0;

    /* TODO use flags */

    hg_bulk_offset_translate(hg_bulk, offset, &segment_index,
        &segment_offset);

    while ((remaining_size > 0) && (count < max_count)) {
        hg_ptr_t segment_address;
        hg_size_t segment_size;

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

    if (actual_count)
        *actual_count = count;
}

/*---------------------------------------------------------------------------*/
static int
hg_bulk_transfer_cb(const struct na_cb_info *callback_info)
{
    struct hg_bulk_op_id *hg_bulk_op_id =
        (struct hg_bulk_op_id *) callback_info->arg;
    int ret = 0;

    /* If canceled, mark handle as canceled */
    if (callback_info->ret == NA_CANCELED)
        hg_atomic_cas32(&hg_bulk_op_id->canceled, 0, 1);
    else
        HG_CHECK_ERROR_NORET(callback_info->ret != NA_SUCCESS, done,
            "Error in NA callback (s)", NA_Error_to_string(callback_info->ret));

    /* When all NA transfers that correspond to bulk operation complete
     * add HG user callback to completion queue
     */
    if ((unsigned int) hg_atomic_incr32(&hg_bulk_op_id->op_completed_count)
        == hg_bulk_op_id->op_count) {
        hg_bulk_complete(hg_bulk_op_id);
        ret++;
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_bulk_transfer_pieces(na_bulk_op_t na_bulk_op, na_addr_t origin_addr, na_uint8_t origin_id,
    hg_bool_t HG_BULK_UNUSED use_sm, struct hg_bulk *hg_bulk_origin,
    hg_size_t origin_segment_start_index, hg_size_t origin_segment_start_offset,
    struct hg_bulk *hg_bulk_local, hg_size_t local_segment_start_index,
    hg_size_t local_segment_start_offset, hg_size_t size,
    hg_bool_t scatter_gather, struct hg_bulk_op_id *hg_bulk_op_id,
    unsigned int *na_op_count)
{
    hg_size_t origin_segment_index = origin_segment_start_index;
    hg_size_t na_origin_segment_index =
        hg_bulk_origin->na_mem_handle_count > 1 ? origin_segment_index : 0;
    hg_size_t local_segment_index = local_segment_start_index;
    hg_size_t na_local_segment_index =
        hg_bulk_local->na_mem_handle_count > 1 ? local_segment_index : 0;
    hg_size_t origin_segment_offset = origin_segment_start_offset;
    hg_size_t local_segment_offset = local_segment_start_offset;
    na_mem_handle_t *na_origin_mem_handles =
#ifdef HG_HAS_SM_ROUTING
        use_sm ? hg_bulk_origin->na_sm_mem_handles :
#endif
            hg_bulk_origin->na_mem_handles;
    na_mem_handle_t *na_local_mem_handles =
#ifdef HG_HAS_SM_ROUTING
        use_sm ? hg_bulk_local->na_sm_mem_handles :
#endif
            hg_bulk_local->na_mem_handles;
    hg_size_t remaining_size = size;
    unsigned int count = 0;
    hg_return_t ret = HG_SUCCESS;
    na_return_t na_ret;

    for (;;) {
        hg_size_t origin_transfer_size, local_transfer_size;
        hg_size_t transfer_size = remaining_size;

        if (!scatter_gather) {
            /* Can only transfer smallest size */
            origin_transfer_size =
                hg_bulk_origin->segments[origin_segment_index].size
                    - origin_segment_offset;
            local_transfer_size =
                hg_bulk_local->segments[local_segment_index].size
                    - local_segment_offset;
            transfer_size = HG_BULK_MIN(origin_transfer_size,
                local_transfer_size);

            /* Remaining size may be smaller */
            transfer_size = HG_BULK_MIN(remaining_size, transfer_size);
        }

        if (na_bulk_op) {
            na_ret = na_bulk_op(hg_bulk_op_id->na_class,
                hg_bulk_op_id->na_context, hg_bulk_transfer_cb, hg_bulk_op_id,
                na_local_mem_handles[na_local_segment_index],
                hg_bulk_local->segments[local_segment_index].address,
                local_segment_offset,
                na_origin_mem_handles[na_origin_segment_index],
                hg_bulk_origin->segments[origin_segment_index].address,
                origin_segment_offset, transfer_size, origin_addr, origin_id,
                &hg_bulk_op_id->na_op_ids[count]);
            if (na_ret == NA_AGAIN)
                HG_GOTO_DONE(done, ret, HG_AGAIN);
            HG_CHECK_ERROR(na_ret != NA_SUCCESS, done, ret,
                (hg_return_t ) na_ret, "Could not transfer data (%s)",
                NA_Error_to_string(na_ret));
        }
        count++;

        /* Decrease remaining size from the size of data we transferred
         * and exit if everything has been transferred */
        remaining_size -= transfer_size;
        if (!remaining_size)
            break;

        /* Increment offsets from the size of data we transferred */
        origin_segment_offset += transfer_size;
        local_segment_offset += transfer_size;

        /* Change segment if new offset exceeds segment size */
        if (origin_segment_offset >=
            hg_bulk_origin->segments[origin_segment_index].size) {
            origin_segment_index++;
            if (hg_bulk_origin->na_mem_handle_count > 1)
                na_origin_segment_index = origin_segment_index;
            origin_segment_offset = 0;
        }
        if (local_segment_offset >=
            hg_bulk_local->segments[local_segment_index].size) {
            local_segment_index++;
            if (hg_bulk_local->na_mem_handle_count > 1)
                na_local_segment_index = local_segment_index;
            local_segment_offset = 0;
        }
    }

done:
    /* Set number of NA operations issued */
    if (na_op_count)
        *na_op_count = count;

    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_bulk_transfer(hg_context_t *context, hg_cb_t callback, void *arg,
    hg_bulk_op_t op, struct hg_addr *origin_addr, hg_uint8_t origin_id,
    struct hg_bulk *hg_bulk_origin, hg_size_t origin_offset,
    struct hg_bulk *hg_bulk_local, hg_size_t local_offset, hg_size_t size,
    hg_op_id_t *op_id)
{
    hg_uint32_t origin_segment_start_index = 0, local_segment_start_index = 0;
    hg_size_t origin_segment_start_offset = origin_offset,
        local_segment_start_offset = local_offset;
    struct hg_bulk_op_id *hg_bulk_op_id = NULL;
    na_bulk_op_t na_bulk_op;
    na_addr_t na_origin_addr = HG_Core_addr_get_na((hg_core_addr_t) origin_addr);
    na_class_t *na_class = hg_bulk_origin->na_class;
    na_context_t *na_context = HG_Core_context_get_na(context->core_context);
    hg_bool_t use_sm = HG_FALSE;
#ifdef HG_HAS_SM_ROUTING
    na_class_t *na_sm_class = hg_bulk_origin->na_sm_class;
    na_context_t *na_sm_context = HG_Core_context_get_na_sm(context->core_context);
#endif
    na_class_t *na_origin_addr_class = HG_Core_addr_get_na_class(
        (hg_core_addr_t) origin_addr);
    hg_bool_t is_self = NA_Addr_is_self(na_origin_addr_class, na_origin_addr);
    hg_bool_t scatter_gather =
        (na_class->ops->mem_handle_create_segments && !is_self) ? HG_TRUE :
            HG_FALSE;
    hg_return_t ret = HG_SUCCESS;
    unsigned int i;

    /* Map op to NA op */
    switch (op) {
        case HG_BULK_PUSH:
            na_bulk_op = (is_self) ? hg_bulk_memcpy_put : hg_bulk_na_put;
            break;
        case HG_BULK_PULL:
            /* Eager mode can only be used when data is pulled from origin */
            na_bulk_op = (is_self || hg_bulk_origin->eager_mode) ?
                hg_bulk_memcpy_get : hg_bulk_na_get;
            if (hg_bulk_origin->eager_mode) /* Force scatter gather to false */
                scatter_gather = HG_FALSE;
            break;
        default:
            HG_GOTO_ERROR(error, ret, HG_INVALID_ARG, "Unknown bulk operation");
    }

    /* Allocate op_id */
    hg_bulk_op_id = (struct hg_bulk_op_id *) malloc(
        sizeof(struct hg_bulk_op_id));
    HG_CHECK_ERROR(hg_bulk_op_id == NULL, error, ret, HG_NOMEM,
        "Could not allocate HG Bulk operation ID");

    hg_bulk_op_id->context = context;
#ifdef HG_HAS_SM_ROUTING
    if (na_sm_class == na_origin_addr_class) {
        hg_bulk_op_id->na_class = na_sm_class;
        hg_bulk_op_id->na_context = na_sm_context;
        use_sm = HG_TRUE;
    } else {
#endif
        hg_bulk_op_id->na_class = na_class;
        hg_bulk_op_id->na_context = na_context;
#ifdef HG_HAS_SM_ROUTING
    }
#endif
    hg_bulk_op_id->callback = callback;
    hg_bulk_op_id->arg = arg;
    hg_atomic_set32(&hg_bulk_op_id->completed, 0);
    hg_atomic_set32(&hg_bulk_op_id->canceled, 0);
    hg_bulk_op_id->op_count = 1; /* Default */
    hg_atomic_set32(&hg_bulk_op_id->op_completed_count, 0);
    hg_bulk_op_id->op = op;
    hg_bulk_op_id->hg_bulk_origin = hg_bulk_origin;
    hg_atomic_incr32(&hg_bulk_origin->ref_count); /* Increment ref count */
    hg_bulk_op_id->hg_bulk_local = hg_bulk_local;
    hg_atomic_incr32(&hg_bulk_local->ref_count); /* Increment ref count */
    hg_bulk_op_id->na_op_ids = NULL;
    hg_bulk_op_id->is_self = is_self;

    /* Translate bulk_offset */
    if (origin_offset && !scatter_gather)
        hg_bulk_offset_translate(hg_bulk_origin, origin_offset,
            &origin_segment_start_index, &origin_segment_start_offset);

    /* Translate block offset */
    if (local_offset && !scatter_gather)
        hg_bulk_offset_translate(hg_bulk_local, local_offset,
            &local_segment_start_index, &local_segment_start_offset);

    /* Figure out number of NA operations required */
    if (!scatter_gather) {
        ret = hg_bulk_transfer_pieces(NULL, NA_ADDR_NULL, origin_id, use_sm,
            hg_bulk_origin, origin_segment_start_index,
            origin_segment_start_offset, hg_bulk_local,
            local_segment_start_index, local_segment_start_offset, size,
            HG_FALSE, NULL, &hg_bulk_op_id->op_count);
        HG_CHECK_HG_ERROR(error, ret, "Could not get bulk op count");
        HG_CHECK_ERROR(hg_bulk_op_id->op_count == 0, error, ret,
            HG_INVALID_ARG, "Could not get bulk op_count");
    }

    /* Allocate memory for NA operation IDs */
    hg_bulk_op_id->na_op_ids = malloc(
        sizeof(na_op_id_t) * hg_bulk_op_id->op_count);
    HG_CHECK_ERROR(hg_bulk_op_id->na_op_ids == NULL, error, ret, HG_NOMEM,
        "Could not allocate memory for op_ids");

    for (i = 0; i < hg_bulk_op_id->op_count; i++) {
        hg_bulk_op_id->na_op_ids[i] = NA_Op_create(hg_bulk_op_id->na_class);
        HG_CHECK_ERROR(hg_bulk_op_id->na_op_ids[i] == NA_OP_ID_NULL, error, ret,
            HG_NA_ERROR, "Could not create NA op ID");
    }

    /* Do actual transfer */
    ret = hg_bulk_transfer_pieces(na_bulk_op, na_origin_addr, origin_id, use_sm,
        hg_bulk_origin, origin_segment_start_index, origin_segment_start_offset,
        hg_bulk_local, local_segment_start_index, local_segment_start_offset,
        size, scatter_gather, hg_bulk_op_id, NULL);
    if (ret == HG_AGAIN)
       goto error;
    HG_CHECK_HG_ERROR(error, ret, "Could not transfer data pieces");

    /* Assign op_id */
    if (op_id && op_id != HG_OP_ID_IGNORE)
        *op_id = (hg_op_id_t) hg_bulk_op_id;

    return ret;

error:
    if (hg_bulk_op_id) {
        free(hg_bulk_op_id->na_op_ids);
        free(hg_bulk_op_id);
    }
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_bulk_complete(struct hg_bulk_op_id *hg_bulk_op_id)
{
    hg_context_t *context = hg_bulk_op_id->context;
    hg_return_t ret = HG_SUCCESS;

    /* Mark operation as completed */
    hg_atomic_incr32(&hg_bulk_op_id->completed);

    if (hg_bulk_op_id->hg_bulk_origin->eager_mode) {
        /* In the case of eager bulk transfer, directly trigger the operation
         * to avoid potential deadlocks */
        ret = hg_bulk_trigger_entry(hg_bulk_op_id);
        HG_CHECK_HG_ERROR(done, ret, "Could not trigger completion entry");
    } else {
        struct hg_completion_entry *hg_completion_entry =
            &hg_bulk_op_id->hg_completion_entry;

        hg_completion_entry->op_type = HG_BULK;
        hg_completion_entry->op_id.hg_bulk_op_id = hg_bulk_op_id;

        ret = hg_core_completion_add(context->core_context, hg_completion_entry,
            hg_bulk_op_id->is_self);
        HG_CHECK_HG_ERROR(done, ret,
            "Could not add HG completion entry to completion queue");
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
hg_bulk_trigger_entry(struct hg_bulk_op_id *hg_bulk_op_id)
{
    hg_return_t ret = HG_SUCCESS;
    unsigned int i;

    /* Execute callback */
    if (hg_bulk_op_id->callback) {
        struct hg_cb_info hg_cb_info;

        hg_cb_info.arg = hg_bulk_op_id->arg;
        hg_cb_info.ret =
            hg_atomic_get32(&hg_bulk_op_id->canceled) ? HG_CANCELED :
                HG_SUCCESS;
        hg_cb_info.type = HG_CB_BULK;
        hg_cb_info.info.bulk.op = hg_bulk_op_id->op;
        hg_cb_info.info.bulk.origin_handle =
            (hg_bulk_t) hg_bulk_op_id->hg_bulk_origin;
        hg_cb_info.info.bulk.local_handle =
            (hg_bulk_t) hg_bulk_op_id->hg_bulk_local;

        hg_bulk_op_id->callback(&hg_cb_info);
    }

    /* Decrement ref_count */
    ret = hg_bulk_free(hg_bulk_op_id->hg_bulk_origin);
    HG_CHECK_HG_ERROR(done, ret, "Could not free bulk handle");

    ret = hg_bulk_free(hg_bulk_op_id->hg_bulk_local);
    HG_CHECK_HG_ERROR(done, ret, "Could not free bulk handle");

    /* Free op */
    for (i = 0; i < hg_bulk_op_id->op_count; i++) {
        na_return_t na_ret = NA_Op_destroy(hg_bulk_op_id->na_class,
            hg_bulk_op_id->na_op_ids[i]);
        HG_CHECK_ERROR(na_ret != NA_SUCCESS, done, ret, (hg_return_t) na_ret,
            "Could not destroy NA op ID (%s)", NA_Error_to_string(na_ret));
    }
    free(hg_bulk_op_id->na_op_ids);
    free(hg_bulk_op_id);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Bulk_create(hg_class_t *hg_class, hg_uint32_t count, void **buf_ptrs,
    const hg_size_t *buf_sizes, hg_uint8_t flags, hg_bulk_t *handle)
{
    struct hg_bulk *hg_bulk = NULL;
    hg_return_t ret = HG_SUCCESS;

    HG_CHECK_ERROR(hg_class == NULL, done, ret, HG_INVALID_ARG,
        "NULL HG class");
    HG_CHECK_ERROR(count == 0, done, ret, HG_INVALID_ARG,
        "Invalid number of segments");
    HG_CHECK_ERROR(buf_sizes == NULL, done, ret, HG_INVALID_ARG,
        "NULL segment size pointer");

    switch (flags) {
        case HG_BULK_READWRITE:
        case HG_BULK_READ_ONLY:
        case HG_BULK_WRITE_ONLY:
            break;
        default:
            HG_GOTO_ERROR(done, ret, HG_INVALID_ARG,
                "Unrecognized handle flag");
    }

    ret = hg_bulk_create(hg_class, count, buf_ptrs, buf_sizes, flags, &hg_bulk);
    HG_CHECK_HG_ERROR(done, ret, "Could not create bulk handle");

    *handle = (hg_bulk_t) hg_bulk;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Bulk_free(hg_bulk_t handle)
{
    hg_return_t ret = HG_SUCCESS;
    struct hg_bulk *hg_bulk = (struct hg_bulk *) handle;

    if (!hg_bulk)
        goto done;

    ret = hg_bulk_free(hg_bulk);
    HG_CHECK_HG_ERROR(done, ret, "Could not free bulk handle");

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Bulk_ref_incr(hg_bulk_t handle)
{
    struct hg_bulk *hg_bulk = (struct hg_bulk *) handle;
    hg_return_t ret = HG_SUCCESS;

    HG_CHECK_ERROR(hg_bulk == NULL, done, ret, HG_INVALID_ARG,
        "NULL memory handle passed");

    /* Increment ref count */
    hg_atomic_incr32(&hg_bulk->ref_count);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Bulk_bind(hg_bulk_t handle, hg_context_t *context)
{
    struct hg_bulk *hg_bulk = (struct hg_bulk *) handle;
    struct hg_context *hg_context = context;
    hg_return_t ret = HG_SUCCESS;

    HG_CHECK_ERROR(hg_bulk == NULL, done, ret, HG_INVALID_ARG,
        "NULL memory handle passed");
    HG_CHECK_ERROR(context == NULL, done, ret, HG_INVALID_ARG,
        "NULL HG context");
    HG_CHECK_ERROR(hg_bulk->addr != HG_CORE_ADDR_NULL, done, ret,
        HG_INVALID_ARG, "Handle is already bound to existing address");

    /* Retrieve self address */
    ret = HG_Core_addr_self(hg_bulk->hg_class->core_class, &hg_bulk->addr);
    HG_CHECK_HG_ERROR(done, ret, "Could not get self address");

    /* Add context ID */
    hg_bulk->context_id = HG_Core_context_get_id(hg_context->core_context);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_addr_t
HG_Bulk_get_addr(hg_bulk_t handle)
{
    struct hg_bulk *hg_bulk = (struct hg_bulk *) handle;
    hg_core_addr_t ret = HG_CORE_ADDR_NULL;

    HG_CHECK_ERROR_NORET(hg_bulk == NULL, done, "NULL memory handle passed");

    ret = hg_bulk->addr;

done:
    return (hg_addr_t) ret;
}

/*---------------------------------------------------------------------------*/
hg_uint8_t
HG_Bulk_get_context_id(hg_bulk_t handle)
{
    struct hg_bulk *hg_bulk = (struct hg_bulk *) handle;
    hg_uint8_t ret = 0;

    HG_CHECK_ERROR_NORET(hg_bulk == NULL, done, "NULL memory handle passed");

    ret = hg_bulk->context_id;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Bulk_access(hg_bulk_t handle, hg_size_t offset, hg_size_t size,
    hg_uint8_t flags, hg_uint32_t max_count, void **buf_ptrs,
    hg_size_t *buf_sizes, hg_uint32_t *actual_count)
{
    struct hg_bulk *hg_bulk = (struct hg_bulk *) handle;
    hg_return_t ret = HG_SUCCESS;

    HG_CHECK_ERROR(hg_bulk == NULL, done, ret, HG_INVALID_ARG,
        "NULL memory handle passed");

    if (!size || !max_count)
        goto done;

    hg_bulk_access(hg_bulk, offset, size, flags, max_count, buf_ptrs,
        buf_sizes, actual_count);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_size_t
HG_Bulk_get_size(hg_bulk_t handle)
{
    hg_size_t ret = 0;
    struct hg_bulk *hg_bulk = (struct hg_bulk *) handle;

    HG_CHECK_ERROR_NORET(hg_bulk == NULL, done, "NULL memory handle passed");

    ret = hg_bulk->total_size;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_uint32_t
HG_Bulk_get_segment_count(hg_bulk_t handle)
{
    struct hg_bulk *hg_bulk = (struct hg_bulk *) handle;
    hg_uint32_t ret = 0;

    HG_CHECK_ERROR_NORET(hg_bulk == NULL, done, "NULL bulk handle passed");

    ret = hg_bulk->segment_count;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_size_t
HG_Bulk_get_serialize_size(hg_bulk_t handle, hg_bool_t request_eager)
{
    struct hg_bulk *hg_bulk = (struct hg_bulk *) handle;
    hg_size_t ret = 0;
    hg_uint32_t i;

    HG_CHECK_ERROR_NORET(hg_bulk == NULL, done, "NULL memory handle passed");

    /* Permission flags */
    ret = sizeof(hg_bulk->flags);

    /* Address information is bound */
    ret += sizeof(hg_bool_t);

    /* Address information */
    if (hg_bulk->addr != HG_CORE_ADDR_NULL) {
        ret += sizeof(na_size_t) + NA_Addr_get_serialize_size(hg_bulk->na_class,
            HG_Core_addr_get_na(hg_bulk->addr));
        ret += sizeof(hg_bulk->context_id);
    }

    /* Segments */
    ret += sizeof(hg_bulk->total_size) + sizeof(hg_bulk->segment_count)
        + hg_bulk->segment_count * sizeof(*hg_bulk->segments);

    /* NA mem handles */
    ret += sizeof(hg_bulk->na_mem_handle_count);
    for (i = 0; i < hg_bulk->na_mem_handle_count; i++) {
        na_size_t serialize_size = 0;

        if (hg_bulk->na_mem_handles[i])
            serialize_size = NA_Mem_handle_get_serialize_size(
                hg_bulk->na_class, hg_bulk->na_mem_handles[i]);
        ret += sizeof(serialize_size) + serialize_size;
#ifdef HG_HAS_SM_ROUTING
        if (hg_bulk->na_sm_mem_handles) {
            if (hg_bulk->na_sm_mem_handles[i])
                serialize_size = NA_Mem_handle_get_serialize_size(
                    hg_bulk->na_sm_class, hg_bulk->na_sm_mem_handles[i]);
            ret += sizeof(serialize_size) + serialize_size;
        }
#endif
    }

    /* Eager mode */
    ret += sizeof(hg_bulk->eager_mode);
    if (request_eager && (hg_bulk->flags == HG_BULK_READ_ONLY))
        ret += hg_bulk->total_size;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Bulk_serialize(void *buf, hg_size_t buf_size, hg_bool_t request_eager,
    hg_bulk_t handle)
{
    struct hg_bulk *hg_bulk = (struct hg_bulk *) handle;
    char *buf_ptr = (char *) buf;
    ssize_t buf_size_left = (ssize_t) buf_size;
    hg_return_t ret = HG_SUCCESS;
    na_return_t na_ret;
    hg_bool_t bind_addr;
    hg_bool_t eager_mode;
    na_class_t *na_class;
#ifdef HG_HAS_SM_ROUTING
    na_class_t *na_sm_class;
#endif
    hg_uint32_t i;

    HG_CHECK_ERROR(hg_bulk == NULL, done, ret, HG_INVALID_ARG,
        "NULL memory handle passed");

    /* Get NA class */
    na_class = hg_bulk->na_class;
#ifdef HG_HAS_SM_ROUTING
    na_sm_class = hg_bulk->na_sm_class;
#endif

    /* Publish handle at this point if not published yet */
    if (!hg_bulk->segment_published) {
        for (i = 0; i < hg_bulk->na_mem_handle_count; i++) {
            if (!hg_bulk->na_mem_handles[i])
                continue;

            na_ret = NA_Mem_publish(na_class, hg_bulk->na_mem_handles[i]);
            HG_CHECK_ERROR(na_ret != NA_SUCCESS, done, ret,
                (hg_return_t ) na_ret, "NA_Mem_publish() failed (%s)",
                NA_Error_to_string(na_ret));

#ifdef HG_HAS_SM_ROUTING
            if (hg_bulk->na_sm_mem_handles && hg_bulk->na_sm_mem_handles[i]) {
                na_ret = NA_Mem_publish(na_sm_class,
                    hg_bulk->na_sm_mem_handles[i]);
                HG_CHECK_ERROR(na_ret != NA_SUCCESS, done, ret,
                    (hg_return_t ) na_ret,
                    "NA_Mem_publish() for SM failed (%s)",
                    NA_Error_to_string(na_ret));
            }
#endif
        }
        hg_bulk->segment_published = HG_TRUE;
    }

    /* Add the permission flags */
    ret = hg_bulk_serialize_memcpy(&buf_ptr, &buf_size_left,
        &hg_bulk->flags, sizeof(hg_bulk->flags));
    HG_CHECK_HG_ERROR(done, ret, "Could not encode permission flags");

    /* Address information is bound */
    bind_addr = (hg_bool_t) (hg_bulk->addr != HG_CORE_ADDR_NULL);
    ret = hg_bulk_serialize_memcpy(&buf_ptr, &buf_size_left,
        &bind_addr, sizeof(bind_addr));
    HG_CHECK_HG_ERROR(done, ret, "Could not encode bind address boolean");

    /* Add the address information and context ID */
    if (hg_bulk->addr != HG_CORE_ADDR_NULL) {
        na_size_t serialize_size = NA_Addr_get_serialize_size(
            na_class, HG_Core_addr_get_na(hg_bulk->addr));

        ret = hg_bulk_serialize_memcpy(&buf_ptr, &buf_size_left,
            &serialize_size, sizeof(serialize_size));
        HG_CHECK_HG_ERROR(done, ret, "Could not encode serialize size");

        na_ret = NA_Addr_serialize(na_class, buf_ptr, (na_size_t) buf_size_left,
            HG_Core_addr_get_na(hg_bulk->addr));
        HG_CHECK_ERROR(na_ret != NA_SUCCESS, done, ret, (hg_return_t) na_ret,
            "Could not serialize address (%s)", NA_Error_to_string(na_ret));

        buf_ptr += serialize_size;
        buf_size_left -= (ssize_t) serialize_size;

        ret = hg_bulk_serialize_memcpy(&buf_ptr, &buf_size_left,
            &hg_bulk->context_id, sizeof(hg_bulk->context_id));
        HG_CHECK_HG_ERROR(done, ret, "Could not encode context ID");
    }

    /* Add the total size of the segments */
    ret = hg_bulk_serialize_memcpy(&buf_ptr, &buf_size_left,
        &hg_bulk->total_size, sizeof(hg_bulk->total_size));
    HG_CHECK_HG_ERROR(done, ret, "Could not encode total size");

    /* Add the number of segments */
    ret = hg_bulk_serialize_memcpy(&buf_ptr, &buf_size_left,
        &hg_bulk->segment_count, sizeof(hg_bulk->segment_count));
    HG_CHECK_HG_ERROR(done, ret, "Could not encode segment count");

    /* Add the array of segments */
    for (i = 0; i < hg_bulk->segment_count; i++) {
        ret = hg_bulk_serialize_memcpy(&buf_ptr, &buf_size_left,
            &hg_bulk->segments[i], sizeof(hg_bulk->segments[i]));
        HG_CHECK_HG_ERROR(done, ret, "Could not encode segment");
    }

    /* Add the number of NA memory handles */
    ret = hg_bulk_serialize_memcpy(&buf_ptr, &buf_size_left,
        &hg_bulk->na_mem_handle_count, sizeof(hg_bulk->na_mem_handle_count));
    HG_CHECK_HG_ERROR(done, ret, "Could not encode NA memory handle count");

    /* Add the NA memory handles */
    for (i = 0; i < hg_bulk->na_mem_handle_count; i++) {
        na_size_t serialize_size = 0;

        if (hg_bulk->na_mem_handles[i])
            serialize_size = NA_Mem_handle_get_serialize_size(
                na_class, hg_bulk->na_mem_handles[i]);

        ret = hg_bulk_serialize_memcpy(&buf_ptr, &buf_size_left,
            &serialize_size, sizeof(serialize_size));
        HG_CHECK_HG_ERROR(done, ret, "Could not encode serialize size");

        if (hg_bulk->na_mem_handles[i]) {
            na_ret = NA_Mem_handle_serialize(na_class, buf_ptr,
                (na_size_t) buf_size_left, hg_bulk->na_mem_handles[i]);
            HG_CHECK_ERROR(na_ret != NA_SUCCESS, done, ret,
                (hg_return_t ) na_ret, "Could not serialize memory handle (%s)",
                NA_Error_to_string(na_ret));

            buf_ptr += serialize_size;
            buf_size_left -= (ssize_t) serialize_size;
        }

#ifdef HG_HAS_SM_ROUTING
        if (hg_bulk->na_sm_mem_handles) {
            if (hg_bulk->na_sm_mem_handles[i]) {
                serialize_size = NA_Mem_handle_get_serialize_size(
                    na_class, hg_bulk->na_sm_mem_handles[i]);
            } else
                serialize_size = 0;
            ret = hg_bulk_serialize_memcpy(&buf_ptr, &buf_size_left,
                &serialize_size, sizeof(serialize_size));
            HG_CHECK_HG_ERROR(done, ret, "Could not encode serialize size");

            if (hg_bulk->na_sm_mem_handles[i]) {
                na_ret = NA_Mem_handle_serialize(na_sm_class, buf_ptr,
                    (na_size_t) buf_size_left, hg_bulk->na_sm_mem_handles[i]);
                HG_CHECK_ERROR(na_ret != NA_SUCCESS, done, ret,
                    (hg_return_t ) na_ret,
                    "Could not serialize SM memory handle (%s)",
                    NA_Error_to_string(na_ret));

                buf_ptr += serialize_size;
                buf_size_left -= (ssize_t) serialize_size;
            }
        }
#endif
    }

    /* Eager mode is used only when data is set to HG_BULK_READ_ONLY */
    eager_mode = (request_eager && (hg_bulk->flags == HG_BULK_READ_ONLY));
    ret = hg_bulk_serialize_memcpy(&buf_ptr, &buf_size_left, &eager_mode,
        sizeof(eager_mode));
    HG_CHECK_HG_ERROR(done, ret, "Could not encode eager_mode bool");

    /* Add the serialized data */
    if (eager_mode) {
        for (i = 0; i < hg_bulk->segment_count; i++) {
            if (!hg_bulk->segments[i].size)
                continue;

            ret = hg_bulk_serialize_memcpy(&buf_ptr, &buf_size_left,
                (const void *) hg_bulk->segments[i].address,
                hg_bulk->segments[i].size);
            HG_CHECK_HG_ERROR(done, ret, "Could not encode segment data");
        }
    }

    HG_CHECK_WARNING(buf_size_left > 0, "Buf size left greater than 0, %zd",
        buf_size_left);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Bulk_deserialize(hg_class_t *hg_class, hg_bulk_t *handle, const void *buf,
    hg_size_t buf_size)
{
    struct hg_bulk *hg_bulk = NULL;
    const char *buf_ptr = (const char *) buf;
    ssize_t buf_size_left = (ssize_t) buf_size;
    hg_return_t ret = HG_SUCCESS;
    na_return_t na_ret;
    hg_bool_t bind_addr;
    hg_uint32_t i;

    HG_CHECK_ERROR(handle == NULL, error, ret, HG_INVALID_ARG,
        "NULL memory handle passed");

    hg_bulk = (struct hg_bulk *) malloc(sizeof(struct hg_bulk));
    HG_CHECK_ERROR(hg_bulk == NULL, error, ret, HG_NOMEM,
        "Could not allocate handle");

    memset(hg_bulk, 0, sizeof(struct hg_bulk));
    hg_bulk->hg_class = hg_class;
    hg_bulk->na_class = HG_Core_class_get_na(hg_class->core_class);
#ifdef HG_HAS_SM_ROUTING
    hg_bulk->na_sm_class = HG_Core_class_get_na_sm(hg_class->core_class);
#endif
    hg_atomic_set32(&hg_bulk->ref_count, 1);

    /* Get the permission flags */
    ret = hg_bulk_deserialize_memcpy(&buf_ptr, &buf_size_left,
        &hg_bulk->flags, sizeof(hg_bulk->flags));
    HG_CHECK_HG_ERROR(error, ret, "Could not decode permission flags");

    /* Address information is bound */
    ret = hg_bulk_deserialize_memcpy(&buf_ptr, &buf_size_left,
        &bind_addr, sizeof(bind_addr));
    HG_CHECK_HG_ERROR(error, ret, "Could not decode bind address boolean");

    /* Get the address information and context ID */
    if (bind_addr) {
        na_addr_t na_addr;
        na_size_t serialize_size;

        ret = hg_bulk_deserialize_memcpy(&buf_ptr, &buf_size_left,
            &serialize_size, sizeof(serialize_size));
        HG_CHECK_HG_ERROR(error, ret, "Could not decode serialize size");

        na_ret = NA_Addr_deserialize(hg_bulk->na_class, &na_addr, buf_ptr,
            (na_size_t) buf_size_left);
        HG_CHECK_ERROR(na_ret != NA_SUCCESS, error, ret, (hg_return_t) na_ret,
            "Could not deserialize address (%s)", NA_Error_to_string(na_ret));

        buf_ptr += serialize_size;
        buf_size_left -= (ssize_t) serialize_size;

        ret = HG_Core_addr_create(hg_bulk->hg_class->core_class,
            &hg_bulk->addr);
        HG_CHECK_HG_ERROR(error, ret, "Could not create core addr");

        HG_Core_addr_set_na(hg_bulk->addr, na_addr);

        /* Decode context ID */
        ret = hg_bulk_deserialize_memcpy(&buf_ptr, &buf_size_left,
            &hg_bulk->context_id, sizeof(hg_bulk->context_id));
        HG_CHECK_HG_ERROR(error, ret, "Could not decode context ID");
    }

    /* Get the total size of the segments */
    ret = hg_bulk_deserialize_memcpy(&buf_ptr, &buf_size_left,
        &hg_bulk->total_size, sizeof(hg_bulk->total_size));
    HG_CHECK_HG_ERROR(error, ret, "Could not decode total size");

    /* Get the number of segments */
    ret = hg_bulk_deserialize_memcpy(&buf_ptr, &buf_size_left,
        &hg_bulk->segment_count, sizeof(hg_bulk->segment_count));
    HG_CHECK_HG_ERROR(error, ret, "Could not decode segment count");

    /* Get the array of segments */
    hg_bulk->segments = (struct hg_bulk_segment *) malloc(
            hg_bulk->segment_count * sizeof(struct hg_bulk_segment));
    HG_CHECK_ERROR(hg_bulk->segments == NULL, error, ret, HG_NOMEM,
        "Could not allocate segment array");

    for (i = 0; i < hg_bulk->segment_count; i++) {
        ret = hg_bulk_deserialize_memcpy(&buf_ptr, &buf_size_left,
            &hg_bulk->segments[i], sizeof(hg_bulk->segments[i]));
        HG_CHECK_HG_ERROR(error, ret, "Could not decode segment");
    }

    /* Get the number of NA memory handles */
    ret = hg_bulk_deserialize_memcpy(&buf_ptr, &buf_size_left,
        &hg_bulk->na_mem_handle_count, sizeof(hg_bulk->na_mem_handle_count));
    HG_CHECK_HG_ERROR(error, ret, "Could not decode NA memory handle count");

    /* Get the NA memory handles */
    hg_bulk->na_mem_handles = (na_mem_handle_t *) malloc(
            hg_bulk->na_mem_handle_count * sizeof(na_mem_handle_t));
    HG_CHECK_ERROR(hg_bulk->na_mem_handles == NULL, error, ret, HG_NOMEM,
        "Could not allocate NA memory handle array");

#ifdef HG_HAS_SM_ROUTING
    if (hg_bulk->na_sm_class) {
        hg_bulk->na_sm_mem_handles = (na_mem_handle_t *) malloc(
                hg_bulk->na_mem_handle_count * sizeof(na_mem_handle_t));
        HG_CHECK_ERROR(hg_bulk->na_sm_mem_handles == NULL, error, ret,
            HG_NOMEM, "Could not allocate NA SM memory handle array");
    }
#endif

    for (i = 0; i < hg_bulk->na_mem_handle_count; i++) {
        na_size_t serialize_size;

        ret = hg_bulk_deserialize_memcpy(&buf_ptr, &buf_size_left,
            &serialize_size, sizeof(serialize_size));
        HG_CHECK_HG_ERROR(error, ret, "Could not decode serialize size");

        if (serialize_size) {
            na_ret = NA_Mem_handle_deserialize(hg_bulk->na_class,
                &hg_bulk->na_mem_handles[i], buf_ptr,
                (na_size_t) buf_size_left);
            HG_CHECK_ERROR(na_ret != NA_SUCCESS, error, ret,
                (hg_return_t ) na_ret, "Could not deserialize memory handle");

            buf_ptr += serialize_size;
            buf_size_left -= (ssize_t) serialize_size;
        } else
            hg_bulk->na_mem_handles[i] = NA_MEM_HANDLE_NULL;

#ifdef HG_HAS_SM_ROUTING
        if (hg_bulk->na_sm_mem_handles) {
            ret = hg_bulk_deserialize_memcpy(&buf_ptr, &buf_size_left,
                &serialize_size, sizeof(serialize_size));
            HG_CHECK_HG_ERROR(error, ret, "Could not decode serialize size");

            if (serialize_size) {
                na_ret = NA_Mem_handle_deserialize(hg_bulk->na_sm_class,
                    &hg_bulk->na_sm_mem_handles[i], buf_ptr,
                    (na_size_t) buf_size_left);
                HG_CHECK_ERROR(na_ret != NA_SUCCESS, error, ret,
                    (hg_return_t ) na_ret,
                    "Could not deserialize SM memory handle (%s)",
                    NA_Error_to_string(na_ret));

                buf_ptr += serialize_size;
                buf_size_left -= (ssize_t) serialize_size;
            } else
                hg_bulk->na_sm_mem_handles[i] = NA_MEM_HANDLE_NULL;
        }
#endif
    }

    /* Get whether data is serialized or not */
    ret = hg_bulk_deserialize_memcpy(&buf_ptr, &buf_size_left,
        &hg_bulk->eager_mode, sizeof(hg_bulk->eager_mode));
    HG_CHECK_HG_ERROR(error, ret, "Could not decode eager_mode bool");

    /* Get the serialized data */
    if (hg_bulk->eager_mode) {
        hg_bulk->segment_alloc = HG_TRUE;
        for (i = 0; i < hg_bulk->segment_count; i++) {
            if (!hg_bulk->segments[i].size)
                continue;

            /* Use calloc to avoid uninitialized memory used for transfer */
            hg_bulk->segments[i].address = (hg_ptr_t) calloc(
                hg_bulk->segments[i].size, sizeof(char));
            HG_CHECK_ERROR(hg_bulk->segments[i].address == 0, error, ret,
                HG_NOMEM, "Could not allocate segment");

            ret = hg_bulk_deserialize_memcpy(&buf_ptr, &buf_size_left,
                (void *) hg_bulk->segments[i].address,
                hg_bulk->segments[i].size);
            HG_CHECK_HG_ERROR(error, ret, "Could not decode segment data");
        }
    }

    HG_CHECK_WARNING(buf_size_left > 0, "Buf size left greater than 0, %zd",
        buf_size_left);

    *handle = (hg_bulk_t) hg_bulk;

    return ret;

error:
    hg_bulk_free(hg_bulk);

    return ret;
}

/*---------------------------------------------------------------------------*/
void *
HG_Bulk_get_serialize_cached_ptr(hg_bulk_t handle)
{
    struct hg_bulk *hg_bulk = (struct hg_bulk *) handle;

    HG_CHECK_ERROR_NORET(hg_bulk == NULL, error, "NULL memory handle passed");

    return hg_bulk->serialize_ptr;

error:
    return NULL;
}

/*---------------------------------------------------------------------------*/
hg_size_t
HG_Bulk_get_serialize_cached_size(hg_bulk_t handle)
{
    struct hg_bulk *hg_bulk = (struct hg_bulk *) handle;

    HG_CHECK_ERROR_NORET(hg_bulk == NULL, error, "NULL memory handle passed");

    return hg_bulk->serialize_size;

error:
    return 0;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Bulk_set_serialize_cached_ptr(hg_bulk_t handle, void *buf,
    na_size_t buf_size)
{
    struct hg_bulk *hg_bulk = (struct hg_bulk *) handle;
    hg_return_t ret = HG_SUCCESS;

    HG_CHECK_ERROR(hg_bulk == NULL, done, ret, HG_INVALID_ARG,
        "NULL memory handle passed");

    hg_bulk->serialize_ptr = buf;
    hg_bulk->serialize_size = buf_size;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Bulk_transfer(hg_context_t *context, hg_cb_t callback, void *arg,
    hg_bulk_op_t op, hg_addr_t origin_addr, hg_bulk_t origin_handle,
    hg_size_t origin_offset, hg_bulk_t local_handle, hg_size_t local_offset,
    hg_size_t size, hg_op_id_t *op_id)
{
    struct hg_bulk *hg_bulk_origin = (struct hg_bulk *) origin_handle;
    hg_return_t ret = HG_SUCCESS;

    HG_CHECK_ERROR(hg_bulk_origin == NULL, done, ret, HG_INVALID_ARG,
        "NULL origin handle passed");
    HG_CHECK_ERROR(hg_bulk_origin->addr != HG_CORE_ADDR_NULL
        && hg_bulk_origin->addr != (hg_core_addr_t) origin_addr, done, ret,
        HG_INVALID_ARG, "Mismatched address information from origin handle");

    ret = HG_Bulk_transfer_id(context, callback, arg, op, origin_addr, 0,
        origin_handle, origin_offset, local_handle, local_offset, size, op_id);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Bulk_bind_transfer(hg_context_t *context, hg_cb_t callback, void *arg,
    hg_bulk_op_t op, hg_bulk_t origin_handle, hg_size_t origin_offset,
    hg_bulk_t local_handle, hg_size_t local_offset, hg_size_t size,
    hg_op_id_t *op_id)
{
    struct hg_bulk *hg_bulk_origin = (struct hg_bulk *) origin_handle;
    hg_return_t ret = HG_SUCCESS;

    HG_CHECK_ERROR(hg_bulk_origin == NULL, done, ret, HG_INVALID_ARG,
        "NULL origin handle passed");
    HG_CHECK_ERROR(hg_bulk_origin->addr == HG_CORE_ADDR_NULL, done, ret,
        HG_INVALID_ARG, "No address information found on bulk handle, "
        "HG_Bulk_bind() must be called on bulk handle");

    ret = HG_Bulk_transfer_id(context, callback, arg, op,
        (hg_addr_t) hg_bulk_origin->addr, hg_bulk_origin->context_id,
        origin_handle, origin_offset, local_handle, local_offset, size, op_id);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Bulk_transfer_id(hg_context_t *context, hg_cb_t callback, void *arg,
    hg_bulk_op_t op, hg_addr_t origin_addr, hg_uint8_t origin_id,
    hg_bulk_t origin_handle, hg_size_t origin_offset, hg_bulk_t local_handle,
    hg_size_t local_offset, hg_size_t size, hg_op_id_t *op_id)
{
    struct hg_bulk *hg_bulk_origin = (struct hg_bulk *) origin_handle;
    struct hg_bulk *hg_bulk_local = (struct hg_bulk *) local_handle;
    hg_return_t ret = HG_SUCCESS;

    HG_CHECK_ERROR(context == NULL, done, ret, HG_INVALID_ARG,
        "NULL HG context");
    HG_CHECK_ERROR(hg_bulk_origin == NULL || hg_bulk_local == NULL, done, ret,
        HG_INVALID_ARG, "NULL memory handle passed");
    HG_CHECK_ERROR(hg_bulk_origin->addr != HG_CORE_ADDR_NULL
        && hg_bulk_origin->addr != (hg_core_addr_t) origin_addr, done, ret,
        HG_INVALID_ARG, "Mismatched address information from origin handle");
    HG_CHECK_ERROR(hg_bulk_origin->addr != HG_CORE_ADDR_NULL
        && hg_bulk_origin->context_id != origin_id, done, ret, HG_INVALID_ARG,
        "Mismatched context ID information from origin handle");
    HG_CHECK_ERROR(size == 0, done, ret, HG_INVALID_ARG,
        "Transfer size must be non-zero");
    HG_CHECK_ERROR(size > hg_bulk_origin->total_size, done, ret, HG_INVALID_ARG,
        "Exceeding size of memory exposed by origin handle");
    HG_CHECK_ERROR(size > hg_bulk_local->total_size, done, ret, HG_INVALID_ARG,
        "Exceeding size of memory exposed by local handle");

    switch (op) {
        case HG_BULK_PUSH:
            HG_CHECK_ERROR(!(hg_bulk_origin->flags & HG_BULK_WRITE_ONLY)
                || !(hg_bulk_local->flags & HG_BULK_READ_ONLY), done, ret,
                HG_PERMISSION, "Invalid permission flags for PUSH operation "
                "(origin=%d, local=%d)", hg_bulk_origin->flags,
                hg_bulk_local->flags);
            break;
        case HG_BULK_PULL:
            HG_CHECK_ERROR(!(hg_bulk_origin->flags & HG_BULK_READ_ONLY)
                || !(hg_bulk_local->flags & HG_BULK_WRITE_ONLY), done, ret,
                HG_PERMISSION, "Invalid permission flags for PULL operation "
                "(origin=%d, local=%d)", hg_bulk_origin->flags,
                hg_bulk_local->flags);
            break;
        default:
            HG_GOTO_ERROR(done, ret, HG_INVALID_ARG, "Unknown bulk operation");
    }

    ret = hg_bulk_transfer(context, callback, arg, op, origin_addr, origin_id,
        hg_bulk_origin, origin_offset, hg_bulk_local, local_offset, size,
        op_id);
    if (ret == HG_AGAIN)
        goto done;
    HG_CHECK_HG_ERROR(done, ret, "Could not start transfer of bulk data");

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Bulk_cancel(hg_op_id_t op_id)
{
    struct hg_bulk_op_id *hg_bulk_op_id = (struct hg_bulk_op_id *) op_id;
    hg_return_t ret = HG_SUCCESS;

    HG_CHECK_ERROR(hg_bulk_op_id == NULL, done, ret, HG_INVALID_ARG,
        "NULL HG bulk operation ID");

    if (HG_UTIL_TRUE != hg_atomic_cas32(&hg_bulk_op_id->completed, 1, 0)) {
        unsigned int i = 0;

        /* Cancel all NA operations issued */
        for (i = 0; i < hg_bulk_op_id->op_count; i++) {
            na_return_t na_ret = NA_Cancel(hg_bulk_op_id->na_class,
                hg_bulk_op_id->na_context, hg_bulk_op_id->na_op_ids[i]);
            HG_CHECK_ERROR(na_ret != NA_SUCCESS, done, ret,
                (hg_return_t ) na_ret, "Could not cancel NA op ID (%s)",
                NA_Error_to_string(na_ret));
        }
    }

done:
    return ret;
}
