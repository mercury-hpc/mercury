/*
 * Copyright (C) 2013-2019 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#include "mercury.h"
#include "mercury_bulk.h"
#include "mercury_proc.h"
#include "mercury_proc_bulk.h"

#include "mercury_hash_string.h"
#include "mercury_mem.h"
#include "mercury_thread_spin.h"

#include <stdlib.h>
#include <string.h>

/****************/
/* Local Macros */
/****************/

#define HG_POST_LIMIT_DEFAULT 256

/* Convert value to string */
#define HG_ERROR_STRING_MACRO(def, value, string) \
  if (value == def) string = #def

#define HG_CONTEXT_CLASS(context) \
    ((struct hg_private_class *)(context->hg_class))

/************************************/
/* Local Type and Struct Definition */
/************************************/

/* HG class */
struct hg_private_class {
    struct hg_class hg_class;       /* Must remain as first field */
    hg_thread_spin_t register_lock; /* Register lock */

    /* Callbacks */
    hg_return_t (*handle_create)(hg_handle_t, void *);  /* handle_create */
    void *handle_create_arg;                            /* handle_create arg */
};

/* Info for function map */
struct hg_proc_info {
    hg_rpc_cb_t rpc_cb;             /* RPC callback */
    hg_proc_cb_t in_proc_cb;        /* Input proc callback */
    hg_proc_cb_t out_proc_cb;       /* Output proc callback */
    hg_bool_t no_response;          /* RPC response not expected */
    void *data;                     /* User data */
    void (*free_callback)(void *);  /* User data free callback */
};

/* HG handle */
struct hg_private_handle {
    struct hg_handle handle;        /* Must remain as first field */
    hg_cb_t forward_cb;             /* Forward callback */
    void *forward_arg;              /* Forward callback args */
    hg_cb_t respond_cb;             /* Respond callback */
    void *respond_arg;              /* Respond callback args */
    struct hg_header hg_header;     /* Header for input/output */
    hg_proc_t in_proc;              /* Proc for input */
    hg_proc_t out_proc;             /* Proc for output */
    void *in_extra_buf;             /* Extra input buffer */
    hg_size_t in_extra_buf_size;    /* Extra input buffer size */
    hg_bulk_t in_extra_bulk;        /* Extra input bulk handle */
    void *out_extra_buf;            /* Extra output buffer */
    hg_size_t out_extra_buf_size;   /* Extra output buffer size */
    hg_bulk_t out_extra_bulk;       /* Extra output bulk handle */
    hg_return_t (*extra_bulk_transfer_cb)(hg_core_handle_t); /* Bulk transfer callback */
};

/* HG op id */
struct hg_op_info_lookup {
    struct hg_addr *hg_addr;        /* Address */
    hg_core_op_id_t core_op_id;     /* Operation ID for lookup */
};

struct hg_op_id {
    struct hg_context *context;     /* Context */
    hg_cb_type_t type;              /* Callback type */
    hg_cb_t callback;               /* Callback */
    void *arg;                      /* Callback arguments */
    union {
        struct hg_op_info_lookup lookup;
    } info;
};

/********************/
/* Local Prototypes */
/********************/

/**
 * Free function for value in function map.
 */
static void
hg_proc_info_free(
        void *arg
        );

/**
 * Alloc function for private data.
 */
static struct hg_private_handle *
hg_handle_create(
        struct hg_private_class *hg_class
        );

/**
 * Free function for private data.
 */
static void
hg_handle_free(
        void *arg
        );

/**
 * Create handle callback.
 */
static hg_return_t
hg_handle_create_cb(
        hg_core_handle_t core_handle,
        void *arg
        );

/**
 * More data callback.
 */
static hg_return_t
hg_more_data_cb(
        hg_core_handle_t core_handle,
        hg_op_t op,
        hg_return_t (*done_cb)(hg_core_handle_t)
        );

/**
 * More data free callback.
 */
static void
hg_more_data_free_cb(
        hg_core_handle_t core_handle
        );

/**
 * Core RPC callback.
 */
static HG_INLINE hg_return_t
hg_core_rpc_cb(
        hg_core_handle_t core_handle
        );

/**
 * Core lookup callback.
 */
static HG_INLINE hg_return_t
hg_core_addr_lookup_cb(
        const struct hg_core_cb_info *callback_info
        );

/**
 * Decode and get input/output structure.
 */
static hg_return_t
hg_get_struct(
        struct hg_private_handle *hg_handle,
        const struct hg_proc_info *hg_proc_info,
        hg_op_t op,
        void *struct_ptr
        );

/**
 * Set and encode input/output structure.
 */
static hg_return_t
hg_set_struct(
        struct hg_private_handle *hg_handle,
        const struct hg_proc_info *hg_proc_info,
        hg_op_t op,
        void *struct_ptr,
        hg_size_t *payload_size,
        hg_bool_t *more_data
        );

/**
 * Free allocated members from input/output structure.
 */
static hg_return_t
hg_free_struct(
        struct hg_private_handle *hg_handle,
        const struct hg_proc_info *hg_proc_info,
        hg_op_t op,
        void *struct_ptr
        );

/**
 * Get extra user payload using bulk transfer.
 */
static hg_return_t
hg_get_extra_payload(
        struct hg_private_handle *hg_handle,
        hg_op_t op,
        hg_return_t (*done_cb)(hg_core_handle_t)
        );

/**
 * Get extra payload bulk transfer callback.
 */
static HG_INLINE hg_return_t
hg_get_extra_payload_cb(
        const struct hg_cb_info *callback_info
        );

/**
 * Free allocated extra payload.
 */
static void
hg_free_extra_payload(
        struct hg_private_handle *hg_handle
        );

/**
 * Forward callback.
 */
static HG_INLINE hg_return_t
hg_core_forward_cb(
        const struct hg_core_cb_info *callback_info
        );

/**
 * Respond callback.
 */
static HG_INLINE hg_return_t
hg_core_respond_cb(
        const struct hg_core_cb_info *callback_info
        );

/*******************/
/* Local Variables */
/*******************/

/*---------------------------------------------------------------------------*/
/**
 * Free function for value in function map.
 */
static void
hg_proc_info_free(void *arg)
{
    struct hg_proc_info *hg_proc_info = (struct hg_proc_info *) arg;

    if (hg_proc_info->free_callback)
        hg_proc_info->free_callback(hg_proc_info->data);
    free(hg_proc_info);
}

/*---------------------------------------------------------------------------*/
static struct hg_private_handle *
hg_handle_create(struct hg_private_class *hg_class)
{
    struct hg_private_handle *hg_handle = NULL;
    hg_return_t ret;

    /* Create private data to wrap callbacks etc */
    hg_handle = (struct hg_private_handle *) malloc(
        sizeof(struct hg_private_handle));
    if (!hg_handle) {
        HG_LOG_ERROR("Could not allocate private data");
        goto done;
    }
    memset(hg_handle, 0, sizeof(struct hg_private_handle));
    hg_handle->handle.info.hg_class = (hg_class_t *) hg_class;
    hg_header_init(&hg_handle->hg_header, HG_UNDEF);

    /* CRC32 is enough for small size buffers */
    ret = hg_proc_create((hg_class_t *) hg_class, HG_CRC32, &hg_handle->in_proc);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Cannot create HG proc");
        goto done;
    }
    ret = hg_proc_create((hg_class_t *) hg_class, HG_CRC32, &hg_handle->out_proc);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Cannot create HG proc");
        goto done;
    }

done:
    return hg_handle;
}

/*---------------------------------------------------------------------------*/
static void
hg_handle_free(void *arg)
{
    struct hg_private_handle *hg_handle = (struct hg_private_handle *) arg;

    if (hg_handle->handle.data_free_callback)
        hg_handle->handle.data_free_callback(hg_handle->handle.data);
    if (hg_handle->in_proc != HG_PROC_NULL)
        hg_proc_free(hg_handle->in_proc);
    if (hg_handle->out_proc != HG_PROC_NULL)
        hg_proc_free(hg_handle->out_proc);
    hg_header_finalize(&hg_handle->hg_header);
    free(hg_handle);
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_handle_create_cb(hg_core_handle_t core_handle, void *arg)
{
    struct hg_context *hg_context = (struct hg_context *) arg;
    struct hg_private_handle *hg_handle;
    hg_return_t ret = HG_SUCCESS;

    hg_handle = hg_handle_create(HG_CONTEXT_CLASS(hg_context));
    if (!hg_handle) {
        HG_LOG_ERROR("Could not create HG handle");
        ret = HG_NOMEM_ERROR;
        goto done;
    }
    hg_handle->handle.core_handle = core_handle;
    hg_handle->handle.info.context = hg_context;

    HG_Core_set_data(core_handle, hg_handle, hg_handle_free);

    /* Call handle create if defined */
    if (HG_CONTEXT_CLASS(hg_context)->handle_create) {
        ret = HG_CONTEXT_CLASS(hg_context)->handle_create(
            (hg_handle_t) hg_handle,
            HG_CONTEXT_CLASS(hg_context)->handle_create_arg);
        if (ret != HG_SUCCESS) {
            HG_LOG_ERROR("Error in handle create callback");
            goto done;
        }
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_more_data_cb(hg_core_handle_t core_handle, hg_op_t op,
    hg_return_t (*done_cb)(hg_core_handle_t))
{
    struct hg_private_handle *hg_handle;
    void *extra_buf;
    hg_return_t ret = HG_SUCCESS;

    /* Retrieve private data */
    hg_handle = (struct hg_private_handle *) HG_Core_get_data(core_handle);
    if (!hg_handle) {
        HG_LOG_ERROR("Could not get private data");
        ret = HG_PROTOCOL_ERROR;
        goto done;
    }

    switch (op) {
        case HG_INPUT:
            extra_buf = hg_handle->in_extra_buf;
            break;
        case HG_OUTPUT:
            extra_buf = hg_handle->out_extra_buf;
            break;
        default:
            HG_LOG_ERROR("Invalid HG op");
            ret = HG_INVALID_PARAM;
            goto done;
    }

    if (extra_buf) {
        /* We were forwarding to ourself and the extra buf is already set */
        ret = done_cb(core_handle);
        if (ret != HG_SUCCESS) {
            HG_LOG_ERROR("Could not execute more data done callback");
            goto done;
        }
    } else {
        /* We need to do a bulk transfer to get the extra data */
        ret = hg_get_extra_payload(hg_handle, op, done_cb);
        if (ret != HG_SUCCESS) {
            HG_LOG_ERROR("Could not get extra input");
            goto done;
        }
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static void
hg_more_data_free_cb(hg_core_handle_t core_handle)
{
    struct hg_private_handle *hg_handle;

    /* Retrieve private data */
    hg_handle = (struct hg_private_handle *) HG_Core_get_data(core_handle);
    if (!hg_handle) {
        goto done;
    }

    hg_free_extra_payload(hg_handle);

done:
    return;
}

/*---------------------------------------------------------------------------*/
static HG_INLINE hg_return_t
hg_core_rpc_cb(hg_core_handle_t core_handle)
{
    const struct hg_core_info *hg_core_info = HG_Core_get_info(core_handle);
    const struct hg_proc_info *hg_proc_info =
        (const struct hg_proc_info *) HG_Core_get_rpc_data(core_handle);
    struct hg_private_handle *hg_handle =
        (struct hg_private_handle *) HG_Core_get_data(core_handle);
    hg_return_t ret = HG_SUCCESS;

    hg_handle->handle.info.addr = (hg_addr_t) hg_core_info->addr;
    hg_handle->handle.info.context_id = hg_core_info->context_id;
    hg_handle->handle.info.id = hg_core_info->id;

    if (!hg_proc_info->rpc_cb) {
        HG_LOG_ERROR("No RPC callback registered");
        /* Need to decrement refcount on handle */
        HG_Core_destroy(core_handle);
        ret = HG_INVALID_PARAM;
        goto done;
    }
    ret = hg_proc_info->rpc_cb((hg_handle_t) hg_handle);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static HG_INLINE hg_return_t
hg_core_addr_lookup_cb(const struct hg_core_cb_info *callback_info)
{
    struct hg_op_id *hg_op_id = (struct hg_op_id *) callback_info->arg;
    struct hg_cb_info hg_cb_info;
    hg_return_t ret = HG_SUCCESS;

    hg_cb_info.arg = hg_op_id->arg;
    hg_cb_info.ret = callback_info->ret;
    hg_cb_info.type = hg_op_id->type;
    hg_cb_info.info.lookup.addr = (hg_addr_t) callback_info->info.lookup.addr;
    if (hg_op_id->callback)
        hg_op_id->callback(&hg_cb_info);

    free(hg_op_id);
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_get_struct(struct hg_private_handle *hg_handle,
    const struct hg_proc_info *hg_proc_info, hg_op_t op, void *struct_ptr)
{
    hg_proc_t proc = HG_PROC_NULL;
    hg_proc_cb_t proc_cb = NULL;
    void *buf, *extra_buf;
    hg_size_t buf_size, extra_buf_size;
    struct hg_header *hg_header = &hg_handle->hg_header;
#ifdef HG_HAS_CHECKSUMS
    struct hg_header_hash *hg_header_hash = NULL;
#endif
    hg_size_t header_offset = hg_header_get_size(op);
    hg_return_t ret = HG_SUCCESS;

    switch (op) {
        case HG_INPUT:
            /* Use custom header offset */
            header_offset += hg_handle->handle.info.hg_class->in_offset;
            /* Set input proc */
            proc = hg_handle->in_proc;
            proc_cb = hg_proc_info->in_proc_cb;
#ifdef HG_HAS_CHECKSUMS
            hg_header_hash = &hg_header->msg.input.hash;
#endif
            /* Get core input buffer */
            ret = HG_Core_get_input(hg_handle->handle.core_handle, &buf, &buf_size);
            if (ret != HG_SUCCESS) {
                HG_LOG_ERROR("Could not get input buffer");
                goto done;
            }
            extra_buf = hg_handle->in_extra_buf;
            extra_buf_size = hg_handle->in_extra_buf_size;
            break;
        case HG_OUTPUT:
            /* Cannot respond if no_response flag set */
            if (hg_proc_info->no_response) {
                HG_LOG_ERROR("No output was produced on that RPC (no response)");
                ret = HG_PROTOCOL_ERROR;
                goto done;
            }
            /* Use custom header offset */
            header_offset += hg_handle->handle.info.hg_class->out_offset;
            /* Set output proc */
            proc = hg_handle->out_proc;
            proc_cb = hg_proc_info->out_proc_cb;
#ifdef HG_HAS_CHECKSUMS
            hg_header_hash = &hg_header->msg.output.hash;
#endif
            /* Get core output buffer */
            ret = HG_Core_get_output(hg_handle->handle.core_handle, &buf, &buf_size);
            if (ret != HG_SUCCESS) {
                HG_LOG_ERROR("Could not get output buffer");
                goto done;
            }
            extra_buf = hg_handle->out_extra_buf;
            extra_buf_size = hg_handle->out_extra_buf_size;
            break;
        default:
            HG_LOG_ERROR("Invalid HG op");
            ret = HG_INVALID_PARAM;
            goto done;
    }
    if (!proc_cb) {
        HG_LOG_ERROR("No proc set, proc must be set in HG_Register()");
        ret = HG_PROTOCOL_ERROR;
        goto done;
    }

    /* Reset header */
    hg_header_reset(hg_header, op);

    /* Get header */
    ret = hg_header_proc(HG_DECODE, buf, buf_size, hg_header);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not process header");
        goto done;
    }

    /* If the payload did not fit into the core buffer and we have an extra
     * buffer set, use that buffer directly */
    if (extra_buf) {
        buf = extra_buf;
        buf_size = extra_buf_size;
    } else {
        /* Include our own header offset */
        buf = (char *) buf + header_offset;
        buf_size -= header_offset;
    }

    /* Reset proc */
    ret = hg_proc_reset(proc, buf, buf_size, HG_DECODE);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not reset proc");
        goto done;
    }

    /* Decode parameters */
    ret = proc_cb(proc, struct_ptr);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not decode parameters");
        goto done;
    }

    /* Flush proc */
    ret = hg_proc_flush(proc);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Error in proc flush");
        goto done;
    }

#ifdef HG_HAS_CHECKSUMS
    /* Compare checksum with header hash */
    ret = hg_proc_checksum_verify(proc, &hg_header_hash->payload,
        sizeof(hg_header_hash->payload));
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Error in proc checksum verify");
        goto done;
    }
#endif

    /* Increment ref count on handle so that it remains valid until free_struct
     * is called */
    HG_Core_ref_incr(hg_handle->handle.core_handle);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_set_struct(struct hg_private_handle *hg_handle,
    const struct hg_proc_info *hg_proc_info, hg_op_t op, void *struct_ptr,
    hg_size_t *payload_size, hg_bool_t *more_data)
{
    hg_proc_t proc = HG_PROC_NULL;
    hg_proc_cb_t proc_cb = NULL;
    void *buf, **extra_buf;
    hg_size_t buf_size, *extra_buf_size;
    hg_bulk_t *extra_bulk;
    struct hg_header *hg_header = &hg_handle->hg_header;
#ifdef HG_HAS_CHECKSUMS
    struct hg_header_hash *hg_header_hash = NULL;
#endif
    hg_size_t header_offset = hg_header_get_size(op);
    hg_return_t ret = HG_SUCCESS;

    switch (op) {
        case HG_INPUT:
            /* Use custom header offset */
            header_offset += hg_handle->handle.info.hg_class->in_offset;
            /* Set input proc */
            proc = hg_handle->in_proc;
            proc_cb = hg_proc_info->in_proc_cb;
#ifdef HG_HAS_CHECKSUMS
            hg_header_hash = &hg_header->msg.input.hash;
#endif
            /* Get core input buffer */
            ret = HG_Core_get_input(hg_handle->handle.core_handle, &buf, &buf_size);
            if (ret != HG_SUCCESS) {
                HG_LOG_ERROR("Could not get input buffer");
                goto done;
            }
            extra_buf = &hg_handle->in_extra_buf;
            extra_buf_size = &hg_handle->in_extra_buf_size;
            extra_bulk = &hg_handle->in_extra_bulk;
            break;
        case HG_OUTPUT:
            /* Cannot respond if no_response flag set */
            if (hg_proc_info->no_response) {
                HG_LOG_ERROR("No output was produced on that RPC (no response)");
                ret = HG_PROTOCOL_ERROR;
                goto done;
            }
            /* Use custom header offset */
            header_offset += hg_handle->handle.info.hg_class->out_offset;
            /* Set output proc */
            proc = hg_handle->out_proc;
            proc_cb = hg_proc_info->out_proc_cb;
#ifdef HG_HAS_CHECKSUMS
            hg_header_hash = &hg_header->msg.output.hash;
#endif
            /* Get core output buffer */
            ret = HG_Core_get_output(hg_handle->handle.core_handle, &buf, &buf_size);
            if (ret != HG_SUCCESS) {
                HG_LOG_ERROR("Could not get output buffer");
                goto done;
            }
            extra_buf = &hg_handle->out_extra_buf;
            extra_buf_size = &hg_handle->out_extra_buf_size;
            extra_bulk = &hg_handle->out_extra_bulk;
            break;
        default:
            HG_LOG_ERROR("Invalid HG op");
            ret = HG_INVALID_PARAM;
            goto done;
    }
    if (!proc_cb || !struct_ptr) {
        /* Silently skip */
        *payload_size = header_offset;
        goto done;
    }

    /* Reset header */
    hg_header_reset(hg_header, op);

    /* Include our own header offset */
    buf = (char *) buf + header_offset;
    buf_size -= header_offset;

    /* Reset proc */
    ret = hg_proc_reset(proc, buf, buf_size, HG_ENCODE);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not reset proc");
        goto done;
    }

    /* Encode parameters */
    ret = proc_cb(proc, struct_ptr);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not encode parameters");
        goto done;
    }

    /* Flush proc */
    ret = hg_proc_flush(proc);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Error in proc flush");
        goto done;
    }

#ifdef HG_HAS_CHECKSUMS
    /* Set checksum in header */
    ret = hg_proc_checksum_get(proc, &hg_header_hash->payload,
        sizeof(hg_header_hash->payload));
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Error in getting proc checksum");
        goto done;
    }
#endif

    /* The proc object may have allocated an extra buffer at this point.
     * If the payload did not fit into the original buffer, we need to send a
     * message with "more data" flag set along with the bulk data descriptor
     * for the extra buffer so that the target can pull that buffer and use
     * it to retrieve the data.
     */
    if (hg_proc_get_extra_buf(proc)) {
        /* Potentially free previous payload if handle was not reset */
        hg_free_extra_payload(hg_handle);
#ifdef HG_HAS_XDR
        HG_LOG_ERROR("Extra encoding using XDR is not yet supported");
        ret = HG_SIZE_ERROR;
        goto done;
#endif
        /* Create a bulk descriptor only of the size that is used */
        *extra_buf = hg_proc_get_extra_buf(proc);
        *extra_buf_size = hg_proc_get_size_used(proc);

        /* Prevent buffer from being freed when proc_reset is called */
        hg_proc_set_extra_buf_is_mine(proc, HG_TRUE);

        /* Create bulk descriptor */
        ret = HG_Bulk_create(hg_handle->handle.info.hg_class, 1, extra_buf,
            extra_buf_size, HG_BULK_READ_ONLY, extra_bulk);
        if (ret != HG_SUCCESS) {
            HG_LOG_ERROR("Could not create bulk data handle");
            goto done;
        }

        /* Reset proc */
        ret = hg_proc_reset(proc, buf, buf_size, HG_ENCODE);
        if (ret != HG_SUCCESS) {
            HG_LOG_ERROR("Could not reset proc");
            goto done;
        }

        /* Encode extra_bulk_handle, we can do that safely here because
         * the user payload has been copied so we don't have to worry
         * about overwriting the user's data */
        ret = hg_proc_hg_bulk_t(proc, extra_bulk);
        if (ret != HG_SUCCESS) {
            HG_LOG_ERROR("Could not process extra bulk handle");
            goto done;
        }

        ret = hg_proc_flush(proc);
        if (ret != HG_SUCCESS) {
            HG_LOG_ERROR("Error in proc flush");
            goto done;
        }

        if (hg_proc_get_extra_buf(proc)) {
            HG_LOG_ERROR("Extra bulk handle could not fit into buffer");
            ret = HG_PROTOCOL_ERROR;
            goto done;
        }

        *more_data = HG_TRUE;
    }

    /* Encode header */
    buf = (char *) buf - header_offset;
    buf_size += header_offset;
    ret = hg_header_proc(HG_ENCODE, buf, buf_size, hg_header);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not process header");
        goto done;
    }

    /* Only send the actual size of the data, not the entire buffer */
    *payload_size = hg_proc_get_size_used(proc) + header_offset;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_free_struct(struct hg_private_handle *hg_handle,
    const struct hg_proc_info *hg_proc_info, hg_op_t op, void *struct_ptr)
{
    hg_proc_t proc = HG_PROC_NULL;
    hg_proc_cb_t proc_cb = NULL;
    hg_return_t ret = HG_SUCCESS;

    switch (op) {
        case HG_INPUT:
            /* Set input proc */
            proc = hg_handle->in_proc;
            proc_cb = hg_proc_info->in_proc_cb;
            break;
        case HG_OUTPUT:
            /* Set output proc */
            proc = hg_handle->out_proc;
            proc_cb = hg_proc_info->out_proc_cb;
            break;
        default:
            HG_LOG_ERROR("Invalid HG op");
            ret = HG_INVALID_PARAM;
            goto done;
    }
    if (!proc_cb) {
        HG_LOG_ERROR("No proc set, proc must be set in HG_Register()");
        ret = HG_PROTOCOL_ERROR;
        goto done;
    }

    /* Reset proc */
    ret = hg_proc_reset(proc, NULL, 0, HG_FREE);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not reset proc");
        goto done;
    }

    /* Free memory allocated during decode operation */
    ret = proc_cb(proc, struct_ptr);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not free allocated parameters");
        goto done;
    }

    /* Decrement ref count or free */
    ret = HG_Core_destroy(hg_handle->handle.core_handle);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not decrement handle ref count");
        goto done;
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_get_extra_payload(struct hg_private_handle *hg_handle, hg_op_t op,
    hg_return_t (*done_cb)(hg_core_handle_t core_handle))
{
    const struct hg_core_info *hg_core_info = HG_Core_get_info(
        hg_handle->handle.core_handle);
    hg_proc_t proc = HG_PROC_NULL;
    void *buf, **extra_buf;
    hg_size_t buf_size, *extra_buf_size;
    hg_bulk_t *extra_bulk = NULL;
    hg_size_t header_offset = hg_header_get_size(op);
    hg_size_t page_size = (hg_size_t) hg_mem_get_page_size();
    hg_bulk_t local_handle = HG_BULK_NULL;
    hg_return_t ret = HG_SUCCESS;

    switch (op) {
        case HG_INPUT:
            /* Use custom header offset */
            header_offset += hg_handle->handle.info.hg_class->in_offset;
            /* Set input proc */
            proc = hg_handle->in_proc;
            /* Get core input buffer */
            ret = HG_Core_get_input(hg_handle->handle.core_handle, &buf, &buf_size);
            if (ret != HG_SUCCESS) {
                HG_LOG_ERROR("Could not get input buffer");
                goto done;
            }
            extra_buf = &hg_handle->in_extra_buf;
            extra_buf_size = &hg_handle->in_extra_buf_size;
            extra_bulk = &hg_handle->in_extra_bulk;
            break;
        case HG_OUTPUT:
            /* Use custom header offset */
            header_offset += hg_handle->handle.info.hg_class->out_offset;
            /* Set output proc */
            proc = hg_handle->out_proc;
            /* Get core output buffer */
            ret = HG_Core_get_output(hg_handle->handle.core_handle, &buf, &buf_size);
            if (ret != HG_SUCCESS) {
                HG_LOG_ERROR("Could not get output buffer");
                goto done;
            }
            extra_buf = &hg_handle->out_extra_buf;
            extra_buf_size = &hg_handle->out_extra_buf_size;
            extra_bulk = &hg_handle->out_extra_bulk;
            break;
        default:
            HG_LOG_ERROR("Invalid HG op");
            ret = HG_INVALID_PARAM;
            goto done;
    }

    /* Include our own header offset */
    buf = (char *) buf + header_offset;
    buf_size -= header_offset;

    ret = hg_proc_reset(proc, buf, buf_size, HG_DECODE);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not reset proc");
        goto done;
    }

    /* Decode extra bulk handle */
    ret = hg_proc_hg_bulk_t(proc, extra_bulk);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not process extra bulk handle");
        goto done;
    }

    ret = hg_proc_flush(proc);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Error in proc flush");
        goto done;
    }

    /* Create a new local handle to read the data */
    *extra_buf_size = HG_Bulk_get_size(*extra_bulk);
    *extra_buf = hg_mem_aligned_alloc(page_size, *extra_buf_size);
    if (!*extra_buf) {
        HG_LOG_ERROR("Could not allocate extra payload buffer");
        ret = HG_NOMEM_ERROR;
        goto done;
    }

    ret = HG_Bulk_create(hg_handle->handle.info.hg_class, 1, extra_buf,
        extra_buf_size, HG_BULK_READWRITE, &local_handle);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not create HG bulk handle");
        goto done;
    }

    /* Read bulk data here and wait for the data to be here  */
    hg_handle->extra_bulk_transfer_cb = done_cb;
    ret = HG_Bulk_transfer_id(hg_handle->handle.info.context,
        hg_get_extra_payload_cb, hg_handle, HG_BULK_PULL,
        (hg_addr_t) hg_core_info->addr, hg_core_info->context_id,
        *extra_bulk, 0, local_handle, 0, *extra_buf_size,
        HG_OP_ID_IGNORE /* TODO not used for now */);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not transfer bulk data");
        goto done;
    }

done:
    HG_Bulk_free(local_handle);
    if (extra_bulk) {
        HG_Bulk_free(*extra_bulk);
        *extra_bulk = HG_BULK_NULL;
    }
    return ret;
}

/*---------------------------------------------------------------------------*/
static HG_INLINE hg_return_t
hg_get_extra_payload_cb(const struct hg_cb_info *callback_info)
{
    struct hg_private_handle *hg_handle =
        (struct hg_private_handle *) callback_info->arg;
    hg_return_t ret = HG_SUCCESS;

    ret = hg_handle->extra_bulk_transfer_cb(hg_handle->handle.core_handle);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not execute bulk transfer callback");
        goto done;
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static void
hg_free_extra_payload(struct hg_private_handle *hg_handle)
{
    /* Free extra bulk buf if there was any */
    if (hg_handle->in_extra_buf) {
        HG_Bulk_free(hg_handle->in_extra_bulk);
        hg_handle->in_extra_bulk = HG_BULK_NULL;
        hg_mem_aligned_free(hg_handle->in_extra_buf);
        hg_handle->in_extra_buf = NULL;
        hg_handle->in_extra_buf_size = 0;
    }

    if (hg_handle->out_extra_buf) {
        HG_Bulk_free(hg_handle->out_extra_bulk);
        hg_handle->out_extra_bulk = HG_BULK_NULL;
        hg_mem_aligned_free(hg_handle->out_extra_buf);
        hg_handle->out_extra_buf = NULL;
        hg_handle->out_extra_buf_size = 0;
    }
}

/*---------------------------------------------------------------------------*/
static HG_INLINE hg_return_t
hg_core_forward_cb(const struct hg_core_cb_info *callback_info)
{
    struct hg_private_handle *hg_handle =
            (struct hg_private_handle *) callback_info->arg;
    hg_return_t ret = HG_SUCCESS;

    /* Execute callback */
    if (hg_handle->forward_cb) {
        struct hg_cb_info hg_cb_info;

        hg_cb_info.arg = hg_handle->forward_arg;
        hg_cb_info.ret = callback_info->ret;
        hg_cb_info.type = callback_info->type;
        hg_cb_info.info.forward.handle = (hg_handle_t) hg_handle;

        hg_handle->forward_cb(&hg_cb_info);
    }

    return ret;
}

/*---------------------------------------------------------------------------*/
static HG_INLINE hg_return_t
hg_core_respond_cb(const struct hg_core_cb_info *callback_info)
{
    struct hg_private_handle *hg_handle =
            (struct hg_private_handle *) callback_info->arg;
    hg_return_t ret = HG_SUCCESS;

    /* Execute callback */
    if (hg_handle->respond_cb) {
        struct hg_cb_info hg_cb_info;

        hg_cb_info.arg = hg_handle->respond_arg;
        hg_cb_info.ret = callback_info->ret;
        hg_cb_info.type = callback_info->type;
        hg_cb_info.info.respond.handle = (hg_handle_t) hg_handle;

        hg_handle->respond_cb(&hg_cb_info);
    }

    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Version_get(unsigned int *major, unsigned int *minor, unsigned int *patch)
{
    hg_return_t ret = HG_SUCCESS;

    if (major) *major = HG_VERSION_MAJOR;
    if (minor) *minor = HG_VERSION_MINOR;
    if (patch) *patch = HG_VERSION_PATCH;

    return ret;
}

/*---------------------------------------------------------------------------*/
const char *
HG_Error_to_string(hg_return_t errnum)
{
    const char *hg_error_string = "UNDEFINED/UNRECOGNIZED NA ERROR";

    HG_ERROR_STRING_MACRO(HG_SUCCESS, errnum, hg_error_string);
    HG_ERROR_STRING_MACRO(HG_NA_ERROR, errnum, hg_error_string);
    HG_ERROR_STRING_MACRO(HG_TIMEOUT, errnum, hg_error_string);
    HG_ERROR_STRING_MACRO(HG_INVALID_PARAM, errnum, hg_error_string);
    HG_ERROR_STRING_MACRO(HG_SIZE_ERROR, errnum, hg_error_string);
    HG_ERROR_STRING_MACRO(HG_NOMEM_ERROR, errnum, hg_error_string);
    HG_ERROR_STRING_MACRO(HG_PROTOCOL_ERROR, errnum, hg_error_string);
    HG_ERROR_STRING_MACRO(HG_NO_MATCH, errnum, hg_error_string);
    HG_ERROR_STRING_MACRO(HG_CHECKSUM_ERROR, errnum, hg_error_string);
    HG_ERROR_STRING_MACRO(HG_CANCELED, errnum, hg_error_string);
    HG_ERROR_STRING_MACRO(HG_OTHER_ERROR, errnum, hg_error_string);

    return hg_error_string;
}

/*---------------------------------------------------------------------------*/
hg_class_t *
HG_Init(const char *na_info_string, hg_bool_t na_listen)
{
    return HG_Init_opt(na_info_string, na_listen, NULL);
}

/*---------------------------------------------------------------------------*/
hg_class_t *
HG_Init_opt(const char *na_info_string, hg_bool_t na_listen,
    const struct hg_init_info *hg_init_info)
{
    struct hg_private_class *hg_class = NULL;

    hg_class = malloc(sizeof(struct hg_private_class));
    if (!hg_class) {
        HG_LOG_ERROR("Could not allocate HG class");
        goto done;
    }
    memset(hg_class, 0, sizeof(struct hg_private_class));
    hg_thread_spin_init(&hg_class->register_lock);

    hg_class->hg_class.core_class = HG_Core_init_opt(na_info_string, na_listen,
        hg_init_info);
    if (!hg_class->hg_class.core_class) {
        HG_LOG_ERROR("Could not create HG core class");
        goto done;
    }

    /* Set more data callback */
    HG_Core_set_more_data_callback(hg_class->hg_class.core_class,
        hg_more_data_cb, hg_more_data_free_cb);

done:
    return (hg_class_t *) hg_class;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Finalize(hg_class_t *hg_class)
{
    struct hg_private_class *private_class =
        (struct hg_private_class *) hg_class;
    hg_return_t ret = HG_SUCCESS;

    ret = HG_Core_finalize(private_class->hg_class.core_class);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not finalize HG core class");
        goto done;
    }
    hg_thread_spin_destroy(&private_class->register_lock);
    free(private_class);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
void
HG_Cleanup(void)
{
    HG_Core_cleanup();
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Class_set_handle_create_callback(hg_class_t *hg_class,
    hg_return_t (*callback)(hg_handle_t, void *), void *arg)
{
    struct hg_private_class *private_class =
        (struct hg_private_class *) hg_class;
    hg_return_t ret = HG_SUCCESS;

    if (!hg_class) {
        HG_LOG_ERROR("NULL HG class");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    private_class->handle_create = callback;
    private_class->handle_create_arg = arg;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_context_t *
HG_Context_create(hg_class_t *hg_class)
{
    return HG_Context_create_id(hg_class, 0);
}

/*---------------------------------------------------------------------------*/
hg_context_t *
HG_Context_create_id(hg_class_t *hg_class, hg_uint8_t id)
{
    struct hg_context *hg_context = NULL;
#ifdef HG_POST_LIMIT
    unsigned int request_count =
        (HG_POST_LIMIT > 0) ? HG_POST_LIMIT : HG_POST_LIMIT_DEFAULT;
#else
    unsigned int request_count = HG_POST_LIMIT_DEFAULT;
#endif
    hg_return_t ret = HG_SUCCESS;

    if (!hg_class) {
        HG_LOG_ERROR("NULL HG class");
        goto done;
    }

    hg_context = malloc(sizeof(struct hg_context));
    if (!hg_context) {
        HG_LOG_ERROR("Could not allocate HG context");
        goto done;
    }
    memset(hg_context, 0, sizeof(struct hg_context));
    hg_context->hg_class = hg_class;
    hg_context->core_context = HG_Core_context_create_id(
        hg_class->core_class, id);
    if (!hg_context->core_context) {
        HG_LOG_ERROR("Could not create context for ID %u", id);
        goto done;
    }

    /* Set handle create callback */
    HG_Core_context_set_handle_create_callback(hg_context->core_context,
        hg_handle_create_cb, hg_context);

    /* If we are listening, start posting requests */
    if (HG_Core_class_is_listening(hg_class->core_class)) {
        ret = HG_Core_context_post(hg_context->core_context, request_count,
            HG_TRUE);
        if (ret != HG_SUCCESS) {
            HG_LOG_ERROR("Could not post context requests");
            goto done;
        }
    }

done:
    return hg_context;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Context_destroy(hg_context_t *context)
{
    hg_return_t ret = HG_SUCCESS;

    if (!context) {
        HG_LOG_ERROR("NULL HG context");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    ret = HG_Core_context_destroy(context->core_context);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not destroy HG core context");
        goto done;
    }
    free(context);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_id_t
HG_Register_name(hg_class_t *hg_class, const char *func_name,
    hg_proc_cb_t in_proc_cb, hg_proc_cb_t out_proc_cb, hg_rpc_cb_t rpc_cb)
{
    hg_id_t id = 0;
    hg_return_t ret = HG_SUCCESS;

    if (!hg_class) {
        HG_LOG_ERROR("NULL HG class");
        goto done;
    }
    if (!func_name) {
        HG_LOG_ERROR("NULL string");
        goto done;
    }

    /* Generate an ID from the function name */
    id = hg_hash_string(func_name);

    /* Register RPC */
    ret = HG_Register(hg_class, id, in_proc_cb, out_proc_cb, rpc_cb);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not register RPC id");
        goto done;
    }

done:
    return id;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Registered_name(hg_class_t *hg_class, const char *func_name, hg_id_t *id,
    hg_bool_t *flag)
{
    struct hg_private_class *private_class =
        (struct hg_private_class *) hg_class;
    hg_id_t rpc_id = 0;
    hg_return_t ret = HG_SUCCESS;

    if (!hg_class) {
        HG_LOG_ERROR("NULL HG class");
        ret = HG_INVALID_PARAM;
        goto done;
    }
    if (!func_name) {
        HG_LOG_ERROR("NULL string");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    hg_thread_spin_lock(&private_class->register_lock);

    /* Generate an ID from the function name */
    rpc_id = hg_hash_string(func_name);

    ret = HG_Core_registered(private_class->hg_class.core_class, rpc_id, flag);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not check for registered RPC id");
        hg_thread_spin_unlock(&private_class->register_lock);
        goto done;
    }

    if (id) *id = rpc_id;

    hg_thread_spin_unlock(&private_class->register_lock);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Register(hg_class_t *hg_class, hg_id_t id, hg_proc_cb_t in_proc_cb,
    hg_proc_cb_t out_proc_cb, hg_rpc_cb_t rpc_cb)
{
    struct hg_private_class *private_class =
        (struct hg_private_class *) hg_class;
    struct hg_proc_info *hg_proc_info = NULL;
    hg_bool_t registered;
    hg_return_t ret = HG_SUCCESS;

    if (!hg_class) {
        HG_LOG_ERROR("NULL HG class");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    hg_thread_spin_lock(&private_class->register_lock);

    /* Check if already registered */
    ret = HG_Core_registered(hg_class->core_class, id, &registered);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not check for registered RPC id");
        goto done;
    }

    /* Register RPC (register only RPC callback if already registered) */
    ret = HG_Core_register(hg_class->core_class, id, hg_core_rpc_cb);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not register RPC id");
        goto done;
    }

    if (!registered) {
        hg_proc_info =
            (struct hg_proc_info *) malloc(sizeof(struct hg_proc_info));
        if (!hg_proc_info) {
            HG_LOG_ERROR("Could not allocate proc info");
            ret = HG_NOMEM_ERROR;
            goto done;
        }
        memset(hg_proc_info, 0, sizeof(struct hg_proc_info));

        /* Attach proc info to RPC ID */
        ret = HG_Core_register_data(hg_class->core_class, id, hg_proc_info,
            hg_proc_info_free);
        if (ret != HG_SUCCESS) {
            HG_LOG_ERROR("Could not set proc info");
            goto done;
        }
    } else {
        /* Retrieve proc function from function map */
        hg_proc_info = (struct hg_proc_info *) HG_Core_registered_data(
            hg_class->core_class, id);
        if (!hg_proc_info) {
            HG_LOG_ERROR("Could not get registered data");
            goto done;
        }
    }
    hg_proc_info->rpc_cb = rpc_cb;
    hg_proc_info->in_proc_cb = in_proc_cb;
    hg_proc_info->out_proc_cb = out_proc_cb;

done:
    if (ret != HG_SUCCESS) {
        free(hg_proc_info);
    }
    if (hg_class)
        hg_thread_spin_unlock(&private_class->register_lock);
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Deregister(hg_class_t *hg_class, hg_id_t id)
{
    struct hg_private_class *private_class =
        (struct hg_private_class *) hg_class;
    hg_return_t ret = HG_SUCCESS;

    if (!hg_class) {
        HG_LOG_ERROR("NULL HG class");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    hg_thread_spin_lock(&private_class->register_lock);
    ret = HG_Core_deregister(hg_class->core_class, id);
    hg_thread_spin_unlock(&private_class->register_lock);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Registered(hg_class_t *hg_class, hg_id_t id, hg_bool_t *flag)
{
    struct hg_private_class *private_class =
        (struct hg_private_class *) hg_class;
    hg_return_t ret = HG_SUCCESS;

    if (!hg_class) {
        HG_LOG_ERROR("NULL HG class");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    hg_thread_spin_lock(&private_class->register_lock);
    ret = HG_Core_registered(hg_class->core_class, id, flag);
    hg_thread_spin_unlock(&private_class->register_lock);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Registered_proc_cb(hg_class_t *hg_class, hg_id_t id, hg_bool_t *flag,
    hg_proc_cb_t *in_proc_cb, hg_proc_cb_t *out_proc_cb)
{
    struct hg_private_class *private_class =
        (struct hg_private_class *) hg_class;
    struct hg_proc_info *hg_proc_info = NULL;
    hg_return_t ret = HG_SUCCESS;

    if (!hg_class) {
        HG_LOG_ERROR("NULL HG class");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    hg_thread_spin_lock(&private_class->register_lock);

    ret = HG_Core_registered(hg_class->core_class, id, flag);
    if(ret == HG_SUCCESS && *flag) {
        /* if RPC is registered, retrieve pointers */
        hg_proc_info = (struct hg_proc_info *) HG_Core_registered_data(
            hg_class->core_class, id);
        if (!hg_proc_info) {
            HG_LOG_ERROR("Could not get registered data");
            ret = HG_NO_MATCH;
            hg_thread_spin_unlock(&private_class->register_lock);
            goto done;
        }
        if (in_proc_cb)
            *in_proc_cb = hg_proc_info->in_proc_cb;
        if (out_proc_cb)
            *out_proc_cb = hg_proc_info->out_proc_cb;
    }

    hg_thread_spin_unlock(&private_class->register_lock);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Register_data(hg_class_t *hg_class, hg_id_t id, void *data,
    void (*free_callback)(void *))
{
    struct hg_private_class *private_class =
        (struct hg_private_class *) hg_class;
    struct hg_proc_info *hg_proc_info = NULL;
    hg_return_t ret = HG_SUCCESS;

    if (!hg_class) {
        HG_LOG_ERROR("NULL HG class");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    hg_thread_spin_lock(&private_class->register_lock);

    /* Retrieve proc function from function map */
    hg_proc_info = (struct hg_proc_info *) HG_Core_registered_data(
        hg_class->core_class, id);
    if (!hg_proc_info) {
        HG_LOG_ERROR("Could not get registered data");
        ret = HG_NO_MATCH;
        hg_thread_spin_unlock(&private_class->register_lock);
        goto done;
    }

    hg_proc_info->data = data;
    hg_proc_info->free_callback = free_callback;

    hg_thread_spin_unlock(&private_class->register_lock);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
void *
HG_Registered_data(hg_class_t *hg_class, hg_id_t id)
{
    struct hg_private_class *private_class =
        (struct hg_private_class *) hg_class;
    struct hg_proc_info *hg_proc_info = NULL;
    void *data = NULL;

    if (!hg_class) {
        HG_LOG_ERROR("NULL HG class");
        goto done;
    }

    hg_thread_spin_lock(&private_class->register_lock);

    /* Retrieve proc function from function map */
    hg_proc_info = (struct hg_proc_info *) HG_Core_registered_data(
        hg_class->core_class, id);
    if (!hg_proc_info) {
        HG_LOG_ERROR("Could not get registered data");
        hg_thread_spin_unlock(&private_class->register_lock);
        goto done;
    }

    data = hg_proc_info->data;

    hg_thread_spin_unlock(&private_class->register_lock);

done:
    return data;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Registered_disable_response(hg_class_t *hg_class, hg_id_t id,
    hg_bool_t disable)
{
    struct hg_private_class *private_class =
        (struct hg_private_class *) hg_class;
    struct hg_proc_info *hg_proc_info = NULL;
    hg_return_t ret = HG_SUCCESS;

    if (!hg_class) {
        HG_LOG_ERROR("NULL HG class");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    hg_thread_spin_lock(&private_class->register_lock);

    /* Retrieve proc function from function map */
    hg_proc_info = (struct hg_proc_info *) HG_Core_registered_data(
        hg_class->core_class, id);
    if (!hg_proc_info) {
        HG_LOG_ERROR("Could not get registered data");
        ret = HG_NO_MATCH;
        hg_thread_spin_unlock(&private_class->register_lock);
        goto done;
    }

    hg_proc_info->no_response = disable;

    hg_thread_spin_unlock(&private_class->register_lock);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Registered_disabled_response(hg_class_t *hg_class, hg_id_t id,
    hg_bool_t *disabled)
{
    struct hg_private_class *private_class =
        (struct hg_private_class *) hg_class;
    struct hg_proc_info *hg_proc_info = NULL;
    hg_return_t ret = HG_SUCCESS;

    if (!hg_class) {
        HG_LOG_ERROR("NULL HG class");
        ret = HG_INVALID_PARAM;
        goto done;
    }
    if (!disabled) {
        HG_LOG_ERROR("NULL pointer to disabled flag");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    hg_thread_spin_lock(&private_class->register_lock);

    /* Retrieve proc function from function map */
    hg_proc_info = (struct hg_proc_info *) HG_Core_registered_data(
        hg_class->core_class, id);
    if (!hg_proc_info) {
        HG_LOG_ERROR("Could not get registered data");
        ret = HG_NO_MATCH;
        hg_thread_spin_unlock(&private_class->register_lock);
        goto done;
    }

    *disabled = hg_proc_info->no_response;

    hg_thread_spin_unlock(&private_class->register_lock);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Addr_lookup(hg_context_t *context, hg_cb_t callback, void *arg,
    const char *name, hg_op_id_t *op_id)
{
    struct hg_op_id *hg_op_id = NULL;
    hg_return_t ret = HG_SUCCESS;

    if (!context) {
        HG_LOG_ERROR("NULL HG context");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    /* Allocate op_id */
    hg_op_id = (struct hg_op_id *) malloc(sizeof(struct hg_op_id));
    if (!hg_op_id) {
        HG_LOG_ERROR("Could not allocate HG operation ID");
        ret = HG_NOMEM_ERROR;
        goto done;
    }
    hg_op_id->context = context;
    hg_op_id->type = HG_CB_LOOKUP;
    hg_op_id->callback = callback;
    hg_op_id->arg = arg;
    hg_op_id->info.lookup.hg_addr = HG_ADDR_NULL;

    /* Assign op_id */
    if (op_id && op_id != HG_OP_ID_IGNORE)
        *op_id = (hg_op_id_t) hg_op_id;

    ret = HG_Core_addr_lookup(context->core_context, hg_core_addr_lookup_cb,
        hg_op_id, name, &hg_op_id->info.lookup.core_op_id);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Addr_free(hg_class_t *hg_class, hg_addr_t addr)
{
    hg_return_t ret = HG_SUCCESS;

    if (!hg_class) {
        HG_LOG_ERROR("NULL HG class");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    ret = HG_Core_addr_free(hg_class->core_class, (hg_core_addr_t) addr);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Addr_self(hg_class_t *hg_class, hg_addr_t *addr)
{
    hg_return_t ret = HG_SUCCESS;

    if (!hg_class) {
        HG_LOG_ERROR("NULL HG class");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    ret = HG_Core_addr_self(hg_class->core_class, (hg_core_addr_t *) addr);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Addr_dup(hg_class_t *hg_class, hg_addr_t addr, hg_addr_t *new_addr)
{
    hg_return_t ret = HG_SUCCESS;

    if (!hg_class) {
        HG_LOG_ERROR("NULL HG class");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    ret = HG_Core_addr_dup(hg_class->core_class, (hg_core_addr_t) addr,
        (hg_core_addr_t *) new_addr);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Addr_to_string(hg_class_t *hg_class, char *buf, hg_size_t *buf_size,
    hg_addr_t addr)
{
    hg_return_t ret = HG_SUCCESS;

    if (!hg_class) {
        HG_LOG_ERROR("NULL HG class");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    ret = HG_Core_addr_to_string(hg_class->core_class, buf, buf_size,
        (hg_core_addr_t) addr);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Create(hg_context_t *context, hg_addr_t addr, hg_id_t id,
    hg_handle_t *handle)
{
    struct hg_private_handle *hg_handle = NULL;
    hg_core_handle_t core_handle;
    hg_return_t ret = HG_SUCCESS;

    if (!context) {
        HG_LOG_ERROR("NULL HG context");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    /* Create HG core handle (calls handle_create_cb) */
    ret = HG_Core_create(context->core_context, (hg_core_addr_t) addr, id,
        &core_handle);
    if (ret != HG_SUCCESS) {
        if (ret != HG_NO_MATCH) /* silence error if invalid ID is used */
            HG_LOG_ERROR("Cannot create HG handle with ID %lu", id);
        goto done;
    }

    /* Get data and HG info */
    hg_handle = (struct hg_private_handle *) HG_Core_get_data(core_handle);
    hg_handle->handle.info.addr = addr;
    hg_handle->handle.info.id = id;

    *handle = (hg_handle_t) hg_handle;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Destroy(hg_handle_t handle)
{
    hg_return_t ret = HG_SUCCESS;

    if (!handle) {
        HG_LOG_ERROR("NULL HG handle");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    ret = HG_Core_destroy(handle->core_handle);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Reset(hg_handle_t handle, hg_addr_t addr, hg_id_t id)
{
    struct hg_private_handle *private_handle =
        (struct hg_private_handle *) handle;
    hg_return_t ret = HG_SUCCESS;

    if (!handle) {
        HG_LOG_ERROR("NULL HG handle");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    /* Call core reset */
    ret = HG_Core_reset(handle->core_handle, (hg_core_addr_t) addr, id);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not reset core HG handle");
        goto done;
    }

    /* Set info */
    private_handle->handle.info.addr = addr;
    private_handle->handle.info.id = id;
    private_handle->handle.info.context_id = 0;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Get_input(hg_handle_t handle, void *in_struct)
{
    const struct hg_proc_info *hg_proc_info;
    hg_return_t ret = HG_SUCCESS;

    if (!handle) {
        HG_LOG_ERROR("NULL HG handle");
        ret = HG_INVALID_PARAM;
        goto done;
    }
    if (!in_struct) {
        HG_LOG_ERROR("NULL pointer to input struct");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    /* Retrieve RPC data */
    hg_proc_info = (const struct hg_proc_info *) HG_Core_get_rpc_data(
        handle->core_handle);
    if (!hg_proc_info) {
        HG_LOG_ERROR("Could not get proc info");
        ret = HG_PROTOCOL_ERROR;
        goto done;
    }

    /* Get input struct */
    ret = hg_get_struct((struct hg_private_handle *) handle, hg_proc_info,
        HG_INPUT, in_struct);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not get input");
        goto done;
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Free_input(hg_handle_t handle, void *in_struct)
{
    const struct hg_proc_info *hg_proc_info;
    hg_return_t ret = HG_SUCCESS;

    if (!handle) {
        HG_LOG_ERROR("NULL HG handle");
        ret = HG_INVALID_PARAM;
        goto done;
    }
    if (!in_struct) {
        HG_LOG_ERROR("NULL pointer to input struct");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    /* Retrieve RPC data */
    hg_proc_info = (const struct hg_proc_info *) HG_Core_get_rpc_data(
        handle->core_handle);
    if (!hg_proc_info) {
        HG_LOG_ERROR("Could not get proc info");
        ret = HG_PROTOCOL_ERROR;
        goto done;
    }

    /* Free input struct */
    ret = hg_free_struct((struct hg_private_handle *) handle, hg_proc_info,
        HG_INPUT, in_struct);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not free input");
        goto done;
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Get_output(hg_handle_t handle, void *out_struct)
{
    const struct hg_proc_info *hg_proc_info;
    hg_return_t ret = HG_SUCCESS;

    if (!handle) {
        HG_LOG_ERROR("NULL HG handle");
        ret = HG_INVALID_PARAM;
        goto done;
    }
    if (!out_struct) {
        HG_LOG_ERROR("NULL pointer to output struct");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    /* Retrieve RPC data */
    hg_proc_info = (const struct hg_proc_info *) HG_Core_get_rpc_data(
        handle->core_handle);
    if (!hg_proc_info) {
        HG_LOG_ERROR("Could not get proc info");
        ret = HG_PROTOCOL_ERROR;
        goto done;
    }

    /* Get output struct */
    ret = hg_get_struct((struct hg_private_handle *) handle, hg_proc_info,
        HG_OUTPUT, out_struct);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not get output");
        goto done;
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Free_output(hg_handle_t handle, void *out_struct)
{
    const struct hg_proc_info *hg_proc_info;
    hg_return_t ret = HG_SUCCESS;

    if (!handle) {
        HG_LOG_ERROR("NULL HG handle");
        ret = HG_INVALID_PARAM;
        goto done;
    }
    if (!out_struct) {
        HG_LOG_ERROR("NULL pointer to output struct");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    /* Retrieve RPC data */
    hg_proc_info = (const struct hg_proc_info *) HG_Core_get_rpc_data(
        handle->core_handle);
    if (!hg_proc_info) {
        HG_LOG_ERROR("Could not get proc info");
        ret = HG_PROTOCOL_ERROR;
        goto done;
    }

    /* Free output struct */
    ret = hg_free_struct((struct hg_private_handle *) handle, hg_proc_info,
        HG_OUTPUT, out_struct);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not free output");
        goto done;
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Get_input_buf(hg_handle_t handle, void **in_buf, hg_size_t *in_buf_size)
{
    struct hg_private_handle *private_handle =
        (struct hg_private_handle *) handle;
    hg_return_t ret = HG_SUCCESS;

    if (!handle) {
        HG_LOG_ERROR("NULL HG handle");
        ret = HG_INVALID_PARAM;
        goto done;
    }
    if (!in_buf) {
        HG_LOG_ERROR("NULL pointer");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    /* Space must be left for input header, no offset if extra buffer since
     * only the user payload is copied */
    if (private_handle->in_extra_buf) {
        *in_buf = private_handle->in_extra_buf;
        if (in_buf_size)
            *in_buf_size = private_handle->in_extra_buf_size;
    } else {
        void *buf;
        hg_size_t buf_size, header_offset = hg_header_get_size(HG_INPUT);

        /* Get core input buffer */
        ret = HG_Core_get_input(handle->core_handle, &buf, &buf_size);
        if (ret != HG_SUCCESS) {
            HG_LOG_ERROR("Could not get input buffer");
            goto done;
        }

        *in_buf = (char *) buf + header_offset;
        if (in_buf_size)
            *in_buf_size = buf_size - header_offset;
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Get_output_buf(hg_handle_t handle, void **out_buf, hg_size_t *out_buf_size)
{
    struct hg_private_handle *private_handle =
        (struct hg_private_handle *) handle;
    hg_return_t ret = HG_SUCCESS;

    if (!handle) {
        HG_LOG_ERROR("NULL HG handle");
        ret = HG_INVALID_PARAM;
        goto done;
    }
    if (!out_buf) {
        HG_LOG_ERROR("NULL pointer");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    /* Space must be left for output header, no offset if extra buffer since
     * only the user payload is copied */
    if (private_handle->out_extra_buf) {
        *out_buf = private_handle->out_extra_buf;
        if (out_buf_size)
            *out_buf_size = private_handle->out_extra_buf_size;
    } else {
        void *buf;
        hg_size_t buf_size, header_offset = hg_header_get_size(HG_OUTPUT);

        /* Get core output buffer */
        ret = HG_Core_get_output(handle->core_handle, &buf, &buf_size);
        if (ret != HG_SUCCESS) {
            HG_LOG_ERROR("Could not get output buffer");
            goto done;
        }

        *out_buf = (char *) buf + header_offset;
        if (out_buf_size)
            *out_buf_size = buf_size - header_offset;
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Forward(hg_handle_t handle, hg_cb_t callback, void *arg, void *in_struct)
{
    struct hg_private_handle *private_handle =
        (struct hg_private_handle *) handle;
    const struct hg_proc_info *hg_proc_info;
    hg_size_t payload_size;
    hg_bool_t more_data = HG_FALSE;
    hg_uint8_t flags = 0;
    hg_return_t ret = HG_SUCCESS;

    if (!handle) {
        HG_LOG_ERROR("NULL HG handle");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    /* Set callback data */
    private_handle->forward_cb = callback;
    private_handle->forward_arg = arg;

    /* Retrieve RPC data */
    hg_proc_info = (const struct hg_proc_info *) HG_Core_get_rpc_data(
        handle->core_handle);
    if (!hg_proc_info) {
        HG_LOG_ERROR("Could not get proc info");
        ret = HG_PROTOCOL_ERROR;
        goto done;
    }

    /* Set input struct */
    ret = hg_set_struct(private_handle, hg_proc_info, HG_INPUT, in_struct,
        &payload_size, &more_data);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not set input");
        goto done;
    }

    /* Set more data flag on handle so that handle_more_callback is triggered */
    if (more_data)
        flags |= HG_CORE_MORE_DATA;

    /* Set no response flag if no response required */
    if (hg_proc_info->no_response)
        flags |= HG_CORE_NO_RESPONSE;

    /* Send request */
    ret = HG_Core_forward(handle->core_handle, hg_core_forward_cb, handle,
        flags, payload_size);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not forward call");
        goto done;
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Respond(hg_handle_t handle, hg_cb_t callback, void *arg, void *out_struct)
{
    struct hg_private_handle *private_handle =
        (struct hg_private_handle *) handle;
    const struct hg_proc_info *hg_proc_info;
    hg_size_t payload_size;
    hg_bool_t more_data = HG_FALSE;
    hg_uint8_t flags = 0;
    hg_return_t ret = HG_SUCCESS;

    if (!handle) {
        HG_LOG_ERROR("NULL HG handle");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    /* Set callback data */
    private_handle->respond_cb = callback;
    private_handle->respond_arg = arg;

    /* Retrieve RPC data */
    hg_proc_info = (const struct hg_proc_info *) HG_Core_get_rpc_data(
        handle->core_handle);
    if (!hg_proc_info) {
        HG_LOG_ERROR("Could not get proc info");
        ret = HG_PROTOCOL_ERROR;
        goto done;
    }

    /* Set output struct */
    ret = hg_set_struct(private_handle, hg_proc_info, HG_OUTPUT, out_struct,
        &payload_size, &more_data);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not set output");
        goto done;
    }

    /* Set more data flag on handle so that handle_more_callback is triggered */
    if (more_data)
        flags |= HG_CORE_MORE_DATA;

    /* Send response back */
    ret = HG_Core_respond(handle->core_handle, hg_core_respond_cb, handle,
        flags, payload_size);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not respond");
        goto done;
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Progress(hg_context_t *context, unsigned int timeout)
{
    hg_return_t ret = HG_SUCCESS;

    if (!context) {
        HG_LOG_ERROR("NULL HG context");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    ret = HG_Core_progress(context->core_context, timeout);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Trigger(hg_context_t *context, unsigned int timeout, unsigned int max_count,
    unsigned int *actual_count)
{
    hg_return_t ret = HG_SUCCESS;

    if (!context) {
        HG_LOG_ERROR("NULL HG context");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    ret = HG_Core_trigger(context->core_context, timeout, max_count,
        actual_count);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Cancel(hg_handle_t handle)
{
    hg_return_t ret = HG_SUCCESS;

    if (!handle) {
        HG_LOG_ERROR("NULL HG handle");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    ret = HG_Core_cancel(handle->core_handle);

done:
    return ret;
}
