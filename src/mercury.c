/*
 * Copyright (C) 2013-2020 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#include "mercury.h"
#include "mercury_bulk.h"
#include "mercury_error.h"
#include "mercury_proc.h"
#include "mercury_proc_bulk.h"

#include "mercury_hash_string.h"
#include "mercury_mem.h"
#include "mercury_thread_spin.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

/****************/
/* Local Macros */
/****************/

#define HG_CONTEXT_CLASS(context)                                              \
    ((struct hg_private_class *) ((context)->hg_class))

#define HG_HANDLE_CLASS(handle)                                                \
    ((struct hg_private_class *) ((handle)->info.hg_class))

/* Name of this subsystem */
#define HG_SUBSYS_NAME        hg
#define HG_STRINGIFY(x)       HG_UTIL_STRINGIFY(x)
#define HG_SUBSYS_NAME_STRING HG_STRINGIFY(HG_SUBSYS_NAME)

/************************************/
/* Local Type and Struct Definition */
/************************************/

/* HG class */
struct hg_private_class {
    struct hg_class hg_class; /* Must remain as first field */
    hg_return_t (*handle_create)(hg_handle_t, void *); /* handle_create */
    void *handle_create_arg;                           /* handle_create arg */
    hg_thread_spin_t register_lock;                    /* Register lock */
    hg_bool_t bulk_eager;                              /* Eager bulk proc */
};

/* Info for function map */
struct hg_proc_info {
    hg_rpc_cb_t rpc_cb;            /* RPC callback */
    hg_proc_cb_t in_proc_cb;       /* Input proc callback */
    hg_proc_cb_t out_proc_cb;      /* Output proc callback */
    void *data;                    /* User data */
    void (*free_callback)(void *); /* User data free callback */
    hg_bool_t no_response;         /* RPC response not expected */
};

/* HG handle */
struct hg_private_handle {
    struct hg_handle handle;    /* Must remain as first field */
    struct hg_header hg_header; /* Header for input/output */
    hg_cb_t forward_cb;         /* Forward callback */
    hg_cb_t respond_cb;         /* Respond callback */
    hg_return_t (*extra_bulk_transfer_cb)(
        hg_core_handle_t);        /* Bulk transfer callback */
    void *forward_arg;            /* Forward callback args */
    void *respond_arg;            /* Respond callback args */
    void *in_extra_buf;           /* Extra input buffer */
    void *out_extra_buf;          /* Extra output buffer */
    hg_proc_t in_proc;            /* Proc for input */
    hg_proc_t out_proc;           /* Proc for output */
    hg_bulk_t in_extra_bulk;      /* Extra input bulk handle */
    hg_bulk_t out_extra_bulk;     /* Extra output bulk handle */
    hg_size_t in_extra_buf_size;  /* Extra input buffer size */
    hg_size_t out_extra_buf_size; /* Extra output buffer size */
};

/* HG op id */
struct hg_op_info_lookup {
    struct hg_addr *hg_addr; /* Address */
};

struct hg_op_id {
    union {
        struct hg_op_info_lookup lookup;
    } info;
    struct hg_context *context; /* Context */
    hg_cb_t callback;           /* Callback */
    void *arg;                  /* Callback arguments */
    hg_cb_type_t type;          /* Callback type */
};

/********************/
/* Local Prototypes */
/********************/

/**
 * Free function for value in function map.
 */
static void
hg_proc_info_free(void *arg);

/**
 * Alloc function for private data.
 */
static struct hg_private_handle *
hg_handle_create(struct hg_private_class *hg_class);

/**
 * Free function for private data.
 */
static void
hg_handle_free(void *arg);

/**
 * Create handle callback.
 */
static hg_return_t
hg_handle_create_cb(hg_core_handle_t core_handle, void *arg);

/**
 * More data callback.
 */
static hg_return_t
hg_more_data_cb(hg_core_handle_t core_handle, hg_op_t op,
    hg_return_t (*done_cb)(hg_core_handle_t));

/**
 * More data free callback.
 */
static void
hg_more_data_free_cb(hg_core_handle_t core_handle);

/**
 * Core RPC callback.
 */
static hg_return_t
hg_core_rpc_cb(hg_core_handle_t core_handle);

/**
 * Core lookup callback.
 */
static HG_INLINE hg_return_t
hg_core_addr_lookup_cb(const struct hg_core_cb_info *callback_info);

/**
 * Decode and get input/output structure.
 */
static hg_return_t
hg_get_struct(struct hg_private_handle *hg_handle,
    const struct hg_proc_info *hg_proc_info, hg_op_t op, void *struct_ptr);

/**
 * Set and encode input/output structure.
 */
static hg_return_t
hg_set_struct(struct hg_private_handle *hg_handle,
    const struct hg_proc_info *hg_proc_info, hg_op_t op, void *struct_ptr,
    hg_size_t *payload_size, hg_bool_t *more_data);

/**
 * Free allocated members from input/output structure.
 */
static hg_return_t
hg_free_struct(struct hg_private_handle *hg_handle,
    const struct hg_proc_info *hg_proc_info, hg_op_t op, void *struct_ptr);

/**
 * Get extra user payload using bulk transfer.
 */
static hg_return_t
hg_get_extra_payload(struct hg_private_handle *hg_handle, hg_op_t op,
    hg_return_t (*done_cb)(hg_core_handle_t));

/**
 * Get extra payload bulk transfer callback.
 */
static HG_INLINE hg_return_t
hg_get_extra_payload_cb(const struct hg_cb_info *callback_info);

/**
 * Free allocated extra payload.
 */
static void
hg_free_extra_payload(struct hg_private_handle *hg_handle);

/**
 * Forward callback.
 */
static HG_INLINE hg_return_t
hg_core_forward_cb(const struct hg_core_cb_info *callback_info);

/**
 * Respond callback.
 */
static HG_INLINE hg_return_t
hg_core_respond_cb(const struct hg_core_cb_info *callback_info);

/*******************/
/* Local Variables */
/*******************/

/* Return code string table */
#define X(a) #a,
static const char *const hg_return_name[] = {HG_RETURN_VALUES};
#undef X

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
    hg_handle =
        (struct hg_private_handle *) malloc(sizeof(struct hg_private_handle));
    HG_CHECK_ERROR_NORET(
        hg_handle == NULL, error, "Could not allocate handle private data");

    memset(hg_handle, 0, sizeof(struct hg_private_handle));
    hg_handle->handle.info.hg_class = (hg_class_t *) hg_class;
    hg_header_init(&hg_handle->hg_header, HG_UNDEF);

    /* CRC32 is enough for small size buffers */
    ret =
        hg_proc_create((hg_class_t *) hg_class, HG_CRC32, &hg_handle->in_proc);
    HG_CHECK_HG_ERROR(error, ret, "Cannot create HG proc");

    ret =
        hg_proc_create((hg_class_t *) hg_class, HG_CRC32, &hg_handle->out_proc);
    HG_CHECK_HG_ERROR(error, ret, "Cannot create HG proc");

    return hg_handle;

error:
    hg_handle_free(hg_handle);
    return NULL;
}

/*---------------------------------------------------------------------------*/
static void
hg_handle_free(void *arg)
{
    struct hg_private_handle *hg_handle = (struct hg_private_handle *) arg;

    if (!hg_handle)
        return;

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
    HG_CHECK_ERROR(
        hg_handle == NULL, error, ret, HG_NOMEM, "Could not create HG handle");

    hg_handle->handle.core_handle = core_handle;
    hg_handle->handle.info.context = hg_context;

    HG_Core_set_data(core_handle, hg_handle, hg_handle_free);

    /* Call handle create if defined */
    if (HG_CONTEXT_CLASS(hg_context)->handle_create) {
        ret = HG_CONTEXT_CLASS(hg_context)
                  ->handle_create((hg_handle_t) hg_handle,
                      HG_CONTEXT_CLASS(hg_context)->handle_create_arg);
        HG_CHECK_HG_ERROR(error, ret, "Error in handle create callback");
    }

    return ret;

error:
    hg_handle_free(hg_handle);
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_more_data_cb(hg_core_handle_t core_handle, hg_op_t op,
    hg_return_t (*done_cb)(hg_core_handle_t))
{
    struct hg_private_handle *hg_handle;
    void *extra_buf;
    hg_return_t ret;

    /* Retrieve private data */
    hg_handle = (struct hg_private_handle *) HG_Core_get_data(core_handle);
    HG_CHECK_ERROR(
        hg_handle == NULL, error, ret, HG_FAULT, "Could not get private data");

    switch (op) {
        case HG_INPUT:
            extra_buf = hg_handle->in_extra_buf;
            break;
        case HG_OUTPUT:
            extra_buf = hg_handle->out_extra_buf;
            break;
        default:
            HG_GOTO_ERROR(error, ret, HG_INVALID_ARG, "Invalid HG op");
    }

    if (extra_buf) {
        /* We were forwarding to ourself and the extra buf is already set */
        ret = done_cb(core_handle);
        HG_CHECK_HG_ERROR(
            error, ret, "Could not execute more data done callback");
    } else {
        /* We need to do a bulk transfer to get the extra data */
        ret = hg_get_extra_payload(hg_handle, op, done_cb);
        HG_CHECK_HG_ERROR(error, ret, "Could not get extra payload");
    }

    return HG_SUCCESS;

error:
    return ret;
}

/*---------------------------------------------------------------------------*/
static void
hg_more_data_free_cb(hg_core_handle_t core_handle)
{
    struct hg_private_handle *hg_handle;

    /* Retrieve private data */
    hg_handle = (struct hg_private_handle *) HG_Core_get_data(core_handle);
    if (!hg_handle)
        return;

    hg_free_extra_payload(hg_handle);
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_rpc_cb(hg_core_handle_t core_handle)
{
    const struct hg_core_info *hg_core_info;
    struct hg_private_handle *hg_handle;
    const struct hg_proc_info *hg_proc_info;
    hg_return_t ret;

    hg_core_info = HG_Core_get_info(core_handle);
    HG_CHECK_ERROR(hg_core_info == NULL, error, ret, HG_INVALID_ARG, "No info");

    hg_handle = (struct hg_private_handle *) HG_Core_get_data(core_handle);
    HG_CHECK_ERROR(
        hg_handle == NULL, error, ret, HG_INVALID_ARG, "NULL handle");

    hg_handle->handle.info.addr = (hg_addr_t) hg_core_info->addr;
    hg_handle->handle.info.context_id = hg_core_info->context_id;
    hg_handle->handle.info.id = hg_core_info->id;

    hg_proc_info =
        (const struct hg_proc_info *) HG_Core_get_rpc_data(core_handle);
    HG_CHECK_ERROR(
        hg_proc_info == NULL, error, ret, HG_INVALID_ARG, "No proc info");
    HG_CHECK_ERROR(hg_proc_info->rpc_cb == NULL, error, ret, HG_INVALID_ARG,
        "No RPC callback registered");

    ret = hg_proc_info->rpc_cb((hg_handle_t) hg_handle);

    return HG_SUCCESS;

error:
    /* Need to decrement refcount on handle */
    HG_Core_destroy(core_handle);

    return ret;
}

/*---------------------------------------------------------------------------*/
static HG_INLINE hg_return_t
hg_core_addr_lookup_cb(const struct hg_core_cb_info *callback_info)
{
    struct hg_op_id *hg_op_id = (struct hg_op_id *) callback_info->arg;
    struct hg_cb_info hg_cb_info = {.arg = hg_op_id->arg,
        .ret = callback_info->ret,
        .type = hg_op_id->type,
        .info.lookup.addr = (hg_addr_t) callback_info->info.lookup.addr};

    if (hg_op_id->callback)
        hg_op_id->callback(&hg_cb_info);

    /* NB. OK to free after callback execution, op ID is not re-used */
    free(hg_op_id);

    return HG_SUCCESS;
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
            ret = HG_Core_get_input(
                hg_handle->handle.core_handle, &buf, &buf_size);
            HG_CHECK_HG_ERROR(done, ret, "Could not get input buffer");

            extra_buf = hg_handle->in_extra_buf;
            extra_buf_size = hg_handle->in_extra_buf_size;
            break;
        case HG_OUTPUT:
            /* Cannot respond if no_response flag set */
            HG_CHECK_ERROR(hg_proc_info->no_response, done, ret,
                HG_OPNOTSUPPORTED,
                "No output was produced on that RPC (no response)");

            /* Use custom header offset */
            header_offset += hg_handle->handle.info.hg_class->out_offset;
            /* Set output proc */
            proc = hg_handle->out_proc;
            proc_cb = hg_proc_info->out_proc_cb;
#ifdef HG_HAS_CHECKSUMS
            hg_header_hash = &hg_header->msg.output.hash;
#endif
            /* Get core output buffer */
            ret = HG_Core_get_output(
                hg_handle->handle.core_handle, &buf, &buf_size);
            HG_CHECK_HG_ERROR(done, ret, "Could not get output buffer");

            extra_buf = hg_handle->out_extra_buf;
            extra_buf_size = hg_handle->out_extra_buf_size;
            break;
        default:
            HG_GOTO_ERROR(done, ret, HG_INVALID_ARG, "Invalid HG op");
    }
    HG_CHECK_ERROR(proc_cb == NULL, done, ret, HG_FAULT,
        "No proc set, proc must be set in HG_Register()");

    /* Reset header */
    hg_header_reset(hg_header, op);

    /* Get header */
    ret = hg_header_proc(HG_DECODE, buf, buf_size, hg_header);
    HG_CHECK_HG_ERROR(done, ret, "Could not process header");

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
    HG_CHECK_HG_ERROR(done, ret, "Could not reset proc");

    /* Decode parameters */
    ret = proc_cb(proc, struct_ptr);
    HG_CHECK_HG_ERROR(done, ret, "Could not decode parameters");

    /* Flush proc */
    ret = hg_proc_flush(proc);
    HG_CHECK_HG_ERROR(done, ret, "Error in proc flush");

#ifdef HG_HAS_CHECKSUMS
    /* Compare checksum with header hash */
    ret = hg_proc_checksum_verify(
        proc, &hg_header_hash->payload, sizeof(hg_header_hash->payload));
    HG_CHECK_HG_ERROR(done, ret, "Error in proc checksum verify");
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
    hg_uint8_t proc_flags = 0;
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
            ret = HG_Core_get_input(
                hg_handle->handle.core_handle, &buf, &buf_size);
            HG_CHECK_HG_ERROR(done, ret, "Could not get input buffer");

            extra_buf = &hg_handle->in_extra_buf;
            extra_buf_size = &hg_handle->in_extra_buf_size;
            extra_bulk = &hg_handle->in_extra_bulk;
            break;
        case HG_OUTPUT:
            /* Cannot respond if no_response flag set */
            HG_CHECK_ERROR(hg_proc_info->no_response, done, ret,
                HG_OPNOTSUPPORTED,
                "No output was produced on that RPC (no response)");

            /* Use custom header offset */
            header_offset += hg_handle->handle.info.hg_class->out_offset;
            /* Set output proc */
            proc = hg_handle->out_proc;
            proc_cb = hg_proc_info->out_proc_cb;
#ifdef HG_HAS_CHECKSUMS
            hg_header_hash = &hg_header->msg.output.hash;
#endif
            /* Get core output buffer */
            ret = HG_Core_get_output(
                hg_handle->handle.core_handle, &buf, &buf_size);
            HG_CHECK_HG_ERROR(done, ret, "Could not get output buffer");

            extra_buf = &hg_handle->out_extra_buf;
            extra_buf_size = &hg_handle->out_extra_buf_size;
            extra_bulk = &hg_handle->out_extra_bulk;
            break;
        default:
            HG_GOTO_ERROR(done, ret, HG_INVALID_ARG, "Invalid HG op");
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
    HG_CHECK_HG_ERROR(done, ret, "Could not reset proc");

#ifdef NA_HAS_SM
    /* Determine if we need special handling for SM */
    if (HG_Core_addr_get_na_sm(hg_handle->handle.core_handle->info.addr) !=
        NA_ADDR_NULL)
        proc_flags |= HG_PROC_SM;
#endif

    /* Attempt to use eager bulk transfers when appropriate */
    if (HG_HANDLE_CLASS(&hg_handle->handle)->bulk_eager &&
        !HG_Core_addr_is_self(hg_handle->handle.core_handle->info.addr))
        proc_flags |= HG_PROC_BULK_EAGER;

    hg_proc_set_flags(proc, proc_flags);

    /* Encode parameters */
    ret = proc_cb(proc, struct_ptr);
    HG_CHECK_HG_ERROR(done, ret, "Could not encode parameters");

    /* Flush proc */
    ret = hg_proc_flush(proc);
    HG_CHECK_HG_ERROR(done, ret, "Error in proc flush");

#ifdef HG_HAS_CHECKSUMS
    /* Set checksum in header */
    ret = hg_proc_checksum_get(
        proc, &hg_header_hash->payload, sizeof(hg_header_hash->payload));
    HG_CHECK_HG_ERROR(done, ret, "Error in getting proc checksum");
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
        HG_GOTO_ERROR(done, ret, HG_OVERFLOW,
            "Arguments overflow is not supported with XDR");
#endif
        /* Create a bulk descriptor only of the size that is used */
        *extra_buf = hg_proc_get_extra_buf(proc);
        *extra_buf_size = hg_proc_get_size_used(proc);

        /* Prevent buffer from being freed when proc_reset is called */
        hg_proc_set_extra_buf_is_mine(proc, HG_TRUE);

        /* Create bulk descriptor */
        ret = HG_Bulk_create(hg_handle->handle.info.hg_class, 1, extra_buf,
            extra_buf_size, HG_BULK_READ_ONLY, extra_bulk);
        HG_CHECK_HG_ERROR(done, ret, "Could not create bulk data handle");

        /* Reset proc */
        ret = hg_proc_reset(proc, buf, buf_size, HG_ENCODE);
        HG_CHECK_HG_ERROR(done, ret, "Could not reset proc");

        /* Reset proc flags */
        proc_flags = 0;

#ifdef NA_HAS_SM
        /* Determine if we need special handling for SM */
        if (HG_Core_addr_get_na_sm(hg_handle->handle.core_handle->info.addr) !=
            NA_ADDR_NULL)
            proc_flags |= HG_PROC_SM;
#endif

        /* Attempt to use eager bulk transfers when appropriate */
        if (HG_HANDLE_CLASS(&hg_handle->handle)->bulk_eager &&
            !HG_Core_addr_is_self(hg_handle->handle.core_handle->info.addr))
            proc_flags |= HG_PROC_BULK_EAGER;

        hg_proc_set_flags(proc, proc_flags);

        /* Encode extra_bulk_handle, we can do that safely here because
         * the user payload has been copied so we don't have to worry
         * about overwriting the user's data */
        ret = hg_proc_hg_bulk_t(proc, extra_bulk);
        HG_CHECK_HG_ERROR(done, ret, "Could not process extra bulk handle");

        ret = hg_proc_flush(proc);
        HG_CHECK_HG_ERROR(done, ret, "Error in proc flush");

        HG_CHECK_ERROR(hg_proc_get_extra_buf(proc), done, ret, HG_OVERFLOW,
            "Extra bulk handle could not fit into buffer");

        *more_data = HG_TRUE;
    }

    /* Encode header */
    buf = (char *) buf - header_offset;
    buf_size += header_offset;
    ret = hg_header_proc(HG_ENCODE, buf, buf_size, hg_header);
    HG_CHECK_HG_ERROR(done, ret, "Could not process header");

#ifdef HG_HAS_XDR
    /* XDR requires entire buffer payload */
    *payload_size = buf_size;
#else
    /* Only send the actual size of the data, not the entire buffer */
    *payload_size = hg_proc_get_size_used(proc) + header_offset;
#endif

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_free_struct(struct hg_private_handle *hg_handle,
    const struct hg_proc_info *hg_proc_info, hg_op_t op, void *struct_ptr)
{
    void *buf = NULL;
    hg_size_t buf_size = 0;
#ifdef HG_HAS_XDR
    hg_size_t header_offset = hg_header_get_size(op);
#endif
    hg_proc_t proc = HG_PROC_NULL;
    hg_proc_cb_t proc_cb = NULL;
    hg_return_t ret = HG_SUCCESS;

    switch (op) {
        case HG_INPUT:
            /* Set input proc */
            proc = hg_handle->in_proc;
            proc_cb = hg_proc_info->in_proc_cb;
#ifdef HG_HAS_XDR
            /* Get core input buffer */
            ret = HG_Core_get_input(
                hg_handle->handle.core_handle, &buf, &buf_size);
            HG_CHECK_HG_ERROR(done, ret, "Could not get input buffer");
#endif
            break;
        case HG_OUTPUT:
            /* Set output proc */
            proc = hg_handle->out_proc;
            proc_cb = hg_proc_info->out_proc_cb;
#ifdef HG_HAS_XDR
            /* Get core output buffer */
            ret = HG_Core_get_output(
                hg_handle->handle.core_handle, &buf, &buf_size);
            HG_CHECK_HG_ERROR(done, ret, "Could not get input buffer");
#endif
            break;
        default:
            HG_GOTO_ERROR(done, ret, HG_INVALID_ARG, "Invalid HG op");
    }
    HG_CHECK_ERROR(proc_cb == NULL, done, ret, HG_FAULT,
        "No proc set, proc must be set in HG_Register()");

#ifdef HG_HAS_XDR
    /* Include our own header offset */
    buf = (char *) buf + header_offset;
    buf_size -= header_offset;
#endif

    /* Reset proc */
    ret = hg_proc_reset(proc, buf, buf_size, HG_FREE);
    HG_CHECK_HG_ERROR(done, ret, "Could not reset proc");

    /* Free memory allocated during decode operation */
    ret = proc_cb(proc, struct_ptr);
    HG_CHECK_HG_ERROR(done, ret, "Could not free allocated parameters");

    /* Decrement ref count or free */
    ret = HG_Core_destroy(hg_handle->handle.core_handle);
    HG_CHECK_HG_ERROR(done, ret, "Could not decrement handle ref count");

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_get_extra_payload(struct hg_private_handle *hg_handle, hg_op_t op,
    hg_return_t (*done_cb)(hg_core_handle_t core_handle))
{
    const struct hg_core_info *hg_core_info =
        HG_Core_get_info(hg_handle->handle.core_handle);
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
            ret = HG_Core_get_input(
                hg_handle->handle.core_handle, &buf, &buf_size);
            HG_CHECK_HG_ERROR(done, ret, "Could not get input buffer");

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
            ret = HG_Core_get_output(
                hg_handle->handle.core_handle, &buf, &buf_size);
            HG_CHECK_HG_ERROR(done, ret, "Could not get output buffer");

            extra_buf = &hg_handle->out_extra_buf;
            extra_buf_size = &hg_handle->out_extra_buf_size;
            extra_bulk = &hg_handle->out_extra_bulk;
            break;
        default:
            HG_GOTO_ERROR(done, ret, HG_INVALID_ARG, "Invalid HG op");
    }

    /* Include our own header offset */
    buf = (char *) buf + header_offset;
    buf_size -= header_offset;

    ret = hg_proc_reset(proc, buf, buf_size, HG_DECODE);
    HG_CHECK_HG_ERROR(done, ret, "Could not reset proc");

    /* Decode extra bulk handle */
    ret = hg_proc_hg_bulk_t(proc, extra_bulk);
    HG_CHECK_HG_ERROR(done, ret, "Could not process extra bulk handle");

    ret = hg_proc_flush(proc);
    HG_CHECK_HG_ERROR(done, ret, "Error in proc flush");

    /* Create a new local handle to read the data */
    *extra_buf_size = HG_Bulk_get_size(*extra_bulk);
    *extra_buf = hg_mem_aligned_alloc(page_size, *extra_buf_size);
    HG_CHECK_ERROR(*extra_buf == NULL, done, ret, HG_NOMEM,
        "Could not allocate extra payload buffer");

    ret = HG_Bulk_create(hg_handle->handle.info.hg_class, 1, extra_buf,
        extra_buf_size, HG_BULK_READWRITE, &local_handle);
    HG_CHECK_HG_ERROR(done, ret, "Could not create HG bulk handle");

    /* Read bulk data here and wait for the data to be here  */
    hg_handle->extra_bulk_transfer_cb = done_cb;
    ret = HG_Bulk_transfer_id(hg_handle->handle.info.context,
        hg_get_extra_payload_cb, hg_handle, HG_BULK_PULL,
        (hg_addr_t) hg_core_info->addr, hg_core_info->context_id, *extra_bulk,
        0, local_handle, 0, *extra_buf_size,
        HG_OP_ID_IGNORE /* TODO not used for now */);
    HG_CHECK_HG_ERROR(done, ret, "Could not transfer bulk data");

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
    hg_return_t ret =
        hg_handle->extra_bulk_transfer_cb(hg_handle->handle.core_handle);
    HG_CHECK_HG_ERROR(done, ret, "Could not execute bulk transfer callback");

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

    /* Execute callback */
    if (hg_handle->forward_cb) {
        struct hg_cb_info hg_cb_info = {.arg = hg_handle->forward_arg,
            .ret = callback_info->ret,
            .type = callback_info->type,
            .info.forward.handle = (hg_handle_t) hg_handle};
        hg_handle->forward_cb(&hg_cb_info);
    }

    return HG_SUCCESS;
}

/*---------------------------------------------------------------------------*/
static HG_INLINE hg_return_t
hg_core_respond_cb(const struct hg_core_cb_info *callback_info)
{
    struct hg_private_handle *hg_handle =
        (struct hg_private_handle *) callback_info->arg;

    /* Execute callback */
    if (hg_handle->respond_cb) {
        struct hg_cb_info hg_cb_info = {.arg = hg_handle->respond_arg,
            .ret = callback_info->ret,
            .type = callback_info->type,
            .info.respond.handle = (hg_handle_t) hg_handle};
        hg_handle->respond_cb(&hg_cb_info);
    }

    return HG_SUCCESS;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Version_get(unsigned int *major, unsigned int *minor, unsigned int *patch)
{
    if (major)
        *major = HG_VERSION_MAJOR;
    if (minor)
        *minor = HG_VERSION_MINOR;
    if (patch)
        *patch = HG_VERSION_PATCH;

    return HG_SUCCESS;
}

/*---------------------------------------------------------------------------*/
const char *
HG_Error_to_string(hg_return_t errnum)
{
    return hg_return_name[errnum];
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

    /* Make sure error return codes match */
    assert(HG_CANCELED == (hg_return_t) NA_CANCELED);

    hg_class = malloc(sizeof(struct hg_private_class));
    HG_CHECK_ERROR_NORET(
        hg_class == NULL, error, "Could not allocate HG class");

    memset(hg_class, 0, sizeof(struct hg_private_class));
    hg_thread_spin_init(&hg_class->register_lock);

    /* Save bulk eager information */
    hg_class->bulk_eager =
        (hg_init_info) ? !hg_init_info->no_bulk_eager : HG_TRUE;

    hg_class->hg_class.core_class =
        HG_Core_init_opt(na_info_string, na_listen, hg_init_info);
    HG_CHECK_ERROR_NORET(hg_class->hg_class.core_class == NULL, error,
        "Could not create HG core class");

    /* Set more data callback */
    HG_Core_set_more_data_callback(
        hg_class->hg_class.core_class, hg_more_data_cb, hg_more_data_free_cb);

    return (hg_class_t *) hg_class;

error:
    if (hg_class) {
        hg_thread_spin_destroy(&hg_class->register_lock);
        free(hg_class);
    }
    return NULL;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Finalize(hg_class_t *hg_class)
{
    struct hg_private_class *private_class =
        (struct hg_private_class *) hg_class;
    hg_return_t ret = HG_SUCCESS;

    ret = HG_Core_finalize(private_class->hg_class.core_class);
    HG_CHECK_HG_ERROR(done, ret, "Could not finalize HG core class");

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
void
HG_Set_log_level(const char *level)
{
    hg_log_set_subsys_level(HG_SUBSYS_NAME_STRING, hg_log_name_to_level(level));
}

/*---------------------------------------------------------------------------*/
void
HG_Set_log_subsys(const char *subsys)
{
    hg_log_set_subsys(subsys);
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Class_set_handle_create_callback(hg_class_t *hg_class,
    hg_return_t (*callback)(hg_handle_t, void *), void *arg)
{
    struct hg_private_class *private_class =
        (struct hg_private_class *) hg_class;
    hg_return_t ret = HG_SUCCESS;

    HG_CHECK_ERROR(
        hg_class == NULL, done, ret, HG_INVALID_ARG, "NULL HG class");

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

    HG_CHECK_ERROR_NORET(hg_class == NULL, error, "NULL HG class");

    hg_context = malloc(sizeof(struct hg_context));
    HG_CHECK_ERROR_NORET(
        hg_context == NULL, error, "Could not allocate HG context");

    memset(hg_context, 0, sizeof(struct hg_context));
    hg_context->hg_class = hg_class;
    hg_context->core_context =
        HG_Core_context_create_id(hg_class->core_class, id);
    HG_CHECK_ERROR_NORET(hg_context->core_context == NULL, error,
        "Could not create context for ID %u", id);

    /* Set handle create callback */
    HG_Core_context_set_handle_create_callback(
        hg_context->core_context, hg_handle_create_cb, hg_context);

    /* If we are listening, start posting requests */
    if (HG_Core_class_is_listening(hg_class->core_class)) {
        hg_return_t ret = HG_Core_context_post(hg_context->core_context);
        HG_CHECK_HG_ERROR(error, ret, "Could not post context requests (%s)",
            HG_Error_to_string(ret));
    }

    return hg_context;

error:
    if (hg_context) {
        if (hg_context->core_context) {
            hg_return_t ret = HG_Core_context_destroy(hg_context->core_context);
            HG_CHECK_ERROR_DONE(
                ret != HG_SUCCESS, "Could not destroy HG core context");
        }
        free(hg_context);
    }
    return NULL;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Context_destroy(hg_context_t *context)
{
    hg_return_t ret = HG_SUCCESS;

    HG_CHECK_ERROR(
        context == NULL, done, ret, HG_INVALID_ARG, "NULL HG context");

    ret = HG_Core_context_destroy(context->core_context);
    HG_CHECK_HG_ERROR(done, ret, "Could not destroy HG core context (%s)",
        HG_Error_to_string(ret));

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
    hg_return_t ret;

    HG_CHECK_ERROR_NORET(hg_class == NULL, done, "NULL HG class");
    HG_CHECK_ERROR_NORET(func_name == NULL, done, "NULL string");

    /* Generate an ID from the function name */
    id = hg_hash_string(func_name);

    /* Register RPC */
    ret = HG_Register(hg_class, id, in_proc_cb, out_proc_cb, rpc_cb);
    HG_CHECK_HG_ERROR(
        done, ret, "Could not register RPC ID (%s)", HG_Error_to_string(ret));

done:
    return id;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Registered_name(
    hg_class_t *hg_class, const char *func_name, hg_id_t *id, hg_bool_t *flag)
{
    struct hg_private_class *private_class =
        (struct hg_private_class *) hg_class;
    hg_id_t rpc_id = 0;
    hg_return_t ret = HG_SUCCESS;

    HG_CHECK_ERROR(
        hg_class == NULL, done, ret, HG_INVALID_ARG, "NULL HG class");
    HG_CHECK_ERROR(func_name == NULL, done, ret, HG_INVALID_ARG, "NULL string");

    /* Generate an ID from the function name */
    rpc_id = hg_hash_string(func_name);

    hg_thread_spin_lock(&private_class->register_lock);

    ret = HG_Core_registered(private_class->hg_class.core_class, rpc_id, flag);
    HG_CHECK_HG_ERROR(unlock, ret, "Could not check for registered RPC ID (%s)",
        HG_Error_to_string(ret));

    if (id)
        *id = rpc_id;

unlock:
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
    hg_bool_t registered = HG_FALSE;
    hg_return_t ret = HG_SUCCESS;

    HG_CHECK_ERROR(
        hg_class == NULL, done, ret, HG_INVALID_ARG, "NULL HG class");

    hg_thread_spin_lock(&private_class->register_lock);

    /* Check if already registered */
    ret = HG_Core_registered(hg_class->core_class, id, &registered);
    HG_CHECK_HG_ERROR(error, ret, "Could not check for registered RPC ID (%s)",
        HG_Error_to_string(ret));

    /* Register RPC (register only RPC callback if already registered) */
    ret = HG_Core_register(hg_class->core_class, id, hg_core_rpc_cb);
    HG_CHECK_HG_ERROR(
        error, ret, "Could not register RPC ID (%s)", HG_Error_to_string(ret));

    if (!registered) {
        hg_proc_info =
            (struct hg_proc_info *) malloc(sizeof(struct hg_proc_info));
        HG_CHECK_ERROR(hg_proc_info == NULL, error, ret, HG_NOMEM,
            "Could not allocate proc info");
        memset(hg_proc_info, 0, sizeof(struct hg_proc_info));

        /* Attach proc info to RPC ID */
        ret = HG_Core_register_data(
            hg_class->core_class, id, hg_proc_info, hg_proc_info_free);
        HG_CHECK_HG_ERROR(error, ret, "Could not set proc info (%s)",
            HG_Error_to_string(ret));
        registered = HG_TRUE;
    } else {
        /* Retrieve proc function from function map */
        hg_proc_info = (struct hg_proc_info *) HG_Core_registered_data(
            hg_class->core_class, id);
        HG_CHECK_ERROR(hg_proc_info == NULL, error, ret, HG_FAULT,
            "Could not get registered data");
    }
    hg_proc_info->rpc_cb = rpc_cb;
    hg_proc_info->in_proc_cb = in_proc_cb;
    hg_proc_info->out_proc_cb = out_proc_cb;

    hg_thread_spin_unlock(&private_class->register_lock);

done:
    return ret;

error:
    if (registered)
        HG_Core_deregister(hg_class->core_class, id);
    else
        free(hg_proc_info);
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

    HG_CHECK_ERROR(
        hg_class == NULL, done, ret, HG_INVALID_ARG, "NULL HG class");

    hg_thread_spin_lock(&private_class->register_lock);
    ret = HG_Core_deregister(hg_class->core_class, id);
    hg_thread_spin_unlock(&private_class->register_lock);
    HG_CHECK_HG_ERROR(
        done, ret, "Could not deregister RPC ID (%s)", HG_Error_to_string(ret));

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

    HG_CHECK_ERROR(
        hg_class == NULL, done, ret, HG_INVALID_ARG, "NULL HG class");

    hg_thread_spin_lock(&private_class->register_lock);
    ret = HG_Core_registered(hg_class->core_class, id, flag);
    hg_thread_spin_unlock(&private_class->register_lock);
    HG_CHECK_HG_ERROR(done, ret, "Could not check for registered RPC ID (%s)",
        HG_Error_to_string(ret));

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

    HG_CHECK_ERROR(
        hg_class == NULL, done, ret, HG_INVALID_ARG, "NULL HG class");

    hg_thread_spin_lock(&private_class->register_lock);

    ret = HG_Core_registered(hg_class->core_class, id, flag);
    HG_CHECK_HG_ERROR(unlock, ret, "Could not check for registered RPC ID (%s)",
        HG_Error_to_string(ret));

    if (*flag) {
        /* if RPC is registered, retrieve pointers */
        hg_proc_info = (struct hg_proc_info *) HG_Core_registered_data(
            hg_class->core_class, id);
        HG_CHECK_ERROR(hg_proc_info == NULL, unlock, ret, HG_FAULT,
            "Could not get registered data");

        if (in_proc_cb)
            *in_proc_cb = hg_proc_info->in_proc_cb;
        if (out_proc_cb)
            *out_proc_cb = hg_proc_info->out_proc_cb;
    }

unlock:
    hg_thread_spin_unlock(&private_class->register_lock);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Register_data(
    hg_class_t *hg_class, hg_id_t id, void *data, void (*free_callback)(void *))
{
    struct hg_private_class *private_class =
        (struct hg_private_class *) hg_class;
    struct hg_proc_info *hg_proc_info = NULL;
    hg_return_t ret = HG_SUCCESS;

    HG_CHECK_ERROR(
        hg_class == NULL, done, ret, HG_INVALID_ARG, "NULL HG class");

    hg_thread_spin_lock(&private_class->register_lock);

    /* Retrieve proc function from function map */
    hg_proc_info = (struct hg_proc_info *) HG_Core_registered_data(
        hg_class->core_class, id);
    HG_CHECK_ERROR(hg_proc_info == NULL, unlock, ret, HG_NOENTRY,
        "Could not get registered data");

    hg_proc_info->data = data;
    hg_proc_info->free_callback = free_callback;

unlock:
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

    HG_CHECK_ERROR_NORET(hg_class == NULL, done, "NULL HG class");

    hg_thread_spin_lock(&private_class->register_lock);

    /* Retrieve proc function from function map */
    hg_proc_info = (struct hg_proc_info *) HG_Core_registered_data(
        hg_class->core_class, id);
    HG_CHECK_ERROR_NORET(
        hg_proc_info == NULL, unlock, "Could not get registered data");

    data = hg_proc_info->data;

unlock:
    hg_thread_spin_unlock(&private_class->register_lock);

done:
    return data;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Registered_disable_response(
    hg_class_t *hg_class, hg_id_t id, hg_bool_t disable)
{
    struct hg_private_class *private_class =
        (struct hg_private_class *) hg_class;
    struct hg_proc_info *hg_proc_info = NULL;
    hg_return_t ret = HG_SUCCESS;

    HG_CHECK_ERROR(
        hg_class == NULL, done, ret, HG_INVALID_ARG, "NULL HG class");

    hg_thread_spin_lock(&private_class->register_lock);

    /* Retrieve proc function from function map */
    hg_proc_info = (struct hg_proc_info *) HG_Core_registered_data(
        hg_class->core_class, id);
    HG_CHECK_ERROR(hg_proc_info == NULL, unlock, ret, HG_NOENTRY,
        "Could not get registered data");

    hg_proc_info->no_response = disable;

unlock:
    hg_thread_spin_unlock(&private_class->register_lock);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Registered_disabled_response(
    hg_class_t *hg_class, hg_id_t id, hg_bool_t *disabled)
{
    struct hg_private_class *private_class =
        (struct hg_private_class *) hg_class;
    struct hg_proc_info *hg_proc_info = NULL;
    hg_return_t ret = HG_SUCCESS;

    HG_CHECK_ERROR(
        hg_class == NULL, done, ret, HG_INVALID_ARG, "NULL HG class");
    HG_CHECK_ERROR(disabled == NULL, done, ret, HG_INVALID_ARG,
        "NULL pointer to disabled flag");

    hg_thread_spin_lock(&private_class->register_lock);

    /* Retrieve proc function from function map */
    hg_proc_info = (struct hg_proc_info *) HG_Core_registered_data(
        hg_class->core_class, id);
    HG_CHECK_ERROR(hg_proc_info == NULL, unlock, ret, HG_NOENTRY,
        "Could not get registered data");

    *disabled = hg_proc_info->no_response;

unlock:
    hg_thread_spin_unlock(&private_class->register_lock);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Addr_lookup1(hg_context_t *context, hg_cb_t callback, void *arg,
    const char *name, hg_op_id_t *op_id)
{
    struct hg_op_id *hg_op_id = NULL;
    hg_return_t ret;

    HG_CHECK_ERROR(
        context == NULL, error, ret, HG_INVALID_ARG, "NULL HG context");
    (void) op_id;

    /* Allocate op_id */
    hg_op_id = (struct hg_op_id *) malloc(sizeof(struct hg_op_id));
    HG_CHECK_ERROR(hg_op_id == NULL, error, ret, HG_NOMEM,
        "Could not allocate HG operation ID");

    hg_op_id->context = context;
    hg_op_id->type = HG_CB_LOOKUP;
    hg_op_id->callback = callback;
    hg_op_id->arg = arg;
    hg_op_id->info.lookup.hg_addr = HG_ADDR_NULL;

    ret = HG_Core_addr_lookup1(context->core_context, hg_core_addr_lookup_cb,
        hg_op_id, name, HG_CORE_OP_ID_IGNORE);
    HG_CHECK_HG_ERROR(
        error, ret, "Could not lookup %s (%s)", name, HG_Error_to_string(ret));

    return HG_SUCCESS;

error:
    free(hg_op_id);

    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Addr_lookup2(hg_class_t *hg_class, const char *name, hg_addr_t *addr)
{
    hg_return_t ret = HG_SUCCESS;

    HG_CHECK_ERROR(
        hg_class == NULL, done, ret, HG_INVALID_ARG, "NULL HG class");

    ret = HG_Core_addr_lookup2(
        hg_class->core_class, name, (hg_core_addr_t *) addr);
    HG_CHECK_HG_ERROR(
        done, ret, "Could not lookup %s (%s)", name, HG_Error_to_string(ret));

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Addr_free(hg_class_t *hg_class, hg_addr_t addr)
{
    hg_return_t ret = HG_SUCCESS;

    HG_CHECK_ERROR(
        hg_class == NULL, done, ret, HG_INVALID_ARG, "NULL HG class");

    ret = HG_Core_addr_free((hg_core_addr_t) addr);
    HG_CHECK_HG_ERROR(
        done, ret, "Could not free addr (%s)", HG_Error_to_string(ret));

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Addr_set_remove(hg_class_t *hg_class, hg_addr_t addr)
{
    hg_return_t ret = HG_SUCCESS;

    HG_CHECK_ERROR(
        hg_class == NULL, done, ret, HG_INVALID_ARG, "NULL HG class");

    ret = HG_Core_addr_set_remove((hg_core_addr_t) addr);
    HG_CHECK_HG_ERROR(done, ret, "Could not set addr to be removed (%s)",
        HG_Error_to_string(ret));

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Addr_self(hg_class_t *hg_class, hg_addr_t *addr)
{
    hg_return_t ret = HG_SUCCESS;

    HG_CHECK_ERROR(
        hg_class == NULL, done, ret, HG_INVALID_ARG, "NULL HG class");

    ret = HG_Core_addr_self(hg_class->core_class, (hg_core_addr_t *) addr);
    HG_CHECK_HG_ERROR(done, ret, "Could not retrieve self addr (%s)",
        HG_Error_to_string(ret));

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Addr_dup(hg_class_t *hg_class, hg_addr_t addr, hg_addr_t *new_addr)
{
    hg_return_t ret = HG_SUCCESS;

    HG_CHECK_ERROR(
        hg_class == NULL, done, ret, HG_INVALID_ARG, "NULL HG class");

    ret = HG_Core_addr_dup((hg_core_addr_t) addr, (hg_core_addr_t *) new_addr);
    HG_CHECK_HG_ERROR(
        done, ret, "Could not dup addr (%s)", HG_Error_to_string(ret));

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_bool_t
HG_Addr_cmp(hg_class_t *hg_class, hg_addr_t addr1, hg_addr_t addr2)
{
    hg_bool_t ret = HG_FALSE;

    HG_CHECK_ERROR_NORET(hg_class == NULL, done, "NULL HG class");

    ret = HG_Core_addr_cmp((hg_core_addr_t) addr1, (hg_core_addr_t) addr2);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Addr_to_string(
    hg_class_t *hg_class, char *buf, hg_size_t *buf_size, hg_addr_t addr)
{
    hg_return_t ret = HG_SUCCESS;

    HG_CHECK_ERROR(
        hg_class == NULL, done, ret, HG_INVALID_ARG, "NULL HG class");

    ret = HG_Core_addr_to_string(buf, buf_size, (hg_core_addr_t) addr);
    HG_CHECK_HG_ERROR(done, ret, "Could not convert addr to string (%s)",
        HG_Error_to_string(ret));

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Create(
    hg_context_t *context, hg_addr_t addr, hg_id_t id, hg_handle_t *handle)
{
    struct hg_private_handle *hg_handle = NULL;
    hg_core_handle_t core_handle;
    hg_return_t ret = HG_SUCCESS;

    HG_CHECK_ERROR(
        context == NULL, done, ret, HG_INVALID_ARG, "NULL HG context");

    /* Create HG core handle (calls handle_create_cb) */
    ret = HG_Core_create(
        context->core_context, (hg_core_addr_t) addr, id, &core_handle);
    if (ret == HG_NOENTRY)
        goto done; /* silence error if invalid ID is used */
    HG_CHECK_HG_ERROR(done, ret,
        "Cannot create HG handle with ID %" PRIu64 " (%s)", id,
        HG_Error_to_string(ret));

    /* Get data and HG info */
    hg_handle = (struct hg_private_handle *) HG_Core_get_data(core_handle);
    HG_CHECK_ERROR(
        hg_handle == NULL, error, ret, HG_INVALID_ARG, "NULL handle");
    hg_handle->handle.info.addr = addr;
    hg_handle->handle.info.id = id;

    *handle = (hg_handle_t) hg_handle;

done:
    return ret;

error:
    HG_Core_destroy(core_handle);

    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Destroy(hg_handle_t handle)
{
    hg_return_t ret = HG_SUCCESS;

    if (handle == HG_HANDLE_NULL)
        goto done;

    ret = HG_Core_destroy(handle->core_handle);
    HG_CHECK_HG_ERROR(done, ret, "Could not set handle to be destroyed (%s)",
        HG_Error_to_string(ret));

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

    HG_CHECK_ERROR(
        handle == HG_HANDLE_NULL, done, ret, HG_INVALID_ARG, "NULL HG handle");

    /* Call core reset */
    ret = HG_Core_reset(handle->core_handle, (hg_core_addr_t) addr, id);
    HG_CHECK_HG_ERROR(done, ret, "Could not reset core HG handle (%s)",
        HG_Error_to_string(ret));

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

    HG_CHECK_ERROR(
        handle == HG_HANDLE_NULL, done, ret, HG_INVALID_ARG, "NULL HG handle");
    HG_CHECK_ERROR(in_struct == NULL, done, ret, HG_INVALID_ARG,
        "NULL pointer to input struct");

    /* Retrieve RPC data */
    hg_proc_info =
        (const struct hg_proc_info *) HG_Core_get_rpc_data(handle->core_handle);
    HG_CHECK_ERROR(
        hg_proc_info == NULL, done, ret, HG_FAULT, "Could not get proc info");

    /* Get input struct */
    ret = hg_get_struct(
        (struct hg_private_handle *) handle, hg_proc_info, HG_INPUT, in_struct);
    HG_CHECK_HG_ERROR(
        done, ret, "Could not get input (%s)", HG_Error_to_string(ret));

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Free_input(hg_handle_t handle, void *in_struct)
{
    const struct hg_proc_info *hg_proc_info;
    hg_return_t ret = HG_SUCCESS;

    HG_CHECK_ERROR(
        handle == HG_HANDLE_NULL, done, ret, HG_INVALID_ARG, "NULL HG handle");
    HG_CHECK_ERROR(in_struct == NULL, done, ret, HG_INVALID_ARG,
        "NULL pointer to input struct");

    /* Retrieve RPC data */
    hg_proc_info =
        (const struct hg_proc_info *) HG_Core_get_rpc_data(handle->core_handle);
    HG_CHECK_ERROR(
        hg_proc_info == NULL, done, ret, HG_FAULT, "Could not get proc info");

    /* Free input struct */
    ret = hg_free_struct(
        (struct hg_private_handle *) handle, hg_proc_info, HG_INPUT, in_struct);
    HG_CHECK_HG_ERROR(
        done, ret, "Could not free input (%s)", HG_Error_to_string(ret));

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Get_output(hg_handle_t handle, void *out_struct)
{
    const struct hg_proc_info *hg_proc_info;
    hg_return_t ret = HG_SUCCESS;

    HG_CHECK_ERROR(
        handle == HG_HANDLE_NULL, done, ret, HG_INVALID_ARG, "NULL HG handle");
    HG_CHECK_ERROR(out_struct == NULL, done, ret, HG_INVALID_ARG,
        "NULL pointer to output struct");

    /* Retrieve RPC data */
    hg_proc_info =
        (const struct hg_proc_info *) HG_Core_get_rpc_data(handle->core_handle);
    HG_CHECK_ERROR(
        hg_proc_info == NULL, done, ret, HG_FAULT, "Could not get proc info");

    /* Get output struct */
    ret = hg_get_struct((struct hg_private_handle *) handle, hg_proc_info,
        HG_OUTPUT, out_struct);
    HG_CHECK_HG_ERROR(
        done, ret, "Could not get output (%s)", HG_Error_to_string(ret));

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Free_output(hg_handle_t handle, void *out_struct)
{
    const struct hg_proc_info *hg_proc_info;
    hg_return_t ret = HG_SUCCESS;

    HG_CHECK_ERROR(
        handle == HG_HANDLE_NULL, done, ret, HG_INVALID_ARG, "NULL HG handle");
    HG_CHECK_ERROR(out_struct == NULL, done, ret, HG_INVALID_ARG,
        "NULL pointer to output struct");

    /* Retrieve RPC data */
    hg_proc_info =
        (const struct hg_proc_info *) HG_Core_get_rpc_data(handle->core_handle);
    HG_CHECK_ERROR(
        hg_proc_info == NULL, done, ret, HG_FAULT, "Could not get proc info");

    /* Free output struct */
    ret = hg_free_struct((struct hg_private_handle *) handle, hg_proc_info,
        HG_OUTPUT, out_struct);
    HG_CHECK_HG_ERROR(
        done, ret, "Could not free output (%s)", HG_Error_to_string(ret));

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Get_input_buf(hg_handle_t handle, void **in_buf, hg_size_t *in_buf_size)
{
    hg_size_t buf_size, header_offset = hg_header_get_size(HG_INPUT);
    hg_return_t ret = HG_SUCCESS;

    HG_CHECK_ERROR(
        handle == HG_HANDLE_NULL, done, ret, HG_INVALID_ARG, "NULL HG handle");
    HG_CHECK_ERROR(
        in_buf == NULL, done, ret, HG_INVALID_ARG, "NULL input buffer pointer");

    /* Get core input buffer */
    /* Note: any extra header information will be transmitted with the
     * control message, not the extra_buf, if the RPC exceeds the eager size
     * limit.
     */
    ret = HG_Core_get_input(handle->core_handle, in_buf, &buf_size);
    HG_CHECK_HG_ERROR(
        done, ret, "Could not get input buffer (%s)", HG_Error_to_string(ret));

    *in_buf = (char *) *in_buf + header_offset;
    if (in_buf_size)
        *in_buf_size = buf_size - header_offset;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Get_output_buf(hg_handle_t handle, void **out_buf, hg_size_t *out_buf_size)
{
    hg_size_t buf_size, header_offset = hg_header_get_size(HG_OUTPUT);
    hg_return_t ret = HG_SUCCESS;

    HG_CHECK_ERROR(
        handle == HG_HANDLE_NULL, done, ret, HG_INVALID_ARG, "NULL HG handle");
    HG_CHECK_ERROR(out_buf == NULL, done, ret, HG_INVALID_ARG,
        "NULL output buffer pointer");

    /* Get core output buffer */
    /* Note: any extra header information will be transmitted with the
     * control message, not the extra_buf, if the response exceeds the eager
     * size limit.
     */
    ret = HG_Core_get_output(handle->core_handle, out_buf, &buf_size);
    HG_CHECK_HG_ERROR(
        done, ret, "Could not get output buffer (%s)", HG_Error_to_string(ret));

    *out_buf = (char *) *out_buf + header_offset;
    if (out_buf_size)
        *out_buf_size = buf_size - header_offset;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Get_input_extra_buf(
    hg_handle_t handle, void **in_buf, hg_size_t *in_buf_size)
{
    struct hg_private_handle *private_handle =
        (struct hg_private_handle *) handle;
    hg_return_t ret = HG_SUCCESS;

    HG_CHECK_ERROR(
        handle == HG_HANDLE_NULL, done, ret, HG_INVALID_ARG, "NULL HG handle");
    HG_CHECK_ERROR(
        in_buf == NULL, done, ret, HG_INVALID_ARG, "NULL input buffer pointer");

    /* No offset if extra buffer since only the user payload is copied */
    *in_buf = private_handle->in_extra_buf;
    if (in_buf_size)
        *in_buf_size = private_handle->in_extra_buf_size;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Get_output_extra_buf(
    hg_handle_t handle, void **out_buf, hg_size_t *out_buf_size)
{
    struct hg_private_handle *private_handle =
        (struct hg_private_handle *) handle;
    hg_return_t ret = HG_SUCCESS;

    HG_CHECK_ERROR(
        handle == HG_HANDLE_NULL, done, ret, HG_INVALID_ARG, "NULL HG handle");
    HG_CHECK_ERROR(out_buf == NULL, done, ret, HG_INVALID_ARG,
        "NULL output buffer pointer");

    /* No offset if extra buffer since only the user payload is copied */
    *out_buf = private_handle->out_extra_buf;
    if (out_buf_size)
        *out_buf_size = private_handle->out_extra_buf_size;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Forward(hg_handle_t handle, hg_cb_t callback, void *arg, void *in_struct)
{
    struct hg_private_handle *private_handle =
        (struct hg_private_handle *) handle;
    const struct hg_proc_info *hg_proc_info = NULL;
    hg_size_t payload_size = 0;
    hg_bool_t more_data = HG_FALSE;
    hg_uint8_t flags = 0;
    hg_return_t ret = HG_SUCCESS;

    HG_CHECK_ERROR(
        handle == HG_HANDLE_NULL, done, ret, HG_INVALID_ARG, "NULL HG handle");
    HG_CHECK_ERROR(handle->info.addr == HG_ADDR_NULL, done, ret, HG_INVALID_ARG,
        "NULL target addr");

    /* Set callback data */
    private_handle->forward_cb = callback;
    private_handle->forward_arg = arg;

    /* Retrieve RPC data */
    hg_proc_info =
        (const struct hg_proc_info *) HG_Core_get_rpc_data(handle->core_handle);
    HG_CHECK_ERROR(
        hg_proc_info == NULL, done, ret, HG_FAULT, "Could not get proc info");

    /* Set input struct */
    ret = hg_set_struct(private_handle, hg_proc_info, HG_INPUT, in_struct,
        &payload_size, &more_data);
    HG_CHECK_HG_ERROR(
        done, ret, "Could not set input (%s)", HG_Error_to_string(ret));

    /* Set more data flag on handle so that handle_more_callback is triggered */
    if (more_data)
        flags |= HG_CORE_MORE_DATA;

    /* Set no response flag if no response required */
    if (hg_proc_info->no_response)
        flags |= HG_CORE_NO_RESPONSE;

    /* Send request */
    ret = HG_Core_forward(
        handle->core_handle, hg_core_forward_cb, handle, flags, payload_size);
    if (ret == HG_AGAIN)
        goto done;
    HG_CHECK_HG_ERROR(
        done, ret, "Could not forward call (%s)", HG_Error_to_string(ret));

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

    HG_CHECK_ERROR(
        handle == HG_HANDLE_NULL, done, ret, HG_INVALID_ARG, "NULL HG handle");

    /* Set callback data */
    private_handle->respond_cb = callback;
    private_handle->respond_arg = arg;

    /* Retrieve RPC data */
    hg_proc_info =
        (const struct hg_proc_info *) HG_Core_get_rpc_data(handle->core_handle);
    HG_CHECK_ERROR(
        hg_proc_info == NULL, done, ret, HG_FAULT, "Could not get proc info");

    /* Set output struct */
    ret = hg_set_struct(private_handle, hg_proc_info, HG_OUTPUT, out_struct,
        &payload_size, &more_data);
    HG_CHECK_HG_ERROR(
        done, ret, "Could not set output (%s)", HG_Error_to_string(ret));

    /* Set more data flag on handle so that handle_more_callback is triggered */
    if (more_data)
        flags |= HG_CORE_MORE_DATA;

    /* Send response back */
    ret = HG_Core_respond(
        handle->core_handle, hg_core_respond_cb, handle, flags, payload_size);
    HG_CHECK_HG_ERROR(
        done, ret, "Could not respond (%s)", HG_Error_to_string(ret));

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Progress(hg_context_t *context, unsigned int timeout)
{
    hg_return_t ret = HG_SUCCESS;

    HG_CHECK_ERROR(
        context == NULL, done, ret, HG_INVALID_ARG, "NULL HG context");

    ret = HG_Core_progress(context->core_context, timeout);
    HG_CHECK_ERROR_NORET(ret != HG_SUCCESS && ret != HG_TIMEOUT, done,
        "Could not make progress on context (%s)", HG_Error_to_string(ret));

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Trigger(hg_context_t *context, unsigned int timeout, unsigned int max_count,
    unsigned int *actual_count)
{
    hg_return_t ret = HG_SUCCESS;

    HG_CHECK_ERROR(
        context == NULL, done, ret, HG_INVALID_ARG, "NULL HG context");

    ret = HG_Core_trigger(
        context->core_context, timeout, max_count, actual_count);
    HG_CHECK_ERROR_NORET(ret != HG_SUCCESS && ret != HG_TIMEOUT, done,
        "Could not trigger operations from context (%s)",
        HG_Error_to_string(ret));

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Cancel(hg_handle_t handle)
{
    hg_return_t ret = HG_SUCCESS;

    HG_CHECK_ERROR(
        handle == HG_HANDLE_NULL, done, ret, HG_INVALID_ARG, "NULL HG handle");

    ret = HG_Core_cancel(handle->core_handle);
    HG_CHECK_HG_ERROR(
        done, ret, "Could not cancel handle (%s)", HG_Error_to_string(ret));

done:
    return ret;
}
