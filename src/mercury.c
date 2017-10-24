/*
 * Copyright (C) 2013-2017 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#include "mercury.h"
#include "mercury_bulk.h"
#include "mercury_core.h"
#include "mercury_header.h"
#include "mercury_proc.h"
#include "mercury_error.h"

#include "mercury_hash_string.h"
#include "mercury_mem.h"

#include <stdlib.h>
#include <string.h>

/****************/
/* Local Macros */
/****************/

#define HG_POST_LIMIT_DEFAULT 256

/* Convert value to string */
#define HG_ERROR_STRING_MACRO(def, value, string) \
  if (value == def) string = #def

/************************************/
/* Local Type and Struct Definition */
/************************************/

/* Info for function map */
struct hg_proc_info {
    hg_proc_cb_t in_proc_cb;        /* Input proc callback */
    hg_proc_cb_t out_proc_cb;       /* Output proc callback */
    void *data;                     /* User data */
    void (*free_callback)(void *);  /* User data free callback */
};

/* Private handle data */
struct hg_private_data {
    hg_cb_t callback;               /* Callback */
    void *arg;                      /* Callback args */
    struct hg_header in_header;     /* Input header */
    struct hg_header out_header;    /* Output header */
    hg_proc_t in_proc;              /* Input proc */
    hg_proc_t out_proc;             /* Output proc */
    void *extra_bulk_buf;           /* Extra bulk buf */
    size_t extra_bulk_buf_size;     /* Extra bulk buf size */
    hg_bulk_t extra_bulk_handle;    /* Extra bulk handle */
    hg_return_t (*extra_bulk_transfer_cb)(hg_handle_t); /* Bulk transfer callback */
    hg_op_id_t extra_bulk_op_id;    /* Extra bulk operation ID */
};

/***********************/
/* External Prototypes */
/***********************/

/**
 * Get RPC registered data.
 * TODO can be improved / same as calling HG_Registered_data()?
 */
extern void *
hg_core_get_rpc_data(
        struct hg_handle *hg_handle
        );

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
static hg_return_t
hg_private_data_alloc(
        hg_class_t *hg_class,
        hg_handle_t handle
        );

/**
 * Free function for private data.
 */
static void
hg_private_data_free(
        void *arg
        );

/**
 * More data callback.
 */
static hg_return_t
hg_more_data_cb(
        hg_handle_t handle,
        hg_return_t (*done_cb)(hg_handle_t)
        );

/**
 * More data free callback.
 */
static void
hg_more_data_free_cb(
        hg_handle_t handle
        );

/**
 * Decode and get input structure.
 */
static hg_return_t
hg_get_input(
        hg_handle_t handle,
        struct hg_private_data *hg_private_data,
        void *in_struct
        );

/**
 * Set and encode input structure.
 */
static hg_return_t
hg_set_input(
        hg_handle_t handle,
        struct hg_private_data *hg_private_data,
        void *in_struct,
        hg_size_t *payload_size
        );

/**
 * Free allocated members from input structure.
 */
static hg_return_t
hg_free_input(
        hg_handle_t handle,
        struct hg_private_data *hg_private_data,
        void *in_struct
        );

/**
 * Decode and get output structure.
 */
static hg_return_t
hg_get_output(
        hg_handle_t handle,
        struct hg_private_data *hg_private_data,
        void *out_struct
        );

/**
 * Set and encode output structure.
 */
static hg_return_t
hg_set_output(
        hg_handle_t handle,
        struct hg_private_data *hg_private_data,
        void *out_struct,
        hg_size_t *payload_size
        );

/**
 * Free allocated members from output structure.
 */
static hg_return_t
hg_free_output(
        hg_handle_t handle,
        struct hg_private_data *hg_private_data,
        void *out_struct
        );

/**
 * Get extra user payload using bulk transfer.
 */
static hg_return_t
hg_get_extra_input(
        hg_handle_t handle,
        struct hg_private_data *hg_private_data,
        hg_return_t (*done_cb)(hg_handle_t)
        );

/**
 * Get extra input bulk transfer callback.
 */
static hg_return_t
hg_get_extra_input_cb(
        const struct hg_cb_info *callback_info
        );

/**
 * Free allocated extra input.
 */
static void
hg_free_extra_input(
        struct hg_private_data *hg_private_data
        );

/**
 * Forward callback.
 */
static hg_return_t
hg_forward_cb(
        const struct hg_cb_info *callback_info
        );

/**
 * Respond callback.
 */
static hg_return_t
hg_respond_cb(
        const struct hg_cb_info *callback_info
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
static hg_return_t
hg_private_data_alloc(hg_class_t *hg_class, hg_handle_t handle)
{
    struct hg_private_data *hg_private_data;
    hg_return_t ret;

    /* Create private data to wrap callbacks etc */
    hg_private_data = (struct hg_private_data *) malloc(
        sizeof(struct hg_private_data));
    if (!hg_private_data) {
        HG_LOG_ERROR("Could not allocate private data");
        ret = HG_NOMEM_ERROR;
        goto done;
    }
    memset(hg_private_data, 0, sizeof(struct hg_private_data));
    hg_header_input_init(&hg_private_data->in_header);
    hg_header_output_init(&hg_private_data->out_header);

    /* CRC32 is enough for small size buffers */
    ret = hg_proc_create(hg_class, HG_CRC32, &hg_private_data->in_proc);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Cannot create HG proc");
        goto done;
    }
    ret = hg_proc_create(hg_class, HG_CRC32, &hg_private_data->out_proc);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Cannot create HG proc");
        goto done;
    }
    HG_Core_set_private_data(handle, hg_private_data, hg_private_data_free);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static void
hg_private_data_free(void *arg)
{
    struct hg_private_data *hg_private_data = (struct hg_private_data *) arg;

    if (hg_private_data->in_proc != HG_PROC_NULL)
        hg_proc_free(hg_private_data->in_proc);
    if (hg_private_data->out_proc != HG_PROC_NULL)
        hg_proc_free(hg_private_data->out_proc);
    hg_mem_aligned_free(hg_private_data->extra_bulk_buf);
    hg_header_input_finalize(&hg_private_data->in_header);
    hg_header_output_finalize(&hg_private_data->out_header);
    free(hg_private_data);
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_more_data_cb(hg_handle_t handle, hg_return_t (*done_cb)(hg_handle_t))
{
    struct hg_private_data *hg_private_data;
    hg_return_t ret = HG_SUCCESS;

    /* Retrieve private data */
    hg_private_data =
        (struct hg_private_data *) HG_Core_get_private_data(handle);
    if (!hg_private_data) {
        HG_LOG_ERROR("Could not get private data");
        ret = HG_PROTOCOL_ERROR;
        goto done;
    }

    ret = hg_get_extra_input(handle, hg_private_data, done_cb);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not get extra input");
        goto done;
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static void
hg_more_data_free_cb(hg_handle_t handle)
{
    struct hg_private_data *hg_private_data;

    /* Retrieve private data */
    hg_private_data =
        (struct hg_private_data *) HG_Core_get_private_data(handle);
    if (!hg_private_data) {
        HG_LOG_ERROR("Could not get private data");
        goto done;
    }

    hg_free_extra_input(hg_private_data);

done:
    return;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_get_input(hg_handle_t handle, struct hg_private_data *hg_private_data,
    void *in_struct)
{
    struct hg_proc_info *hg_proc_info;
    hg_proc_t proc = hg_private_data->in_proc;
    void *in_buf;
    hg_size_t in_buf_size;
    hg_size_t header_offset = hg_header_input_get_size();
    hg_return_t ret = HG_SUCCESS;

    /* Retrieve proc function from function map */
    hg_proc_info = (struct hg_proc_info *) hg_core_get_rpc_data(handle);
    if (!hg_proc_info) {
        HG_LOG_ERROR("Could not get proc info");
        ret = HG_PROTOCOL_ERROR;
        goto done;
    }
    if (!hg_proc_info->in_proc_cb) {
        HG_LOG_ERROR("No input proc set, proc must be set in HG_Register()");
        ret = HG_PROTOCOL_ERROR;
        goto done;
    }

    /* Get core input buffer */
    ret = HG_Core_get_input(handle, &in_buf, &in_buf_size);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not get input buffer");
        goto done;
    }

    /* Get header */
    hg_header_input_reset(&hg_private_data->in_header);
    ret = hg_header_input_proc(HG_DECODE, in_buf, in_buf_size,
        &hg_private_data->in_header);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not process input header");
        goto done;
    }

    /* If the input did not fit into the core input buffer and we have an extra
     * input buffer set, use that buffer directly */
    if (hg_private_data->extra_bulk_buf) {
        in_buf = hg_private_data->extra_bulk_buf;
        in_buf_size = hg_private_data->extra_bulk_buf_size;
    } else {
        /* Include our own header offset */
        in_buf = (char *) in_buf + header_offset;
        in_buf_size -= header_offset;
    }

    /* Reset proc */
    ret = hg_proc_reset(proc, in_buf, in_buf_size, HG_DECODE);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not reset proc");
        goto done;
    }

    /* Decode input parameters */
    ret = hg_proc_info->in_proc_cb(proc, in_struct);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not decode input parameters");
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
    ret = hg_proc_checksum_verify(proc,
        &hg_private_data->in_header.msg.input.hash.payload,
        sizeof(hg_private_data->in_header.msg.input.hash.payload));
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Error in proc checksum verify");
        goto done;
    }
#endif

    /* Increment ref count on handle so that it remains valid until free_input
     * is called */
    HG_Core_ref_incr(handle);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_set_input(hg_handle_t handle, struct hg_private_data *hg_private_data,
    void *in_struct, hg_size_t *payload_size)
{
    struct hg_proc_info *hg_proc_info;
    hg_proc_t proc = hg_private_data->in_proc;
    void *in_buf;
    hg_size_t in_buf_size;
    hg_size_t header_offset = hg_header_input_get_size();
    hg_return_t ret = HG_SUCCESS;

    /* Retrieve proc function from function map */
    hg_proc_info = (struct hg_proc_info *) hg_core_get_rpc_data(handle);
    if (!hg_proc_info) {
        HG_LOG_ERROR("Could not get proc info");
        ret = HG_PROTOCOL_ERROR;
        goto done;
    }
    if (!hg_proc_info->in_proc_cb || !in_struct) {
        /* Silently skip */
        *payload_size = 0;
        goto done;
    }

    /* Reset header */
    hg_header_input_reset(&hg_private_data->in_header);

    /* Get input buffer */
    ret = HG_Core_get_input(handle, &in_buf, &in_buf_size);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not get input buffer");
        goto done;
    }

    /* Include our own header offset */
    in_buf = (char *) in_buf + header_offset;
    in_buf_size -= header_offset;

    /* Reset proc */
    ret = hg_proc_reset(proc, in_buf, in_buf_size, HG_ENCODE);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not reset proc");
        goto done;
    }

    /* Encode input parameters */
    ret = hg_proc_info->in_proc_cb(proc, in_struct);
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
    ret = hg_proc_checksum_get(proc,
        &hg_private_data->in_header.msg.input.hash.payload,
        sizeof(hg_private_data->in_header.msg.input.hash.payload));
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Error in getting proc checksum");
        goto done;
    }
#endif

    /* The proc object may have allocated an extra buffer at this point.
     * If the input did not fit into the original buffer, we need to send an
     * unexpected message with "more data" flag set along with the bulk data
     * descriptor for the input so that the target can pull that buffer and use
     * it to retrieve the data.
     */
    if (hg_proc_get_extra_buf(proc)) {
        const struct hg_info *hg_info = HG_Core_get_info(handle);

#ifdef HG_HAS_XDR
        HG_LOG_ERROR("Extra encoding using XDR is not yet supported");
        ret = HG_SIZE_ERROR;
        goto done;
#endif
        /* Create a bulk descriptor only of the size that is used */
        hg_private_data->extra_bulk_buf = hg_proc_get_extra_buf(proc);
        hg_private_data->extra_bulk_buf_size = hg_proc_get_size_used(proc);

        /* Prevent buffer from being freed when proc_reset is called */
        hg_proc_set_extra_buf_is_mine(proc, HG_TRUE);

        /* Set more data flag on handle so that handle_more_callback is
         * triggered */
        HG_Core_set_more_data(handle, HG_TRUE);

        ret = HG_Bulk_create(hg_info->hg_class, 1,
            &hg_private_data->extra_bulk_buf,
            &hg_private_data->extra_bulk_buf_size, HG_BULK_READ_ONLY,
            &hg_private_data->extra_bulk_handle);
        if (ret != HG_SUCCESS) {
            HG_LOG_ERROR("Could not create bulk data handle");
            goto done;
        }

        /* Reset proc */
        ret = hg_proc_reset(proc, in_buf, in_buf_size, HG_ENCODE);
        if (ret != HG_SUCCESS) {
            HG_LOG_ERROR("Could not reset proc");
            goto done;
        }

        /* Encode extra_bulk_handle, we can do that safely here because
         * the user payload is copied in this case so we don't have to worry
         * about overwriting the user's data */
        ret = hg_proc_hg_bulk_t(proc, &hg_private_data->extra_bulk_handle);
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
    }

    /* Encode input header */
    in_buf = (char *) in_buf - header_offset;
    in_buf_size += header_offset;
    ret = hg_header_input_proc(HG_ENCODE, in_buf, in_buf_size,
        &hg_private_data->in_header);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not process input header");
        goto done;
    }

    /* Only send the actual size of the data, not the entire buffer */
    *payload_size = hg_proc_get_size_used(proc) + header_offset;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_free_input(hg_handle_t handle, struct hg_private_data *hg_private_data,
    void *in_struct)
{
    struct hg_proc_info *hg_proc_info;
    hg_proc_t proc = hg_private_data->in_proc;
    hg_return_t ret = HG_SUCCESS;

    /* Retrieve proc function from function map */
    hg_proc_info = (struct hg_proc_info *) hg_core_get_rpc_data(handle);
    if (!hg_proc_info) {
        HG_LOG_ERROR("Could not get proc info");
        ret = HG_PROTOCOL_ERROR;
        goto done;
    }
    if (!hg_proc_info->in_proc_cb) {
        HG_LOG_ERROR("No input proc set, proc must be set in HG_Register()");
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
    ret = hg_proc_info->in_proc_cb(proc, in_struct);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not free allocated parameters");
        goto done;
    }

    /* Decrement ref count or free */
    ret = HG_Core_destroy(handle);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not decrement handle ref count");
        goto done;
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_get_output(hg_handle_t handle, struct hg_private_data *hg_private_data,
    void *out_struct)
{
    struct hg_proc_info *hg_proc_info;
    hg_proc_t proc = hg_private_data->out_proc;
    void *out_buf;
    hg_size_t out_buf_size;
    hg_size_t header_offset = hg_header_output_get_size();
    hg_return_t ret = HG_SUCCESS;

    /* Retrieve proc function from function map */
    hg_proc_info = (struct hg_proc_info *) hg_core_get_rpc_data(handle);
    if (!hg_proc_info) {
        HG_LOG_ERROR("Could not get proc info");
        ret = HG_PROTOCOL_ERROR;
        goto done;
    }
    if (!hg_proc_info->out_proc_cb) {
        HG_LOG_ERROR("No output proc set, proc must be set in HG_Register()");
        ret = HG_PROTOCOL_ERROR;
        goto done;
    }

    /* Get output buffer */
    ret = HG_Core_get_output(handle, &out_buf, &out_buf_size);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not get output buffer");
        goto done;
    }

    /* Get header */
    hg_header_output_reset(&hg_private_data->out_header);
    ret = hg_header_output_proc(HG_DECODE, out_buf, out_buf_size,
        &hg_private_data->out_header);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not process output header");
        goto done;
    }

    /* If the output did not fit into the core output buffer and there is an
     * extra output buffer, use that buffer directly */
    if (hg_private_data->extra_bulk_buf) {
        out_buf = hg_private_data->extra_bulk_buf;
        out_buf_size = hg_private_data->extra_bulk_buf_size;
    } else {
        /* Include our own header offset */
        out_buf = (char *) out_buf + header_offset;
        out_buf_size -= header_offset;
    }

    /* Reset proc */
    ret = hg_proc_reset(proc, out_buf, out_buf_size, HG_DECODE);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not reset proc");
        goto done;
    }

    /* Decode output parameters */
    ret = hg_proc_info->out_proc_cb(proc, out_struct);
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
    ret = hg_proc_checksum_verify(proc,
        &hg_private_data->out_header.msg.output.hash.payload,
        sizeof(hg_private_data->out_header.msg.output.hash.payload));
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Error in proc checksum verify");
        goto done;
    }
#endif

    /* Increment ref count on handle so that it remains valid until free_output
     * is called */
    HG_Core_ref_incr(handle);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_set_output(hg_handle_t handle, struct hg_private_data *hg_private_data,
    void *out_struct, hg_size_t *payload_size)
{
    struct hg_proc_info *hg_proc_info;
    hg_proc_t proc = hg_private_data->out_proc;
    void *out_buf;
    hg_size_t out_buf_size;
    hg_size_t header_offset = hg_header_output_get_size();
    hg_return_t ret = HG_SUCCESS;

    /* Retrieve proc function from function map */
    hg_proc_info = (struct hg_proc_info *) hg_core_get_rpc_data(handle);
    if (!hg_proc_info) {
        HG_LOG_ERROR("Could not get proc info");
        ret = HG_PROTOCOL_ERROR;
        goto done;
    }
    if (!hg_proc_info->out_proc_cb || !out_struct) {
        /* Silently skip */
        *payload_size = 0;
        goto done;
    }

    /* Reset header */
    hg_header_output_reset(&hg_private_data->out_header);

    /* Get output buffer */
    ret = HG_Core_get_output(handle, &out_buf, &out_buf_size);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not get output buffer");
        goto done;
    }

    /* Include our own header offset */
    out_buf = (char *) out_buf + header_offset;
    out_buf_size -= header_offset;

    /* Reset proc */
    ret = hg_proc_reset(proc, out_buf, out_buf_size, HG_ENCODE);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not reset proc");
        goto done;
    }

    /* Encode output parameters */
    ret = hg_proc_info->out_proc_cb(proc, out_struct);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not encode output parameters");
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
    ret = hg_proc_checksum_get(proc,
        &hg_private_data->out_header.msg.output.hash.payload,
        sizeof(hg_private_data->out_header.msg.output.hash.payload));
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Error in getting proc checksum");
        goto done;
    }
#endif

    /* Encode output header */
    out_buf = (char *) out_buf - header_offset;
    out_buf_size += header_offset;
    ret = hg_header_output_proc(HG_ENCODE, out_buf, out_buf_size,
        &hg_private_data->out_header);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not process output header");
        goto done;
    }

    /* Only send the actual size of the data, not the entire buffer */
    *payload_size = hg_proc_get_size_used(proc) + header_offset;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_free_output(hg_handle_t handle, struct hg_private_data *hg_private_data,
    void *out_struct)
{
    struct hg_proc_info *hg_proc_info;
    hg_proc_t proc = hg_private_data->out_proc;
    hg_return_t ret = HG_SUCCESS;

    /* Retrieve proc function from function map */
    hg_proc_info = (struct hg_proc_info *) hg_core_get_rpc_data(handle);
    if (!hg_proc_info) {
        HG_LOG_ERROR("Could not get proc info");
        ret = HG_PROTOCOL_ERROR;
        goto done;
    }
    if (!hg_proc_info->out_proc_cb) {
        HG_LOG_ERROR("No output proc set, proc must be set in HG_Register()");
        ret = HG_PROTOCOL_ERROR;
        goto done;
    }

    /* Reset proc */
    ret = hg_proc_reset(proc, NULL, 0, HG_FREE);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not reset proc");
        goto done;
    }

    /* Free memory allocated during output decoding */
    ret = hg_proc_info->out_proc_cb(proc, out_struct);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not free allocated parameters");
        goto done;
    }

    /* Decrement ref count or free */
    ret = HG_Core_destroy(handle);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not decrement handle ref count");
        goto done;
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_get_extra_input(hg_handle_t handle, struct hg_private_data *hg_private_data,
    hg_return_t (*done_cb)(hg_handle_t handle))
{
    hg_proc_t proc = hg_private_data->in_proc;
    void *in_buf;
    hg_size_t in_buf_size;
    hg_size_t header_offset = hg_header_input_get_size();
    const struct hg_info *hg_info = HG_Core_get_info(handle);
    hg_size_t page_size = (hg_size_t) hg_mem_get_page_size();
    hg_bulk_t local_in_handle = HG_BULK_NULL;
    hg_return_t ret = HG_SUCCESS;

    /* Get core input buffer */
    ret = HG_Core_get_input(handle, &in_buf, &in_buf_size);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not get input buffer");
        goto done;
    }

    /* Include our own header offset */
    in_buf = (char *) in_buf + header_offset;
    in_buf_size -= header_offset;

    ret = hg_proc_reset(proc, in_buf, in_buf_size, HG_DECODE);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not reset proc");
        goto done;
    }

    /* Decode extra bulk handle */
    ret = hg_proc_hg_bulk_t(proc, &hg_private_data->extra_bulk_handle);
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
    hg_private_data->extra_bulk_buf_size = HG_Bulk_get_size(
        hg_private_data->extra_bulk_handle);
    hg_private_data->extra_bulk_buf = hg_mem_aligned_alloc(page_size,
        hg_private_data->extra_bulk_buf_size);
    if (!hg_private_data->extra_bulk_buf) {
        HG_LOG_ERROR("Could not allocate extra input buffer");
        ret = HG_NOMEM_ERROR;
        goto done;
    }

    ret = HG_Bulk_create(hg_info->hg_class, 1, &hg_private_data->extra_bulk_buf,
        &hg_private_data->extra_bulk_buf_size, HG_BULK_READWRITE,
        &local_in_handle);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not create HG bulk handle");
        goto done;
    }

    /* Read bulk data here and wait for the data to be here  */
    hg_private_data->extra_bulk_transfer_cb = done_cb;
    ret = HG_Bulk_transfer(hg_info->context, hg_get_extra_input_cb, handle,
        HG_BULK_PULL, hg_info->addr,
        hg_private_data->extra_bulk_handle, 0, local_in_handle, 0,
        hg_private_data->extra_bulk_buf_size,
        &hg_private_data->extra_bulk_op_id);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not transfer bulk data");
        goto done;
    }

done:
    HG_Bulk_free(local_in_handle);
    HG_Bulk_free(hg_private_data->extra_bulk_handle);
    hg_private_data->extra_bulk_handle = HG_BULK_NULL;
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_get_extra_input_cb(const struct hg_cb_info *callback_info)
{
    struct hg_private_data *hg_private_data;
    hg_handle_t handle = (hg_handle_t) callback_info->arg;
    hg_return_t ret = HG_SUCCESS;

    /* Retrieve private data */
    hg_private_data =
        (struct hg_private_data *) HG_Core_get_private_data(handle);
    if (!hg_private_data) {
        HG_LOG_ERROR("Could not get private data");
        ret = HG_PROTOCOL_ERROR;
        goto done;
    }

    ret = hg_private_data->extra_bulk_transfer_cb(handle);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not execute bulk transfer callback");
        goto done;
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static void
hg_free_extra_input(struct hg_private_data *hg_private_data)
{
    /* Free extra bulk buf if there was any */
    if (hg_private_data->extra_bulk_buf) {
        hg_mem_aligned_free(hg_private_data->extra_bulk_buf);
        hg_private_data->extra_bulk_buf = NULL;
        hg_private_data->extra_bulk_buf_size = 0;
    }
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_forward_cb(const struct hg_cb_info *callback_info)
{
    struct hg_private_data *hg_private_data =
            (struct hg_private_data *) callback_info->arg;
    hg_return_t ret = HG_SUCCESS;

    /* Free eventual extra input buffer and handle */
    if (hg_private_data->extra_bulk_buf) {
        HG_Bulk_free(hg_private_data->extra_bulk_handle);
        hg_private_data->extra_bulk_handle = HG_BULK_NULL;
        hg_mem_aligned_free(hg_private_data->extra_bulk_buf);
        hg_private_data->extra_bulk_buf = NULL,
        hg_private_data->extra_bulk_buf_size = 0;
    }

    /* Execute callback */
    if (hg_private_data->callback) {
        struct hg_cb_info hg_cb_info;

        hg_cb_info.arg = hg_private_data->arg;
        hg_cb_info.ret = callback_info->ret;
        hg_cb_info.type = callback_info->type;
        hg_cb_info.info = callback_info->info;

        hg_private_data->callback(&hg_cb_info);
    }

    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_respond_cb(const struct hg_cb_info *callback_info)
{
    struct hg_private_data *hg_private_data =
            (struct hg_private_data *) callback_info->arg;
    hg_return_t ret = HG_SUCCESS;

    /* Execute callback */
    if (hg_private_data->callback) {
        struct hg_cb_info hg_cb_info;

        hg_cb_info.arg = hg_private_data->arg;
        hg_cb_info.ret = callback_info->ret;
        hg_cb_info.type = callback_info->type;
        hg_cb_info.info = callback_info->info;

        hg_private_data->callback(&hg_cb_info);
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
    HG_ERROR_STRING_MACRO(HG_TIMEOUT, errnum, hg_error_string);
    HG_ERROR_STRING_MACRO(HG_INVALID_PARAM, errnum, hg_error_string);
    HG_ERROR_STRING_MACRO(HG_SIZE_ERROR, errnum, hg_error_string);
    HG_ERROR_STRING_MACRO(HG_NOMEM_ERROR, errnum, hg_error_string);
    HG_ERROR_STRING_MACRO(HG_PROTOCOL_ERROR, errnum, hg_error_string);
    HG_ERROR_STRING_MACRO(HG_NO_MATCH, errnum, hg_error_string);
    HG_ERROR_STRING_MACRO(HG_CHECKSUM_ERROR, errnum, hg_error_string);

    return hg_error_string;
}

/*---------------------------------------------------------------------------*/
hg_class_t *
HG_Init(const char *na_info_string, hg_bool_t na_listen)
{
    hg_class_t *hg_class = NULL;

    hg_class = HG_Core_init(na_info_string, na_listen);
    if (!hg_class) {
        HG_LOG_ERROR("Could not create HG class");
        goto done;
    }

    /* Set private data allocation on HG handle create */
    HG_Core_set_create_callback(hg_class, hg_private_data_alloc);

    /* Set more data callback */
    HG_Core_set_more_data_callback(hg_class, hg_more_data_cb,
        hg_more_data_free_cb);

done:
    return hg_class;
}

/*---------------------------------------------------------------------------*/
hg_class_t *
HG_Init_na(na_class_t *na_class)
{
    hg_class_t *hg_class = NULL;

    hg_class = HG_Core_init_na(na_class);
    if (!hg_class) {
        HG_LOG_ERROR("Could not create HG class");
        goto done;
    }

    /* Set private data allocation on HG handle create */
    HG_Core_set_create_callback(hg_class, hg_private_data_alloc);

    /* Set more data callback */
    HG_Core_set_more_data_callback(hg_class, hg_more_data_cb,
        hg_more_data_free_cb);

done:
    return hg_class;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Finalize(hg_class_t *hg_class)
{
    return HG_Core_finalize(hg_class);
}

/*---------------------------------------------------------------------------*/
void
HG_Cleanup(void)
{
    HG_Core_cleanup();
}

/*---------------------------------------------------------------------------*/
const char *
HG_Class_get_name(const hg_class_t *hg_class)
{
    return HG_Core_class_get_name(hg_class);
}

/*---------------------------------------------------------------------------*/
const char *
HG_Class_get_protocol(const hg_class_t *hg_class)
{
    return HG_Core_class_get_protocol(hg_class);
}

/*---------------------------------------------------------------------------*/
hg_size_t
HG_Class_get_input_eager_size(const hg_class_t *hg_class)
{
    hg_size_t ret = HG_Core_class_get_input_eager_size(hg_class);
    hg_size_t header = hg_header_input_get_size();

    if (ret > header)
        ret -= header;
    else
        ret = 0;

    return ret;
}

/*---------------------------------------------------------------------------*/
hg_size_t
HG_Class_get_output_eager_size(const hg_class_t *hg_class)
{
    hg_size_t ret = HG_Core_class_get_output_eager_size(hg_class);
    hg_size_t header = hg_header_output_get_size();

    if (ret > header)
        ret -= header;
    else
        ret = 0;

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
HG_Context_create_id(hg_class_t *hg_class, hg_uint8_t target_id)
{
    hg_context_t *context = NULL;
#ifdef HG_POST_LIMIT
    unsigned int request_count =
        (HG_POST_LIMIT > 0) ? HG_POST_LIMIT : HG_POST_LIMIT_DEFAULT;
#else
    unsigned int request_count = HG_POST_LIMIT_DEFAULT;
#endif
    hg_return_t ret;

    context = HG_Core_context_create(hg_class);
    if (!context) {
        HG_LOG_ERROR("Could not create context");
        goto done;
    }

    /* Set context ID */
    ret = HG_Core_context_set_id(context, target_id);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not set context ID");
        goto done;
    }

    /* If we are listening, start posting requests */
    if (NA_Is_listening(HG_Core_class_get_na(hg_class))) {
        ret = HG_Core_context_post(context, request_count, HG_TRUE);
        if (ret != HG_SUCCESS) {
            HG_LOG_ERROR("Could not post context requests");
            goto done;
        }
    }

done:
    return context;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Context_destroy(hg_context_t *context)
{
    return HG_Core_context_destroy(context);
}

/*---------------------------------------------------------------------------*/
hg_class_t *
HG_Context_get_class(const hg_context_t *context)
{
    return HG_Core_context_get_class(context);
}

/*---------------------------------------------------------------------------*/
hg_uint8_t
HG_Context_get_id(const hg_context_t *context)
{
    return HG_Core_context_get_id(context);
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

    /* Generate an ID from the function name */
    rpc_id = hg_hash_string(func_name);

    ret = HG_Core_registered(hg_class, rpc_id, flag);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not check for registered RPC id");
        goto done;
    }

    if (id) *id = rpc_id;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Register(hg_class_t *hg_class, hg_id_t id, hg_proc_cb_t in_proc_cb,
    hg_proc_cb_t out_proc_cb, hg_rpc_cb_t rpc_cb)
{
    struct hg_proc_info *hg_proc_info = NULL;
    hg_bool_t registered;
    hg_return_t ret = HG_SUCCESS;

    if (!hg_class) {
        HG_LOG_ERROR("NULL HG class");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    /* Check if already registered */
    ret = HG_Registered(hg_class, id, &registered);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not check for registered RPC id");
        goto done;
    }

    /* Register RPC (register only RPC callback if already registered) */
    ret = HG_Core_register(hg_class, id, rpc_cb);
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
        hg_proc_info->in_proc_cb = in_proc_cb;
        hg_proc_info->out_proc_cb = out_proc_cb;
        hg_proc_info->data = NULL;
        hg_proc_info->free_callback = NULL;

        /* Attach proc info to RPC ID */
        ret = HG_Core_register_data(hg_class, id, hg_proc_info,
            hg_proc_info_free);
        if (ret != HG_SUCCESS) {
            HG_LOG_ERROR("Could not set proc info");
            goto done;
        }
    } else {
        /* Retrieve proc function from function map */
        hg_proc_info =
            (struct hg_proc_info *) HG_Core_registered_data(hg_class, id);
        if (!hg_proc_info) {
            HG_LOG_ERROR("Could not get registered data");
            goto done;
        }
        hg_proc_info->in_proc_cb = in_proc_cb;
        hg_proc_info->out_proc_cb = out_proc_cb;
    }

done:
    if (ret != HG_SUCCESS) {
        free(hg_proc_info);
    }
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Registered(hg_class_t *hg_class, hg_id_t id, hg_bool_t *flag)
{
    return HG_Core_registered(hg_class, id, flag);
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Register_data(hg_class_t *hg_class, hg_id_t id, void *data,
    void (*free_callback)(void *))
{
    struct hg_proc_info *hg_proc_info = NULL;
    hg_return_t ret = HG_SUCCESS;

    /* Retrieve proc function from function map */
    hg_proc_info =
        (struct hg_proc_info *) HG_Core_registered_data(hg_class, id);
    if (!hg_proc_info) {
        HG_LOG_ERROR("Could not get registered data");
        ret = HG_NO_MATCH;
        goto done;
    }

    hg_proc_info->data = data;
    hg_proc_info->free_callback = free_callback;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
void *
HG_Registered_data(hg_class_t *hg_class, hg_id_t id)
{
    struct hg_proc_info *hg_proc_info = NULL;
    void *data = NULL;

    /* Retrieve proc function from function map */
    hg_proc_info =
        (struct hg_proc_info *) HG_Core_registered_data(hg_class, id);
    if (!hg_proc_info) {
        HG_LOG_ERROR("Could not get registered data");
        goto done;
    }

    data = hg_proc_info->data;

done:
    return data;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Registered_disable_response(hg_class_t *hg_class, hg_id_t id,
    hg_bool_t disable)
{
    return HG_Core_registered_disable_response(hg_class, id, disable);
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Addr_lookup(hg_context_t *context, hg_cb_t callback, void *arg,
    const char *name, hg_op_id_t *op_id)
{
    return HG_Core_addr_lookup(context, callback, arg, name, op_id);
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Addr_free(hg_class_t *hg_class, hg_addr_t addr)
{
    return HG_Core_addr_free(hg_class, addr);
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Addr_self(hg_class_t *hg_class, hg_addr_t *addr)
{
    return HG_Core_addr_self(hg_class, addr);
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Addr_dup(hg_class_t *hg_class, hg_addr_t addr, hg_addr_t *new_addr)
{
    return HG_Core_addr_dup(hg_class, addr, new_addr);
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Addr_to_string(hg_class_t *hg_class, char *buf, hg_size_t *buf_size,
    hg_addr_t addr)
{
    return HG_Core_addr_to_string(hg_class, buf, buf_size, addr);
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Create(hg_context_t *context, hg_addr_t addr, hg_id_t id,
    hg_handle_t *handle)
{
    hg_handle_t hg_handle = HG_HANDLE_NULL;
    hg_return_t ret = HG_SUCCESS;

    if (!handle) {
        HG_LOG_ERROR("NULL pointer to HG handle");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    ret = HG_Core_create(context, addr, id, &hg_handle);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Cannot create HG handle");
        goto done;
    }

    *handle = (hg_handle_t) hg_handle;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Destroy(hg_handle_t handle)
{
    return HG_Core_destroy(handle);
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Reset(hg_handle_t handle, hg_addr_t addr, hg_id_t id)
{
    return HG_Core_reset(handle, addr, id);
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Ref_incr(hg_handle_t handle)
{
    return HG_Core_ref_incr(handle);
}

/*---------------------------------------------------------------------------*/
const struct hg_info *
HG_Get_info(hg_handle_t handle)
{
    return HG_Core_get_info(handle);
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Get_input(hg_handle_t handle, void *in_struct)
{
    struct hg_private_data *hg_private_data;
    hg_return_t ret = HG_SUCCESS;

    if (!in_struct) {
        HG_LOG_ERROR("NULL pointer to input struct");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    /* Retrieve private data */
    hg_private_data =
        (struct hg_private_data *) HG_Core_get_private_data(handle);
    if (!hg_private_data) {
        HG_LOG_ERROR("Could not get private data");
        ret = HG_PROTOCOL_ERROR;
        goto done;
    }

    ret = hg_get_input(handle, hg_private_data, in_struct);
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
    struct hg_private_data *hg_private_data;
    hg_return_t ret = HG_SUCCESS;

    if (!in_struct) {
        HG_LOG_ERROR("NULL pointer to input struct");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    /* Retrieve private data */
    hg_private_data =
        (struct hg_private_data *) HG_Core_get_private_data(handle);
    if (!hg_private_data) {
        HG_LOG_ERROR("Could not get private data");
        ret = HG_PROTOCOL_ERROR;
        goto done;
    }

    ret = hg_free_input(handle, hg_private_data, in_struct);
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
    struct hg_private_data *hg_private_data;
    hg_return_t ret = HG_SUCCESS;

    if (!out_struct) {
        HG_LOG_ERROR("NULL pointer to output struct");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    /* Retrieve private data */
    hg_private_data =
        (struct hg_private_data *) HG_Core_get_private_data(handle);
    if (!hg_private_data) {
        HG_LOG_ERROR("Could not get private data");
        ret = HG_PROTOCOL_ERROR;
        goto done;
    }

    ret = hg_get_output(handle, hg_private_data, out_struct);
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
    struct hg_private_data *hg_private_data;
    hg_return_t ret = HG_SUCCESS;

    if (!out_struct) {
        HG_LOG_ERROR("NULL pointer to output struct");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    /* Retrieve private data */
    hg_private_data =
        (struct hg_private_data *) HG_Core_get_private_data(handle);
    if (!hg_private_data) {
        HG_LOG_ERROR("Could not get private data");
        ret = HG_PROTOCOL_ERROR;
        goto done;
    }

    ret = hg_free_output(handle, hg_private_data, out_struct);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not free output");
        goto done;
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Set_target_id(hg_handle_t handle, hg_uint8_t target_id)
{
    return HG_Core_set_target_id(handle, target_id);
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Forward(hg_handle_t handle, hg_cb_t callback, void *arg, void *in_struct)
{
    struct hg_private_data *hg_private_data;
    hg_size_t payload_size;
    hg_return_t ret = HG_SUCCESS;

    /* Retrieve private data */
    hg_private_data =
        (struct hg_private_data *) HG_Core_get_private_data(handle);
    if (!hg_private_data) {
        HG_LOG_ERROR("Could not get private data");
        ret = HG_PROTOCOL_ERROR;
        goto done;
    }
    hg_private_data->callback = callback;
    hg_private_data->arg = arg;

    /* Serialize input */
    ret = hg_set_input(handle, hg_private_data, in_struct, &payload_size);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not set input");
        goto done;
    }

    /* Send request */
    ret = HG_Core_forward(handle, hg_forward_cb, hg_private_data, payload_size);
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
    struct hg_private_data *hg_private_data;
    hg_size_t payload_size;
    hg_return_t ret = HG_SUCCESS;

    /* Retrieve private data */
    hg_private_data =
        (struct hg_private_data *) HG_Core_get_private_data(handle);
    if (!hg_private_data) {
        HG_LOG_ERROR("Could not get private data");
        ret = HG_PROTOCOL_ERROR;
        goto done;
    }
    hg_private_data->callback = callback;
    hg_private_data->arg = arg;

    /* Serialize output */
    ret = hg_set_output(handle, hg_private_data, out_struct, &payload_size);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not set output");
        goto done;
    }

    /* Send response back */
    ret = HG_Core_respond(handle, hg_respond_cb, hg_private_data, payload_size);
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
    return HG_Core_progress(context, timeout);
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Trigger(hg_context_t *context, unsigned int timeout, unsigned int max_count,
    unsigned int *actual_count)
{
    return HG_Core_trigger(context, timeout, max_count, actual_count);
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Cancel(hg_handle_t handle)
{
    return HG_Core_cancel(handle);
}
