/*
 * Copyright (C) 2013-2014 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#include "mercury.h"

#include "mercury_proc.h"
#include "mercury_error.h"

#include <stdlib.h>
#include <string.h>

/****************/
/* Local Macros */
/****************/

/************************************/
/* Local Type and Struct Definition */
/************************************/

/* Info for function map */
struct hg_proc_info {
    hg_proc_cb_t in_proc_cb;
    hg_proc_cb_t out_proc_cb;
};

/* Info for wrapping forward callback */
struct hg_forward_cb_info {
    hg_cb_t callback;
    void *arg;
    hg_bulk_t extra_in_handle;
    void *extra_in_buf;
};

/********************/
/* Local Prototypes */
/********************/

/**
 * Decode and get input structure.
 */
static hg_return_t
hg_get_input(
        hg_handle_t handle,
        void *in_struct
        );

/**
 * Set and encode input structure.
 */
static hg_return_t
hg_set_input(
        hg_handle_t handle,
        void *in_struct,
        void **extra_in_buf,
        hg_size_t *extra_in_buf_size
        );

/**
 * Free allocated members from input structure.
 */
static hg_return_t
hg_free_input(
        hg_handle_t handle,
        void *in_struct
        );

/**
 * Decode and get output structure.
 */
static hg_return_t
hg_get_output(
        hg_handle_t handle,
        void *out_struct
        );

/**
 * Set and encode output structure.
 */
static hg_return_t
hg_set_output(
        hg_handle_t handle,
        void *out_struct
        );

/**
 * Free allocated members from output structure.
 */
static hg_return_t
hg_free_output(
        hg_handle_t handle,
        void *out_struct
        );

/**
 * Forward callback.
 */
static hg_return_t
hg_forward_cb(
        const struct hg_cb_info *callback_info
        );

/*******************/
/* Local Variables */
/*******************/

static hg_return_t
hg_get_input(hg_handle_t handle, void *in_struct)
{
    void *in_buf;
    hg_size_t in_buf_size;
    struct hg_info *hg_info;
    struct hg_proc_info *hg_proc_info;
    hg_proc_t proc = HG_PROC_NULL;
    hg_return_t ret = HG_SUCCESS;

    if (!in_struct) goto done;

    /* Get input buffer */
    ret = HG_Get_input_buf(handle, &in_buf, &in_buf_size);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not get input buffer");
        goto done;
    }

    /* Get info from handle */
    hg_info = HG_Get_info(handle);

    /* Retrieve proc function from function map */
    hg_proc_info = (struct hg_proc_info *) HG_Registered_data(hg_info->hg_class,
            hg_info->id);
    if (!hg_proc_info) {
        HG_LOG_ERROR("Could not get registered data");
        ret = HG_NO_MATCH;
        goto done;
    }

    if (!hg_proc_info->in_proc_cb) goto done;

    /* Create a new decoding proc */
    ret = hg_proc_create(in_buf, in_buf_size, HG_DECODE, HG_CRC64,
            hg_info->hg_bulk_class, &proc);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not create proc");
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

done:
    if (proc != HG_PROC_NULL) hg_proc_free(proc);
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_set_input(hg_handle_t handle, void *in_struct, void **extra_in_buf,
        hg_size_t *extra_in_buf_size)
{
    void *in_buf;
    hg_size_t in_buf_size;
    struct hg_info *hg_info;
    struct hg_proc_info *hg_proc_info;
    hg_proc_t proc = HG_PROC_NULL;
    hg_return_t ret = HG_SUCCESS;

    if (!in_struct) goto done;

    /* Get input buffer */
    ret = HG_Get_input_buf(handle, &in_buf, &in_buf_size);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not get input buffer");
        goto done;
    }

    /* Get info from handle */
    hg_info = HG_Get_info(handle);

    /* Retrieve proc function from function map */
    hg_proc_info = (struct hg_proc_info *) HG_Registered_data(hg_info->hg_class,
            hg_info->id);
    if (!hg_proc_info) {
        HG_LOG_ERROR("Could not get registered data");
        ret = HG_NO_MATCH;
        goto done;
    }

    if (!hg_proc_info->in_proc_cb) goto done;

    /* Create a new encoding proc */
    ret = hg_proc_create(in_buf, in_buf_size, HG_ENCODE, HG_CRC64,
            hg_info->hg_bulk_class, &proc);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not create proc");
        goto done;
    }

    /* Encode input parameters */
    ret = hg_proc_info->in_proc_cb(proc, in_struct);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not encode parameters");
        goto done;
    }

    /* The size of the encoding buffer may have changed at this point
     * --> if the buffer is too large, we need to do:
     *  - 1: send an unexpected message with info + eventual bulk data descriptor
     *  - 2: send the remaining data in extra buf using bulk data transfer
     */
    if (hg_proc_get_size(proc) > in_buf_size) {
#ifdef HG_HAS_XDR
        HG_LOG_ERROR("Extra encoding using XDR is not yet supported");
        ret = HG_SIZE_ERROR;
        goto done;
#else
        *extra_in_buf = hg_proc_get_extra_buf(proc);
        *extra_in_buf_size = hg_proc_get_extra_size(proc);
        /* Prevent buffer from being freed when proc_free is called */
        hg_proc_set_extra_buf_is_mine(proc, HG_TRUE);
#endif
    } else {
        *extra_in_buf = NULL;
        *extra_in_buf_size = 0;
    }

    /* Flush proc */
    ret = hg_proc_flush(proc);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Error in proc flush");
        goto done;
    }

done:
    if (proc != HG_PROC_NULL) hg_proc_free(proc);
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_free_input(hg_handle_t handle, void *in_struct)
{
    struct hg_info *hg_info;
    struct hg_proc_info *hg_proc_info;
    hg_proc_t proc = HG_PROC_NULL;
    hg_return_t ret = HG_SUCCESS;

    if (!in_struct) goto done;

    /* Get info from handle */
    hg_info = HG_Get_info(handle);

    /* Retrieve proc function from function map */
    hg_proc_info = (struct hg_proc_info *) HG_Registered_data(hg_info->hg_class,
            hg_info->id);
    if (!hg_proc_info) {
        HG_LOG_ERROR("Could not get registered data");
        ret = HG_NO_MATCH;
        goto done;
    }

    if (!hg_proc_info->in_proc_cb) goto done;

    /* Create a new free proc */
    ret = hg_proc_create(NULL, 0, HG_FREE, HG_NOHASH, hg_info->hg_bulk_class,
            &proc);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not create proc");
        goto done;
    }

    /* Free memory allocated during decode operation */
    ret = hg_proc_info->in_proc_cb(proc, in_struct);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not free allocated parameters");
        goto done;
    }

done:
    if (proc != HG_PROC_NULL) hg_proc_free(proc);
    proc = HG_PROC_NULL;

    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_get_output(hg_handle_t handle, void *out_struct)
{
    void *out_buf;
    hg_size_t out_buf_size;
    struct hg_info *hg_info;
    struct hg_proc_info *hg_proc_info;
    hg_proc_t proc = HG_PROC_NULL;
    hg_return_t ret = HG_SUCCESS;

    if (!out_struct) goto done;

    /* Get output buffer */
    ret = HG_Get_output_buf(handle, &out_buf, &out_buf_size);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not get output buffer");
        goto done;
    }

    /* Get info from handle */
    hg_info = HG_Get_info(handle);

    /* Retrieve proc function from function map */
    hg_proc_info = (struct hg_proc_info *) HG_Registered_data(hg_info->hg_class,
            hg_info->id);
    if (!hg_proc_info) {
        HG_LOG_ERROR("Could not get registered data");
        ret = HG_NO_MATCH;
        goto done;
    }

    if (!hg_proc_info->out_proc_cb) goto done;

    /* Create a new encoding proc */
    ret = hg_proc_create(out_buf, out_buf_size, HG_DECODE, HG_CRC64,
            hg_info->hg_bulk_class, &proc);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not create proc");
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

done:
    if (proc != HG_PROC_NULL) hg_proc_free(proc);
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_set_output(hg_handle_t handle, void *out_struct)
{
    void *out_buf;
    hg_size_t out_buf_size;
    struct hg_info *hg_info;
    struct hg_proc_info *hg_proc_info = NULL;
    hg_proc_t proc = HG_PROC_NULL;
    hg_return_t ret = HG_SUCCESS;

    if (!out_struct) goto done;

    /* Get output buffer */
    ret = HG_Get_output_buf(handle, &out_buf, &out_buf_size);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not get output buffer");
        goto done;
    }

    /* Get info from handle */
    hg_info = HG_Get_info(handle);

    /* Retrieve proc function from function map */
    hg_proc_info = (struct hg_proc_info *) HG_Registered_data(hg_info->hg_class,
            hg_info->id);
    if (!hg_proc_info) {
        HG_LOG_ERROR("Could not get registered data");
        ret = HG_NO_MATCH;
        goto done;
    }

    if (!hg_proc_info->out_proc_cb) goto done;

    /* Create a new encoding proc */
    ret = hg_proc_create(out_buf, out_buf_size, HG_ENCODE, HG_CRC64,
            hg_info->hg_bulk_class, &proc);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not create proc");
        goto done;
    }

    /* Encode output parameters */
    ret = hg_proc_info->out_proc_cb(proc, out_struct);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not encode output parameters");
        goto done;
    }

    /* Get eventual extra buffer
     * TODO need to do something here  */
    if (hg_proc_get_size(proc) > out_buf_size) {
        HG_LOG_WARNING("Output size exceeds NA expected message size");
        ret = HG_SIZE_ERROR;
        goto done;
    }

    /* Flush proc */
    ret = hg_proc_flush(proc);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Error in proc flush");
        goto done;
    }

done:
    if (proc != HG_PROC_NULL) hg_proc_free(proc);
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_free_output(hg_handle_t handle, void *out_struct)
{
    struct hg_info *hg_info;
    struct hg_proc_info *hg_proc_info;
    hg_proc_t proc = HG_PROC_NULL;
    hg_return_t ret = HG_SUCCESS;

    if (!out_struct) goto done;

    /* Get info from handle */
    hg_info = HG_Get_info(handle);

    /* Retrieve proc function from function map */
    hg_proc_info = (struct hg_proc_info *) HG_Registered_data(hg_info->hg_class,
            hg_info->id);
    if (!hg_proc_info) {
        HG_LOG_ERROR("Could not get registered data");
        ret = HG_NO_MATCH;
        goto done;
    }

    if (!hg_proc_info->out_proc_cb) goto done;

    /* Create a new free proc */
    ret = hg_proc_create(NULL, 0, HG_FREE, HG_NOHASH, hg_info->hg_bulk_class,
            &proc);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not create proc");
        goto done;
    }

    /* Free memory allocated during output decoding */
    ret = hg_proc_info->out_proc_cb(proc, out_struct);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not free allocated parameters");
        goto done;
    }

done:
    if (proc != HG_PROC_NULL) hg_proc_free(proc);
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_forward_cb(const struct hg_cb_info *callback_info)
{
    struct hg_forward_cb_info *hg_forward_cb_info =
            (struct hg_forward_cb_info *) callback_info->arg;
    hg_return_t ret = HG_SUCCESS;

    /* Free eventual extra input buffer and handle */
    HG_Bulk_free(hg_forward_cb_info->extra_in_handle);
    free(hg_forward_cb_info->extra_in_buf);

    /* Execute callback */
    if (hg_forward_cb_info->callback) {
        struct hg_cb_info hg_cb_info;

        hg_cb_info.arg = hg_forward_cb_info->arg;
        hg_cb_info.ret = callback_info->ret;
        hg_cb_info.hg_class = callback_info->hg_class;
        hg_cb_info.context = callback_info->context;
        hg_cb_info.handle = callback_info->handle;

        hg_forward_cb_info->callback(&hg_cb_info);
    }

    free(hg_forward_cb_info);
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_id_t
HG_Register(hg_class_t *hg_class, const char *func_name, hg_proc_cb_t in_proc_cb,
        hg_proc_cb_t out_proc_cb, hg_rpc_cb_t rpc_cb)
{
    struct hg_proc_info *hg_proc_info = NULL;
    hg_id_t id = 0;
    hg_return_t ret = HG_SUCCESS;

    if (!hg_class) {
        HG_LOG_ERROR("NULL HG class");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    hg_proc_info = (struct hg_proc_info *) malloc(sizeof(struct hg_proc_info));
    if (!hg_proc_info) {
        HG_LOG_ERROR("Could not allocate proc info");
        ret = HG_NOMEM_ERROR;
        goto done;
    }

    hg_proc_info->in_proc_cb = in_proc_cb;
    hg_proc_info->out_proc_cb = out_proc_cb;

    /* Register RPC callback */
    id = HG_Register_rpc(hg_class, func_name, rpc_cb);

    /* Attach proc info to RPC ID */
    ret = HG_Register_data(hg_class, id, hg_proc_info, free);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not set proc info");
        goto done;
    }

done:
    return id;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Get_input(hg_handle_t handle, void *in_struct)
{
    hg_return_t ret = HG_SUCCESS;

    if (!in_struct) {
        HG_LOG_ERROR("NULL pointer to input struct");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    ret = hg_get_input(handle, in_struct);
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
    hg_return_t ret = HG_SUCCESS;

    if (!in_struct) {
        HG_LOG_ERROR("NULL pointer to input struct");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    ret = hg_free_input(handle, in_struct);
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
    hg_return_t ret = HG_SUCCESS;

    if (!out_struct) {
        HG_LOG_ERROR("NULL pointer to output struct");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    ret = hg_get_output(handle, out_struct);
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
    hg_return_t ret = HG_SUCCESS;

    if (!out_struct) {
        HG_LOG_ERROR("NULL pointer to output struct");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    ret = hg_free_output(handle, out_struct);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not free output");
        goto done;
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Forward(hg_handle_t handle, hg_cb_t callback, void *arg, void *in_struct)
{
    struct hg_forward_cb_info *hg_forward_cb_info = NULL;
    hg_bulk_t extra_in_handle = HG_BULK_NULL;
    void *extra_in_buf = NULL;
    hg_size_t extra_in_buf_size;
    hg_return_t ret = HG_SUCCESS;

    hg_forward_cb_info = (struct hg_forward_cb_info *) malloc(
            sizeof(struct hg_forward_cb_info));
    if (!hg_forward_cb_info) {
        HG_LOG_ERROR("Could not allocate HG forward callback info");
        ret = HG_NOMEM_ERROR;
        goto done;
    }
    hg_forward_cb_info->callback = callback;
    hg_forward_cb_info->arg = arg;
    hg_forward_cb_info->extra_in_handle = HG_BULK_NULL;
    hg_forward_cb_info->extra_in_buf = NULL;

    /* Serialize input */
    ret = hg_set_input(handle, in_struct, &extra_in_buf, &extra_in_buf_size);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not set input");
        goto done;
    }

    if (extra_in_buf) {
        struct hg_info *hg_info = HG_Get_info(handle);

        ret = HG_Bulk_create(hg_info->hg_bulk_class, 1, &extra_in_buf,
                &extra_in_buf_size, HG_BULK_READ_ONLY, &extra_in_handle);
        if (ret != HG_SUCCESS) {
            HG_LOG_ERROR("Could not create bulk data handle");
            goto done;
        }
        hg_forward_cb_info->extra_in_handle = extra_in_handle;
        hg_forward_cb_info->extra_in_buf = extra_in_buf;
    }

    /* Send request */
    ret = HG_Forward_buf(handle, hg_forward_cb, hg_forward_cb_info,
            extra_in_handle);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not forward call");
        goto done;
    }

done:
    if (ret != HG_SUCCESS) {
        free(hg_forward_cb_info);
    }
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Respond(hg_handle_t handle, hg_cb_t callback, void *arg, void *out_struct)
{
    hg_return_t ret = HG_SUCCESS;
    hg_return_t ret_code = HG_SUCCESS;

    /* Serialize output */
    ret = hg_set_output(handle, out_struct);
    if (ret != HG_SUCCESS) {
        if (ret == HG_SIZE_ERROR)
            ret_code = HG_SIZE_ERROR;
        else {
            HG_LOG_ERROR("Could not set output");
            goto done;
        }
    }

    /* Send response back */
    ret = HG_Respond_buf(handle, callback, arg, ret_code);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not respond");
        goto done;
    }

done:
    return ret;
}
