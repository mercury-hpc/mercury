/*
 * Copyright (C) 2013-2016 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#include "mercury.h"

#include "mercury_hash_string.h"
#include "mercury_proc.h"
#include "mercury_proc_header.h"
#include "mercury_error.h"

#include <stdlib.h>
#include <string.h>

/****************/
/* Local Macros */
/****************/

/* Convert value to string */
#define HG_ERROR_STRING_MACRO(def, value, string) \
  if (value == def) string = #def

/************************************/
/* Local Type and Struct Definition */
/************************************/

/* Info for function map */
struct hg_proc_info {
    hg_proc_cb_t in_proc_cb;        /* Input Proc callback */
    hg_proc_cb_t out_proc_cb;       /* Output Proc callback */
    void *data;                     /* User data */
    void (*free_callback)(void *);  /* User data free callback */
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
 * Set private data.
 */
extern void
hg_core_set_private_data(
        struct hg_handle *hg_handle,
        void *private_data
        );

/**
 * Get private data.
 */
extern void *
hg_core_get_private_data(
        struct hg_handle *hg_handle
        );

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
        hg_size_t *extra_in_buf_size,
        hg_size_t *size_to_send
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
        void *out_struct,
        hg_size_t *size_to_send
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

/*---------------------------------------------------------------------------*/
/**
 * Free function for value in function map.
 */
static HG_INLINE void
hg_proc_info_free(void *arg)
{
    struct hg_proc_info *hg_proc_info = (struct hg_proc_info *) arg;

    if (hg_proc_info->free_callback)
        hg_proc_info->free_callback(hg_proc_info->data);
    free(hg_proc_info);
}

/*---------------------------------------------------------------------------*/
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
    ret = HG_Core_get_input(handle, &in_buf, &in_buf_size);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not get input buffer");
        goto done;
    }

    /* Get info from handle */
    hg_info = HG_Core_get_info(handle);

    /* Retrieve proc function from function map */
    hg_proc_info = (struct hg_proc_info *) hg_core_get_private_data(handle);
    if (!hg_proc_info) {
        HG_LOG_ERROR("Could not get proc info");
        ret = HG_NO_MATCH;
        goto done;
    }

    if (!hg_proc_info->in_proc_cb) goto done;

    /* Create a new decoding proc */
    ret = hg_proc_create(hg_info->hg_class, in_buf, in_buf_size, HG_DECODE,
            HG_CHECKSUM_DEFAULT, &proc);
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
        hg_size_t *extra_in_buf_size, hg_size_t *size_to_send)
{
    void *in_buf;
    hg_size_t in_buf_size;
    struct hg_info *hg_info;
    struct hg_proc_info *hg_proc_info;
    hg_proc_t proc = HG_PROC_NULL;
    hg_return_t ret = HG_SUCCESS;

    *size_to_send = hg_proc_header_request_get_size();

    if (!in_struct)
        goto done;

    /* Get input buffer */
    ret = HG_Core_get_input(handle, &in_buf, &in_buf_size);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not get input buffer");
        goto done;
    }

    /* Get info from handle */
    hg_info = HG_Core_get_info(handle);

    /* Retrieve proc function from function map */
    hg_proc_info = (struct hg_proc_info *) hg_core_get_private_data(handle);
    if (!hg_proc_info) {
        HG_LOG_ERROR("Could not get proc info");
        ret = HG_NO_MATCH;
        goto done;
    }

    if (!hg_proc_info->in_proc_cb) goto done;

    /* Create a new encoding proc */
    ret = hg_proc_create(hg_info->hg_class, in_buf, in_buf_size, HG_ENCODE,
            HG_CHECKSUM_DEFAULT, &proc);
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

    /* Flush proc */
    ret = hg_proc_flush(proc);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Error in proc flush");
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
        /* if the request fit in the initial buffer, then we have to add that
         * size to msg send
         */
        *size_to_send += hg_proc_get_size_used(proc);
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
    hg_info = HG_Core_get_info(handle);

    /* Retrieve proc function from function map */
    hg_proc_info = (struct hg_proc_info *) hg_core_get_private_data(handle);
    if (!hg_proc_info) {
        HG_LOG_ERROR("Could not get proc info");
        ret = HG_NO_MATCH;
        goto done;
    }

    if (!hg_proc_info->in_proc_cb) goto done;

    /* Create a new free proc */
    ret = hg_proc_create(hg_info->hg_class, NULL, 0, HG_FREE, HG_NOHASH, &proc);
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
    ret = HG_Core_get_output(handle, &out_buf, &out_buf_size);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not get output buffer");
        goto done;
    }

    /* Get info from handle */
    hg_info = HG_Core_get_info(handle);

    /* Retrieve proc function from function map */
    hg_proc_info = (struct hg_proc_info *) hg_core_get_private_data(handle);
    if (!hg_proc_info) {
        HG_LOG_ERROR("Could not get proc info");
        ret = HG_NO_MATCH;
        goto done;
    }

    if (!hg_proc_info->out_proc_cb) goto done;

    /* Create a new encoding proc */
    ret = hg_proc_create(hg_info->hg_class, out_buf, out_buf_size, HG_DECODE,
            HG_CHECKSUM_DEFAULT, &proc);
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
hg_set_output(hg_handle_t handle, void *out_struct, hg_size_t *size_to_send)
{
    void *out_buf;
    hg_size_t out_buf_size;
    struct hg_info *hg_info;
    struct hg_proc_info *hg_proc_info = NULL;
    hg_proc_t proc = HG_PROC_NULL;
    hg_return_t ret = HG_SUCCESS;
    *size_to_send = hg_proc_header_response_get_size();

    if (!out_struct) 
        goto done;

    /* Get output buffer */
    ret = HG_Core_get_output(handle, &out_buf, &out_buf_size);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not get output buffer");
        goto done;
    }

    /* Get info from handle */
    hg_info = HG_Core_get_info(handle);

    /* Retrieve proc function from function map */
    hg_proc_info = (struct hg_proc_info *) hg_core_get_private_data(handle);
    if (!hg_proc_info) {
        HG_LOG_ERROR("Could not get proc info");
        ret = HG_NO_MATCH;
        goto done;
    }

    if (!hg_proc_info->out_proc_cb) goto done;

    /* Create a new encoding proc */
    ret = hg_proc_create(hg_info->hg_class, out_buf, out_buf_size, HG_ENCODE,
            HG_CHECKSUM_DEFAULT, &proc);
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

    /* Flush proc */
    ret = hg_proc_flush(proc);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Error in proc flush");
        goto done;
    }

    /* Get eventual extra buffer
     * TODO need to do something here  */
    if (hg_proc_get_size(proc) > out_buf_size) {
        HG_LOG_WARNING("Output size exceeds NA expected message size");
        ret = HG_SIZE_ERROR;
        goto done;
    }

    /* add any encoded response size to the size to transmit */
    *size_to_send += hg_proc_get_size_used(proc);

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
    hg_info = HG_Core_get_info(handle);

    /* Retrieve proc function from function map */
    hg_proc_info = (struct hg_proc_info *) hg_core_get_private_data(handle);
    if (!hg_proc_info) {
        HG_LOG_ERROR("Could not get proc info");
        ret = HG_NO_MATCH;
        goto done;
    }

    if (!hg_proc_info->out_proc_cb) goto done;

    /* Create a new free proc */
    ret = hg_proc_create(hg_info->hg_class, NULL, 0, HG_FREE, HG_NOHASH, &proc);
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
    hg_return_t ret = HG_SUCCESS;

    /*
     * callback_info->type should be HG_CB_INTFORWARD.  we'll turn it
     * into a HG_CB_FORWARD and pass up to the user.
     */

    /* Free eventual extra input buffer and handle */
    HG_Bulk_free(callback_info->info.intforward.extra_in_handle);
    free(callback_info->info.intforward.extra_in_buf);

    /* Execute user callback */
    if (callback_info->info.intforward.usercb) {
        struct hg_cb_info hg_cb_info;

        hg_cb_info.arg = callback_info->info.intforward.userarg;
        hg_cb_info.ret = callback_info->ret;
        hg_cb_info.type = HG_CB_FORWARD;   /* converted from INTFORWARD */
        hg_cb_info.info.forward.handle =
            callback_info->info.intforward.handle;

        callback_info->info.intforward.usercb(&hg_cb_info);
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
    return HG_Core_init(na_info_string, na_listen);
}

/*---------------------------------------------------------------------------*/
hg_class_t *
HG_Init_na(na_class_t *na_class, na_context_t *na_context)
{
    return HG_Core_init_na(na_class, na_context);
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Finalize(hg_class_t *hg_class)
{
    return HG_Core_finalize(hg_class);
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
hg_context_t *
HG_Context_create(hg_class_t *hg_class)
{
    return HG_Core_context_create(hg_class);
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Context_destroy(hg_context_t *context)
{
    return HG_Core_context_destroy(context);
}

/*---------------------------------------------------------------------------*/
hg_class_t *
HG_Context_get_class(hg_context_t *context)
{
    return HG_Core_context_get_class(context);
}

/*---------------------------------------------------------------------------*/
hg_id_t
HG_Register_name(hg_class_t *hg_class, const char *func_name, hg_proc_cb_t in_proc_cb,
    hg_proc_cb_t out_proc_cb, hg_rpc_cb_t rpc_cb)
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
HG_Register(hg_class_t *hg_class, hg_id_t id, hg_proc_cb_t in_proc_cb,
    hg_proc_cb_t out_proc_cb, hg_rpc_cb_t rpc_cb)
{
    struct hg_proc_info *hg_proc_info = NULL;
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
    hg_proc_info->data = NULL;
    hg_proc_info->free_callback = NULL;

    /* Register RPC callback */
    ret = HG_Core_register(hg_class, id, rpc_cb);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not register RPC id");
        goto done;
    }

    /* Attach proc info to RPC ID */
    ret = HG_Core_register_data(hg_class, id, hg_proc_info, hg_proc_info_free);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not set proc info");
        goto done;
    }

done:
    if (ret != HG_SUCCESS) {
        free(hg_proc_info);
    }
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Register_data(hg_class_t *hg_class, hg_id_t id, void *data,
    void (*free_callback)(void *))
{
    struct hg_proc_info *hg_proc_info = NULL;
    hg_return_t ret = HG_SUCCESS;

    /* Retrieve proc function from function map */
    hg_proc_info = (struct hg_proc_info *) HG_Core_registered_data(hg_class, id);
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
    hg_proc_info = (struct hg_proc_info *) HG_Core_registered_data(hg_class, id);
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
    struct hg_handle *hg_handle = NULL;
    struct hg_proc_info *hg_proc_info = NULL;
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
    hg_proc_info = (struct hg_proc_info *)
        HG_Core_registered_data(HG_Core_context_get_class(context), id);
    if (!hg_proc_info) {
        HG_LOG_ERROR("Could not get registered data");
        goto done;
    }
    hg_core_set_private_data(hg_handle, hg_proc_info);

    *handle = (hg_handle_t) hg_handle;

done:
    return HG_SUCCESS;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Destroy(hg_handle_t handle)
{
    return HG_Core_destroy(handle);
}

/*---------------------------------------------------------------------------*/
struct hg_info *
HG_Get_info(hg_handle_t handle)
{
    return HG_Core_get_info(handle);
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
    hg_bulk_t extra_in_handle = HG_BULK_NULL;
    void *extra_in_buf = NULL;
    hg_size_t extra_in_buf_size;
    hg_return_t ret = HG_SUCCESS;
    hg_size_t size_to_send;

    /* Serialize input */
    ret = hg_set_input(handle, in_struct, &extra_in_buf, &extra_in_buf_size,
                       &size_to_send);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not set input");
        goto done;
    }

    if (extra_in_buf) {
        struct hg_info *hg_info = HG_Core_get_info(handle);

        ret = HG_Bulk_create(hg_info->hg_class, 1, &extra_in_buf,
                &extra_in_buf_size, HG_BULK_READ_ONLY, &extra_in_handle);
        if (ret != HG_SUCCESS) {
            HG_LOG_ERROR("Could not create bulk data handle");
            goto done;
        }
    }

    /* Send request */
    ret = HG_Core_forward(handle, hg_forward_cb, callback, arg, extra_in_buf,
                          extra_in_handle, size_to_send);
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
    hg_return_t ret = HG_SUCCESS;
    hg_return_t ret_code = HG_SUCCESS;
    hg_size_t size_to_send;

    /* Serialize output */
    ret = hg_set_output(handle, out_struct, &size_to_send);
    if (ret != HG_SUCCESS) {
        if (ret == HG_SIZE_ERROR)
            ret_code = HG_SIZE_ERROR;
        else {
            HG_LOG_ERROR("Could not set output");
            goto done;
        }
    }

    /* Send response back */
    ret = HG_Core_respond(handle, callback, arg, ret_code, size_to_send);
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
