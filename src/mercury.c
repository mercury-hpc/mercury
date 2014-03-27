/*
 * Copyright (C) 2013 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#include "mercury.h"
#include "mercury_proc_header.h"
#include "mercury_proc.h"
#include "mercury_bulk.h"

#include "mercury_private.h"

#include "mercury_hash_table.h"
#include "mercury_hash_string.h"
#include "mercury_atomic.h"
#include "mercury_time.h"
#include "mercury_request.h"

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


/********************/
/* Local Prototypes */
/********************/

/**
 * Get RPC input buffer from handle.
 */
static hg_return_t hg_get_input_buf(struct hg_handle *hg_handle,
        void **in_buf, size_t *in_buf_size);
/**
 * Get RPC output buffer from handle.
 */
static hg_return_t hg_get_output_buf(struct hg_handle *hg_handle,
        void **out_buf, size_t *out_buf_size);
/**
 * Set and encode input structure.
 */
static hg_return_t hg_set_input(struct hg_handle *hg_handle,
        void *in_struct);
/**
 * Decode and get output structure.
 */
static hg_return_t hg_get_output(struct hg_handle *hg_handle,
        void *out_struct);

/**
 * Free allocated members from output structure.
 */
static hg_return_t hg_free_output(struct hg_handle *hg_handle,
        void *out_struct);

/**
 * Send input callback.
 */
static na_return_t hg_send_input_cb(const struct na_cb_info *callback_info);

/**
 * Recv output callback.
 */
static na_return_t hg_recv_output_cb(const struct na_cb_info *callback_info);

/**
 * Progress for request emulation.
 */
int
hg_request_progress_func(unsigned int timeout, void *arg);

/**
 * Trigger for request emulation.
 */
int
hg_request_trigger_func(unsigned int timeout, unsigned int *flag, void *arg);

/*******************/
/* Local Variables */
/*******************/

/* Pointer to NA class */
na_class_t *hg_na_class_g = NULL;
extern na_class_t *hg_bulk_na_class_g;

/* Local context */
na_context_t *hg_context_g = NULL;
extern na_context_t *hg_bulk_context_g;

/* Request class */
hg_request_class_t *hg_request_class_g = NULL;
extern hg_request_class_t *hg_bulk_request_class_g;

/* Bulk interface internally initialized */
static hg_bool_t hg_bulk_initialized_internal_g = HG_FALSE;

/* Function map */
hg_hash_table_t *hg_func_map_g = NULL;

/* Atomic used for tag generation */
static hg_atomic_int32_t hg_request_tag_g;
static na_tag_t hg_request_max_tag_g = 0;

/*---------------------------------------------------------------------------*/
/**
 * Hash function for function map.
 */
static HG_INLINE int
hg_int_equal(void *vlocation1, void *vlocation2)
{
    return *((int *) vlocation1) == *((int *) vlocation2);
}

/*---------------------------------------------------------------------------*/
/**
 * Hash function for function map.
 */
static HG_INLINE unsigned int
hg_int_hash(void *vlocation)
{
    return *((unsigned int *) vlocation);
}

/*---------------------------------------------------------------------------*/
/**
 * Generate a new tag.
 */
static HG_INLINE na_tag_t
hg_gen_request_tag(void)
{
    na_tag_t tag;

    /* Compare and swap tag if reached max tag */
    if (hg_atomic_cas32(&hg_request_tag_g, hg_request_max_tag_g, 0)) {
        tag = 0;
    } else {
        /* Increment tag */
        tag = hg_atomic_incr32(&hg_request_tag_g);
    }

    return tag;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_get_input_buf(struct hg_handle *hg_handle, void **in_buf,
        size_t *in_buf_size)
{
    void *user_input_buf;
    size_t user_input_buf_size;
    size_t header_offset;
    hg_return_t ret = HG_SUCCESS;

    if (!hg_handle) {
        HG_ERROR_DEFAULT("NULL handle");
        ret = HG_FAIL;
        goto done;
    }

    user_input_buf = hg_handle->send_buf;
    user_input_buf_size = hg_handle->send_buf_size;
    header_offset = hg_proc_header_request_get_size();

    /* Space left for request header */
    if (in_buf) *in_buf = (char*) user_input_buf + header_offset;
    if (in_buf_size) *in_buf_size = user_input_buf_size - header_offset;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_get_output_buf(struct hg_handle *hg_handle, void **out_buf,
        size_t *out_buf_size)
{
    void *user_output_buf;
    size_t user_output_buf_size;
    size_t header_offset;
    hg_return_t ret = HG_SUCCESS;

    if (!hg_handle) {
        HG_ERROR_DEFAULT("NULL handle");
        ret = HG_FAIL;
        goto done;
    }

    user_output_buf = hg_handle->recv_buf;
    user_output_buf_size = hg_handle->recv_buf_size;
    header_offset = hg_proc_header_response_get_size();

    /* Space must be left for request header */
    if (out_buf) *out_buf = (char*) user_output_buf + header_offset;
    if (out_buf_size) *out_buf_size = user_output_buf_size - header_offset;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_set_input(struct hg_handle *hg_handle, void *in_struct)
{
    void *in_buf;
    size_t in_buf_size;
    struct hg_info *info;
    hg_proc_t proc = HG_PROC_NULL;
    hg_return_t ret = HG_SUCCESS;

    if (!hg_handle) {
        HG_ERROR_DEFAULT("NULL handle");
        ret = HG_FAIL;
        goto done;
    }

    if (!in_struct) goto done;

    /* Get input buffer */
    ret = hg_get_input_buf(hg_handle, &in_buf, &in_buf_size);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Could not get input buffer");
        goto done;
    }

    /* Retrieve encoding function from function map */
    info = (struct hg_info *) hg_hash_table_lookup(hg_func_map_g,
            (hg_hash_table_key_t) &hg_handle->id);
    if (!info) {
        HG_ERROR_DEFAULT("hg_hash_table_lookup failed");
        ret = HG_FAIL;
        goto done;
    }

    if (!info->input_proc_cb) goto done;

    /* Create a new encoding proc */
    ret = hg_proc_create(in_buf, in_buf_size, HG_ENCODE, HG_CRC64, &proc);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Could not create proc");
        goto done;
    }

    /* Encode input parameters */
    ret = info->input_proc_cb(proc, in_struct);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Could not encode parameters");
        goto done;
    }

    /* The size of the encoding buffer may have changed at this point
     * --> if the buffer is too large, we need to do:
     *  - 1: send an unexpected message with info + eventual bulk data descriptor
     *  - 2: send the remaining data in extra buf using bulk data transfer
     */
    if (hg_proc_get_size(proc) > hg_handle->send_buf_size) {
#ifdef HG_HAS_XDR
        HG_ERROR_DEFAULT("Extra encoding using XDR is not yet supported");
        ret = HG_FAIL;
        goto done;
#else
        hg_handle->extra_send_buf = hg_proc_get_extra_buf(proc);
        hg_handle->extra_send_buf_size = hg_proc_get_extra_size(proc);
        ret = HG_Bulk_handle_create(hg_handle->extra_send_buf,
                hg_handle->extra_send_buf_size, HG_BULK_READ_ONLY,
                &hg_handle->extra_send_buf_handle);
        if (ret != HG_SUCCESS) {
            HG_ERROR_DEFAULT("Could not create bulk data handle");
            goto done;
        }
        hg_proc_set_extra_buf_is_mine(proc, HG_TRUE);
#endif
    }

    /* Flush proc */
    ret = hg_proc_flush(proc);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Error in proc flush");
        goto done;
    }

done:
    if (proc != HG_PROC_NULL) hg_proc_free(proc);
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_get_output(struct hg_handle *hg_handle, void *out_struct)
{
    void *out_buf;
    size_t out_buf_size;
    struct hg_info *info;
    hg_proc_t proc = HG_PROC_NULL;
    hg_return_t ret = HG_SUCCESS;

    if (!hg_handle) {
        HG_ERROR_DEFAULT("NULL handle");
        ret = HG_FAIL;
        goto done;
    }

    if (!out_struct) goto done;

    /* Get output buffer */
    ret = hg_get_output_buf(hg_handle, &out_buf, &out_buf_size);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Could not get input buffer");
        goto done;
    }

    /* Retrieve encoding function from function map */
    info = (struct hg_info *) hg_hash_table_lookup(hg_func_map_g,
            (hg_hash_table_key_t) &hg_handle->id);
    if (!info) {
        HG_ERROR_DEFAULT("hg_hash_table_lookup failed");
        ret = HG_FAIL;
        goto done;
    }

    if (!info->output_proc_cb) goto done;

    /* Create a new encoding proc */
    ret = hg_proc_create(out_buf, out_buf_size, HG_DECODE, HG_CRC64, &proc);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Could not create proc");
        goto done;
    }

    /* Decode output parameters */
    ret = info->output_proc_cb(proc, out_struct);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Could not decode parameters");
        goto done;
    }

    /* Flush proc */
    ret = hg_proc_flush(proc);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Error in proc flush");
        goto done;
    }

done:
    if (proc != HG_PROC_NULL) hg_proc_free(proc);
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_free_output(struct hg_handle *hg_handle, void *out_struct)
{
    struct hg_info *info;
    hg_proc_t proc = HG_PROC_NULL;
    hg_return_t ret = HG_SUCCESS;

    if (!hg_handle) {
        HG_ERROR_DEFAULT("NULL handle");
        ret = HG_FAIL;
        goto done;
    }

    if (!out_struct) goto done;

    /* Retrieve encoding function from function map */
    info = (struct hg_info *) hg_hash_table_lookup(hg_func_map_g,
            (hg_hash_table_key_t) &hg_handle->id);
    if (!info) {
        HG_ERROR_DEFAULT("hg_hash_table_lookup failed");
        ret = HG_FAIL;
        goto done;
    }

    if (!info->output_proc_cb) goto done;

    /* Create a new free proc */
    ret = hg_proc_create(NULL, 0, HG_FREE, HG_NOHASH, &proc);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Could not create proc");
        goto done;
    }

    /* Free memory allocated during output decoding */
    ret = info->output_proc_cb(proc, hg_handle->out_struct);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Could not free allocated parameters");
        goto done;
    }

done:
    if (proc != HG_PROC_NULL) hg_proc_free(proc);
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
hg_send_input_cb(const struct na_cb_info *callback_info)
{
    struct hg_handle *hg_handle = (struct hg_handle *) callback_info->arg;
    na_return_t ret = NA_SUCCESS;

    if (callback_info->ret != NA_SUCCESS) {
        return ret;
    }

    /* Everything has been sent so free unused resources except extra buffer */
    if (hg_handle->send_buf) hg_proc_buf_free(hg_handle->send_buf);
    hg_handle->send_buf = NULL;
    hg_handle->send_buf_size = 0;

    /* Mark request as completed */
    hg_request_complete(hg_handle->send_request);

    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
hg_recv_output_cb(const struct na_cb_info *callback_info)
{
    struct hg_handle *hg_handle = (struct hg_handle *) callback_info->arg;
    struct hg_header_response response_header;
    hg_return_t ret = HG_SUCCESS; /* TODO embed ret into hg_handle */
    na_return_t na_ret = NA_SUCCESS;

    if (callback_info->ret != NA_SUCCESS) {
        goto done;
    }

    /* Now we can free the extra send buf now since we received the response */
    if (hg_handle->extra_send_buf) free(hg_handle->extra_send_buf);
    hg_handle->extra_send_buf = NULL;
    hg_handle->extra_send_buf_size = 0;
    if (hg_handle->extra_send_buf_handle != HG_BULK_NULL)
        HG_Bulk_handle_free(hg_handle->extra_send_buf_handle);
    hg_handle->extra_send_buf_handle = HG_BULK_NULL;

    /* Decode response header */
    ret = hg_proc_header_response(hg_handle->recv_buf,
            hg_handle->recv_buf_size, &response_header, HG_DECODE);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Could not decode header");
        goto done;
    }

    /* Verify header */
    ret = hg_proc_header_response_verify(response_header);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Could not verify header");
        goto done;
    }

    /* Decode the function output parameters */
    ret = hg_get_output(hg_handle, hg_handle->out_struct);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Could not get output");
        goto done;
    }

    /* Everything has been decoded so free unused resources */
    if (hg_handle->recv_buf) hg_proc_buf_free(hg_handle->recv_buf);
    hg_handle->recv_buf = NULL;
    hg_handle->recv_buf_size = 0;

    /* Mark request as completed */
    hg_request_complete(hg_handle->recv_request);

done:
    return na_ret;
}

/*---------------------------------------------------------------------------*/
int
hg_request_progress_func(unsigned int timeout, void *arg)
{
    struct hg_context *hg_context = (struct hg_context *) arg;
    int ret = HG_UTIL_SUCCESS;
    na_return_t na_ret;

    (void) arg;
    na_ret = NA_Progress(hg_context->na_class, hg_context->na_context, timeout);
    if (na_ret != NA_SUCCESS) ret = HG_UTIL_FAIL;

    return ret;
}

/*---------------------------------------------------------------------------*/
int
hg_request_trigger_func(unsigned int timeout, unsigned int *flag, void *arg)
{
    struct hg_context *hg_context = (struct hg_context *) arg;
    int ret = HG_UTIL_SUCCESS;
    unsigned int actual_count;
    na_return_t na_ret;

    (void) arg;
    na_ret = NA_Trigger(hg_context->na_context, timeout, 1, &actual_count);
    if (na_ret != NA_SUCCESS) ret = HG_UTIL_FAIL;
    *flag = (actual_count) ? HG_UTIL_TRUE : HG_UTIL_FALSE;

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
hg_return_t
HG_Init(na_class_t *na_class)
{
    hg_bool_t bulk_initialized = HG_FALSE;
    hg_return_t ret = HG_SUCCESS;

    if (!na_class) {
        HG_ERROR_DEFAULT("Invalid specified na_class");
        ret = HG_FAIL;
        return ret;
    }

    if (hg_na_class_g) {
        HG_ERROR_DEFAULT("Already initialized");
        ret = HG_FAIL;
        return ret;
    }

    hg_na_class_g = na_class;

    /* Create local context if na_class different from hg_bulk_class */
    if (hg_bulk_na_class_g == hg_na_class_g) {
        hg_context_g = hg_bulk_context_g;
        hg_request_class_g = hg_bulk_request_class_g;
    } else {
        static struct hg_context hg_context;

        /* Not initialized yet so must initialize */
        hg_context_g = NA_Context_create(hg_na_class_g);
        if (!hg_context_g) {
            HG_ERROR_DEFAULT("Could not create context.");
            ret = HG_FAIL;
            return ret;
        }

        hg_context.na_class = hg_na_class_g;
        hg_context.na_context = hg_context_g;

        hg_request_class_g = hg_request_init(
                hg_request_progress_func,
                hg_request_trigger_func, &hg_context);
    }

    /* Initialize bulk module */
    HG_Bulk_initialized(&bulk_initialized, NULL);
    if (!bulk_initialized) {
        ret = HG_Bulk_init(na_class);
        if (ret != HG_SUCCESS)
        {
            HG_ERROR_DEFAULT("Error initializing bulk module.");
            ret = HG_FAIL;
            return ret;
        }
    }
    hg_bulk_initialized_internal_g = (hg_bool_t) (!bulk_initialized);
    
    /* Initialize atomic for tags */
    hg_request_max_tag_g = NA_Msg_get_max_tag(hg_na_class_g);
    hg_atomic_set32(&hg_request_tag_g, 0);

    /* Create new function map */
    hg_func_map_g = hg_hash_table_new(hg_int_hash, hg_int_equal);
    if (!hg_func_map_g) {
        HG_ERROR_DEFAULT("Could not create function map");
        ret = HG_FAIL;
    }
    /* Automatically free all the values with the hash map */
    hg_hash_table_register_free_functions(hg_func_map_g, free, free);

    /* Initialize handler */
    hg_handler_init();

    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Finalize(void)
{
    hg_return_t ret = HG_SUCCESS;
    na_return_t na_ret;

    if (!hg_na_class_g) {
        HG_ERROR_DEFAULT("Already finalized");
        ret = HG_FAIL;
        return ret;
    }

    if (hg_bulk_initialized_internal_g) {
        ret = HG_Bulk_finalize();
        if (ret != HG_SUCCESS) {
            HG_ERROR_DEFAULT("Could not finalize bulk data interface");
            ret = HG_FAIL;
            return ret;
        }
        hg_bulk_initialized_internal_g = HG_FALSE;
    }

    hg_handler_finalize();

    if (hg_bulk_na_class_g && (hg_na_class_g == hg_bulk_na_class_g)) {
        hg_request_class_g = NULL;
        hg_context_g = NULL;
    } else {
        /* Finalize request class */
        hg_request_finalize(hg_request_class_g);
        hg_request_class_g = NULL;

        /* Destroy context */
        na_ret = NA_Context_destroy(hg_na_class_g, hg_context_g);
        if (na_ret != NA_SUCCESS) {
            HG_ERROR_DEFAULT("Could not destroy context.");
            ret = HG_FAIL;
            return ret;
        }
        hg_context_g = NULL;
    }

    /* Delete function map */
    hg_hash_table_free(hg_func_map_g);
    hg_func_map_g = NULL;

    hg_na_class_g = NULL;

    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Initialized(hg_bool_t *flag, na_class_t **na_class)
{
    hg_return_t ret = HG_SUCCESS;

    if (!flag) {
        HG_ERROR_DEFAULT("NULL flag");
        ret = HG_FAIL;
        return ret;
    }

    *flag = (hg_bool_t) (hg_na_class_g != NULL);
    if (na_class) *na_class = hg_na_class_g;

    return HG_SUCCESS;
}

/*---------------------------------------------------------------------------*/
hg_id_t
HG_Register(const char *func_name, hg_proc_cb_t input_proc_cb,
        hg_proc_cb_t output_proc_cb)
{
    hg_id_t ret = 0;
    hg_id_t *id = NULL;
    struct hg_info *info = NULL;

    if (!hg_func_map_g) {
        HG_ERROR_DEFAULT("Mercury must be initialized");
        goto done;
    }

    /* Generate a key from the string */
    id = (hg_id_t *) malloc(sizeof(hg_id_t));
    if (!id) {
        HG_ERROR_DEFAULT("Could not allocate ID");
        goto done;
    }

    *id = hg_hash_string(func_name);

    /* Fill a func info struct and store it into the function map */
    info = (struct hg_info *) malloc(sizeof(struct hg_info));
    if (!info) {
        HG_ERROR_DEFAULT("Could not allocate proc info");
        goto done;
    }

    info->input_proc_cb = input_proc_cb;
    info->output_proc_cb = output_proc_cb;
    if (!hg_hash_table_insert(hg_func_map_g, (hg_hash_table_key_t) id, info)) {
        HG_ERROR_DEFAULT("Could not insert func ID");
        goto done;
    }

    ret = *id;

done:
    if (ret == 0) {
        free(id);
        free(info);
    }
    return ret;
}

/*---------------------------------------------------------------------------*/
HG_EXPORT hg_return_t
HG_Register_rpc_callback(hg_id_t id, hg_rpc_cb_t rpc_cb)
{
    struct hg_info *info = NULL;
    hg_return_t ret = HG_SUCCESS;

    info = (struct hg_info *) hg_hash_table_lookup(hg_func_map_g,
            (hg_hash_table_key_t) &id);
    if (!info) {
        HG_ERROR_DEFAULT("hg_hash_table_lookup failed");
        ret = HG_FAIL;
        goto done;
    }

    info->rpc_cb = rpc_cb;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Registered(const char *func_name, hg_bool_t *flag, hg_id_t *id)
{
    hg_return_t ret = HG_SUCCESS;
    hg_id_t func_id;

    if (!hg_func_map_g) {
        HG_ERROR_DEFAULT("Mercury must be initialized");
        ret = HG_FAIL;
        goto done;
    }

    if (!flag) {
        HG_ERROR_DEFAULT("NULL flag");
        ret = HG_FAIL;
        goto done;
    }

    func_id = hg_hash_string(func_name);

    *flag = (hg_bool_t) (hg_hash_table_lookup(hg_func_map_g,
            (hg_hash_table_key_t) &func_id)
            != HG_HASH_TABLE_NULL);
    if (id) *id = (*flag) ? func_id : 0;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Forward(na_addr_t addr, hg_id_t id, void *in_struct, void *out_struct,
        hg_request_t *request)
{
    hg_return_t ret = HG_SUCCESS;
    na_return_t na_ret;
    na_tag_t send_tag, recv_tag;
    struct hg_handle *hg_handle = NULL;
    struct hg_header_request request_header;

    if (!hg_na_class_g) {
        HG_ERROR_DEFAULT("Mercury must be initialized");
        ret = HG_FAIL;
        goto done;
    }

    hg_handle = (struct hg_handle *) malloc(sizeof(struct hg_handle));
    if (!hg_handle) {
        HG_ERROR_DEFAULT("Could not allocate request");
        ret = HG_FAIL;
        goto done;
    }

    hg_handle->id = id;
    hg_handle->send_buf = NULL;
    hg_handle->recv_buf = NULL;

    /* Extra send buffer set to NULL by default */
    hg_handle->extra_send_buf = NULL;
    hg_handle->extra_send_buf_size = 0;
    hg_handle->extra_send_buf_handle = HG_BULK_NULL;

    /* Keep pointer to output structure */
    hg_handle->out_struct = out_struct;

    /* Send Buffer */
    hg_handle->send_buf_size = NA_Msg_get_max_unexpected_size(hg_na_class_g);
    hg_handle->send_buf = hg_proc_buf_alloc(hg_handle->send_buf_size);
    if (!hg_handle->send_buf) {
        HG_ERROR_DEFAULT("Could not allocate send buffer");
        ret = HG_FAIL;
        goto done;
    }

    /* Recv Buffer */
    hg_handle->recv_buf_size = NA_Msg_get_max_expected_size(hg_na_class_g);
    hg_handle->recv_buf = hg_proc_buf_alloc(hg_handle->recv_buf_size);
    if (!hg_handle->recv_buf) {
        HG_ERROR_DEFAULT("Could not allocate send buffer");
        ret = HG_FAIL;
        goto done;
    }

    /* Create two requests for the send/recv operations */
    hg_handle->send_request = hg_request_create(hg_request_class_g);
    hg_handle->recv_request = hg_request_create(hg_request_class_g);

    /* Encode the function parameters */
    ret = hg_set_input(hg_handle, in_struct);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Could not set input");
        ret = HG_FAIL;
        goto done;
    }

    /* Set header */
    hg_proc_header_request_init(hg_handle->id,
            hg_handle->extra_send_buf_handle,
            &request_header);

    /* Encode request header */
    ret = hg_proc_header_request(hg_handle->send_buf,
            hg_handle->send_buf_size, &request_header, HG_ENCODE);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Could not encode header");
        ret = HG_FAIL;
        goto done;
    }

    /* Post the send message and pre-post the recv message */
    send_tag = hg_gen_request_tag();
    recv_tag = send_tag;

    na_ret = NA_Msg_recv_expected(hg_na_class_g, hg_context_g,
            &hg_recv_output_cb, hg_handle, hg_handle->recv_buf,
            hg_handle->recv_buf_size, addr, recv_tag, NA_OP_ID_IGNORE);
    if (na_ret != NA_SUCCESS) {
        HG_ERROR_DEFAULT("Could not pre-post buffer");
        ret = HG_FAIL;
        goto done;
    }

    na_ret = NA_Msg_send_unexpected(hg_na_class_g, hg_context_g,
            &hg_send_input_cb, hg_handle, hg_handle->send_buf,
            hg_handle->send_buf_size, addr, send_tag, NA_OP_ID_IGNORE);
    if (na_ret != NA_SUCCESS) {
        HG_ERROR_DEFAULT("Could not send buffer");
        ret = HG_FAIL;
        goto done;
    }

    *request = (hg_request_t) hg_handle;

done:
    /* TODO clean that */
    if (ret != HG_SUCCESS) {
        if (hg_handle) {
            free(hg_handle->send_buf);
            free(hg_handle->recv_buf);
            free(hg_handle->extra_send_buf);
            HG_Bulk_handle_free(hg_handle->extra_send_buf_handle);
            hg_handle->extra_send_buf_handle = HG_BULK_NULL;
            free(hg_handle);
        }
     }
     return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Wait(hg_request_t request, unsigned int timeout, hg_status_t *status)
{
    double remaining = timeout / 1000; /* Convert timeout in ms into seconds */
    struct hg_handle *hg_handle = (struct hg_handle *) request;
    hg_return_t ret = HG_SUCCESS;

    if (!hg_na_class_g) {
        HG_ERROR_DEFAULT("Mercury must be initialized");
        ret = HG_FAIL;
        goto done;
    }

    if (!hg_handle) {
        HG_ERROR_DEFAULT("NULL request passed");
        ret = HG_FAIL;
        goto done;
    }

    /* TODO use hg_request_waitall instead */

    if (hg_handle->send_request) {
        hg_time_t t1, t2;
        unsigned int flag;

        hg_time_get_current(&t1);

        if (hg_request_wait(hg_handle->send_request, timeout, &flag) !=
                HG_UTIL_SUCCESS) {
            HG_ERROR_DEFAULT("Could not wait on send_request");
            ret = HG_FAIL;
            goto done;
        }

        hg_time_get_current(&t2);
        remaining -= hg_time_to_double(hg_time_subtract(t2, t1));
        if (remaining < 0)
            remaining = 0;

        if (flag) {
            hg_request_destroy(hg_handle->send_request);
            hg_handle->send_request = NULL;
        }
    }

    if (hg_handle->recv_request) {
        unsigned int flag;

        if (hg_request_wait(hg_handle->recv_request,
                (unsigned int) (remaining * 1000), &flag) != HG_UTIL_SUCCESS) {
            HG_ERROR_DEFAULT("Could not wait on send_request");
            ret = HG_FAIL;
            goto done;
        }

        if (flag) {
            hg_request_destroy(hg_handle->recv_request);
            hg_handle->recv_request = NULL;
        }
    }

done:
    if (status && (status != HG_STATUS_IGNORE) && hg_handle) {
        /* When both are NULL, it's completed */
        *status = (hg_status_t)
                (!hg_handle->send_request && !hg_handle->recv_request);
    }

    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Wait_all(int count, hg_request_t array_of_requests[],
        unsigned int timeout, hg_status_t array_of_statuses[])
{
    hg_return_t ret = HG_SUCCESS;
    int i;

    if (!hg_na_class_g) {
        HG_ERROR_DEFAULT("Mercury must be initialized");
        ret = HG_FAIL;
        return ret;
    }

    /* TODO For now just loop over requests */
    for (i = 0; i < count; i++) {
        ret = HG_Wait(array_of_requests[i], timeout, &array_of_statuses[i]);
    }

    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Request_free(hg_request_t request)
{
    struct hg_handle *hg_handle = (struct hg_handle *) request;
    hg_return_t ret = HG_SUCCESS;

    if (!hg_na_class_g) {
        HG_ERROR_DEFAULT("Mercury must be initialized");
        ret = HG_FAIL;
        goto done;
    }

    if (!hg_handle) {
        HG_ERROR_DEFAULT("NULL request");
        ret = HG_FAIL;
        goto done;
    }

    if (hg_handle->send_request || hg_handle->recv_request) {
        HG_ERROR_DEFAULT("Trying to free an uncompleted request");
        ret = HG_FAIL;
        goto done;
    }

    ret = hg_free_output(hg_handle, hg_handle->out_struct);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Could not free output");
        goto done;
    }

    /* Free request */
    free(hg_handle);
    hg_handle = NULL;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
const char *
HG_Error_to_string(hg_return_t errnum)
{
    const char *hg_error_string = "UNDEFINED/UNRECOGNIZED NA ERROR";

    HG_ERROR_STRING_MACRO(HG_FAIL, errnum, hg_error_string);
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
