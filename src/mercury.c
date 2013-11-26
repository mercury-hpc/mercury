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
#include "mercury_bulk.h"

#include "mercury_hash_table.h"
#include "mercury_hash_string.h"
#include "mercury_atomic.h"
#include "mercury_time.h"
#include "mercury_thread_mutex.h"

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
struct hg_request {
    hg_id_t       id;

    void         *send_buf;
    na_size_t     send_buf_size;
    void         *extra_send_buf;
    na_size_t     extra_send_buf_size;
    hg_bulk_t     extra_send_buf_handle;

    void         *recv_buf;
    na_size_t     recv_buf_size;

    void         *out_struct;

    hg_bool_t     completed;
};

struct hg_proc_info {
    hg_proc_cb_t enc_routine;
    hg_proc_cb_t dec_routine;
};

/********************/
/* Local Prototypes */
/********************/
/**
 * Set and encode and request header.
 */
static hg_return_t hg_set_request_header(struct hg_request *priv_request,
        struct hg_header_request header);
/**
 * Decode and get response header.
 */
static hg_return_t hg_get_response_header(struct hg_request *priv_request,
        struct hg_header_response *header);
/**
 * Get RPC input buffer from handle.
 */
static hg_return_t hg_get_input_buf(struct hg_request *priv_request,
        void **in_buf, size_t *in_buf_size);
/**
 * Get RPC output buffer from handle.
 */
static hg_return_t hg_get_output_buf(struct hg_request *priv_request,
        void **out_buf, size_t *out_buf_size);
/**
 * Set and encode input structure.
 */
static hg_return_t hg_set_input(struct hg_request *priv_request,
        void *in_struct);
/**
 * Decode and get output structure.
 */
static hg_return_t hg_get_output(struct hg_request *priv_request,
        void *out_struct);

/**
 * Send input callback.
 */
static na_return_t hg_send_input_cb(const struct na_cb_info *callback_info);

/**
 * Recv output callback.
 */
static na_return_t hg_recv_output_cb(const struct na_cb_info *callback_info);

/*******************/
/* Local Variables */
/*******************/

/* Function map */
static hg_hash_table_t *hg_func_map_g = NULL;

/* Atomic used for tag generation */
static hg_atomic_int32_t hg_request_tag_g;
static na_tag_t hg_request_max_tag_g = 0;

/* Mutex used for request completion */
static hg_thread_mutex_t hg_request_mutex_g;

/* Pointer to network abstraction class */
static na_class_t *hg_na_class_g = NULL;

/* Bulk interface internally initialized */
static hg_bool_t hg_bulk_initialized_internal_g = HG_FALSE;

/* Mutex to prevent concurrent progress */
extern hg_thread_mutex_t hg_progress_mutex_g;

/*---------------------------------------------------------------------------*/
/**
 * Hash function for function map.
 */
static HG_INLINE int
hg_int_equal(void *vlocation1, void *vlocation2)
{
    int *location1;
    int *location2;

    location1 = (int *) vlocation1;
    location2 = (int *) vlocation2;

    return *location1 == *location2;
}

/*---------------------------------------------------------------------------*/
/**
 * Hash function for function map.
 */
static HG_INLINE unsigned int
hg_int_hash(void *vlocation)
{
    int *location;

    location = (int *) vlocation;

    return (unsigned int) *location;
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
hg_set_request_header(struct hg_request *priv_request,
        struct hg_header_request header)
{
    hg_proc_t proc = HG_PROC_NULL;
    hg_return_t ret = HG_SUCCESS;

    hg_proc_create(priv_request->send_buf, priv_request->send_buf_size,
            HG_ENCODE, HG_CRC16, &proc);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Could not create proc");
        goto done;
    }

    /* Encode request header */
    ret = hg_proc_header_request(proc, &header);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Could not encode header");
        ret = HG_FAIL;
        goto done;
    }

done:
    if (proc != HG_PROC_NULL) hg_proc_free(proc);
    proc = HG_PROC_NULL;

    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_get_response_header(struct hg_request *priv_request,
        struct hg_header_response *header)
{
    hg_proc_t proc = HG_PROC_NULL;
    hg_return_t ret = HG_SUCCESS;

    hg_proc_create(priv_request->recv_buf, priv_request->recv_buf_size,
            HG_DECODE, HG_CRC16, &proc);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Could not create proc");
        goto done;
    }

    /* Decode response header */
    ret = hg_proc_header_response(proc, header);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Could not decode header");
        ret = HG_FAIL;
        goto done;
    }

done:
    if (proc != HG_PROC_NULL) hg_proc_free(proc);
    proc = HG_PROC_NULL;

    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_get_input_buf(struct hg_request *priv_request, void **in_buf, size_t *in_buf_size)
{
    void *user_input_buf;
    size_t user_input_buf_size;
    size_t header_offset;
    hg_return_t ret = HG_SUCCESS;

    if (!priv_request) {
        HG_ERROR_DEFAULT("NULL handle");
        ret = HG_FAIL;
        goto done;
    }

    user_input_buf = priv_request->send_buf;
    user_input_buf_size = priv_request->send_buf_size;
    header_offset = hg_proc_header_request_get_size();

    /* Space must be left for request header */
    if (in_buf) *in_buf = (char*) user_input_buf + header_offset;
    if (in_buf_size) *in_buf_size = user_input_buf_size - header_offset;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_get_output_buf(struct hg_request *priv_request, void **out_buf, size_t *out_buf_size)
{
    void *user_output_buf;
    size_t user_output_buf_size;
    size_t header_offset;
    hg_return_t ret = HG_SUCCESS;

    if (!priv_request) {
        HG_ERROR_DEFAULT("NULL handle");
        ret = HG_FAIL;
        goto done;
    }

    user_output_buf = priv_request->recv_buf;
    user_output_buf_size = priv_request->recv_buf_size;
    header_offset = hg_proc_header_response_get_size();

    /* Space must be left for request header */
    if (out_buf) *out_buf = (char*) user_output_buf + header_offset;
    if (out_buf_size) *out_buf_size = user_output_buf_size - header_offset;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_set_input(struct hg_request *priv_request, void *in_struct)
{
    void *in_buf;
    size_t in_buf_size;
    struct hg_proc_info *proc_info;
    hg_proc_t proc = HG_PROC_NULL;
    hg_return_t ret = HG_SUCCESS;

    if (!priv_request) {
        HG_ERROR_DEFAULT("NULL handle");
        ret = HG_FAIL;
        goto done;
    }

    if (!in_struct) goto done;

    /* Get input buffer */
    ret = hg_get_input_buf(priv_request, &in_buf, &in_buf_size);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Could not get input buffer");
        goto done;
    }

    /* Retrieve encoding function from function map */
    proc_info = (struct hg_proc_info *) hg_hash_table_lookup(hg_func_map_g,
            &priv_request->id);
    if (!proc_info) {
        HG_ERROR_DEFAULT("hg_hash_table_lookup failed");
        ret = HG_FAIL;
        goto done;
    }

    /* Create a new encoding proc */
    ret = hg_proc_create(in_buf, in_buf_size, HG_ENCODE, HG_CRC64, &proc);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Could not create proc");
        goto done;
    }

    /* Encode input parameters */
    ret = proc_info->enc_routine(proc, in_struct);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Could not encode parameters");
        goto done;
    }

    /* The size of the encoding buffer may have changed at this point
     * --> if the buffer is too large, we need to do:
     *  - 1: send an unexpected message with info + eventual bulk data descriptor
     *  - 2: send the remaining data in extra buf using bulk data transfer
     */
    if (hg_proc_get_size(proc) > NA_Msg_get_max_unexpected_size(hg_na_class_g)) {
#ifdef HG_HAS_XDR
        HG_ERROR_DEFAULT("Extra encoding using XDR is not yet supported");
        ret = HG_FAIL;
        goto done;
#else
        priv_request->extra_send_buf = hg_proc_get_extra_buf(proc);
        priv_request->extra_send_buf_size = hg_proc_get_extra_size(proc);
        ret = HG_Bulk_handle_create(priv_request->extra_send_buf,
                priv_request->extra_send_buf_size, HG_BULK_READ_ONLY,
                &priv_request->extra_send_buf_handle);
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
    proc = HG_PROC_NULL;

    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_get_output(struct hg_request *priv_request, void *out_struct)
{
    void *out_buf;
    size_t out_buf_size;
    struct hg_proc_info *proc_info;
    hg_proc_t proc = HG_PROC_NULL;
    hg_return_t ret = HG_SUCCESS;

    if (!priv_request) {
        HG_ERROR_DEFAULT("NULL handle");
        ret = HG_FAIL;
        goto done;
    }

    if (!out_struct) goto done;

    /* Get input buffer */
    ret = hg_get_output_buf(priv_request, &out_buf, &out_buf_size);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Could not get input buffer");
        goto done;
    }

    /* Retrieve encoding function from function map */
    proc_info = (struct hg_proc_info *) hg_hash_table_lookup(hg_func_map_g,
            &priv_request->id);
    if (!proc_info) {
        HG_ERROR_DEFAULT("hg_hash_table_lookup failed");
        ret = HG_FAIL;
        goto done;
    }

    /* Create a new encoding proc */
    ret = hg_proc_create(out_buf, out_buf_size, HG_DECODE, HG_CRC64, &proc);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Could not create proc");
        goto done;
    }

    /* Decode output parameters */
    ret = proc_info->dec_routine(proc, out_struct);
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
    proc = HG_PROC_NULL;

    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
hg_send_input_cb(const struct na_cb_info *callback_info)
{
    struct hg_request *priv_request = (struct hg_request *) callback_info->arg;
    na_return_t ret = NA_SUCCESS;

    if (callback_info->ret != NA_SUCCESS) {
        return ret;
    }

    /* Everything has been sent so free unused resources except extra buffer */
    if (priv_request->send_buf) hg_proc_buf_free(priv_request->send_buf);
    priv_request->send_buf = NULL;
    priv_request->send_buf_size = 0;

    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
hg_recv_output_cb(const struct na_cb_info *callback_info)
{
    struct hg_request *priv_request = (struct hg_request *) callback_info->arg;
    struct hg_header_response response_header;
    hg_return_t ret = HG_SUCCESS; /* TODO embed ret into priv_request */
    na_return_t na_ret = NA_SUCCESS;

    if (callback_info->ret != NA_SUCCESS) {
        goto done;
    }

    /* Now we can free the extra send buf now since we received the response */
    if (priv_request->extra_send_buf) free(priv_request->extra_send_buf);
    priv_request->extra_send_buf = NULL;
    priv_request->extra_send_buf_size = 0;
    if (priv_request->extra_send_buf_handle != HG_BULK_NULL)
        HG_Bulk_handle_free(priv_request->extra_send_buf_handle);
    priv_request->extra_send_buf_handle = HG_BULK_NULL;

    /* Get header */
    ret = hg_get_response_header(priv_request, &response_header);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Could not get header");
        ret = HG_FAIL;
        goto done;
    }

    /* Verify header */
    ret = hg_proc_header_response_verify(response_header);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Could not verify header");
        ret = HG_FAIL;
        goto done;
    }

    /* Decode the function output parameters */
    ret = hg_get_output(priv_request, priv_request->out_struct);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Could not get output");
        ret = HG_FAIL;
        goto done;
    }

    /* Everything has been decoded so free unused resources */
    if (priv_request->recv_buf) hg_proc_buf_free(priv_request->recv_buf);
    priv_request->recv_buf = NULL;
    priv_request->recv_buf_size = 0;

    /* Mark request as completed */
    hg_thread_mutex_lock(&hg_request_mutex_g);

    priv_request->completed = HG_TRUE;

    hg_thread_mutex_unlock(&hg_request_mutex_g);

done:
    return na_ret;
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
    hg_bulk_initialized_internal_g = !bulk_initialized;
    
    /* Initialize atomic for tags */
    hg_request_max_tag_g = NA_Msg_get_max_tag(hg_na_class_g);
    hg_atomic_set32(&hg_request_tag_g, 0);

    /* Initialize request mutex */
    hg_thread_mutex_init(&hg_request_mutex_g);

    /* Create new function map */
    hg_func_map_g = hg_hash_table_new(hg_int_hash, hg_int_equal);
    if (!hg_func_map_g) {
        HG_ERROR_DEFAULT("Could not create function map");
        ret = HG_FAIL;
    }
    /* Automatically free all the values with the hash map */
    hg_hash_table_register_free_functions(hg_func_map_g, free, free);


    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Finalize(void)
{
    hg_return_t ret = HG_SUCCESS;

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

    /* Destroy request mutex */
    hg_thread_mutex_destroy(&hg_request_mutex_g);

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

    *flag = (hg_na_class_g != NULL);
    if (na_class) *na_class = hg_na_class_g;

    return HG_SUCCESS;
}

/*---------------------------------------------------------------------------*/
hg_id_t
HG_Register(const char *func_name, hg_proc_cb_t enc_routine,
        hg_proc_cb_t dec_routine)
{
    hg_id_t ret = 0;
    hg_id_t *id = NULL;
    struct hg_proc_info *proc_info = NULL;

    if (!hg_func_map_g) {
        HG_ERROR_DEFAULT("Mercury must be initialized");
        goto done;
    }

    /* Generate a key from the string */
    id = (hg_id_t*) malloc(sizeof(hg_id_t));
    if (!id) {
        HG_ERROR_DEFAULT("Could not allocate ID");
        goto done;
    }

    *id = hg_hash_string(func_name);

    /* Fill a func info struct and store it into the function map */
    proc_info = (struct hg_proc_info *) malloc(sizeof(struct hg_proc_info));
    if (!proc_info) {
        HG_ERROR_DEFAULT("Could not allocate proc info");
        goto done;
    }

    proc_info->enc_routine = enc_routine;
    proc_info->dec_routine = dec_routine;
    if (!hg_hash_table_insert(hg_func_map_g, id, proc_info)) {
        HG_ERROR_DEFAULT("Could not insert func ID");
        goto done;
    }

    ret = *id;

done:
    if (ret == 0) {
        free(id);
        free(proc_info);
    }
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
        return ret;
    }

    if (!flag) {
        HG_ERROR_DEFAULT("NULL flag");
        ret = HG_FAIL;
        return ret;
    }

    func_id = hg_hash_string(func_name);

    *flag = (hg_hash_table_lookup(hg_func_map_g, &func_id) != HG_HASH_TABLE_NULL);
    if (id) *id = (*flag) ? func_id : 0;

    return HG_SUCCESS;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Forward(na_addr_t addr, hg_id_t id, void *in_struct, void *out_struct,
        hg_request_t *request)
{
    hg_return_t ret = HG_SUCCESS;
    na_return_t na_ret;
    na_tag_t send_tag, recv_tag;
    struct hg_request *priv_request = NULL;
    struct hg_header_request request_header;

    if (!hg_na_class_g) {
        HG_ERROR_DEFAULT("Mercury must be initialized");
        ret = HG_FAIL;
        goto done;
    }

    priv_request = (struct hg_request*) malloc(sizeof(struct hg_request));
    if (!priv_request) {
        HG_ERROR_DEFAULT("Could not allocate request");
        ret = HG_FAIL;
        goto done;
    }

    priv_request->id = id;

    /* Send Buffer */
    priv_request->send_buf_size = NA_Msg_get_max_unexpected_size(hg_na_class_g);
    priv_request->send_buf = hg_proc_buf_alloc(priv_request->send_buf_size);
    if (!priv_request->send_buf) {
        HG_ERROR_DEFAULT("Could not allocate send buffer");
        ret = HG_FAIL;
        goto done;
    }

    /* Recv Buffer */
    priv_request->recv_buf_size = NA_Msg_get_max_expected_size(hg_na_class_g);
    priv_request->recv_buf = hg_proc_buf_alloc(priv_request->recv_buf_size);
    if (!priv_request->recv_buf) {
        HG_ERROR_DEFAULT("Could not allocate send buffer");
        ret = HG_FAIL;
        goto done;
    }

    /* Extra send buffer set to NULL by default */
    priv_request->extra_send_buf = NULL;
    priv_request->extra_send_buf_size = 0;
    priv_request->extra_send_buf_handle = HG_BULK_NULL;

    /* Keep pointer to output structure */
    priv_request->out_struct = out_struct;

    /* Mark request as not completed */
    priv_request->completed = HG_FALSE;

    /* Encode the function parameters */
    ret = hg_set_input(priv_request, in_struct);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Could not set input");
        ret = HG_FAIL;
        goto done;
    }

    /* Set header */
    hg_proc_header_request_init(priv_request->id,
            priv_request->extra_send_buf_handle,
            &request_header);

    ret = hg_set_request_header(priv_request, request_header);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Could not set header");
        ret = HG_FAIL;
        goto done;
    }

    /* Post the send message and pre-post the recv message */
    send_tag = hg_gen_request_tag();
    recv_tag = send_tag;

    na_ret = NA_Msg_send_unexpected(hg_na_class_g, &hg_send_input_cb,
            priv_request, priv_request->send_buf, priv_request->send_buf_size,
            addr, send_tag, NA_OP_ID_IGNORE);
    if (na_ret != NA_SUCCESS) {
        HG_ERROR_DEFAULT("Could not send buffer");
        ret = HG_FAIL;
        goto done;
    }

    na_ret = NA_Msg_recv_expected(hg_na_class_g, &hg_recv_output_cb, priv_request,
            priv_request->recv_buf, priv_request->recv_buf_size, addr, recv_tag,
            NA_OP_ID_IGNORE);
    if (na_ret != NA_SUCCESS) {
        HG_ERROR_DEFAULT("Could not pre-post buffer");
        ret = HG_FAIL;
        goto done;
    }

    *request = (hg_request_t) priv_request;

done:
    if (ret != HG_SUCCESS) {
        if (priv_request != NULL) {
            if (priv_request->send_buf) {
                free(priv_request->send_buf);
                priv_request->send_buf = NULL;
            }
            if (priv_request->recv_buf) {
                free(priv_request->recv_buf);
                priv_request->recv_buf = NULL;
            }
            if (priv_request->extra_send_buf) {
                free(priv_request->extra_send_buf);
                priv_request->extra_send_buf = NULL;
            }
            if (priv_request->extra_send_buf_handle != HG_BULK_NULL) {
                HG_Bulk_handle_free(priv_request->extra_send_buf_handle);
                priv_request->extra_send_buf_handle = HG_BULK_NULL;
            }
            free(priv_request);
            priv_request = NULL;
        }
     }

     return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Wait(hg_request_t request, unsigned int timeout, hg_status_t *status)
{
    double remaining = timeout / 1000; /* Convert timeout in ms into seconds */
    struct hg_request *priv_request = (struct hg_request*) request;
    hg_bool_t completed = HG_FALSE;
    hg_return_t ret = HG_SUCCESS;

    if (!hg_na_class_g) {
        HG_ERROR_DEFAULT("Mercury must be initialized");
        ret = HG_FAIL;
        goto done;
    }

    if (!priv_request) {
        HG_ERROR_DEFAULT("NULL request passed");
        ret = HG_FAIL;
        goto done;
    }

    hg_thread_mutex_lock(&hg_request_mutex_g);

    completed = priv_request->completed;

    hg_thread_mutex_unlock(&hg_request_mutex_g);

    while (!completed) {
        hg_time_t t1, t2;
        na_return_t na_ret;
        int actual_count = 0;

        hg_time_get_current(&t1);

        /* Prevent concurrent trigger in handler */
        hg_thread_mutex_lock(&hg_progress_mutex_g);

        do {
            na_ret = NA_Trigger(0, 1, &actual_count);
        } while ((na_ret == NA_SUCCESS) && actual_count);

        hg_thread_mutex_lock(&hg_request_mutex_g);

        completed = priv_request->completed;

        hg_thread_mutex_unlock(&hg_request_mutex_g);

        if (completed) {
            hg_thread_mutex_unlock(&hg_progress_mutex_g);
            break;
        }

        na_ret = NA_Progress(hg_na_class_g, (unsigned int) (remaining * 1000));
        if (na_ret == NA_TIMEOUT) {
            hg_thread_mutex_unlock(&hg_progress_mutex_g);
            goto done;
        }

        hg_thread_mutex_unlock(&hg_progress_mutex_g);

        hg_time_get_current(&t2);
        remaining -= hg_time_to_double(hg_time_subtract(t2, t1));
        if (remaining < 0) {
            goto done;
        }
    }

done:
    if (status && (status != HG_STATUS_IGNORE)) {
        *status = completed;
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
    struct hg_request *priv_request = (struct hg_request*) request;
    hg_proc_t proc;
    struct hg_proc_info *proc_info;
    hg_return_t ret = HG_SUCCESS;

    if (!hg_na_class_g) {
        HG_ERROR_DEFAULT("Mercury must be initialized");
        ret = HG_FAIL;
        return ret;
    }

    if (!priv_request) {
        HG_ERROR_DEFAULT("NULL request");
        ret = HG_FAIL;
        return ret;
    }

    if (!priv_request->completed) {
        HG_ERROR_DEFAULT("Trying to free an uncompleted request");
        ret = HG_FAIL;
        return ret;
    }

    /* Retrieve decoding function from function map */
    proc_info = (struct hg_proc_info *) hg_hash_table_lookup(hg_func_map_g,
            &priv_request->id);
    if (!proc_info) {
        HG_ERROR_DEFAULT("hg_hash_table_lookup failed");
        ret = HG_FAIL;
        return ret;
    }

    if (priv_request->out_struct && proc_info->dec_routine) {
        /* Create a new free proc */
        ret = hg_proc_create(NULL, 0, HG_FREE, HG_NOHASH, &proc);
        if (ret != HG_SUCCESS) {
            HG_ERROR_DEFAULT("Could not create proc");
            ret = HG_FAIL;
            return ret;
        }

        /* Free memory allocated during output decoding */
        ret = proc_info->dec_routine(proc, priv_request->out_struct);
        if (ret != HG_SUCCESS) {
            HG_ERROR_DEFAULT("Could not free allocated parameters");
            ret = HG_FAIL;
        }

        /* Free proc */
        hg_proc_free(proc);
    }

    /* Free request */
    free(priv_request);
    priv_request = NULL;

    return ret;
}

/*---------------------------------------------------------------------------*/
const char *
HG_Error_to_string(hg_return_t errnum)
{
    const char *hg_error_string = "UNDEFINED/UNRECOGNIZED NA ERROR";

    HG_ERROR_STRING_MACRO(HG_FAIL, errnum, hg_error_string);
    HG_ERROR_STRING_MACRO(HG_SUCCESS, errnum, hg_error_string);
    HG_ERROR_STRING_MACRO(HG_NO_MATCH, errnum, hg_error_string);
    HG_ERROR_STRING_MACRO(HG_PROTOCOL_ERROR, errnum, hg_error_string);
    HG_ERROR_STRING_MACRO(HG_CHECKSUM_ERROR, errnum, hg_error_string);
    HG_ERROR_STRING_MACRO(HG_TIMEOUT, errnum, hg_error_string);

    return hg_error_string;
}
