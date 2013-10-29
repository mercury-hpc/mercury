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

#include "mercury_hash_table.h"
#include "mercury_hash_string.h"
#include "mercury_thread.h"
#include "mercury_thread_mutex.h"
#include "mercury_bulk.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Private structs */
typedef struct hg_priv_request {
    hg_id_t       id;

    void         *send_buf;
    na_size_t     send_buf_size;
    na_request_t  send_request;
    void         *extra_send_buf;
    na_size_t     extra_send_buf_size;
    hg_bulk_t     extra_send_buf_handle;

    void         *recv_buf;
    na_size_t     recv_buf_size;
    na_request_t  recv_request;

    void         *out_struct;

    hg_bool_t     completed;
} hg_priv_request_t;

typedef struct hg_proc_info {
    int (*enc_routine)(hg_proc_t proc, void *in_struct);
    int (*dec_routine)(hg_proc_t proc, void *out_struct);
} hg_proc_info_t;

/* Function map */
static hg_hash_table_t *func_map = NULL;

/* Mutex used for tag generation */
/* TODO use atomic increment instead */
static hg_thread_mutex_t tag_mutex;

/* Pointer to network abstraction class */
static na_class_t *hg_na_class = NULL;

/* Convert value to string */
#define HG_ERROR_STRING_MACRO(def, value, string) \
  if (value == def) string = #def

/**
 * Hash function for function map.
 */
int
hg_int_equal(void *vlocation1, void *vlocation2)
{
    int *location1;
    int *location2;

    location1 = (int *) vlocation1;
    location2 = (int *) vlocation2;

    return *location1 == *location2;
}

/**
 * Hash function for function map.
 */
unsigned int
hg_int_hash(void *vlocation)
{
    int *location;

    location = (int *) vlocation;

    return (unsigned int) *location;
}

/**
 * Generate a new tag.
 */
static HG_INLINE na_tag_t
hg_gen_tag(void)
{
    static long int tag = 0;

    hg_thread_mutex_lock(&tag_mutex);
    tag++;
    if (tag == NA_Msg_get_max_tag(hg_na_class)) tag = 0;
    hg_thread_mutex_unlock(&tag_mutex);

    return tag;
}

/**
 * Set and encode and request header.
 */
static int
hg_set_request_header(hg_priv_request_t *priv_request,
        hg_header_request_t header)
{
    hg_proc_t proc = HG_PROC_NULL;
    int ret = HG_SUCCESS;

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

/**
 * Decode and get response header.
 */
static int
hg_get_response_header(hg_priv_request_t *priv_request,
        hg_header_response_t *header)
{
    hg_proc_t proc = HG_PROC_NULL;
    int ret = HG_SUCCESS;

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

/**
 * Get RPC input buffer from handle.
 */
static int
hg_get_input_buf(hg_priv_request_t *priv_request, void **in_buf, size_t *in_buf_size)
{
    void *user_input_buf;
    size_t user_input_buf_size;
    size_t header_offset;

    int ret = HG_SUCCESS;

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

/**
 * Get RPC output buffer from handle.
 */
static int
hg_get_output_buf(hg_priv_request_t *priv_request, void **out_buf, size_t *out_buf_size)
{
    void *user_output_buf;
    size_t user_output_buf_size;
    size_t header_offset;

    int ret = HG_SUCCESS;

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

/**
 * Set and encode input structure.
 */
static int
hg_set_input(hg_priv_request_t *priv_request, void *in_struct)
{
    void *in_buf;
    size_t in_buf_size;
    hg_proc_info_t *proc_info;
    hg_proc_t proc = HG_PROC_NULL;

    int ret = HG_SUCCESS;

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
    proc_info = (hg_proc_info_t*) hg_hash_table_lookup(func_map, &priv_request->id);
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
    if (hg_proc_get_size(proc) > NA_Msg_get_max_unexpected_size(hg_na_class)) {
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
        hg_proc_set_extra_buf_is_mine(proc, 1);
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

/**
 * Decode and get output structure.
 */
static int
hg_get_output(hg_priv_request_t *priv_request, void *out_struct)
{
    void *out_buf;
    size_t out_buf_size;
    hg_proc_info_t *proc_info;
    hg_proc_t proc = HG_PROC_NULL;

    int ret = HG_SUCCESS;

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
    proc_info = (hg_proc_info_t*) hg_hash_table_lookup(func_map, &priv_request->id);
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
int
HG_Version_get(unsigned int *major, unsigned int *minor, unsigned int *patch)
{
    int ret = HG_SUCCESS;

    if (major) *major = HG_VERSION_MAJOR;
    if (minor) *minor = HG_VERSION_MINOR;
    if (patch) *patch = HG_VERSION_PATCH;

    return ret;
}

/*---------------------------------------------------------------------------*/
int
HG_Init(na_class_t *network_class)
{
    int ret = HG_SUCCESS;

    if (!network_class) {
        HG_ERROR_DEFAULT("Invalid specified network_class");
        ret = HG_FAIL;
        return ret;
    }

    if (hg_na_class) {
        HG_ERROR_DEFAULT("Already initialized");
        ret = HG_FAIL;
        return ret;
    }

    hg_na_class = network_class;

    /* Initialize bulk module */
    ret = HG_Bulk_init(network_class);
    if (ret != HG_SUCCESS)
    {
        HG_ERROR_DEFAULT("Error initializing bulk module.");
        ret = HG_FAIL;
        return ret;
    }
    
    /* Initialize mutex for tags */
    hg_thread_mutex_init(&tag_mutex);

    /* Create new function map */
    func_map = hg_hash_table_new(hg_int_hash, hg_int_equal);
    if (!func_map) {
        HG_ERROR_DEFAULT("Could not create function map");
        ret = HG_FAIL;
    }
    /* Automatically free all the values with the hash map */
    hg_hash_table_register_free_functions(func_map, free, free);

    return ret;
}

/*---------------------------------------------------------------------------*/
int
HG_Finalize(void)
{
    int ret = HG_SUCCESS;

    if (!hg_na_class) {
        HG_ERROR_DEFAULT("Already finalized");
        ret = HG_FAIL;
        return ret;
    }

    /* Delete function map */
    hg_hash_table_free(func_map);
    func_map = NULL;

    /* Free tag mutex */
    hg_thread_mutex_destroy(&tag_mutex);

    hg_na_class = NULL;

    return ret;
}

/*---------------------------------------------------------------------------*/
int
HG_Initialized(hg_bool_t *flag, na_class_t **network_class)
{
    int ret = HG_SUCCESS;

    if (!flag) {
        HG_ERROR_DEFAULT("NULL flag");
        ret = HG_FAIL;
        return ret;
    }

    *flag = (hg_na_class) ? 1 : 0;
    if (network_class) *network_class = (*flag) ? hg_na_class : 0;

    return HG_SUCCESS;
}

/*---------------------------------------------------------------------------*/
hg_id_t
HG_Register(const char *func_name,
        int (*enc_routine)(hg_proc_t proc, void *in_struct),
        int (*dec_routine)(hg_proc_t proc, void *out_struct))
{
    hg_id_t ret = 0;
    hg_id_t *id = NULL;
    hg_proc_info_t *proc_info = NULL;

    if (!func_map) {
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
    proc_info = (hg_proc_info_t*) malloc(sizeof(hg_proc_info_t));
    if (!proc_info) {
        HG_ERROR_DEFAULT("Could not allocate proc info");
        goto done;
    }

    proc_info->enc_routine = enc_routine;
    proc_info->dec_routine = dec_routine;
    if (!hg_hash_table_insert(func_map, id, proc_info)) {
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
int
HG_Registered(const char *func_name, hg_bool_t *flag, hg_id_t *id)
{
    int ret = HG_SUCCESS;
    hg_id_t func_id;

    if (!func_map) {
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

    *flag = (hg_hash_table_lookup(func_map, &func_id) != HG_HASH_TABLE_NULL) ? 1 : 0;
    if (id) *id = (*flag) ? func_id : 0;

    return HG_SUCCESS;
}

/*---------------------------------------------------------------------------*/
int
HG_Forward(na_addr_t addr, hg_id_t id, void *in_struct, void *out_struct,
        hg_request_t *request)
{
    int ret = HG_SUCCESS, na_ret;
    na_tag_t send_tag, recv_tag;
    hg_priv_request_t *priv_request = NULL;
    hg_header_request_t request_header;

    if (!hg_na_class) {
        HG_ERROR_DEFAULT("Mercury must be initialized");
        ret = HG_FAIL;
        goto done;
    }

    priv_request = (hg_priv_request_t*) malloc(sizeof(hg_priv_request_t));
    if (!priv_request) {
        HG_ERROR_DEFAULT("Could not allocate request");
        ret = HG_FAIL;
        goto done;
    }

    priv_request->id = id;

    /* Send Buffer */
    priv_request->send_buf_size = NA_Msg_get_max_unexpected_size(hg_na_class);
    priv_request->send_buf = hg_proc_buf_alloc(priv_request->send_buf_size);
    if (!priv_request->send_buf) {
        HG_ERROR_DEFAULT("Could not allocate send buffer");
        ret = HG_FAIL;
        goto done;
    }
    priv_request->send_request = NA_REQUEST_NULL;

    /* Recv Buffer */
    priv_request->recv_buf_size = NA_Msg_get_max_expected_size(hg_na_class);
    priv_request->recv_buf = hg_proc_buf_alloc(priv_request->recv_buf_size);
    if (!priv_request->recv_buf) {
        HG_ERROR_DEFAULT("Could not allocate send buffer");
        ret = HG_FAIL;
        goto done;
    }
    priv_request->recv_request = NA_REQUEST_NULL;

    /* Extra send buffer set to NULL by default */
    priv_request->extra_send_buf = NULL;
    priv_request->extra_send_buf_size = 0;
    priv_request->extra_send_buf_handle = HG_BULK_NULL;

    /* Keep pointer to output structure */
    priv_request->out_struct = out_struct;

    /* Mark request as not completed */
    priv_request->completed = 0;

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
    send_tag = hg_gen_tag();
    recv_tag = send_tag;

    na_ret = NA_Msg_send_unexpected(hg_na_class, priv_request->send_buf,
            priv_request->send_buf_size, addr, send_tag,
            &priv_request->send_request, NULL);
    if (na_ret != NA_SUCCESS) {
        HG_ERROR_DEFAULT("Could not send buffer");
        ret = HG_FAIL;
        goto done;
    }

    na_ret = NA_Msg_recv(hg_na_class, priv_request->recv_buf,
            priv_request->recv_buf_size, addr, recv_tag,
            &priv_request->recv_request, NULL);
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
int
HG_Wait(hg_request_t request, unsigned int timeout, hg_status_t *status)
{
    hg_priv_request_t *priv_request = (hg_priv_request_t*) request;
    na_status_t send_status, recv_status;

    int ret = HG_SUCCESS;

    if (!hg_na_class) {
        HG_ERROR_DEFAULT("Mercury must be initialized");
        ret = HG_FAIL;
        return ret;
    }

    if (!priv_request) {
        HG_ERROR_DEFAULT("NULL request");
        ret = HG_FAIL;
        return ret;
    }

    if (priv_request->completed) {
        if (status && (status != HG_STATUS_IGNORE)) {
            *status = 1;
        }
        return ret;
    }

    if (priv_request->send_request != NA_REQUEST_NULL) {
        int na_ret;

        na_ret = NA_Wait(hg_na_class, priv_request->send_request, timeout, &send_status);
        if (na_ret != NA_SUCCESS) {
            HG_ERROR_DEFAULT("Error while waiting");
            ret = HG_FAIL;
            return ret;
        }
        if (!send_status.completed) {
            if (timeout == HG_MAX_IDLE_TIME) {
                HG_ERROR_DEFAULT("Reached MAX_IDLE_TIME and the request has not completed yet");
            }
            if (status && (status != HG_STATUS_IGNORE)) {
                *status = 0;
            }
        } else {
            /* Request has been freed so set it to NULL */
            priv_request->send_request = NA_REQUEST_NULL;

            /* Everything has been sent so free unused resources except eventual extra buffer */
            if (priv_request->send_buf) hg_proc_buf_free(priv_request->send_buf);
            priv_request->send_buf = NULL;
            priv_request->send_buf_size = 0;
        }
    }

    if ((priv_request->send_request == NA_REQUEST_NULL) &&
            (priv_request->recv_request != NA_REQUEST_NULL)) {
        int na_ret;

        na_ret = NA_Wait(hg_na_class, priv_request->recv_request, timeout, &recv_status);
        if (na_ret != NA_SUCCESS) {
            HG_ERROR_DEFAULT("Error while waiting");
            ret = HG_FAIL;
            return ret;
        }
        if (!recv_status.completed) {
            if (timeout == HG_MAX_IDLE_TIME) {
                HG_ERROR_DEFAULT("Reached MAX_IDLE_TIME and the request has not completed yet");
            }
            if (status && (status != HG_STATUS_IGNORE)) {
                *status = 0;
            }
        } else {
            /* Request has been freed so set it to NULL */
            priv_request->recv_request = NA_REQUEST_NULL;

            /* We received the response back so safe to free the extra buf now */
            if (priv_request->extra_send_buf) free(priv_request->extra_send_buf);
            priv_request->extra_send_buf = NULL;
            priv_request->extra_send_buf_size = 0;
            if (priv_request->extra_send_buf_handle != HG_BULK_NULL)
                HG_Bulk_handle_free(priv_request->extra_send_buf_handle);
            priv_request->extra_send_buf_handle = HG_BULK_NULL;
        }
    }

    if ((priv_request->send_request == NA_REQUEST_NULL) &&
            (priv_request->recv_request == NA_REQUEST_NULL)) {
        hg_header_response_t response_header;

        /* Mark request as completed */
        priv_request->completed = 1;

        /* Get header */
        ret = hg_get_response_header(priv_request, &response_header);
        if (ret != HG_SUCCESS) {
            HG_ERROR_DEFAULT("Could not get header");
            ret = HG_FAIL;
            goto done;
        }

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

        if (status && (status != HG_STATUS_IGNORE)) {
            *status = 1;
        }
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
int
HG_Wait_all(int count, hg_request_t array_of_requests[],
        unsigned int timeout, hg_status_t array_of_statuses[])
{
    int ret = HG_SUCCESS;
    int i;

    if (!hg_na_class) {
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
int
HG_Request_free(hg_request_t request)
{
    hg_priv_request_t *priv_request = (hg_priv_request_t*) request;
    hg_proc_t proc;
    hg_proc_info_t *proc_info;
    int ret = HG_SUCCESS;

    if (!hg_na_class) {
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
    proc_info = (hg_proc_info_t*) hg_hash_table_lookup(func_map, &priv_request->id);
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
