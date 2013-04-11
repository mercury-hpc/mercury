/*
 * Copyright (C) 2013 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#include "mercury_handler.h"
#include "mercury_hash_table.h"
#include "mercury_list.h"

#include <pthread.h>

/* Private structs */
typedef struct hg_proc_info {
    int (*callback_routine) (hg_handle_t handle);
    int (*dec_routine)(hg_proc_t proc, void *in_struct);
    int (*enc_routine)(hg_proc_t proc, void *out_struct);
} hg_proc_info_t;

typedef struct hg_response_info {
    na_request_t request;
    void *buf;
} hg_response_info_t;

typedef struct hg_priv_handle {
    hg_id_t       id;

    na_addr_t     addr;
    na_tag_t      tag;

    void         *recv_buf;
    na_size_t     recv_buf_size;
    na_request_t  recv_request;
    void         *extra_recv_buf;
    na_size_t     extra_recv_buf_size;

    void         *send_buf;
    na_size_t     send_buf_size;
    na_request_t  send_request;
    void         *extra_send_buf;
    na_size_t     extra_send_buf_size;

    void         *in_struct;
} hg_priv_handle_t;

/* Function map */
static hg_hash_table_t *handler_func_map;
extern int hg_int_equal(void *vlocation1, void *vlocation2);
extern unsigned int hg_int_hash(void *vlocation);

/* List of processed handles */
static hg_list_entry_t *response_handle_list;
static pthread_mutex_t response_handle_list_mutex;

/* Network class */
static na_class_t *handler_na_class = NULL;

/*---------------------------------------------------------------------------
 * Function:    HG_Handler_process_response
 *
 * Purpose:     Process list of handles and wait timeout for response completion
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
static int HG_Handler_process_response_list(unsigned int timeout)
{
    int ret = HG_SUCCESS;

    /* Check if any resources from previous async operations can be freed */
    pthread_mutex_lock(&response_handle_list_mutex); /* Need to prevent concurrent accesses */

    if (hg_list_length(response_handle_list)) {
        /* Iterate over entries and test for their completion */
        hg_list_entry_t *entry = response_handle_list;
        hg_priv_handle_t *response_handle;

        while (entry) {
            hg_status_t response_status;
            hg_list_entry_t *next_entry = hg_list_next(entry);

            response_handle = (hg_priv_handle_t*) hg_list_data(entry);
            ret = HG_Handler_wait_response(response_handle, timeout, &response_status);
            if (ret != HG_SUCCESS) {
                HG_ERROR_DEFAULT("Could not wait for response to complete");
                ret = HG_FAIL;
                break;
            }

            if (response_status) {
                if (!hg_list_remove_entry(&response_handle_list, entry)) {
                    HG_ERROR_DEFAULT("Could not remove entry");
                }
            }

            entry = next_entry;
        }
    }

    pthread_mutex_unlock(&response_handle_list_mutex);

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    HG_Handler_process_extra_recv_buf
 *
 * Purpose:     Get extra buffer and associate it to handle
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
static int HG_Handler_process_extra_recv_buf(hg_proc_t proc, hg_handle_t handle)
{
    int ret = HG_SUCCESS;
    hg_priv_handle_t *priv_handle = (hg_priv_handle_t *) handle;

    hg_bulk_t extra_buf_handle = HG_BULK_NULL;
    hg_bulk_block_t extra_buf_block_handle = HG_BULK_BLOCK_NULL;

    ret = hg_proc_hg_bulk_t(proc, &extra_buf_handle);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Could not decode bulk handle");
        ret = HG_FAIL;
        goto done;
    }

    /* Create a new block handle to read the data */
    priv_handle->extra_recv_buf_size = HG_Bulk_handle_get_size(extra_buf_handle);
    priv_handle->extra_recv_buf = malloc(priv_handle->extra_recv_buf_size);

    ret = HG_Bulk_block_handle_create(priv_handle->extra_recv_buf,
            priv_handle->extra_recv_buf_size, HG_BULK_READWRITE,
            &extra_buf_block_handle);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Could not create block handle");
        ret = HG_FAIL;
        goto done;
    }

    /* Read bulk data here and wait for the data to be here  */
    ret = HG_Bulk_read(extra_buf_handle, priv_handle->addr, extra_buf_block_handle);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Could not read bulk data");
        ret = HG_FAIL;
        goto done;
    }

    ret = HG_Bulk_wait(extra_buf_block_handle, HG_BULK_MAX_IDLE_TIME);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Could not complete bulk data read");
        ret = HG_FAIL;
        goto done;
    }

done:
    if (extra_buf_block_handle != HG_BULK_BLOCK_NULL) {
        ret = HG_Bulk_block_handle_free(extra_buf_block_handle);
        if (ret != HG_SUCCESS) {
            HG_ERROR_DEFAULT("Could not free block handle");
            ret = HG_FAIL;
        }
        extra_buf_block_handle = HG_BULK_BLOCK_NULL;
    }

    if (extra_buf_handle != HG_BULK_BLOCK_NULL) {
        ret = HG_Bulk_handle_free(extra_buf_handle);
        if (ret != HG_SUCCESS) {
            HG_ERROR_DEFAULT("Could not free bulk handle");
            ret = HG_FAIL;
        }
        extra_buf_handle = HG_BULK_NULL;
    }

   return ret;
}

/*---------------------------------------------------------------------------
 * Function:    HG_Handler_init
 *
 * Purpose:     Initialize the function shipper and select a network protocol
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int HG_Handler_init(na_class_t *network_class)
{
    int ret = HG_SUCCESS;

    if (handler_na_class) {
        HG_ERROR_DEFAULT("Already initialized");
        ret = HG_FAIL;
        return ret;
    }

    handler_na_class = network_class;

    /* Create new function map */
    handler_func_map = hg_hash_table_new(hg_int_hash, hg_int_equal);
    if (!handler_func_map) {
        HG_ERROR_DEFAULT("Could not create function map");
        ret = HG_FAIL;
    }

    /* Automatically free all the values with the hash map */
    hg_hash_table_register_free_functions(handler_func_map, free, free);

    pthread_mutex_init(&response_handle_list_mutex, NULL);

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    HG_Handler_finalize
 *
 * Purpose:     Finalize the function shipper
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int HG_Handler_finalize(void)
{
    int ret = HG_SUCCESS, na_ret;

    if (!handler_na_class) {
        HG_ERROR_DEFAULT("Already finalized");
        ret = HG_FAIL;
        return ret;
    }

    /* Wait for previous responses to complete */
    ret = HG_Handler_process_response_list(HG_MAX_IDLE_TIME);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Could not process response list");
        ret = HG_FAIL;
        return ret;
    }

    na_ret = NA_Finalize(handler_na_class);
    if (na_ret != NA_SUCCESS) {
        HG_ERROR_DEFAULT("Could not finalize");
        ret = HG_FAIL;
        return ret;
    }

    /* Delete function map */
    hg_hash_table_free(handler_func_map);
    handler_func_map = NULL;

    handler_na_class = NULL;

    pthread_mutex_destroy(&response_handle_list_mutex);

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    HG_Handler_register
 *
 * Purpose:     Register a function name and provide a unique ID
 *
 * Returns:     Unsigned integer
 *
 *---------------------------------------------------------------------------
 */
void HG_Handler_register(const char *func_name,
        int (*callback_routine) (hg_handle_t handle),
        int (*dec_routine)(hg_proc_t proc, void *in_struct),
        int (*enc_routine)(hg_proc_t proc, void *out_struct))
{
    hg_id_t *id;
    hg_proc_info_t *proc_info;

    /* Generate a key from the string */
    id = malloc(sizeof(hg_id_t));

    *id = hg_proc_string_hash(func_name);

    /* Fill a func info struct and store it into the function map */
    proc_info = malloc(sizeof(hg_proc_info_t));

    proc_info->callback_routine = callback_routine;
    proc_info->dec_routine = dec_routine;
    proc_info->enc_routine = enc_routine;

    if (!hg_hash_table_insert(handler_func_map, id, proc_info)) {
        HG_ERROR_DEFAULT("Could not insert func ID");
        free(proc_info);
        free(id);
    }
}

/*---------------------------------------------------------------------------
 * Function:    HG_Handler_get_addr
 *
 * Purpose:     Get remote addr from handle
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
const na_addr_t HG_Handler_get_addr (hg_handle_t handle)
{
    hg_priv_handle_t *priv_handle = (hg_priv_handle_t *) handle;
    na_addr_t ret = NULL;

    if (priv_handle) ret = priv_handle->addr;

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    HG_Handler_get_input_buf
 *
 * Purpose:     Get input from handle
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int HG_Handler_get_input_buf(hg_handle_t handle, void **in_buf, size_t *in_buf_size)
{
    hg_priv_handle_t *priv_handle = (hg_priv_handle_t *) handle;
    int ret = HG_SUCCESS;

    if (!priv_handle) {
        HG_ERROR_DEFAULT("NULL handle");
        ret = HG_FAIL;
        return ret;
    }

    if (priv_handle->extra_recv_buf) {
        if (in_buf) *in_buf = priv_handle->extra_recv_buf;
        if (in_buf_size) *in_buf_size = priv_handle->extra_recv_buf_size;
    } else {
        if (in_buf) *in_buf = priv_handle->recv_buf + hg_proc_get_header_size();
        if (in_buf_size) *in_buf_size = priv_handle->recv_buf_size - hg_proc_get_header_size();
    }

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    HG_Handler_get_output_buf
 *
 * Purpose:     Get output from handle
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int HG_Handler_get_output_buf(hg_handle_t handle, void **out_buf, size_t *out_buf_size)
{
    hg_priv_handle_t *priv_handle = (hg_priv_handle_t *) handle;
    int ret = HG_SUCCESS;

    if (!priv_handle) {
        HG_ERROR_DEFAULT("NULL handle");
        ret = HG_FAIL;
        return ret;
    }

    if (!priv_handle->send_buf) {
        /* Recv buffer must match the size of unexpected buffer */
        priv_handle->send_buf_size = NA_Get_unexpected_size(handler_na_class);

        ret = hg_proc_buf_alloc(&priv_handle->send_buf, priv_handle->send_buf_size);
        if (ret != HG_SUCCESS) {
            HG_ERROR_DEFAULT("Could not allocate send buffer");
            ret = HG_FAIL;
            return ret;
        }
    }
    if (out_buf) *out_buf = priv_handle->send_buf + hg_proc_get_header_size();
    if (out_buf_size) *out_buf_size = priv_handle->send_buf_size - hg_proc_get_header_size();

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    HG_Handler_process
 *
 * Purpose:     Receive a call from a remote client and process request
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int HG_Handler_process(unsigned int timeout)
{
    hg_priv_handle_t *priv_handle = NULL;
    hg_proc_info_t   *proc_info;

    hg_proc_t dec_proc = HG_PROC_NULL;
    uint8_t extra_recv_buf_used = 0;

//    na_status_t recv_status;

    int ret = HG_SUCCESS, na_ret;

    /* Check if previous responses have completed without waiting */
    ret = HG_Handler_process_response_list(0);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Could not process response list");
        ret = HG_FAIL;
        goto done;
    }

    /* If we don't have an existing handle for the incoming request create
     * a new one */
    if (!priv_handle) {
        /* Create a new handle */
        priv_handle = malloc(sizeof(hg_priv_handle_t));
        priv_handle->id = 0;
        priv_handle->addr = NA_ADDR_NULL;
        priv_handle->tag = 0;

        priv_handle->recv_buf = NULL;
        priv_handle->recv_buf_size = 0;
        priv_handle->recv_request = NA_REQUEST_NULL;
        priv_handle->extra_recv_buf = NULL;
        priv_handle->extra_recv_buf_size = 0;

        priv_handle->send_buf = NULL;
        priv_handle->send_buf_size = 0;
        priv_handle->send_request = NA_REQUEST_NULL;
        priv_handle->extra_send_buf = NULL;
        priv_handle->extra_send_buf_size = 0;

        priv_handle->in_struct = NULL;

        /* Recv buffer must match the size of unexpected buffer */
        priv_handle->recv_buf_size = NA_Get_unexpected_size(handler_na_class);

        ret = hg_proc_buf_alloc(&priv_handle->recv_buf, priv_handle->recv_buf_size);
        if (ret != HG_SUCCESS) {
            HG_ERROR_DEFAULT("Could not allocate recv buffer");
            ret = HG_FAIL;
            goto done;
        }

        /* Start receiving a message from a client */
        na_ret = NA_Recv_unexpected(handler_na_class, priv_handle->recv_buf,
                &priv_handle->recv_buf_size, &priv_handle->addr, &priv_handle->tag,
                &priv_handle->recv_request, NULL);
        if (na_ret != NA_SUCCESS) {
            HG_ERROR_DEFAULT("Could not recv buffer");
            ret = HG_FAIL;
            goto done;
        }
    }

    /* Wait/Test the completion of the unexpected recv */
//    na_ret = NA_Wait(handler_na_class, priv_handle->recv_request, timeout,
//            &recv_status);
//    if (na_ret != NA_SUCCESS) {
//        HG_ERROR_DEFAULT("Error while waiting");
//        ret = HG_FAIL;
//        goto done;
//    }
    /* If not completed yet just exit */
//    if (!recv_status.completed) {
//        goto done;
//    }

    /* Create a new decoding proc */
    ret = hg_proc_create(priv_handle->recv_buf, priv_handle->recv_buf_size,
            HG_DECODE, &dec_proc);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Could not create proc");
        ret = HG_FAIL;
        goto done;
    }

    /* Decode header */
    ret = hg_proc_header_request(dec_proc, &priv_handle->id, &extra_recv_buf_used);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Could not decode header");
        ret = HG_FAIL;
        goto done;
    }

    if (extra_recv_buf_used) {
        /* This will make the extra_buf the recv_buf associated to the handle */
        ret = HG_Handler_process_extra_recv_buf(dec_proc, priv_handle);
        if (ret != HG_SUCCESS) {
            HG_ERROR_DEFAULT("Could not recv extra buffer");
            ret = HG_FAIL;
            goto done;
        }
    }

    /* Retrieve exe function from function map */
    proc_info = hg_hash_table_lookup(handler_func_map, &priv_handle->id);
    if (!proc_info) {
        HG_ERROR_DEFAULT("hg_hash_table_lookup failed");
        ret = HG_FAIL;
        goto done;
    }

    /* Execute function and fill output parameters */
    proc_info->callback_routine((hg_handle_t) priv_handle);

done:
    if (dec_proc != HG_PROC_NULL) hg_proc_free(dec_proc);
    dec_proc = HG_PROC_NULL;

    if (ret != HG_SUCCESS && priv_handle) {
        HG_Handler_free(priv_handle);
        priv_handle = NULL;
    }
    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    HG_Handler_start_response
 *
 * Purpose:     Send the response back to the remote client and free handle
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int HG_Handler_start_response(hg_handle_t handle, const void *extra_out_buf, size_t extra_out_buf_size)
{
    hg_priv_handle_t *priv_handle = (hg_priv_handle_t *) handle;
    hg_proc_info_t   *proc_info;

    hg_proc_t enc_proc = HG_PROC_NULL;
    uint8_t extra_send_buf_used = 0;

    int ret = HG_SUCCESS, na_ret;

    if (!priv_handle) {
        HG_ERROR_DEFAULT("NULL handle");
        ret = HG_FAIL;
        goto done;
    }

    /* if get_output has not been called, call it to create to send_buf */
    ret = HG_Handler_get_output_buf(handle, NULL, NULL);
     if (ret != HG_SUCCESS) {
         HG_ERROR_DEFAULT("Could not get output");
         ret = HG_FAIL;
         goto done;
     }

    /* Retrieve encoding function from function map */
    proc_info = hg_hash_table_lookup(handler_func_map, &priv_handle->id);
    if (!proc_info) {
        HG_ERROR_DEFAULT("hg_hash_table_lookup failed");
        ret = HG_FAIL;
        goto done;
    }

    /* Check out_buf_size, if it's bigger than the size of the pre-posted buffer
     * we need to use an extra buffer again
     */
    if (extra_out_buf_size > priv_handle->send_buf_size) {
        if (!extra_out_buf) {
            HG_ERROR_DEFAULT("No extra buffer given");
            ret = HG_FAIL;
            goto done;
        }
        priv_handle->extra_send_buf = (void*)extra_out_buf;
        priv_handle->extra_send_buf_size = extra_out_buf_size;
        extra_send_buf_used = 1;
    }

    /* Create a new encoding proc */
    ret = hg_proc_create(priv_handle->send_buf, priv_handle->send_buf_size,
            HG_ENCODE, &enc_proc);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Could not create proc");
        ret = HG_FAIL;
        goto done;
    }

    ret = hg_proc_header_response(enc_proc, &extra_send_buf_used);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Could not encode header");
        ret = HG_FAIL;
        goto done;
    }

    /* Respond back */
    na_ret = NA_Send(handler_na_class, priv_handle->send_buf, priv_handle->send_buf_size,
            priv_handle->addr, priv_handle->tag, &priv_handle->send_request, NULL);
    if (na_ret != NA_SUCCESS) {
        HG_ERROR_DEFAULT("Could not send buffer");
        ret = HG_FAIL;
        goto done;
    }

    /* TODO Also add extra buffer response */

done:
    if (enc_proc != HG_PROC_NULL) hg_proc_free(enc_proc);
    enc_proc = HG_PROC_NULL;

    if (ret == HG_SUCCESS && priv_handle) {
        pthread_mutex_lock(&response_handle_list_mutex);

        if (!hg_list_append(&response_handle_list, (hg_list_value_t)priv_handle)) {
            HG_ERROR_DEFAULT("Could not append handle to list");
            ret = HG_FAIL;
        }

        pthread_mutex_unlock(&response_handle_list_mutex);
    }
    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    HG_Handler_wait_response
 *
 * Purpose:     Wait for a response to complete
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int HG_Handler_wait_response(hg_handle_t handle, unsigned int timeout, hg_status_t *status)
{
    hg_priv_handle_t *priv_handle = (hg_priv_handle_t *) handle;
    na_status_t na_status;
    int ret = HG_SUCCESS, na_ret;

    if (!priv_handle) {
        HG_ERROR_DEFAULT("NULL handle");
        ret = HG_FAIL;
        return ret;
    }

    if (priv_handle->send_request == NA_REQUEST_NULL) {
        HG_ERROR_DEFAULT("NULL send request, does not need to wait");
        ret = HG_FAIL;
        return ret;
    }

    /* Wait for send_request to complete */
    na_ret = NA_Wait(handler_na_class, priv_handle->send_request,
            timeout, &na_status);
    if (na_ret != NA_SUCCESS) {
        HG_ERROR_DEFAULT("Error while waiting");
        ret = HG_FAIL;
        return ret;
    }

    if (na_status.completed) {
        HG_Handler_free(priv_handle);
        priv_handle = NULL;
    }

    if (status && (status != HG_STATUS_IGNORE)) {
        *status = na_status.completed;
    }

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    HG_Handler_free
 *
 * Purpose:     Free the handle (N.B. called in hg_handler_respond)
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int HG_Handler_free(hg_handle_t handle)
{
    hg_priv_handle_t *priv_handle = (hg_priv_handle_t *) handle;
    int ret = HG_SUCCESS;

    if (!priv_handle) {
        HG_ERROR_DEFAULT("Already freed");
        ret = HG_FAIL;
        return ret;
    }

    // TODO Check send_request and recv_request here as well

    if (priv_handle->addr != NA_ADDR_NULL) {
        NA_Addr_free(handler_na_class, priv_handle->addr);
        priv_handle->addr = NA_ADDR_NULL;
    }

    if (priv_handle->recv_buf) {
        free(priv_handle->recv_buf);
        priv_handle->recv_buf = NULL;
    }

    if (priv_handle->extra_recv_buf) {
        free(priv_handle->extra_recv_buf);
        priv_handle->extra_recv_buf = NULL;
    }

    if (priv_handle->send_buf) {
        free(priv_handle->send_buf);
        priv_handle->send_buf = NULL;
    }

    if (priv_handle->extra_send_buf) {
        free(priv_handle->extra_send_buf);
        priv_handle->extra_send_buf = NULL;
    }

    free(priv_handle);
    priv_handle = NULL;

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    HG_Handler_get_input
 *
 * Purpose:     Get input structure from handle
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int HG_Handler_get_input(hg_handle_t handle, void *in_struct)
{
    hg_priv_handle_t *priv_handle = (hg_priv_handle_t *) handle;
    int ret = HG_SUCCESS;

    void *in_buf;
    size_t in_buf_size;
    hg_proc_info_t *proc_info;
    hg_proc_t proc;

    if (!in_struct) {
        HG_ERROR_DEFAULT("NULL pointer to input struct");
        ret = HG_FAIL;
        return ret;
    } else {
        /* Keep reference to in_struct to eventually free decoded params later */
        priv_handle->in_struct = in_struct;
    }

    /* Get input buffer */
    ret = HG_Handler_get_input_buf(handle, &in_buf, &in_buf_size);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Could not get input buffer");
        return ret;
    }

    /* Retrieve decode function from function map */
    proc_info = hg_hash_table_lookup(handler_func_map, &priv_handle->id);
    if (!proc_info) {
        HG_ERROR_DEFAULT("hg_hash_table_lookup failed");
        ret = HG_FAIL;
        return ret;
    }

    /* Create a new decoding proc */
    ret = hg_proc_create(in_buf, in_buf_size, HG_DECODE, &proc);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Could not create proc");
        ret = HG_FAIL;
        return ret;
    }

    /* Decode input parameters */
    ret = proc_info->dec_routine(proc, in_struct);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Could not decode input parameters");
        ret = HG_FAIL;
    }

    /* Free proc */
    hg_proc_free(proc);

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    HG_Handler_start_output
 *
 * Purpose:     Start sending output structure from handle
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int HG_Handler_start_output(hg_handle_t handle, void *out_struct)
{
    hg_priv_handle_t *priv_handle = (hg_priv_handle_t *) handle;
    int ret = HG_SUCCESS;

    void *out_buf;
    size_t out_buf_size;
    void *out_extra_buf = NULL;
    size_t out_extra_buf_size = 0;
    hg_proc_info_t *proc_info;
    hg_proc_t proc;

    /* Get output buffer */
    ret = HG_Handler_get_output_buf(handle, &out_buf, &out_buf_size);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Could not get output buffer");
        ret = HG_FAIL;
        return ret;
    }

    /* Retrieve decode function from function map */
    proc_info = hg_hash_table_lookup(handler_func_map, &priv_handle->id);
    if (!proc_info) {
        HG_ERROR_DEFAULT("hg_hash_table_lookup failed");
        ret = HG_FAIL;
        return ret;
    }

    if (out_struct && proc_info->enc_routine) {
        /* Create a new encoding proc */
        ret = hg_proc_create(out_buf, out_buf_size, HG_ENCODE, &proc);
        if (ret != HG_SUCCESS) {
            HG_ERROR_DEFAULT("Could not create proc");
            ret = HG_FAIL;
            return ret;
        }

        /* Encode output parameters */
        ret = proc_info->enc_routine(proc, out_struct);
        if (ret != HG_SUCCESS) {
            HG_ERROR_DEFAULT("Could not encode output parameters");
            ret = HG_FAIL;
        }


        /* Get eventual extra buffer */
        if (hg_proc_get_extra_buf(proc)) {
            out_extra_buf = hg_proc_get_extra_buf(proc);
            out_extra_buf_size = hg_proc_get_extra_size(proc);
            hg_proc_set_extra_buf_is_mine(proc, 1);
        }

        /* Free proc */
        hg_proc_free(proc);
    }

    /* Free handle and send response back */
    ret = HG_Handler_start_response(handle, out_extra_buf, out_extra_buf_size);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Could not respond");
        ret = HG_FAIL;
        return ret;
    }

    if (priv_handle->in_struct && proc_info->dec_routine) {
        /* Create a new free proc */
        ret = hg_proc_create(NULL, 0, HG_FREE, &proc);
        if (ret != HG_SUCCESS) {
            HG_ERROR_DEFAULT("Could not create proc");
            ret = HG_FAIL;
            return ret;
        }

        /* Free memory allocated during input decoding */
        ret = proc_info->dec_routine(proc, priv_handle->in_struct);
        if (ret != HG_SUCCESS) {
            HG_ERROR_DEFAULT("Could not free allocated parameters");
            ret = HG_FAIL;
        }

        /* Free proc */
        hg_proc_free(proc);
    }

    return ret;
}
