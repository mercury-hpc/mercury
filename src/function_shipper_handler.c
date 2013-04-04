/*
 * Copyright (C) 2013 Argonne National Laboratory, Department of Energy,
 *                    and UChicago Argonne, LLC.
 * Copyright (C) 2013 The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#include "function_shipper_handler.h"
#include "function_map.h"
#include "handle_list.h"
#include "iofsl_compat.h"
#include "shipper_error.h"

#include <pthread.h>

/* Private structs */
typedef struct fs_proc_info {
    int (*fs_routine) (fs_handle_t handle);
} fs_proc_info_t;

typedef struct fs_response_info {
    na_request_t request;
    void *buf;
} fs_response_info_t;

typedef struct fs_priv_handle {
    fs_id_t       id;

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
} fs_priv_handle_t;

/* Function map */
static func_map_t *handler_func_map;

/* List of processed handles */
static handle_entry_t *handle_list;
static pthread_mutex_t handle_list_mutex;

/* Network class */
static na_network_class_t *handler_network_class = NULL;

/*---------------------------------------------------------------------------
 * Function:    fs_handler_process_extra_buf
 *
 * Purpose:     Get extra buffer and associate it to handle
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
static int fs_handler_process_extra_recv_buf(fs_proc_t proc, fs_handle_t handle)
{
    int ret = S_SUCCESS;
    fs_priv_handle_t *priv_handle = (fs_priv_handle_t *) handle;

    bds_handle_t extra_buf_handle = BDS_HANDLE_NULL;
    bds_block_handle_t extra_buf_block_handle = BDS_BLOCK_HANDLE_NULL;

    ret = fs_proc_bds_handle_t(proc, &extra_buf_handle);
    if (ret != S_SUCCESS) {
        S_ERROR_DEFAULT("Could not decode bulk handle");
        ret = S_FAIL;
        goto done;
    }

    /* Creat a new block handle to read the data */
    priv_handle->extra_recv_buf_size = bds_handle_get_size(extra_buf_handle);
    priv_handle->extra_recv_buf = malloc(priv_handle->extra_recv_buf_size);

    ret = bds_block_handle_create(priv_handle->extra_recv_buf,
            priv_handle->extra_recv_buf_size, BDS_READWRITE,
            &extra_buf_block_handle);
    if (ret != S_SUCCESS) {
        S_ERROR_DEFAULT("Could not create block handle");
        ret = S_FAIL;
        goto done;
    }

    /* Read bulk data here and wait for the data to be here  */
    ret = bds_read(extra_buf_handle, priv_handle->addr, extra_buf_block_handle);
    if (ret != S_SUCCESS) {
        S_ERROR_DEFAULT("Could not read bulk data");
        ret = S_FAIL;
        goto done;
    }

    ret = bds_wait(extra_buf_block_handle, BDS_MAX_IDLE_TIME);
    if (ret != S_SUCCESS) {
        S_ERROR_DEFAULT("Could not complete bulk data read");
        ret = S_FAIL;
        goto done;
    }

done:
    if (extra_buf_block_handle != BDS_BLOCK_HANDLE_NULL) {
        ret = bds_block_handle_free(extra_buf_block_handle);
        if (ret != S_SUCCESS) {
            S_ERROR_DEFAULT("Could not free block handle");
            ret = S_FAIL;
        }
        extra_buf_block_handle = BDS_BLOCK_HANDLE_NULL;
    }

    if (extra_buf_handle != BDS_BLOCK_HANDLE_NULL) {
        ret = bds_handle_free(extra_buf_handle);
        if (ret != S_SUCCESS) {
            S_ERROR_DEFAULT("Could not free bulk handle");
            ret = S_FAIL;
        }
        extra_buf_handle = BDS_HANDLE_NULL;
    }

   return ret;
}

/*---------------------------------------------------------------------------
 * Function:    fs_handler_init
 *
 * Purpose:     Initialize the function shipper and select a network protocol
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int fs_handler_init(na_network_class_t *network_class)
{
    int ret = S_SUCCESS;

    if (handler_network_class) {
        S_ERROR_DEFAULT("Already initialized");
        ret = S_FAIL;
        return ret;
    }

    handler_network_class = network_class;

    /* Create new function map */
    handler_func_map = func_map_new();
    if (!handler_func_map) {
        S_ERROR_DEFAULT("Could not create function map");
        ret = S_FAIL;
    }

    pthread_mutex_init(&handle_list_mutex, NULL);

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    fs_handler_finalize
 *
 * Purpose:     Finalize the function shipper
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int fs_handler_finalize(void)
{
    int ret = S_SUCCESS;

    if (!handler_network_class) {
        S_ERROR_DEFAULT("Already finalized");
        ret = S_FAIL;
        return ret;
    }

    na_finalize(handler_network_class);

    /* Delete function map */
    func_map_free(handler_func_map);
    handler_func_map = NULL;

    handler_network_class = NULL;

    pthread_mutex_destroy(&handle_list_mutex);

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    fs_handler_register
 *
 * Purpose:     Register a function name and provide a unique ID
 *
 * Returns:     Unsigned integer
 *
 *---------------------------------------------------------------------------
 */
void fs_handler_register(const char *func_name,
        int (*fs_routine) (fs_handle_t handle))
{
    fs_id_t *id;
    fs_proc_info_t *proc_info;

    /* Generate a key from the string */
    id = malloc(sizeof(fs_id_t));

    *id = fs_proc_string_hash(func_name);

    /* Fill a func info struct and store it into the function map */
    proc_info = malloc(sizeof(fs_proc_info_t));

    proc_info->fs_routine  = fs_routine;
    func_map_insert(handler_func_map, id, proc_info);
}

/*---------------------------------------------------------------------------
 * Function:    fs_handler_get_addr
 *
 * Purpose:     Get remote addr from handle
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
const na_addr_t fs_handler_get_addr (fs_handle_t handle)
{
    fs_priv_handle_t *priv_handle = (fs_priv_handle_t *) handle;
    na_addr_t ret = NULL;

    if (priv_handle) ret = priv_handle->addr;

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    fs_handler_get_input
 *
 * Purpose:     Get input from handle
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int fs_handler_get_input(fs_handle_t handle, void **in_buf, size_t *in_buf_size)
{
    fs_priv_handle_t *priv_handle = (fs_priv_handle_t *) handle;
    int ret = S_SUCCESS;

    if (!priv_handle) {
        S_ERROR_DEFAULT("NULL handle");
        ret = S_FAIL;
        return ret;
    }

    if (priv_handle->extra_recv_buf) {
        if (in_buf) *in_buf = priv_handle->extra_recv_buf;
        if (in_buf_size) *in_buf_size = priv_handle->extra_recv_buf_size;
    } else {
        if (in_buf) *in_buf = priv_handle->recv_buf + fs_proc_get_header_size();
        if (in_buf_size) *in_buf_size = priv_handle->recv_buf_size - fs_proc_get_header_size();
    }

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    fs_handler_get_output
 *
 * Purpose:     Get output from handle
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int fs_handler_get_output(fs_handle_t handle, void **out_buf, size_t *out_buf_size)
{
    fs_priv_handle_t *priv_handle = (fs_priv_handle_t *) handle;
    int ret = S_SUCCESS;

    if (!priv_handle) {
        S_ERROR_DEFAULT("NULL handle");
        ret = S_FAIL;
        return ret;
    }

    if (!priv_handle->send_buf) {
        /* Recv buffer must match the size of unexpected buffer */
        priv_handle->send_buf_size = na_get_unexpected_size(handler_network_class);

        ret = fs_proc_buf_alloc(&priv_handle->send_buf, priv_handle->send_buf_size);
        if (ret != S_SUCCESS) {
            S_ERROR_DEFAULT("Could not allocate send buffer");
            ret = S_FAIL;
            return ret;
        }
    }
    if (out_buf) *out_buf = priv_handle->send_buf + fs_proc_get_header_size();
    if (out_buf_size) *out_buf_size = priv_handle->send_buf_size - fs_proc_get_header_size();

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    fs_handler_process
 *
 * Purpose:     Receive a call from a remote client and process request
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int fs_handler_process(unsigned int timeout)
{
    fs_priv_handle_t *priv_handle = NULL;
    fs_proc_info_t   *proc_info;

    fs_proc_t dec_proc = FS_PROC_NULL;
    uint8_t extra_recv_buf_used = 0;

    na_status_t recv_status;

    int ret = S_SUCCESS;

    /* Check if any resources from previous async operations can be freed */
    pthread_mutex_lock(&handle_list_mutex); /* Need to prevent concurrent accesses */

    if (handle_list_get_size(handle_list)) {
        /* Iterate over entries and test for their completion */
        handle_entry_t *entry = handle_list;
        fs_priv_handle_t *completing_handle;

        while (entry) {
            fs_status_t send_status;

            completing_handle = (fs_priv_handle_t*) handle_list_value(entry);
            fs_handler_wait_response(completing_handle, 0, &send_status);
            if (send_status) {
                handle_list_remove_entry(&handle_list, entry);
            }
            entry = handle_list_next(entry);
        }
    }

    pthread_mutex_unlock(&handle_list_mutex);

    /* If we don't have an existing handle for the incoming request create
     * a new one */
    if (!priv_handle) {
        /* Create a new handle */
        priv_handle = malloc(sizeof(fs_priv_handle_t));
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

        /* Recv buffer must match the size of unexpected buffer */
        priv_handle->recv_buf_size = na_get_unexpected_size(handler_network_class);

        ret = fs_proc_buf_alloc(&priv_handle->recv_buf, priv_handle->recv_buf_size);
        if (ret != S_SUCCESS) {
            S_ERROR_DEFAULT("Could not allocate recv buffer");
            ret = S_FAIL;
            goto done;
        }

        /* Start receiving a message from a client */
        ret = na_recv_unexpected(handler_network_class, priv_handle->recv_buf,
                &priv_handle->recv_buf_size, &priv_handle->addr, &priv_handle->tag,
                &priv_handle->recv_request, NULL);
        if (ret != S_SUCCESS) {
            S_ERROR_DEFAULT("Could not recv buffer");
            ret = S_FAIL;
            goto done;
        }
    }

    /* Wait/Test the completion of the unexpected recv */
//    ret = na_wait(handler_network_class, priv_handle->recv_request, timeout,
//            &recv_status);
//    if (ret != S_SUCCESS) {
//        S_ERROR_DEFAULT("Error while waiting");
//        ret = S_FAIL;
//        goto done;
//    }
    /* If not completed yet just exit */
//    if (!recv_status.completed) {
//        goto done;
//    }

    /* Create a new decoding proc */
    ret = fs_proc_create(priv_handle->recv_buf, priv_handle->recv_buf_size,
            FS_DECODE, &dec_proc);
    if (ret != S_SUCCESS) {
        S_ERROR_DEFAULT("Could not create proc");
        ret = S_FAIL;
        goto done;
    }

    /* Decode header */
    ret = fs_proc_header_request(dec_proc, &priv_handle->id, &extra_recv_buf_used);
    if (ret != S_SUCCESS) {
        S_ERROR_DEFAULT("Could not decode header");
        ret = S_FAIL;
        goto done;
    }

    if (extra_recv_buf_used) {
        /* This will make the extra_buf the recv_buf associated to the handle */
        ret = fs_handler_process_extra_recv_buf(dec_proc, priv_handle);
        if (ret != S_SUCCESS) {
            S_ERROR_DEFAULT("Could not recv extra buffer");
            ret = S_FAIL;
            goto done;
        }
    }

    /* Retrieve exe function from function map */
    proc_info = func_map_lookup(handler_func_map, &priv_handle->id);
    if (!proc_info) {
        S_ERROR_DEFAULT("func_map_lookup failed");
        ret = S_FAIL;
        return ret;
    }

    /* Execute function and fill output parameters */
    proc_info->fs_routine((fs_handle_t) priv_handle);

done:
    if (dec_proc != FS_PROC_NULL) fs_proc_free(dec_proc);
    dec_proc = FS_PROC_NULL;

    if (ret != S_SUCCESS && priv_handle) {
        fs_handler_free(priv_handle);
        priv_handle = NULL;
    }
    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    fs_handler_start_response
 *
 * Purpose:     Send the response back to the remote client and free handle
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int fs_handler_start_response(fs_handle_t handle, const void *extra_out_buf, size_t extra_out_buf_size)
{
    fs_priv_handle_t *priv_handle = (fs_priv_handle_t *) handle;
    fs_proc_info_t   *proc_info;

    fs_proc_t enc_proc = FS_PROC_NULL;
    uint8_t extra_send_buf_used = 0;

    int ret = S_SUCCESS;

    if (!priv_handle) {
        S_ERROR_DEFAULT("NULL handle");
        ret = S_FAIL;
        goto done;
    }

    /* if get_output has not been called, call it to create to send_buf */
    ret = fs_handler_get_output(handle, NULL, NULL);
     if (ret != S_SUCCESS) {
         S_ERROR_DEFAULT("Could not get output");
         ret = S_FAIL;
         goto done;
     }

    /* Retrieve encoding function from function map */
    proc_info = func_map_lookup(handler_func_map, &priv_handle->id);
    if (!proc_info) {
        S_ERROR_DEFAULT("func_map_lookup failed");
        ret = S_FAIL;
        goto done;
    }

    /* Check out_buf_size, if it's bigger than the size of the pre-posted buffer
     * we need to use an extra buffer again
     */
    if (extra_out_buf_size > priv_handle->send_buf_size) {
        if (!extra_out_buf) {
            S_ERROR_DEFAULT("No extra buffer given");
            ret = S_FAIL;
            goto done;
        }
        priv_handle->extra_send_buf = (void*)extra_out_buf;
        priv_handle->extra_send_buf_size = extra_out_buf_size;
        extra_send_buf_used = 1;
    }

    /* Create a new encoding proc */
    ret = fs_proc_create(priv_handle->send_buf, priv_handle->send_buf_size,
            FS_ENCODE, &enc_proc);
    if (ret != S_SUCCESS) {
        S_ERROR_DEFAULT("Could not create proc");
        ret = S_FAIL;
        goto done;
    }

    ret = fs_proc_header_response(enc_proc, &extra_send_buf_used);
    if (ret != S_SUCCESS) {
        S_ERROR_DEFAULT("Could not encode header");
        ret = S_FAIL;
        goto done;
    }

    /* Respond back */
    ret = na_send(handler_network_class, priv_handle->send_buf, priv_handle->send_buf_size,
            priv_handle->addr, priv_handle->tag, &priv_handle->send_request, NULL);
    if (ret != S_SUCCESS) {
        S_ERROR_DEFAULT("Could not send buffer");
        ret = S_FAIL;
        goto done;
    }

    /* TODO Also add extra buffer response */

done:
    if (enc_proc != FS_PROC_NULL) fs_proc_free(enc_proc);
    enc_proc = FS_PROC_NULL;

    if (ret == S_SUCCESS && priv_handle) {
        pthread_mutex_lock(&handle_list_mutex);

        ret = handle_list_append(&handle_list, (handle_value_t)priv_handle);
        if (ret != S_SUCCESS) {
            S_ERROR_DEFAULT("Could not append handle to list");
            ret = S_FAIL;
        }

        pthread_mutex_unlock(&handle_list_mutex);
    }
    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    fs_handler_wait_response
 *
 * Purpose:     Wait for a response to complete
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int fs_handler_wait_response(fs_handle_t handle, unsigned int timeout, fs_status_t *status)
{
    fs_priv_handle_t *priv_handle = (fs_priv_handle_t *) handle;
    na_status_t na_status;
    int ret = S_SUCCESS;

    if (!priv_handle) {
        S_ERROR_DEFAULT("NULL handle");
        ret = S_FAIL;
        return ret;
    }

    if (priv_handle->send_request == NA_REQUEST_NULL) {
        S_ERROR_DEFAULT("NULL send request, does not need to wait");
        ret = S_FAIL;
        return ret;
    }

    /* Wait for send_request to complete */
    ret = na_wait(handler_network_class, priv_handle->send_request,
            timeout, &na_status);
    if (ret != S_SUCCESS) {
        S_ERROR_DEFAULT("Error while waiting");
        ret = S_FAIL;
        return ret;
    }

    if (na_status.completed) {
        fs_handler_free(priv_handle);
        priv_handle = NULL;
    }

    if (status && (status != FS_STATUS_IGNORE)) {
        *status = na_status.completed;
    }

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    fs_handler_free
 *
 * Purpose:     Free the handle (N.B. called in fs_handler_respond)
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int fs_handler_free(fs_handle_t handle)
{
    fs_priv_handle_t *priv_handle = (fs_priv_handle_t *) handle;
    int ret = S_SUCCESS;

    if (!priv_handle) {
        S_ERROR_DEFAULT("Already freed");
        ret = S_FAIL;
        return ret;
    }

    // TODO Check send_request and recv_request here as well

    if (priv_handle->addr != NA_ADDR_NULL) {
        na_addr_free(handler_network_class, priv_handle->addr);
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
