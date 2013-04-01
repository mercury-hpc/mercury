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

#include "function_shipper.h"
#include "function_map.h"
#include "iofsl_compat.h"
#include "shipper_error.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <assert.h>

/* Private structs */
typedef struct fs_priv_request {
    fs_id_t       id;

    void         *send_buf;
    na_size_t     send_buf_size;
    na_request_t  send_request;
    void         *extra_send_buf;
    na_size_t     extra_send_buf_size;
    bds_handle_t  extra_send_buf_handle;

    void         *recv_buf;
    na_size_t     recv_buf_size;
    na_request_t  recv_request;

    void         *out_struct;
} fs_priv_request_t;

typedef struct fs_proc_info {
    int (*enc_routine)(fs_proc_t proc, void *in_struct);
    int (*dec_routine)(fs_proc_t proc, void *out_struct);
} fs_proc_info_t;

/* Function map */
static func_map_t *func_map;

/* TLS key for tag */
static pthread_key_t ptk_tag;
static unsigned int next_tag = 0;
static pthread_mutex_t tag_lock = PTHREAD_MUTEX_INITIALIZER;

static na_network_class_t *fs_network_class = NULL;

#define FS_MAXTAG 65536

/* Generate a new tag */
static inline na_tag_t gen_tag(void)
{
    long int tag;

    tag = (long int) pthread_getspecific(ptk_tag);
    if (!tag) {
        pthread_mutex_lock(&tag_lock);
        tag = ++next_tag;
        pthread_mutex_unlock(&tag_lock);
        pthread_setspecific(ptk_tag, (void*) tag);
    }
    assert(tag < FS_MAXTAG);
    return tag;
}

/*---------------------------------------------------------------------------
 * Function:    fs_init
 *
 * Purpose:     Initialize the function shipper and select a network protocol
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int fs_init(na_network_class_t *network_class)
{
    int ret = S_SUCCESS;

    if (fs_network_class) {
        S_ERROR_DEFAULT("Already initialized");
        ret = S_FAIL;
        return ret;
    }

    fs_network_class = network_class;

    /* Initialize TLS tags */
    pthread_key_create(&ptk_tag, 0);
    next_tag = 1;

    /* Create new function map */
    func_map = func_map_new();
    if (!func_map) {
        S_ERROR_DEFAULT("Could not create function map");
        ret = S_FAIL;
    }

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    fs_finalize
 *
 * Purpose:     Finalize the function shipper
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int fs_finalize(void)
{
    int ret = S_SUCCESS;

    if (!fs_network_class) {
        S_ERROR_DEFAULT("Already finalized");
        ret = S_FAIL;
        return ret;
    }

    ret = na_finalize(fs_network_class);
    if (ret != S_SUCCESS) {
        S_ERROR_DEFAULT("Could not finalize");
        ret = S_FAIL;
        return ret;
    }

    /* Delete function map */
    func_map_free(func_map);
    func_map = NULL;

    /* Free TLS key */
    pthread_key_delete(ptk_tag);

    fs_network_class = NULL;

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    fs_register
 *
 * Purpose:     Register a function name and provide a unique ID
 *
 * Returns:     Unsigned integer
 *
 *---------------------------------------------------------------------------
 */
fs_id_t fs_register(const char *func_name,
        int (*enc_routine)(fs_proc_t proc, void *in_struct),
        int (*dec_routine)(fs_proc_t proc, void *out_struct))
{
    fs_id_t *id;
    fs_proc_info_t *proc_info;

    /* Generate a key from the string */
    id = malloc(sizeof(fs_id_t));

    *id = fs_proc_string_hash(func_name);

    /* Fill a func info struct and store it into the function map */
    proc_info = malloc(sizeof(fs_proc_info_t));

    proc_info->enc_routine = enc_routine;
    proc_info->dec_routine = dec_routine;
    if (func_map_insert(func_map, id, proc_info) != S_SUCCESS) {
        S_ERROR_DEFAULT("Could not insert func ID");
        free(proc_info);
        free(id);
        return 0;
    }

    return *id;
}

/*---------------------------------------------------------------------------
 * Function:    fs_forward
 *
 * Purpose:     Forward a call to a remote server
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int fs_forward(na_addr_t addr, fs_id_t id, const void *in_struct, void *out_struct,
        fs_request_t *request)
{
    int ret = S_SUCCESS;

    fs_proc_info_t *proc_info;
    fs_proc_t enc_proc = FS_PROC_NULL;
    uint8_t extra_send_buf_used = 0;

    static int tag_incr = 0;
    na_tag_t   send_tag, recv_tag;

    fs_priv_request_t *priv_request = NULL;

    /* Retrieve encoding function from function map */
    proc_info = func_map_lookup(func_map, &id);
    if (!proc_info) {
        S_ERROR_DEFAULT("func_map_lookup failed");
        ret = S_FAIL;
        goto done;
    }

    priv_request = malloc(sizeof(fs_priv_request_t));

    priv_request->id = id;

    /* Send Buffer */
    priv_request->send_buf_size = na_get_unexpected_size(fs_network_class);
    ret = fs_proc_buf_alloc(&priv_request->send_buf, priv_request->send_buf_size);
    if (ret != S_SUCCESS) {
        S_ERROR_DEFAULT("Could not allocate send buffer");
        ret = S_FAIL;
        goto done;
    }
    priv_request->send_request = NA_REQUEST_NULL;

    /* Recv Buffer */
    priv_request->recv_buf_size = na_get_unexpected_size(fs_network_class);
    ret = fs_proc_buf_alloc(&priv_request->recv_buf, priv_request->recv_buf_size);
    if (ret != S_SUCCESS) {
        S_ERROR_DEFAULT("Could not allocate send buffer");
        ret = S_FAIL;
        goto done;
    }
    priv_request->recv_request = NA_REQUEST_NULL;

    /* Extra send buffer set to NULL by default */
    priv_request->extra_send_buf = NULL;
    priv_request->extra_send_buf_size = 0;
    priv_request->extra_send_buf_handle = BDS_HANDLE_NULL;

    /* Keep pointer to output structure */
    priv_request->out_struct = out_struct;

    /* Create a new encoding proc */
    ret = fs_proc_create(priv_request->send_buf, priv_request->send_buf_size,
            FS_ENCODE, &enc_proc);
    if (ret != S_SUCCESS) {
        S_ERROR_DEFAULT("Could not create proc");
        ret = S_FAIL;
        goto done;
    }

    /* Leave some space for the header */
    ret = fs_proc_set_buf_ptr(enc_proc, priv_request->send_buf + fs_proc_get_header_size());
    if (ret != S_SUCCESS) {
        S_ERROR_DEFAULT("Could not move proc to user data");
        ret = S_FAIL;
        goto done;
    }

    /* Encode the function parameters */
    if (proc_info->enc_routine) {
        ret = proc_info->enc_routine(enc_proc, (void*)in_struct);
        if (ret != S_SUCCESS) {
            S_ERROR_DEFAULT("Could not encode parameters");
            ret = S_FAIL;
        }
    }

    /* The size of the encoding buffer may have changed at this point
     * --> if the buffer is too large, we need to do:
     *  - 1: send an unexpected message with info + eventual bulk data descriptor
     *  - 2: send the remaining data in extra buf using bulk data transfer
     */
    if (fs_proc_get_size(enc_proc) > na_get_unexpected_size(fs_network_class)) {
        priv_request->extra_send_buf = fs_proc_get_extra_buf(enc_proc);
        priv_request->extra_send_buf_size = fs_proc_get_extra_size(enc_proc);
        ret = bds_handle_create(priv_request->extra_send_buf,
                priv_request->extra_send_buf_size, BDS_READ_ONLY,
                &priv_request->extra_send_buf_handle);
        if (ret != S_SUCCESS) {
            S_ERROR_DEFAULT("Could not create bulk data handle");
            goto done;
        }
        fs_proc_set_extra_buf_is_mine(enc_proc, 1);
        extra_send_buf_used = 1;
    }

    /* Encode header */
    ret = fs_proc_header_request(enc_proc, &id, &extra_send_buf_used);
    if (ret != S_SUCCESS) {
        S_ERROR_DEFAULT("Could not encode header");
        ret = S_FAIL;
        goto done;
    }

    if (extra_send_buf_used) {
        ret = fs_proc_bds_handle_t(enc_proc, &priv_request->extra_send_buf_handle);
        if (ret != S_SUCCESS) {
            S_ERROR_DEFAULT("Could not encode handle");
            ret = S_FAIL;
            goto done;
        }
    }

    /* Post the send message and pre-post the recv message */
    send_tag = gen_tag() + tag_incr;
    recv_tag = gen_tag() + tag_incr;
    tag_incr++;
    if (send_tag > FS_MAXTAG) tag_incr = 0;

    ret = na_send_unexpected(fs_network_class, priv_request->send_buf,
            priv_request->send_buf_size, addr, send_tag,
            &priv_request->send_request, NULL);
    if (ret != S_SUCCESS) {
        S_ERROR_DEFAULT("Could not send buffer");
        ret = S_FAIL;
        goto done;
    }

    ret = na_recv(fs_network_class, priv_request->recv_buf,
            priv_request->recv_buf_size, addr, recv_tag,
            &priv_request->recv_request, NULL);
    if (ret != S_SUCCESS) {
        S_ERROR_DEFAULT("Could not pre-post buffer");
        ret = S_FAIL;
        goto done;
    }

    *request = (fs_request_t) priv_request;

done:
    if (enc_proc != FS_PROC_NULL) fs_proc_free(enc_proc);
    enc_proc = FS_PROC_NULL;

    if (ret != S_SUCCESS) {
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
            if (priv_request->extra_send_buf_handle != BDS_HANDLE_NULL) {
                bds_handle_free(priv_request->extra_send_buf_handle);
                priv_request->extra_send_buf_handle = BDS_HANDLE_NULL;
            }
            free(priv_request);
            priv_request = NULL;
        }
     }

     return ret;
}

/*---------------------------------------------------------------------------
 * Function:    fs_wait
 *
 * Purpose:     Wait for an operation request to complete
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int fs_wait(fs_request_t request, unsigned int timeout, fs_status_t *status)
{
    fs_priv_request_t *priv_request = (fs_priv_request_t*) request;
    na_status_t        send_status;
    na_status_t        recv_status;
    fs_proc_info_t    *proc_info;

    int ret = S_SUCCESS;

    if (!priv_request) {
        S_ERROR_DEFAULT("NULL request");
        ret = S_FAIL;
        return ret;
    }

    if (priv_request->send_request != NA_REQUEST_NULL) {
        ret = na_wait(fs_network_class, priv_request->send_request, timeout, &send_status);
        if (ret != S_SUCCESS) {
            S_ERROR_DEFAULT("Error while waiting");
            ret = S_FAIL;
            return ret;
        }
        if (!send_status.completed) {
            if (timeout == FS_MAX_IDLE_TIME) {
                S_ERROR_DEFAULT("Reached MAX_IDLE_TIME and the request has not completed yet");
            }
            if (status && (status != FS_STATUS_IGNORE)) {
                *status = 0;
            }
        } else {
            /* Request has been freed so set it to NULL */
            priv_request->send_request = NA_REQUEST_NULL;

            /* Everything has been sent so free unused resources */
            if (priv_request->send_buf) free (priv_request->send_buf);
            priv_request->send_buf = NULL;
            priv_request->send_buf_size = 0;
            if (priv_request->extra_send_buf) free(priv_request->extra_send_buf);
            priv_request->extra_send_buf = NULL;
            priv_request->extra_send_buf_size = 0;
            if (priv_request->extra_send_buf_handle != BDS_HANDLE_NULL)
                bds_handle_free(priv_request->extra_send_buf_handle);
            priv_request->extra_send_buf_handle = BDS_HANDLE_NULL;
        }
    }

    if ((priv_request->send_request == NA_REQUEST_NULL) &&
            (priv_request->recv_request != NA_REQUEST_NULL)) {
        ret = na_wait(fs_network_class, priv_request->recv_request, timeout, &recv_status);
        if (ret != S_SUCCESS) {
            S_ERROR_DEFAULT("Error while waiting");
            ret = S_FAIL;
            return ret;
        }
        if (!recv_status.completed) {
            if (timeout == FS_MAX_IDLE_TIME) {
                S_ERROR_DEFAULT("Reached MAX_IDLE_TIME and the request has not completed yet");
            }
            if (status && (status != FS_STATUS_IGNORE)) {
                *status = 0;
            }
        } else {
            /* Request has been freed so set it to NULL */
            priv_request->recv_request = NA_REQUEST_NULL;
        }
    }

    if ((priv_request->send_request == NA_REQUEST_NULL) &&
            (priv_request->recv_request == NA_REQUEST_NULL)) {
        fs_proc_t dec_proc;
        uint8_t extra_recv_buf_used;

        /* Decode depending on op ID */
        proc_info = func_map_lookup(func_map, &priv_request->id);
        if (!proc_info) {
            S_ERROR_DEFAULT("func_map_lookup failed");
            ret = S_FAIL;
            return ret;
        }

        ret = fs_proc_create(priv_request->recv_buf, priv_request->recv_buf_size,
                FS_DECODE, &dec_proc);
        if (ret != S_SUCCESS) {
            S_ERROR_DEFAULT("Could not create proc");
            ret = S_FAIL;
            return ret;
        }

        ret = fs_proc_header_response(dec_proc, &extra_recv_buf_used);
        if (ret != S_SUCCESS) {
            S_ERROR_DEFAULT("Could not decode header");
            ret = S_FAIL;
            return ret;
        }

        if (extra_recv_buf_used) {
            /* TODO Receive extra buffer now */
        } else {
            /* Set buffer to user data */
            ret = fs_proc_set_buf_ptr(dec_proc, priv_request->recv_buf + fs_proc_get_header_size());
            if (ret != S_SUCCESS) {
                S_ERROR_DEFAULT("Could not move proc to user data");
                ret = S_FAIL;
                return ret;
            }
        }

        /* Decode function parameters */
        if (proc_info->dec_routine) {
            ret = proc_info->dec_routine(dec_proc, priv_request->out_struct);
            if (ret != S_SUCCESS) {
                S_ERROR_DEFAULT("Could not decode return parameters");
                ret = S_FAIL;
                return ret;
            }
        }

        /* Free the decoding proc */
        fs_proc_free(dec_proc);

        /* Everything has been decode so free unused resources */
        if (priv_request->recv_buf) free (priv_request->recv_buf);
        priv_request->recv_buf = NULL;
        priv_request->recv_buf_size = 0;

        /* Free request */
        free(priv_request);
        priv_request = NULL;

        if (status && (status != FS_STATUS_IGNORE)) {
            *status = 1;
        }
    }

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    fs_wait_all
 *
 * Purpose:     Wait for all operations to complete
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int fs_wait_all(int count, fs_request_t array_of_requests[],
        unsigned int timeout, fs_status_t array_of_statuses[])
{
    int ret = S_SUCCESS;
    int i;

    /* TODO For now just loop over requests */
    for (i = 0; i < count; i++) {
        ret = fs_wait(array_of_requests[i], timeout, &array_of_statuses[i]);
    }

    return ret;
}
