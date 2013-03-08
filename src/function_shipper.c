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
    fs_id_t      id;
    fs_proc_t    enc_proc;
    fs_proc_t    dec_proc;
    void *       out_struct;
    na_request_t send_request;
    na_request_t recv_request;
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

    na_finalize(fs_network_class);

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
    func_map_insert(func_map, id, proc_info);

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

    fs_priv_proc_t *priv_enc_proc;
    fs_priv_proc_t *priv_dec_proc;
    uint8_t extra_buf_used = 0;
    uint64_t extra_buf_size;

    /* buf len is the size of an unexpected message by default */
    na_size_t send_buf_len = na_get_unexpected_size(fs_network_class);
    na_size_t recv_buf_len = na_get_unexpected_size(fs_network_class);

    static int tag_incr = 0;
    na_tag_t   send_tag, recv_tag;
    fs_priv_request_t *priv_request = NULL;

    /* Retrieve encoding function from function map */
    proc_info = func_map_lookup(func_map, &id);
    if (!proc_info) {
        S_ERROR_DEFAULT("func_map_lookup failed");
        ret = S_FAIL;
        return ret;
    }

    priv_request = malloc(sizeof(fs_priv_request_t));

    priv_request->id = id;
    priv_request->out_struct = out_struct;

    /* Create a new encoding proc */
    fs_proc_create(NULL, send_buf_len, FS_ENCODE, &priv_request->enc_proc);
    priv_enc_proc = (fs_priv_proc_t*) priv_request->enc_proc;

    /* Add IOFSL op id to parameters (used for IOFSL compat) */
    iofsl_compat_proc_id(priv_request->enc_proc);

    /* Add generic op id now (do a simple memcpy) */
    fs_proc_uint32_t(priv_request->enc_proc, &id);

    /* Need to keep here some extra space in case we need to add extra buf info */
    fs_proc_uint8_t(priv_request->enc_proc, &extra_buf_used);

    /* Need to keep here some extra space in case we need to add extra buf_size */
    extra_buf_size = 0;
    fs_proc_uint64_t(priv_request->enc_proc, &extra_buf_size);

//    printf("Proc size: %lu\n", fs_proc_get_size(priv_request->enc_proc));
//    printf("Proc size left: %lu\n", fs_proc_get_size_left(priv_request->enc_proc));

    /* Encode the function parameters */
    proc_info->enc_routine(priv_request->enc_proc, (void*)in_struct);

    /* The size of the encoding buffer may have changed at this point
     * --> if the buffer is too large, we need to do:
     *  - 1: send an unexpected message with info + eventual bulk data descriptor
     *  - 2: send the remaining data in extra buf using either point to point or bulk transfer
     */
    if (fs_proc_get_size(priv_request->enc_proc) > na_get_unexpected_size(fs_network_class)) {
        /* Use bulk transfer */

    } else {

    }

    /* Create a new decoding proc now to prepost decoding buffer */
    fs_proc_create(NULL, recv_buf_len, FS_DECODE, &priv_request->dec_proc);
    priv_dec_proc = (fs_priv_proc_t*) priv_request->dec_proc;

    /* Post the send message and pre-post the recv message */
    send_tag = gen_tag() + tag_incr;
    recv_tag = gen_tag() + tag_incr;
    tag_incr++;
    if (send_tag > FS_MAXTAG) tag_incr = 0;

    ret = na_send_unexpected(fs_network_class, priv_enc_proc->proc_buf.buf,
            send_buf_len, addr, send_tag, &priv_request->send_request, NULL);
    if (ret != S_SUCCESS) {
        ret = S_FAIL;
        fs_proc_free(priv_request->enc_proc);
        fs_proc_free(priv_request->dec_proc);
        free(priv_request);
        priv_request = NULL;
        return ret;
    }
    ret = na_recv(fs_network_class, priv_dec_proc->proc_buf.buf,
            recv_buf_len, addr, recv_tag, &priv_request->recv_request, NULL);
    if (ret != S_SUCCESS) {
        ret = S_FAIL;
        fs_proc_free(priv_request->enc_proc);
        fs_proc_free(priv_request->dec_proc);
        free(priv_request);
        priv_request = NULL;
        return ret;
    }

    *request = (fs_request_t) priv_request;

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

    if (priv_request->send_request) {
        ret = na_wait(fs_network_class, priv_request->send_request, timeout, &send_status);
        if (ret != S_SUCCESS) {
            S_ERROR_DEFAULT("Error while waiting");
            /* TODO what do we do at that point ? */
        }
        if (!send_status.completed) {
            if (timeout == NA_MAX_IDLE_TIME) {
                S_ERROR_DEFAULT("Reached MAX_IDLE_TIME and the request has not completed yet");
            }
            if (status && (status != FS_STATUS_IGNORE)) {
                *status = 0;
            }
        } else {
            /* Request has been freed so set it to NULL */
            priv_request->send_request = NULL;
        }
    }

    if (!priv_request->send_request && priv_request->recv_request) {
        ret = na_wait(fs_network_class, priv_request->recv_request, timeout, &recv_status);
        if (ret != S_SUCCESS) {
            S_ERROR_DEFAULT("Error while waiting");
            /* TODO what do we do at that point ? */
        }
        if (!recv_status.completed) {
            if (timeout == NA_MAX_IDLE_TIME) {
                S_ERROR_DEFAULT("Reached MAX_IDLE_TIME and the request has not completed yet");
            }
            if (status && (status != FS_STATUS_IGNORE)) {
                *status = 0;
            }
        } else {
            /* Request has been freed so set it to NULL */
            priv_request->recv_request = NULL;
        }
    }

    if (!priv_request->send_request && !priv_request->recv_request) {
        /* Decode depending on op ID */
        proc_info = func_map_lookup(func_map, &priv_request->id);
        if (!proc_info) {
            S_ERROR_DEFAULT("func_map_lookup failed");
            ret = S_FAIL;
            return ret;
        }

        /* Check op status from parameters (used for IOFSL compat) */
        iofsl_compat_proc_status(priv_request->dec_proc);

        /* Decode function parameters */
        proc_info->dec_routine(priv_request->dec_proc, priv_request->out_struct);

        /* Free the encoding proc */
        fs_proc_free(priv_request->enc_proc);

        /* Free the decoding proc */
        fs_proc_free(priv_request->dec_proc);

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
    return S_SUCCESS;
}
