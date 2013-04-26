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
#include "mercury_hash_table.h"
#include "mercury_thread_mutex.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

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
} hg_priv_request_t;

typedef struct hg_proc_info {
    int (*enc_routine)(hg_proc_t proc, void *in_struct);
    int (*dec_routine)(hg_proc_t proc, void *out_struct);
} hg_proc_info_t;

/* Function map */
static hg_hash_table_t *func_map;

/* TLS key for tag */
static pthread_key_t ptk_tag;
static unsigned int next_tag = 0;
static hg_thread_mutex_t tag_mutex;

static na_class_t *hg_na_class = NULL;

#define HG_MAXTAG 65536

/* Hash functions for function map */
int hg_int_equal(void *vlocation1, void *vlocation2)
{
    int *location1;
    int *location2;

    location1 = (int *) vlocation1;
    location2 = (int *) vlocation2;

    return *location1 == *location2;
}

unsigned int hg_int_hash(void *vlocation)
{
    int *location;

    location = (int *) vlocation;

    return (unsigned int) *location;
}

/* Generate a new tag */
static inline na_tag_t gen_tag(void)
{
    long int tag;

    tag = (long int) pthread_getspecific(ptk_tag);
    if (!tag) {
        hg_thread_mutex_lock(&tag_mutex);
        tag = ++next_tag;
        hg_thread_mutex_unlock(&tag_mutex);
        pthread_setspecific(ptk_tag, (void*) tag);
    }
    assert(tag < HG_MAXTAG);
    return tag;
}

/*---------------------------------------------------------------------------
 * Function:    HG_Init
 *
 * Purpose:     Initialize the function shipper and select a network protocol
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int HG_Init(na_class_t *network_class)
{
    int ret = HG_SUCCESS;

    if (hg_na_class) {
        HG_ERROR_DEFAULT("Already initialized");
        ret = HG_FAIL;
        return ret;
    }

    hg_na_class = network_class;

    /* Initialize TLS tags */
    hg_thread_mutex_init(&tag_mutex);
    pthread_key_create(&ptk_tag, 0);
    next_tag = 1;

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

/*---------------------------------------------------------------------------
 * Function:    HG_Finalize
 *
 * Purpose:     Finalize the function shipper
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int HG_Finalize(void)
{
    int ret = HG_SUCCESS, na_ret;

    if (!hg_na_class) {
        HG_ERROR_DEFAULT("Already finalized");
        ret = HG_FAIL;
        return ret;
    }

    na_ret = NA_Finalize(hg_na_class);
    if (na_ret != NA_SUCCESS) {
        HG_ERROR_DEFAULT("Could not finalize");
        ret = HG_FAIL;
        return ret;
    }

    /* Delete function map */
    hg_hash_table_free(func_map);
    func_map = NULL;

    /* Free TLS key */
    hg_thread_mutex_destroy(&tag_mutex);
    pthread_key_delete(ptk_tag);

    hg_na_class = NULL;

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    HG_Register
 *
 * Purpose:     Register a function name and provide a unique ID
 *
 * Returns:     Unsigned integer
 *
 *---------------------------------------------------------------------------
 */
hg_id_t HG_Register(const char *func_name,
        int (*enc_routine)(hg_proc_t proc, void *in_struct),
        int (*dec_routine)(hg_proc_t proc, void *out_struct))
{
    hg_id_t *id;
    hg_proc_info_t *proc_info;

    /* Generate a key from the string */
    id = malloc(sizeof(hg_id_t));

    *id = hg_proc_string_hash(func_name);

    /* Fill a func info struct and store it into the function map */
    proc_info = malloc(sizeof(hg_proc_info_t));

    proc_info->enc_routine = enc_routine;
    proc_info->dec_routine = dec_routine;
    if (!hg_hash_table_insert(func_map, id, proc_info)) {
        HG_ERROR_DEFAULT("Could not insert func ID");
        free(proc_info);
        free(id);
        return 0;
    }

    return *id;
}

/*---------------------------------------------------------------------------
 * Function:    HG_Forward
 *
 * Purpose:     Forward a call to a remote server
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int HG_Forward(na_addr_t addr, hg_id_t id, const void *in_struct, void *out_struct,
        hg_request_t *request)
{
    int ret = HG_SUCCESS, na_ret;

    hg_proc_info_t *proc_info;
    hg_proc_t enc_proc = HG_PROC_NULL;
    uint8_t extra_send_buf_used = 0;

    static int tag_incr = 0;
    na_tag_t   send_tag, recv_tag;

    hg_priv_request_t *priv_request = NULL;

    /* Retrieve encoding function from function map */
    proc_info = hg_hash_table_lookup(func_map, &id);
    if (!proc_info) {
        HG_ERROR_DEFAULT("hg_hash_table_lookup failed");
        ret = HG_FAIL;
        goto done;
    }

    priv_request = malloc(sizeof(hg_priv_request_t));

    priv_request->id = id;

    /* Send Buffer */
    priv_request->send_buf_size = NA_Get_unexpected_size(hg_na_class);
    ret = hg_proc_buf_alloc(&priv_request->send_buf, priv_request->send_buf_size);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Could not allocate send buffer");
        ret = HG_FAIL;
        goto done;
    }
    priv_request->send_request = NA_REQUEST_NULL;

    /* Recv Buffer */
    priv_request->recv_buf_size = NA_Get_unexpected_size(hg_na_class);
    ret = hg_proc_buf_alloc(&priv_request->recv_buf, priv_request->recv_buf_size);
    if (ret != HG_SUCCESS) {
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

    /* Create a new encoding proc */
    ret = hg_proc_create(priv_request->send_buf, priv_request->send_buf_size,
            HG_ENCODE, &enc_proc);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Could not create proc");
        ret = HG_FAIL;
        goto done;
    }

    /* Leave some space for the header */
    ret = hg_proc_set_buf_ptr(enc_proc, priv_request->send_buf + hg_proc_get_header_size());
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Could not move proc to user data");
        ret = HG_FAIL;
        goto done;
    }

    /* Encode the function parameters */
    if (proc_info->enc_routine) {
        ret = proc_info->enc_routine(enc_proc, (void*)in_struct);
        if (ret != HG_SUCCESS) {
            HG_ERROR_DEFAULT("Could not encode parameters");
            ret = HG_FAIL;
        }
    }

    /* The size of the encoding buffer may have changed at this point
     * --> if the buffer is too large, we need to do:
     *  - 1: send an unexpected message with info + eventual bulk data descriptor
     *  - 2: send the remaining data in extra buf using bulk data transfer
     */
    if (hg_proc_get_size(enc_proc) > NA_Get_unexpected_size(hg_na_class)) {
        priv_request->extra_send_buf = hg_proc_get_extra_buf(enc_proc);
        priv_request->extra_send_buf_size = hg_proc_get_extra_size(enc_proc);
        ret = HG_Bulk_handle_create(priv_request->extra_send_buf,
                priv_request->extra_send_buf_size, HG_BULK_READ_ONLY,
                &priv_request->extra_send_buf_handle);
        if (ret != HG_SUCCESS) {
            HG_ERROR_DEFAULT("Could not create bulk data handle");
            goto done;
        }
        hg_proc_set_extra_buf_is_mine(enc_proc, 1);
        extra_send_buf_used = 1;
    }

    /* Encode header */
    ret = hg_proc_header_request(enc_proc, &id, &extra_send_buf_used);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Could not encode header");
        ret = HG_FAIL;
        goto done;
    }

    if (extra_send_buf_used) {
        ret = hg_proc_hg_bulk_t(enc_proc, &priv_request->extra_send_buf_handle);
        if (ret != HG_SUCCESS) {
            HG_ERROR_DEFAULT("Could not encode handle");
            ret = HG_FAIL;
            goto done;
        }
    }

    /* Post the send message and pre-post the recv message */
    send_tag = gen_tag() + tag_incr;
    recv_tag = gen_tag() + tag_incr;
    tag_incr++;
    if (send_tag > HG_MAXTAG) tag_incr = 0;

    na_ret = NA_Send_unexpected(hg_na_class, priv_request->send_buf,
            priv_request->send_buf_size, addr, send_tag,
            &priv_request->send_request, NULL);
    if (na_ret != NA_SUCCESS) {
        HG_ERROR_DEFAULT("Could not send buffer");
        ret = HG_FAIL;
        goto done;
    }

    na_ret = NA_Recv(hg_na_class, priv_request->recv_buf,
            priv_request->recv_buf_size, addr, recv_tag,
            &priv_request->recv_request, NULL);
    if (na_ret != NA_SUCCESS) {
        HG_ERROR_DEFAULT("Could not pre-post buffer");
        ret = HG_FAIL;
        goto done;
    }

    *request = (hg_request_t) priv_request;

done:
    if (enc_proc != HG_PROC_NULL) hg_proc_free(enc_proc);
    enc_proc = HG_PROC_NULL;

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

/*---------------------------------------------------------------------------
 * Function:    HG_Wait
 *
 * Purpose:     Wait for an operation request to complete
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int HG_Wait(hg_request_t request, unsigned int timeout, hg_status_t *status)
{
    hg_priv_request_t *priv_request = (hg_priv_request_t*) request;
    na_status_t        send_status;
    na_status_t        recv_status;
    hg_proc_info_t    *proc_info;

    int ret = HG_SUCCESS;

    if (!priv_request) {
        HG_ERROR_DEFAULT("NULL request");
        ret = HG_FAIL;
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

            /* Everything has been sent so free unused resources */
            if (priv_request->send_buf) free (priv_request->send_buf);
            priv_request->send_buf = NULL;
            priv_request->send_buf_size = 0;
            if (priv_request->extra_send_buf) free(priv_request->extra_send_buf);
            priv_request->extra_send_buf = NULL;
            priv_request->extra_send_buf_size = 0;
            if (priv_request->extra_send_buf_handle != HG_BULK_NULL)
                HG_Bulk_handle_free(priv_request->extra_send_buf_handle);
            priv_request->extra_send_buf_handle = HG_BULK_NULL;
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
        }
    }

    if ((priv_request->send_request == NA_REQUEST_NULL) &&
            (priv_request->recv_request == NA_REQUEST_NULL)) {
        hg_proc_t dec_proc;
        uint8_t extra_recv_buf_used;

        /* Decode depending on op ID */
        proc_info = hg_hash_table_lookup(func_map, &priv_request->id);
        if (!proc_info) {
            HG_ERROR_DEFAULT("hg_hash_table_lookup failed");
            ret = HG_FAIL;
            return ret;
        }

        ret = hg_proc_create(priv_request->recv_buf, priv_request->recv_buf_size,
                HG_DECODE, &dec_proc);
        if (ret != HG_SUCCESS) {
            HG_ERROR_DEFAULT("Could not create proc");
            ret = HG_FAIL;
            return ret;
        }

        ret = hg_proc_header_response(dec_proc, &extra_recv_buf_used);
        if (ret != HG_SUCCESS) {
            HG_ERROR_DEFAULT("Could not decode header");
            ret = HG_FAIL;
            return ret;
        }

        if (extra_recv_buf_used) {
            /* TODO Receive extra buffer now */
        } else {
            /* Set buffer to user data */
            ret = hg_proc_set_buf_ptr(dec_proc, priv_request->recv_buf + hg_proc_get_header_size());
            if (ret != HG_SUCCESS) {
                HG_ERROR_DEFAULT("Could not move proc to user data");
                ret = HG_FAIL;
                return ret;
            }
        }

        /* Decode function parameters */
        if (proc_info->dec_routine) {
            ret = proc_info->dec_routine(dec_proc, priv_request->out_struct);
            if (ret != HG_SUCCESS) {
                HG_ERROR_DEFAULT("Could not decode return parameters");
                ret = HG_FAIL;
                return ret;
            }
        }

        /* Free the decoding proc */
        hg_proc_free(dec_proc);

        /* Everything has been decode so free unused resources */
        if (priv_request->recv_buf) free (priv_request->recv_buf);
        priv_request->recv_buf = NULL;
        priv_request->recv_buf_size = 0;

        /* Free request */
        free(priv_request);
        priv_request = NULL;

        if (status && (status != HG_STATUS_IGNORE)) {
            *status = 1;
        }
    }

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    HG_Wait_all
 *
 * Purpose:     Wait for all operations to complete
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int HG_Wait_all(int count, hg_request_t array_of_requests[],
        unsigned int timeout, hg_status_t array_of_statuses[])
{
    int ret = HG_SUCCESS;
    int i;

    /* TODO For now just loop over requests */
    for (i = 0; i < count; i++) {
        ret = HG_Wait(array_of_requests[i], timeout, &array_of_statuses[i]);
    }

    return ret;
}
