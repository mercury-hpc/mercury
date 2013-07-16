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
#include "mercury_proc.h"

#include "mercury_hash_table.h"
#include "mercury_thread.h"
#include "mercury_thread_mutex.h"

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
} hg_priv_request_t;

typedef struct hg_proc_info {
    int (*enc_routine)(hg_proc_t proc, void *in_struct);
    int (*dec_routine)(hg_proc_t proc, void *out_struct);
} hg_proc_info_t;

/* Function map */
static hg_hash_table_t *func_map;

/* Mutex used for tag generation */
/* TODO use atomic increment instead */
static hg_thread_mutex_t tag_mutex;

/* Pointer to network abstraction class */
static na_class_t *hg_na_class = NULL;

/* Pointer to function called at termination */
static void (*hg_atfinalize)(void) = NULL;
static hg_bool_t hg_dont_atexit = 0;

/**
 * Hash functions for function map
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
 *
 */
unsigned int
hg_int_hash(void *vlocation)
{
    int *location;

    location = (int *) vlocation;

    return (unsigned int) *location;
}

/**
 * Generate a new tag
 */
static HG_INLINE na_tag_t
hg_gen_tag(void)
{
    static long int tag = 0;

    hg_thread_mutex_lock(&tag_mutex);
    tag++;
    if (tag == NA_Msg_get_maximum_tag(hg_na_class)) tag = 0;
    hg_thread_mutex_unlock(&tag_mutex);

    return tag;
}

/**
 * Automatically called at exit
 */
static void
hg_atexit(void)
{
    if (hg_na_class) {
        int hg_ret;

        printf("Auto finalize is called\n");

        /* Finalize interface */
        hg_ret = HG_Finalize();
        if (hg_ret != HG_SUCCESS) {
            HG_ERROR_DEFAULT("Could not finalize mercury interface");
        }
    }
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

    /*
     * Install atexit() library cleanup routine unless hg_dont_atexit is set.
     * Once we add something to the atexit() list it stays there permanently,
     * so we set hg_dont_atexit after we add it to prevent adding it again
     * later if the library is closed and reopened.
     */
    if (!hg_dont_atexit) {
        (void) atexit(hg_atexit);
        hg_dont_atexit = 1;
    }

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

    /* Call extra finalize callback if required */
    if (hg_atfinalize) hg_atfinalize();

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
int
HG_Atfinalize(void (*function)(void))
{
    int ret = HG_SUCCESS;

    hg_atfinalize = function;

    return ret;
}

/*---------------------------------------------------------------------------*/
hg_id_t
HG_Register(const char *func_name,
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

/*---------------------------------------------------------------------------*/
int
HG_Registered(const char *func_name, hg_bool_t *flag, hg_id_t *id)
{
    int ret = HG_SUCCESS;
    hg_id_t func_id;

    if (!flag) {
        HG_ERROR_DEFAULT("NULL flag");
        ret = HG_FAIL;
        return ret;
    }

    func_id = hg_proc_string_hash(func_name);

    *flag = (hg_hash_table_lookup(func_map, &func_id) != HG_HASH_TABLE_NULL) ? 1 : 0;
    if (id) *id = (*flag) ? func_id : 0;

    return HG_SUCCESS;
}

/*---------------------------------------------------------------------------*/
int
HG_Forward(na_addr_t addr, hg_id_t id, const void *in_struct, void *out_struct,
        hg_request_t *request)
{
    int ret = HG_SUCCESS, na_ret;

    hg_proc_info_t *proc_info;
    hg_proc_t enc_proc = HG_PROC_NULL;
    hg_uint8_t extra_send_buf_used = 0;

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
    priv_request->send_buf_size = NA_Msg_get_maximum_size(hg_na_class);
    ret = hg_proc_buf_alloc(&priv_request->send_buf, priv_request->send_buf_size);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Could not allocate send buffer");
        ret = HG_FAIL;
        goto done;
    }
    priv_request->send_request = NA_REQUEST_NULL;

    /* Recv Buffer */
    priv_request->recv_buf_size = NA_Msg_get_maximum_size(hg_na_class);
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
    ret = hg_proc_set_buf_ptr(enc_proc, (char*) priv_request->send_buf + hg_proc_get_header_size());
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
    if (hg_proc_get_size(enc_proc) > NA_Msg_get_maximum_size(hg_na_class)) {
#ifdef HG_HAS_XDR
        HG_ERROR_DEFAULT("Extra encoding using XDR is not yet supported");
        ret = HG_FAIL;
        goto done;
#else
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
#endif
    }

    /* Encode header */
    ret = hg_proc_header_request(enc_proc, &id, &extra_send_buf_used,
            &priv_request->extra_send_buf_handle);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Could not encode header");
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

/*---------------------------------------------------------------------------*/
int
HG_Wait(hg_request_t request, unsigned int timeout, hg_status_t *status)
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

            /* Everything has been sent so free unused resources except eventual extra buffer */
            if (priv_request->send_buf) free (priv_request->send_buf);
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
        hg_proc_t dec_proc;
        hg_uint8_t extra_recv_buf_used;

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
            ret = hg_proc_set_buf_ptr(dec_proc, (char*) priv_request->recv_buf + hg_proc_get_header_size());
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

        /* Everything has been decoded so free unused resources */
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

/*---------------------------------------------------------------------------*/
int
HG_Wait_all(int count, hg_request_t array_of_requests[],
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
