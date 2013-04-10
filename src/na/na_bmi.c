/*
 * Copyright (C) 2013 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#include "na_bmi.h"

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <errno.h>
#include <stdbool.h>
#include <assert.h>
#include <sys/time.h>
#include <string.h>
#include <unistd.h>

static int na_bmi_finalize(void);
static na_size_t na_bmi_get_unexpected_size(void);
static int na_bmi_addr_lookup(const char *name, na_addr_t *addr);
static int na_bmi_addr_free(na_addr_t addr);
static int na_bmi_send_unexpected(const void *buf, na_size_t buf_len, na_addr_t dest,
        na_tag_t tag, na_request_t *request, void *op_arg);
static int na_bmi_recv_unexpected(void *buf, na_size_t *buf_len, na_addr_t *source,
        na_tag_t *tag, na_request_t *request, void *op_arg);
static int na_bmi_send(const void *buf, na_size_t buf_len, na_addr_t dest,
        na_tag_t tag, na_request_t *request, void *op_arg);
static int na_bmi_recv(void *buf, na_size_t buf_len, na_addr_t source,
        na_tag_t tag, na_request_t *request, void *op_arg);
static int na_bmi_mem_register(void *buf, na_size_t buf_len, unsigned long flags, na_mem_handle_t *mem_handle);
static int na_bmi_mem_deregister(na_mem_handle_t mem_handle);
static int na_bmi_mem_handle_serialize(void *buf, na_size_t buf_len, na_mem_handle_t mem_handle);
static int na_bmi_mem_handle_deserialize(na_mem_handle_t *mem_handle, const void *buf, na_size_t buf_len);
static int na_bmi_mem_handle_free(na_mem_handle_t mem_handle);
static int na_bmi_put(na_mem_handle_t local_mem_handle, na_offset_t local_offset,
        na_mem_handle_t remote_mem_handle, na_offset_t remote_offset,
        na_size_t length, na_addr_t remote_addr, na_request_t *request);
static int na_bmi_get(na_mem_handle_t local_mem_handle, na_offset_t local_offset,
        na_mem_handle_t remote_mem_handle, na_offset_t remote_offset,
        na_size_t length, na_addr_t remote_addr, na_request_t *request);
static int na_bmi_wait(na_request_t request, unsigned int timeout, na_status_t *status);

static na_class_t na_bmi_g = {
        na_bmi_finalize,               /* finalize */
        na_bmi_get_unexpected_size,    /* get_unexpected_size */
        na_bmi_addr_lookup,            /* addr_lookup */
        na_bmi_addr_free,              /* addr_free */
        na_bmi_send_unexpected,        /* send_unexpected */
        na_bmi_recv_unexpected,        /* recv_unexpected */
        na_bmi_send,                   /* send */
        na_bmi_recv,                   /* recv */
        na_bmi_mem_register,           /* mem_register */
        na_bmi_mem_deregister,         /* mem_deregister */
        na_bmi_mem_handle_serialize,   /* mem_handle_serialize */
        na_bmi_mem_handle_deserialize, /* mem_handle_deserialize */
        na_bmi_mem_handle_free,        /* mem_handle_free */
        na_bmi_put,                    /* put */
        na_bmi_get,                    /* get */
        na_bmi_wait                    /* wait */
};

typedef struct bmi_request {
    bmi_op_id_t op_id;       /* BMI op ID */
    bool completed;          /* 1 if operation has completed */
    void *user_ptr;          /* Extra info passed to BMI to identify request */
    bmi_size_t actual_size;  /* Actual buffer size (must only be a pointer if we return it in the receive) */
} bmi_request_t;

static bmi_context_id  bmi_context;
static pthread_mutex_t request_mutex;
static pthread_mutex_t testcontext_mutex;
static pthread_cond_t  testcontext_cond;
static bool            is_testing_context;

na_class_t *NA_BMI_Init(const char *method_list, const char *listen_addr, int flags)
{
    int bmi_ret;

    /* Initialize BMI */
    bmi_ret = BMI_initialize(method_list, listen_addr, flags);
    if (bmi_ret < 0) {
        NA_ERROR_DEFAULT("BMI_initialize() failed");
    }

    /* Create a new BMI context */
    bmi_ret = BMI_open_context(&bmi_context);

    if (bmi_ret < 0) {
        NA_ERROR_DEFAULT("BMI_open_context() failed");
    }

    /* Initialize cond variable */
    pthread_mutex_init(&request_mutex, NULL);
    pthread_mutex_init(&testcontext_mutex, NULL);
    pthread_cond_init(&testcontext_cond, NULL);
    is_testing_context = 0;

    return &na_bmi_g;
}

static int na_bmi_finalize(void)
{
    int bmi_ret, ret = NA_SUCCESS;

    /* Close BMI context */
    BMI_close_context(bmi_context);

    /* Finalize BMI */
    bmi_ret = BMI_finalize();

    if (bmi_ret < 0) {
        NA_ERROR_DEFAULT("BMI_finalize() failed");
        ret = NA_FAIL;
    }

    pthread_mutex_destroy(&request_mutex);
    pthread_mutex_destroy(&testcontext_mutex);
    pthread_cond_destroy(&testcontext_cond);

    return ret;
}

static na_size_t na_bmi_get_unexpected_size()
{
    na_size_t max_unexpected_size = 4*1024;
    return max_unexpected_size;
}

static int na_bmi_addr_lookup(const char *name, na_addr_t *addr)
{
    int bmi_ret, ret = NA_SUCCESS;
    BMI_addr_t *bmi_addr = NULL;

    /* Perform an address addr_lookup on the ION */
    bmi_addr = malloc(sizeof(BMI_addr_t));
    bmi_ret = BMI_addr_lookup(bmi_addr, name);

    if (bmi_ret < 0) {
        NA_ERROR_DEFAULT("BMI_addr_lookup() failed");
        free(bmi_addr);
        bmi_addr = NULL;
        ret = NA_FAIL;
    } else {
        if (addr) *addr = (na_addr_t) bmi_addr;
    }
    return ret;
}

static int na_bmi_addr_free(na_addr_t addr)
{
    BMI_addr_t *bmi_addr = (BMI_addr_t*) addr;
    int ret = NA_SUCCESS;

    /* Cleanup peer_addr */
    if (bmi_addr) {
        free(bmi_addr);
        bmi_addr = NULL;
    } else {
        NA_ERROR_DEFAULT("Already freed");
        ret = NA_FAIL;
    }
    return ret;
}

static int na_bmi_send_unexpected(const void *buf, na_size_t buf_len, na_addr_t dest,
        na_tag_t tag, na_request_t *request, void *op_arg)
{
    int bmi_ret, ret = NA_SUCCESS;
    bmi_size_t bmi_buf_len = (bmi_size_t) buf_len;
    BMI_addr_t *bmi_peer_addr = (BMI_addr_t*) dest;
    bmi_msg_tag_t bmi_tag = (bmi_msg_tag_t) tag;
    bmi_request_t *bmi_request = NULL;

    /* Allocate request */
    bmi_request = malloc(sizeof(bmi_request_t));
    bmi_request->completed = 0;
    bmi_request->actual_size = 0;
    bmi_request->user_ptr = op_arg;

    /* Post the BMI unexpected send request */
    bmi_ret = BMI_post_sendunexpected(&bmi_request->op_id, *bmi_peer_addr, buf, bmi_buf_len,
            BMI_EXT_ALLOC, bmi_tag, bmi_request, bmi_context, NULL);

    if (bmi_ret < 0) {
        NA_ERROR_DEFAULT("BMI_post_sendunexpected() failed");
        free(bmi_request);
        bmi_request = NULL;
        ret = NA_FAIL;
    } else {
        pthread_mutex_lock(&request_mutex);
        /* Mark request as done if immediate bmi completion detected */
        bmi_request->completed = bmi_ret ? 1 : 0;
        *request = (na_request_t) bmi_request;
        pthread_mutex_unlock(&request_mutex);
    }
    return ret;
}

static int na_bmi_recv_unexpected(void *buf, na_size_t *buf_len, na_addr_t *source,
        na_tag_t *tag, na_request_t *request, void *op_arg)
{
    int ret = NA_SUCCESS;
    int bmi_ret, outcount = 0;
    struct BMI_unexpected_info request_info;

    do {
        bmi_ret = BMI_testunexpected(1, &outcount, &request_info, 0);
    } while (bmi_ret == 0 && outcount == 0);

    if (bmi_ret < 0 || request_info.error_code != 0) {
        NA_ERROR_DEFAULT("Request recv failure (bad state)");
        NA_ERROR_DEFAULT("BMI_testunexpected failed");
        ret = NA_FAIL;
    } else {
        if (outcount) {
            if (source) {
                BMI_addr_t **peer_addr = (BMI_addr_t**) source;
                *peer_addr = malloc(sizeof(BMI_addr_t));
                **peer_addr = request_info.addr;
            }
            if (buf_len) *buf_len = (na_size_t) request_info.size;
            if (tag) *tag = (na_tag_t) request_info.tag;
            if (buf) memcpy(buf, request_info.buffer, request_info.size);
            BMI_unexpected_free(request_info.addr, request_info.buffer);
        } else {
            NA_ERROR_DEFAULT("No pending message found");
            ret = NA_FAIL;
        }
    }
    return ret;
}

static int na_bmi_send(const void *buf, na_size_t buf_len, na_addr_t dest,
        na_tag_t tag, na_request_t *request, void *op_arg)
{
    int ret = NA_SUCCESS, bmi_ret;
    bmi_size_t bmi_buf_len = (bmi_size_t) buf_len;
    BMI_addr_t *bmi_peer_addr = (BMI_addr_t*) dest;
    bmi_msg_tag_t bmi_tag = (bmi_msg_tag_t) tag;
    bmi_request_t *bmi_request = NULL;

    /* Allocate request */
    bmi_request = malloc(sizeof(bmi_request_t));
    bmi_request->completed = 0;
    bmi_request->actual_size = 0;
    bmi_request->user_ptr = op_arg;

    /* Post the BMI send request */
    bmi_ret = BMI_post_send(&bmi_request->op_id, *bmi_peer_addr, buf, bmi_buf_len,
            BMI_EXT_ALLOC, bmi_tag, bmi_request, bmi_context, NULL);

    if (bmi_ret < 0) {
        NA_ERROR_DEFAULT("BMI_post_send() failed");
        free(bmi_request);
        bmi_request = NULL;
        ret = NA_FAIL;
        return ret;
    }

    pthread_mutex_lock(&request_mutex);
    /* Mark request as done if immediate BMI completion detected */
    bmi_request->completed = ret ? 1 : 0;
    *request = (na_request_t) bmi_request;
    pthread_mutex_unlock(&request_mutex);

    return ret;
}

static int na_bmi_recv(void *buf, na_size_t buf_len, na_addr_t source,
        na_tag_t tag, na_request_t *request, void *op_arg)
{
    int bmi_ret, ret = NA_SUCCESS;
    bmi_size_t bmi_buf_len = (bmi_size_t) buf_len;
    BMI_addr_t *bmi_peer_addr = (BMI_addr_t*) source;
    bmi_msg_tag_t bmi_tag = (bmi_msg_tag_t) tag;
    bmi_request_t *bmi_request = NULL;

    /* Allocate request */
    bmi_request = malloc(sizeof(bmi_request_t));
    bmi_request->completed = 0;
    bmi_request->actual_size = 0; /* (bmi_size_t*) actual_size; */
    bmi_request->user_ptr = op_arg;

    /* Post the BMI recv request */
    bmi_ret = BMI_post_recv(&bmi_request->op_id, *bmi_peer_addr, buf, bmi_buf_len,
            &bmi_request->actual_size, BMI_EXT_ALLOC, bmi_tag, bmi_request, bmi_context, NULL);

    if (bmi_ret < 0) {
        NA_ERROR_DEFAULT("BMI_post_recv() failed");
        free(bmi_request);
        bmi_request = NULL;
        ret = NA_FAIL;
        return ret;
    }

    pthread_mutex_lock(&request_mutex);
    /* Mark request as done if immediate BMI completion detected */
    bmi_request->completed = bmi_ret ? 1 : 0;
    *request = (na_request_t) bmi_request;
    pthread_mutex_unlock(&request_mutex);

    return ret;
}

static int na_bmi_mem_register(void *buf, na_size_t buf_len, unsigned long flags, na_mem_handle_t *mem_handle)
{
    return 0;
}

static int na_bmi_mem_deregister(na_mem_handle_t mem_handle)
{
    return 0;
}

static int na_bmi_mem_handle_serialize(void *buf, na_size_t buf_len, na_mem_handle_t mem_handle)
{
    return 0;
}

static int na_bmi_mem_handle_deserialize(na_mem_handle_t *mem_handle, const void *buf, na_size_t buf_len)
{
    return 0;
}

static int na_bmi_mem_handle_free(na_mem_handle_t mem_handle)
{
    return 0;
}

static int na_bmi_put(na_mem_handle_t local_mem_handle, na_offset_t local_offset,
        na_mem_handle_t remote_mem_handle, na_offset_t remote_offset,
        na_size_t length, na_addr_t remote_addr, na_request_t *request)
{
    return 0;
}

static int na_bmi_get(na_mem_handle_t local_mem_handle, na_offset_t local_offset,
        na_mem_handle_t remote_mem_handle, na_offset_t remote_offset,
        na_size_t length, na_addr_t remote_addr, na_request_t *request)
{
    return 0;
}

static int na_bmi_wait(na_request_t request, unsigned int timeout, na_status_t *status)
{
    bmi_request_t *bmi_wait_request = (bmi_request_t*) request;
    unsigned int remaining = timeout;
    int ret = NA_SUCCESS;
    bool wait_request_completed = 0;

    /* Only the thread that has created the request should wait and free that request
     * even if the request may have been marked as completed by other threads */
    if (!bmi_wait_request) {
        NA_ERROR_DEFAULT("NULL request");
        ret = NA_FAIL;
        return ret;
    }

    /* TODO ensure that request is well protected */
    pthread_mutex_lock(&request_mutex);
    wait_request_completed = bmi_wait_request->completed;
    pthread_mutex_unlock(&request_mutex);

    if (!wait_request_completed)
    do {
        struct timespec ts1, ts2;
        ldiv_t ld;
        int pthread_cond_ret = 0;

        /* Convert from ms to timespec */
        ld = ldiv(remaining, 1000);
        ts1.tv_sec = ld.quot;
        ts1.tv_nsec = ld.rem * 1000000L;
        ts2 = ts1;

        pthread_mutex_lock(&testcontext_mutex);

        while (is_testing_context) {
            pthread_cond_ret = pthread_cond_timedwait(&testcontext_cond, &testcontext_mutex, &ts2);
        }
        is_testing_context = 1;

        pthread_mutex_unlock(&testcontext_mutex);

        if (ETIMEDOUT == pthread_cond_ret) {
            ret = NA_FAIL;
            break;
        }
        remaining -= (ts1.tv_sec - ts2.tv_sec) * 1000 + (ts1.tv_nsec - ts2.tv_nsec) / 1000000;

        /* Only one calling thread at a time should reach that point */
        pthread_mutex_lock(&testcontext_mutex);

        /* Test again here as request may have completed while waiting */
        pthread_mutex_lock(&request_mutex);
        wait_request_completed = bmi_wait_request->completed;
        pthread_mutex_unlock(&request_mutex);

        if (!wait_request_completed) {
            int bmi_ret = 0, outcount = 0;
            bmi_error_code_t error_code = 0;
            bmi_op_id_t bmi_op_id = 0;
            bmi_size_t  bmi_actual_size = 0;
            void *bmi_user_ptr = NULL;
            struct timeval t1, t2;

            gettimeofday(&t1, NULL);

            bmi_ret = BMI_testcontext(1, &bmi_op_id, &outcount, &error_code,
                    &bmi_actual_size, &bmi_user_ptr, remaining, bmi_context);

            gettimeofday(&t2, NULL);
            remaining -= (t2.tv_sec - t1.tv_sec) * 1000 + (t2.tv_usec - t1.tv_usec) / 1000;

            if (bmi_ret < 0 || error_code != 0) {
                NA_ERROR_DEFAULT("BMI_testcontext failed");
                ret = NA_FAIL;
                return ret;
            }

            if (bmi_user_ptr) {
                bmi_request_t *bmi_request;

                pthread_mutex_lock(&request_mutex);
                bmi_request = (bmi_request_t *) bmi_user_ptr;
                assert(bmi_op_id == bmi_request->op_id);
                /* Mark the request as completed */
                bmi_request->completed = 1;
                /* Our request may have been marked as completed as well */
                wait_request_completed = bmi_wait_request->completed;
                /* Only set the actual size if it's a receive request */
                bmi_request->actual_size = bmi_actual_size;
                pthread_mutex_unlock(&request_mutex);
            }
        }

        /* Wake up others */
        is_testing_context = 0;
        pthread_cond_signal(&testcontext_cond);

        pthread_mutex_unlock(&testcontext_mutex);
    } while (!wait_request_completed && remaining > 0);

    pthread_mutex_lock(&request_mutex);

    if (status && status != NA_STATUS_IGNORE) {
        status->completed = bmi_wait_request->completed;

        /* Fill status and free request if completed */
        if (bmi_wait_request->completed) {
            status->count = bmi_wait_request->actual_size;
            free(bmi_wait_request);
            bmi_wait_request = NULL;
        }
    }

    pthread_mutex_unlock(&request_mutex);

    return ret;
}
