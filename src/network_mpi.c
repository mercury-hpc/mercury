/*
 * network_mpi.c
 *
 *  Created on: Nov 5, 2012
 *      Author: soumagne
 */

#include "network_mpi.h"

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <errno.h>
#include <stdbool.h>
#include <assert.h>
#include <string.h>

static void na_mpi_finalize(void);
static na_size_t na_mpi_get_unexpected_size(void);
static int na_mpi_lookup(const char *name, na_addr_t *target);
static int na_mpi_free(na_addr_t target);
static int na_mpi_send_unexpected(const void *buf, na_size_t buf_len, na_addr_t dest,
        na_tag_t tag, na_request_t *request, void *op_arg);
static int na_mpi_recv_unexpected(void *buf, na_size_t *buf_len, na_addr_t *source,
        na_tag_t *tag, na_request_t *request, void *op_arg);
static int na_mpi_send(const void *buf, na_size_t buf_len, na_addr_t dest,
        na_tag_t tag, na_request_t *request, void *op_arg);
static int na_mpi_recv(void *buf, na_size_t buf_len, na_addr_t source,
        na_tag_t tag, na_request_t *request, void *op_arg);
static int na_mpi_mem_register(void *buf, na_size_t buf_len, unsigned long flags, na_mem_handle_t *mem_handle);
static int na_mpi_mem_deregister(na_mem_handle_t mem_handle);
static int na_mpi_mem_handle_serialize(void *buf, na_size_t buf_len, na_mem_handle_t mem_handle);
static int na_mpi_mem_handle_deserialize(na_mem_handle_t *mem_handle, const void *buf, na_size_t buf_len);
static int na_mpi_put(na_mem_handle_t local_mem_handle, na_offset_t local_offset,
        na_mem_handle_t remote_mem_handle, na_offset_t remote_offset,
        na_size_t length, na_addr_t remote_addr, na_request_t *request);
static int na_mpi_get(na_mem_handle_t local_mem_handle, na_offset_t local_offset,
        na_mem_handle_t remote_mem_handle, na_offset_t remote_offset,
        na_size_t length, na_addr_t remote_addr, na_request_t *request);
static int na_mpi_wait(na_request_t request, int *flag, int timeout, na_status_t *status);

static network_class_t na_mpi_g = {
        na_mpi_finalize,               /* finalize */
        na_mpi_get_unexpected_size,    /* get_unexpected_size */
        na_mpi_lookup,                 /* lookup */
        na_mpi_free,                   /* free */
        na_mpi_send_unexpected,        /* send_unexpected */
        na_mpi_recv_unexpected,        /* recv_unexpected */
        na_mpi_send,                   /* send */
        na_mpi_recv,                   /* recv */
        na_mpi_mem_register,           /* mem_register */
        na_mpi_mem_deregister,         /* mem_deregister */
        na_mpi_mem_handle_serialize,   /* mem_handle_serialize */
        na_mpi_mem_handle_deserialize, /* mem_handle_deserialize */
        na_mpi_put,                    /* put */
        na_mpi_get,                    /* get */
        na_mpi_wait                    /* wait */
};

static int mpi_ext_initialized;
static MPI_Comm mpi_intra_comm = MPI_COMM_NULL;
static char mpi_port_name[MPI_MAX_PORT_NAME];
static bool na_server = 0;

typedef struct mpi_target_t {
    MPI_Comm  comm;
    bool      is_reference;
} mpi_target_t;

/* TODO must be stored in a container */
static mpi_target_t server_target;

void na_mpi_init(MPI_Comm *intra_comm, int flags)
{
    /* MPI_Init */
    MPI_Initialized(&mpi_ext_initialized);
    if (!mpi_ext_initialized) {
        printf("Internally initializing MPI...\n");
        MPI_Init(NULL, NULL);
    }

    /* Assign MPI intra comm */
    if (intra_comm && (*intra_comm != MPI_COMM_NULL)) {
        MPI_Comm_dup(*intra_comm, &mpi_intra_comm);
    } else {
        MPI_Comm_dup(MPI_COMM_WORLD, &mpi_intra_comm);
    }

    /* If server open a port */
    /* TODO How do we communicate the port name to the client */
    if (flags == MPI_INIT_SERVER) {
        FILE *config;
        na_server = 1;
        MPI_Open_port(MPI_INFO_NULL, mpi_port_name);
        printf("Using MPI port name: %s.\n", mpi_port_name);
        config = fopen("port.cfg", "w+");
        fwrite(mpi_port_name, sizeof(char), MPI_MAX_PORT_NAME, config);
        fclose(config);

        MPI_Comm_accept(mpi_port_name, MPI_INFO_NULL, 0, mpi_intra_comm, &server_target.comm);
        server_target.is_reference = 0;
    }
    na_register(&na_mpi_g);
}

static void na_mpi_finalize(void)
{
    int mpi_ext_finalized;

    /* If server open a port */
    if (na_server) {
        MPI_Comm_free(&server_target.comm);
        MPI_Close_port(mpi_port_name);
    }

    /* Free the dup'ed comm */
    MPI_Comm_free(&mpi_intra_comm);

    /* MPI_Finalize */
    MPI_Finalized(&mpi_ext_finalized);
    if (mpi_ext_finalized) fprintf(stderr, "MPI already finalized\n");
    if (!mpi_ext_initialized && !mpi_ext_finalized) {
        printf("Internally finalizing MPI...\n");
        MPI_Finalize();
    }
}

static na_size_t na_mpi_get_unexpected_size()
{
    na_size_t max_unexpected_size = 4*1024*1024;
    return max_unexpected_size;
}

static int na_mpi_lookup(const char *name, na_addr_t *target)
{
    int mpi_ret, ret = NA_SUCCESS;
    char *port_name = (char*) name;
    mpi_target_t *mpi_target;

    /* Allocate the target */
    mpi_target = malloc(sizeof(mpi_target_t));
    mpi_target->comm = MPI_COMM_NULL;
    /* Comm is not a reference as it is created in connect */
    mpi_target->is_reference = 0;

    /* Try to connect */
    mpi_ret = MPI_Comm_connect(port_name, MPI_INFO_NULL, 0, mpi_intra_comm, &mpi_target->comm);
    if (mpi_ret != MPI_SUCCESS) {
        NA_ERROR_DEFAULT("Could not connect");
        free(mpi_target);
        mpi_target = NULL;
        ret = NA_FAIL;
    } else {
        printf("Connected!\n");
        if (target) *target = (na_addr_t) mpi_target;
    }
    return ret;
}

static int na_mpi_free(na_addr_t target)
{
    mpi_target_t *mpi_target = (mpi_target_t*) target;
    int ret = NA_SUCCESS;

    if (mpi_target) {
        /* TODO improve target to have two fields so we know it's been dup'ed or not */
        if (!mpi_target->is_reference) MPI_Comm_free(&mpi_target->comm);
        free(mpi_target);
        mpi_target = NULL;
    } else {
        NA_ERROR_DEFAULT("Already freed");
        ret = NA_FAIL;
    }
    return ret;
}

static int na_mpi_send_unexpected(const void *buf, na_size_t buf_len, na_addr_t dest,
        na_tag_t tag, na_request_t *request, void *op_arg)
{
    /* TODO */
    return na_mpi_send(buf, buf_len, dest, tag, request, op_arg);
}

static int na_mpi_recv_unexpected(void *buf, na_size_t *buf_len, na_addr_t *source,
        na_tag_t *tag, na_request_t *request, void *op_arg)
{
    int mpi_ret, ret = NA_SUCCESS;
    MPI_Status mpi_status;
    int flag = 0;

    do {
       mpi_ret = MPI_Iprobe(0, MPI_ANY_TAG, server_target.comm, &flag, &mpi_status);
    } while (flag == 0 && mpi_ret == MPI_SUCCESS);

    if (flag) {
        void *mpi_buf;
        int *mpi_buf_len = (int*) buf_len;
        int *mpi_tag = (int*) tag;
        int mpi_source;
        MPI_Status recv_status;

        if (source) {
            mpi_target_t **peer_addr_ptr = (mpi_target_t**) source;
            mpi_target_t *peer_addr;
            *peer_addr_ptr = malloc(sizeof(mpi_target_t));
            peer_addr = *peer_addr_ptr;
            peer_addr->comm = server_target.comm;
            peer_addr->is_reference = 1;
        }
        MPI_Get_count(&mpi_status, MPI_UNSIGNED_CHAR, mpi_buf_len);
        mpi_buf = malloc(*mpi_buf_len);
        mpi_source = mpi_status.MPI_SOURCE;
        if (mpi_tag) *mpi_tag = mpi_status.MPI_TAG;

        mpi_ret = MPI_Recv(mpi_buf, *mpi_buf_len, MPI_UNSIGNED_CHAR, mpi_source,
                *mpi_tag, server_target.comm, &recv_status);
        if (mpi_ret != MPI_SUCCESS) {
            NA_ERROR_DEFAULT("MPI_Recv() failed");
            ret = NA_FAIL;
        } else {
            if (buf) memcpy(buf, mpi_buf, recv_status.count);
        }
        free(mpi_buf);
        mpi_buf = NULL;
    } else {
        NA_ERROR_DEFAULT("No pending message found");
        ret = NA_FAIL;
    }
    return ret;
}

static int na_mpi_send(const void *buf, na_size_t buf_len, na_addr_t dest,
        na_tag_t tag, na_request_t *request, void *op_arg)
{
    int mpi_ret, ret = NA_SUCCESS;
    void *mpi_buf = (void*) buf;
    int mpi_buf_len = (int) buf_len;
    int mpi_tag = (int) tag;
    mpi_target_t *mpi_target = (mpi_target_t*) dest;
    MPI_Request *mpi_request;

    mpi_request = malloc(sizeof(MPI_Request));
    *mpi_request = 0;

    mpi_ret = MPI_Isend(mpi_buf, mpi_buf_len, MPI_UNSIGNED_CHAR, 0, mpi_tag, mpi_target->comm, mpi_request);
    if (mpi_ret != MPI_SUCCESS) {
        NA_ERROR_DEFAULT("MPI_Isend() failed");
        free(mpi_request);
        mpi_request = NULL;
        ret = NA_FAIL;
    } else {
        *request = (na_request_t) mpi_request;
    }
    return ret;
}

static int na_mpi_recv(void *buf, na_size_t buf_len, na_addr_t source,
        na_tag_t tag, na_request_t *request, void *op_arg)
{
    int mpi_ret, ret = NA_SUCCESS;
    void *mpi_buf = (void*) buf;
    int mpi_buf_len = (int) buf_len;
    int mpi_tag = (int) tag;
    mpi_target_t *mpi_target = (mpi_target_t*) source;
    MPI_Request *mpi_request;

    mpi_request = malloc(sizeof(MPI_Request));
    *mpi_request = 0;

    mpi_ret = MPI_Irecv(mpi_buf, mpi_buf_len, MPI_UNSIGNED_CHAR, 0, mpi_tag, mpi_target->comm, mpi_request);
    if (mpi_ret != MPI_SUCCESS) {
        NA_ERROR_DEFAULT("MPI_IRecv() failed");
        free(mpi_request);
        mpi_request = NULL;
        ret = NA_FAIL;
    } else {
        *request = (na_request_t) mpi_request;
    }
    return ret;
}

int na_mpi_mem_register(void *buf, na_size_t buf_len, unsigned long flags, na_mem_handle_t *mem_handle)
{
    return 0;
}

int na_mpi_mem_deregister(na_mem_handle_t mem_handle)
{
    return 0;
}

int na_mpi_mem_handle_serialize(void *buf, na_size_t buf_len, na_mem_handle_t mem_handle)
{
    return 0;
}

int na_mpi_mem_handle_deserialize(na_mem_handle_t *mem_handle, const void *buf, na_size_t buf_len)
{
    return 0;
}

int na_mpi_put(na_mem_handle_t local_mem_handle, na_offset_t local_offset,
        na_mem_handle_t remote_mem_handle, na_offset_t remote_offset,
        na_size_t length, na_addr_t remote_addr, na_request_t *request)
{
    return 0;
}

int na_mpi_get(na_mem_handle_t local_mem_handle, na_offset_t local_offset,
        na_mem_handle_t remote_mem_handle, na_offset_t remote_offset,
        na_size_t length, na_addr_t remote_addr, na_request_t *request)
{
    return 0;
}

//static int na_mpi_test(na_request_t request, int *flag, na_status_t *status)
//{
//    int ret = NA_SUCCESS;
//    MPI_Request *mpi_request = (MPI_Request*) request;
//    MPI_Status mpi_status; /* or MPI_STATUS_IGNORE */
//
//    assert(flag);
//
//    MPI_Test(mpi_request, flag, &mpi_status);
//    if (*flag) {
//        if (status && status != NA_STATUS_IGNORE) status->count = (na_size_t) mpi_status.count;
//        free(mpi_request);
//        mpi_request = NULL;
//    }
//    return ret;
//}

static int na_mpi_wait(na_request_t request, int *flag, int timeout, na_status_t *status)
{
    int mpi_ret, ret = NA_SUCCESS;
    MPI_Request *mpi_request = (MPI_Request*) request;
    MPI_Status mpi_status; /* or MPI_STATUS_IGNORE */

    /* TODO use timeout */
    mpi_ret = MPI_Wait(mpi_request, &mpi_status);
    if (mpi_ret != MPI_SUCCESS) {
        NA_ERROR_DEFAULT("MPI_Wait() failed");
        ret = NA_FAIL;
    } else {
        if (status && status != NA_STATUS_IGNORE) status->count = (na_size_t) mpi_status.count;
        free(mpi_request);
        mpi_request = NULL;

    }
    return ret;
}
