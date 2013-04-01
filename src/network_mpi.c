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

#include "network_mpi.h"
#include "mem_handle_map.h"
#include "shipper_error.h"

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <errno.h>
#include <stdbool.h>
#include <assert.h>
#include <string.h>
#include <stdint.h>

static int na_mpi_finalize(void);
static na_size_t na_mpi_get_unexpected_size(void);
static int na_mpi_addr_lookup(const char *name, na_addr_t *addr);
static int na_mpi_addr_free(na_addr_t addr);
static int na_mpi_send_unexpected(const void *buf, na_size_t buf_len,
        na_addr_t dest, na_tag_t tag, na_request_t *request, void *op_arg);
static int na_mpi_recv_unexpected(void *buf, na_size_t *buf_len,
        na_addr_t *source, na_tag_t *tag, na_request_t *request, void *op_arg);
static int na_mpi_send(const void *buf, na_size_t buf_len, na_addr_t dest,
        na_tag_t tag, na_request_t *request, void *op_arg);
static int na_mpi_recv(void *buf, na_size_t buf_len, na_addr_t source,
        na_tag_t tag, na_request_t *request, void *op_arg);
static int na_mpi_mem_register(void *buf, na_size_t buf_len, unsigned long flags,
        na_mem_handle_t *mem_handle);
static int na_mpi_mem_deregister(na_mem_handle_t mem_handle);
static int na_mpi_mem_handle_serialize(void *buf, na_size_t buf_len, na_mem_handle_t mem_handle);
static int na_mpi_mem_handle_deserialize(na_mem_handle_t *mem_handle, const void *buf, na_size_t buf_len);
static int na_mpi_mem_handle_free(na_mem_handle_t mem_handle);
static int na_mpi_put(na_mem_handle_t local_mem_handle, na_offset_t local_offset,
        na_mem_handle_t remote_mem_handle, na_offset_t remote_offset,
        na_size_t length, na_addr_t remote_addr, na_request_t *request);
static int na_mpi_get(na_mem_handle_t local_mem_handle, na_offset_t local_offset,
        na_mem_handle_t remote_mem_handle, na_offset_t remote_offset,
        na_size_t length, na_addr_t remote_addr, na_request_t *request);
static int na_mpi_wait(na_request_t request, unsigned int timeout,
        na_status_t *status);

static na_network_class_t na_mpi_g = {
        na_mpi_finalize,               /* finalize */
        na_mpi_get_unexpected_size,    /* get_unexpected_size */
        na_mpi_addr_lookup,            /* addr_lookup */
        na_mpi_addr_free,              /* addr_free */
        na_mpi_send_unexpected,        /* send_unexpected */
        na_mpi_recv_unexpected,        /* recv_unexpected */
        na_mpi_send,                   /* send */
        na_mpi_recv,                   /* recv */
        na_mpi_mem_register,           /* mem_register */
        na_mpi_mem_deregister,         /* mem_deregister */
        na_mpi_mem_handle_serialize,   /* mem_handle_serialize */
        na_mpi_mem_handle_deserialize, /* mem_handle_deserialize */
        na_mpi_mem_handle_free,        /* mem_handle_free */
        na_mpi_put,                    /* put */
        na_mpi_get,                    /* get */
        na_mpi_wait                    /* wait */
};


/* FIXME Force MPI version to 2 for now */
#undef MPI_VERSION
#define MPI_VERSION 2

/* Private structs */
typedef struct mpi_addr {
    MPI_Comm  comm;          /* Communicator */
    int       rank;          /* Rank in this communicator */
    bool      is_reference;  /* Reference to existing address */
    MPI_Comm  onesided_comm; /* Additional communicator for one-sided operations */
} mpi_addr_t;

typedef struct mpi_mem_handle {
    void *base;                 /* Initial address of memory */
    MPI_Aint size;              /* Size of memory */
    unsigned long attr;         /* Flag of operation access */
} mpi_mem_handle_t;

#if MPI_VERSION < 3
typedef enum mpi_onesided_op {
    MPI_ONESIDED_PUT,       /* Request a put operation */
    MPI_ONESIDED_GET,       /* Request a get operation */
    MPI_ONESIDED_END        /* Request end of one-sided operations */
} mpi_onesided_op_t;

typedef struct mpi_onesided_info {
    void    *base;         /* Initial address of memory */
    MPI_Aint disp;         /* Offset from initial address */
    int      count;        /* Number of entries */
    mpi_onesided_op_t op;  /* Operation requested */
} mpi_onesided_info_t;
#endif

typedef struct mpi_req {
    MPI_Request request;
    uint8_t     ack;
    MPI_Request ack_request;
} mpi_req_t;

/* Private variables */
static int mpi_ext_initialized;                 /* MPI initialized */
static MPI_Comm mpi_intra_comm = MPI_COMM_NULL; /* Private plugin intra-comm */
static char mpi_port_name[MPI_MAX_PORT_NAME];   /* Connection port */
static bool is_server = 0;                      /* Used in server mode */
static mpi_addr_t server_remote_addr;           /* Remote address */
#if MPI_VERSION < 3
static mh_map_t *mem_handle_map = NULL;         /* Map mem addresses to mem handles */
#else
static MPI_Win mpi_dynamic_win;                 /* Dynamic window */
#endif

#define NA_MPI_ONESIDED_TAG        0x80 /* Default tag used for one-sided over two-sided */
#define NA_MPI_ONESIDED_ACK_TAG    0x81

#if MPI_VERSION < 3
pthread_t mpi_onesided_service;
pthread_mutex_t mem_map_mutex;
static void* na_mpi_onesided_service(void *args)
{
    int mpi_ret;
    bool service_done = 0;
    mpi_addr_t *mpi_remote_addr = (mpi_addr_t*) args;

    if (!mpi_remote_addr) {
        S_ERROR_DEFAULT("NULL address");
        return NULL;
    }

    while (!service_done) {
        MPI_Status mpi_status;
        mpi_onesided_info_t onesided_info;
        MPI_Comm mpi_onesided_comm = mpi_remote_addr->onesided_comm;
        mpi_mem_handle_t *mpi_mem_handle = NULL;
        bool error = 0;

        mpi_ret = MPI_Recv(&onesided_info, sizeof(onesided_info), MPI_BYTE,
                MPI_ANY_SOURCE, MPI_ANY_TAG, mpi_onesided_comm, &mpi_status);
        if (mpi_ret != MPI_SUCCESS) {
            S_ERROR_DEFAULT("MPI_Recv() failed");
            error = 1;
        }

        if (error || (onesided_info.op == MPI_ONESIDED_END)) {
            service_done = 1;
            break;
        }

        /* Here better to keep the mutex locked the time we operate on mpi_mem_handle
         * since it's a pointer to a mem_handle
         */
        pthread_mutex_lock(&mem_map_mutex);

        mpi_mem_handle = mh_map_lookup(mem_handle_map, onesided_info.base);

        if (!mpi_mem_handle) {
            S_ERROR_DEFAULT("Could not find memory handle, registered?");
            pthread_mutex_unlock(&mem_map_mutex);
            break;
        }

        switch (onesided_info.op) {
            uint8_t ack = 1;
            /* Remote wants to do a put so wait in a recv */
            case MPI_ONESIDED_PUT:
                MPI_Recv(mpi_mem_handle->base + onesided_info.disp, onesided_info.count,
                        MPI_BYTE, mpi_status.MPI_SOURCE, NA_MPI_ONESIDED_TAG,
                        mpi_onesided_comm, MPI_STATUS_IGNORE);
                /* Send an ack to ensure that the data has been received */
                MPI_Send(&ack, 1, MPI_UINT8_T, mpi_status.MPI_SOURCE, NA_MPI_ONESIDED_ACK_TAG,
                        mpi_onesided_comm);
                break;
                /* Remote wants to do a get so do a send */
            case MPI_ONESIDED_GET:
                MPI_Send(mpi_mem_handle->base + onesided_info.disp, onesided_info.count,
                        MPI_BYTE, mpi_status.MPI_SOURCE, NA_MPI_ONESIDED_TAG,
                        mpi_onesided_comm);
                break;
            default:
                S_ERROR_DEFAULT("Operation not supported");
                break;
        }

        pthread_mutex_unlock(&mem_map_mutex);
    }

    return NULL;
}
#endif

/*---------------------------------------------------------------------------
 * Function:    na_mpi_init
 *
 * Purpose:     Initialize the network abstraction layer
 *
 *---------------------------------------------------------------------------
 */
na_network_class_t *na_mpi_init(MPI_Comm *intra_comm, int flags)
{
    /* MPI_Init */
    MPI_Initialized(&mpi_ext_initialized);

    if (!mpi_ext_initialized) {
        /* printf("Internally initializing MPI...\n"); */
        if (flags != MPI_INIT_SERVER) {
#if MPI_VERSION < 3
            int provided;
            /* Need a MPI_THREAD_MULTIPLE level if onesided thread required */
            MPI_Init_thread(NULL, NULL, MPI_THREAD_MULTIPLE, &provided);
            if (provided != MPI_THREAD_MULTIPLE) {
                S_ERROR_DEFAULT("MPI_THREAD_MULTIPLE cannot be set");
            }
#else
            MPI_Init(NULL, NULL);
#endif
        } else {
            MPI_Init(NULL, NULL);
        }
    }

    /* Assign MPI intra comm */
    if (intra_comm && (*intra_comm != MPI_COMM_NULL)) {
        MPI_Comm_dup(*intra_comm, &mpi_intra_comm);
    } else {
        MPI_Comm_dup(MPI_COMM_WORLD, &mpi_intra_comm);
    }

#if MPI_VERSION < 3
    /* Create hash table for memory registration */
    mem_handle_map = mh_map_new();
#endif

    /* If server open a port */
    if (flags == MPI_INIT_SERVER) {
        FILE *config;
        is_server = 1;
        MPI_Open_port(MPI_INFO_NULL, mpi_port_name);
        /* printf("Using MPI port name: %s.\n", mpi_port_name); */
        config = fopen("port.cfg", "w+");
        fwrite(mpi_port_name, sizeof(char), MPI_MAX_PORT_NAME, config);
        fclose(config);

        /* TODO server waits for connection here but that should be handled separately really */
        MPI_Comm_accept(mpi_port_name, MPI_INFO_NULL, 0, mpi_intra_comm, &server_remote_addr.comm);
        server_remote_addr.is_reference = 0;
        server_remote_addr.rank = -1; /* the address returned does not bind to a specific process */

#if MPI_VERSION < 3
        /* To be thread-safe and create a new context, dup the remote comm to a new comm */
        MPI_Comm_dup(server_remote_addr.comm, &server_remote_addr.onesided_comm);
#else
        MPI_Intercomm_merge(server_remote_addr.comm, is_server, &server_remote_addr.onesided_comm);
        /* Create dynamic window */
        MPI_Win_create_dynamic(MPI_INFO_NULL, server_remote_addr.onesided_comm, &mpi_dynamic_win);
        ///////////////////////////////////////////////
        /// DEBUG
        // int my_rank;
        // MPI_Comm_rank(mpi_addr->onesided_comm, &my_rank);
        // printf("my rank is: %d\n", my_rank);
#endif
    }
    return &na_mpi_g;
}

/*---------------------------------------------------------------------------
 * Function:    na_mpi_finalize
 *
 * Purpose:     Finalize the network abstraction layer
 *
 *---------------------------------------------------------------------------
 */
static int na_mpi_finalize(void)
{
    int mpi_ext_finalized, ret = S_SUCCESS;

    /* If server opened a port */
    if (is_server) {
#if MPI_VERSION < 3
        int num_clients, i;
        mpi_onesided_info_t onesided_info;
        onesided_info.base = NULL;
        onesided_info.count = 0;
        onesided_info.disp = 0;
        onesided_info.op = MPI_ONESIDED_END;

        MPI_Comm_remote_size(server_remote_addr.onesided_comm, &num_clients);
        for (i = 0; i < num_clients; i++) {
            /* Send to one-sided thread a termination request (should be handled with disconnection) */
            MPI_Send(&onesided_info, sizeof(mpi_onesided_info_t), MPI_BYTE, i,
                    NA_MPI_ONESIDED_TAG, server_remote_addr.onesided_comm);
        }
#else
        /* Destroy dynamic window */
        MPI_Win_free(&mpi_dynamic_win);
#endif
        MPI_Comm_free(&server_remote_addr.onesided_comm);
        /* TODO Server disconnects here but that should be handled separately really */
        MPI_Comm_disconnect(&server_remote_addr.comm);
        MPI_Close_port(mpi_port_name);
    }

#if MPI_VERSION < 3
    /* Free hash table for memory registration */
    mh_map_free(mem_handle_map);
#endif

    /* Free the private dup'ed comm */
    MPI_Comm_free(&mpi_intra_comm);

    /* MPI_Finalize */
    MPI_Finalized(&mpi_ext_finalized);
    if (mpi_ext_finalized) {
        S_ERROR_DEFAULT("MPI already finalized");
        ret = S_FAIL;
    }
    if (!mpi_ext_initialized && !mpi_ext_finalized) {
        /* printf("Internally finalizing MPI...\n"); */
        MPI_Finalize();
    }

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    na_mpi_get_unexpected_size
 *
 * Purpose:     Get the maximum size of an unexpected message
 *
 *---------------------------------------------------------------------------
 */
static na_size_t na_mpi_get_unexpected_size()
{
    na_size_t max_unexpected_size = 4*1024;
    return max_unexpected_size;
}

/*---------------------------------------------------------------------------
 * Function:    na_mpi_addr_lookup
 *
 * Purpose:     addr_lookup a addr from a peer address/name
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
static int na_mpi_addr_lookup(const char *name, na_addr_t *addr)
{
    int mpi_ret, ret = S_SUCCESS;
    char *port_name = (char*) name;
    mpi_addr_t *mpi_addr;

    /* Allocate the addr */
    mpi_addr = malloc(sizeof(mpi_addr_t));
    mpi_addr->comm = MPI_COMM_NULL;
    mpi_addr->is_reference = 0;
    mpi_addr->rank = 0; /* TODO Only one rank for server but this may need to be improved */

    /* Try to connect */
    mpi_ret = MPI_Comm_connect(port_name, MPI_INFO_NULL, 0, mpi_intra_comm, &mpi_addr->comm);
    if (mpi_ret != MPI_SUCCESS) {
        S_ERROR_DEFAULT("Could not connect");
        free(mpi_addr);
        mpi_addr = NULL;
        ret = S_FAIL;
    } else {
        int remote_size;
        /* printf("Connected!\n"); */
        MPI_Comm_remote_size(mpi_addr->comm, &remote_size);
        if (remote_size != 1) {
            S_ERROR_DEFAULT("Connected to more than one server?");
        }
        if (addr) *addr = (na_addr_t) mpi_addr;
    }
#if MPI_VERSION < 3
    /* To be thread-safe and create a new context, dup the remote comm to a new comm */
    MPI_Comm_dup(mpi_addr->comm, &mpi_addr->onesided_comm);
    /* TODO temporary to handle one-sided exchanges with remote server */
    pthread_mutex_init(&mem_map_mutex, NULL);
    pthread_create(&mpi_onesided_service, NULL, &na_mpi_onesided_service, (void*)mpi_addr);
#else
    MPI_Intercomm_merge(mpi_addr->comm, is_server, &mpi_addr->onesided_comm);
    /* Create dynamic window */
    MPI_Win_create_dynamic(MPI_INFO_NULL, mpi_addr->onesided_comm, &mpi_dynamic_win);
    ///////////////////////////////////////////////
    /// DEBUG
    // int my_rank;
    // MPI_Comm_rank(mpi_addr->onesided_comm, &my_rank);
    // printf("my rank is: %d\n", my_rank);
#endif
    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    na_mpi_addr_free
 *
 * Purpose:     Free the addr from the list of peers
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
static int na_mpi_addr_free(na_addr_t addr)
{
    mpi_addr_t *mpi_addr = (mpi_addr_t*) addr;
    int ret = S_SUCCESS;

    if (!mpi_addr) {
        S_ERROR_DEFAULT("Already freed");
        ret = S_FAIL;
        return ret;
    }

    if (!mpi_addr->is_reference) {
#if MPI_VERSION < 3
        /* Wait for one-sided thread to complete */
        pthread_join(mpi_onesided_service, NULL);
        pthread_mutex_destroy(&mem_map_mutex);
#else
        /* Destroy dynamic window */
        MPI_Win_free(&mpi_dynamic_win);
#endif
        MPI_Comm_free(&mpi_addr->onesided_comm);
        MPI_Comm_disconnect(&mpi_addr->comm);
    }
    free(mpi_addr);
    mpi_addr = NULL;

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    na_mpi_send_unexpected
 *
 * Purpose:     Send a message to dest (unexpected asynchronous)
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
static int na_mpi_send_unexpected(const void *buf, na_size_t buf_len,
        na_addr_t dest, na_tag_t tag, na_request_t *request, void *op_arg)
{
    /* There should not be any difference for MPI */
    return na_mpi_send(buf, buf_len, dest, tag, request, op_arg);
}

/*---------------------------------------------------------------------------
 * Function:    na_mpi_recv_unexpected
 *
 * Purpose:     Receive a message from source (unexpected asynchronous)
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
static int na_mpi_recv_unexpected(void *buf, na_size_t *buf_len,
        na_addr_t *source, na_tag_t *tag, na_request_t *request, void *op_arg)
{
    int mpi_ret, ret = S_SUCCESS;
    MPI_Status mpi_status;
    int flag = 0;

    do {
        mpi_ret = MPI_Iprobe(MPI_ANY_SOURCE, MPI_ANY_TAG, server_remote_addr.comm, &flag, &mpi_status);
    } while (flag == 0 && mpi_ret == MPI_SUCCESS);

    if (flag) {
        void *mpi_buf;
        int  *mpi_buf_len = (int*) buf_len;
        int  *mpi_tag = (int*) tag;
        int   mpi_source;
        MPI_Status recv_status;

        MPI_Get_count(&mpi_status, MPI_BYTE, mpi_buf_len);
        mpi_buf = malloc(*mpi_buf_len);
        mpi_source = mpi_status.MPI_SOURCE;
        if (mpi_tag) *mpi_tag = mpi_status.MPI_TAG;

        if (source) {
            mpi_addr_t **peer_addr_ptr = (mpi_addr_t**) source;
            mpi_addr_t *peer_addr;
            *peer_addr_ptr = malloc(sizeof(mpi_addr_t));
            peer_addr = *peer_addr_ptr;
            peer_addr->comm = server_remote_addr.comm;
            peer_addr->rank = mpi_source;
            peer_addr->is_reference = 1;
            peer_addr->onesided_comm = server_remote_addr.onesided_comm;
        }

        mpi_ret = MPI_Recv(mpi_buf, *mpi_buf_len, MPI_BYTE, mpi_source,
                *mpi_tag, server_remote_addr.comm, &recv_status);
        if (mpi_ret != MPI_SUCCESS) {
            S_ERROR_DEFAULT("MPI_Recv() failed");
            ret = S_FAIL;
        } else {
            int count;
            MPI_Get_count(&recv_status, MPI_BYTE, &count);
            if (buf) memcpy(buf, mpi_buf, count);
        }
        free(mpi_buf);
        mpi_buf = NULL;
    } else {
        S_ERROR_DEFAULT("No pending message found");
        ret = S_FAIL;
    }
    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    na_mpi_send
 *
 * Purpose:     Send a message to dest (asynchronous)
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
static int na_mpi_send(const void *buf, na_size_t buf_len, na_addr_t dest,
        na_tag_t tag, na_request_t *request, void *op_arg)
{
    int mpi_ret, ret = S_SUCCESS;
    void *mpi_buf = (void*) buf;
    int mpi_buf_len = (int) buf_len;
    int mpi_tag = (int) tag;
    mpi_addr_t *mpi_addr = (mpi_addr_t*) dest;
    mpi_req_t *mpi_request;

    mpi_request = malloc(sizeof(mpi_req_t));
    mpi_request->ack = 0;
    mpi_request->ack_request = MPI_REQUEST_NULL;
    mpi_request->request = MPI_REQUEST_NULL;

    mpi_ret = MPI_Isend(mpi_buf, mpi_buf_len, MPI_BYTE, mpi_addr->rank, mpi_tag, mpi_addr->comm, &mpi_request->request);
    if (mpi_ret != MPI_SUCCESS) {
        S_ERROR_DEFAULT("MPI_Isend() failed");
        free(mpi_request);
        mpi_request = NULL;
        ret = S_FAIL;
    } else {
        *request = (na_request_t) mpi_request;
    }
    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    na_mpi_recv
 *
 * Purpose:     Receive a message from source (asynchronous)
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
static int na_mpi_recv(void *buf, na_size_t buf_len, na_addr_t source,
        na_tag_t tag, na_request_t *request, void *op_arg)
{
    int mpi_ret, ret = S_SUCCESS;
    void *mpi_buf = (void*) buf;
    int mpi_buf_len = (int) buf_len;
    int mpi_tag = (int) tag;
    mpi_addr_t *mpi_addr = (mpi_addr_t*) source;
    mpi_req_t *mpi_request;

    mpi_request = malloc(sizeof(mpi_req_t));
    mpi_request->ack = 0;
    mpi_request->ack_request = MPI_REQUEST_NULL;
    mpi_request->request = MPI_REQUEST_NULL;

    mpi_ret = MPI_Irecv(mpi_buf, mpi_buf_len, MPI_BYTE, mpi_addr->rank, mpi_tag, mpi_addr->comm, &mpi_request->request);
    if (mpi_ret != MPI_SUCCESS) {
        S_ERROR_DEFAULT("MPI_Irecv() failed");
        free(mpi_request);
        mpi_request = NULL;
        ret = S_FAIL;
    } else {
        *request = (na_request_t) mpi_request;
    }
    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    na_mpi_mem_register
 *
 * Purpose:     Register memory for RMA operations
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int na_mpi_mem_register(void *buf, na_size_t buf_size, unsigned long flags,
        na_mem_handle_t *mem_handle)
{
    int ret = S_SUCCESS;
    void *mpi_buf_base = buf;
    MPI_Aint mpi_buf_size = (MPI_Aint) buf_size;
    mpi_mem_handle_t *mpi_mem_handle;

    mpi_mem_handle = malloc(sizeof(mpi_mem_handle_t));
    mpi_mem_handle->base = mpi_buf_base;
    mpi_mem_handle->size = mpi_buf_size;
    mpi_mem_handle->attr = flags;

    *mem_handle = (na_mem_handle_t) mpi_mem_handle;

#if MPI_VERSION < 3
    pthread_mutex_lock(&mem_map_mutex);
    /* store this handle */
    if (mh_map_insert(mem_handle_map, mpi_mem_handle->base, mpi_mem_handle) < 0) {
        S_ERROR_DEFAULT("Could not register memory handle");
        ret = S_FAIL;
    }
    pthread_mutex_unlock(&mem_map_mutex);
#else
    int mpi_ret;

    mpi_ret = MPI_Win_attach(mpi_dynamic_win, mpi_mem_handle->base, mpi_mem_handle->size);
    if (mpi_ret != MPI_SUCCESS) {
        S_ERROR_DEFAULT("MPI_Win_attach() failed");
        ret = S_FAIL;
    }
#endif
    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    na_mpi_mem_deregister
 *
 * Purpose:     Deregister memory for RMA operations
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int na_mpi_mem_deregister(na_mem_handle_t mem_handle)
{
    int ret = S_SUCCESS;
    mpi_mem_handle_t *mpi_mem_handle = (mpi_mem_handle_t*) mem_handle;

#if MPI_VERSION < 3
    pthread_mutex_lock(&mem_map_mutex);
    /* remove the handle */
    if (mh_map_remove(mem_handle_map, mpi_mem_handle->base) < 0) {
        S_ERROR_DEFAULT("Could not deregister memory handle");
        ret = S_FAIL;
    }
    pthread_mutex_unlock(&mem_map_mutex);
#else
    int mpi_ret;

    mpi_ret = MPI_Win_detach(mpi_dynamic_win, mpi_mem_handle->base);
    if (mpi_ret != MPI_SUCCESS) {
        S_ERROR_DEFAULT("MPI_Win_detach() failed");
        ret = S_FAIL;
    }
#endif
    if (mpi_mem_handle) {
        free(mpi_mem_handle);
        mpi_mem_handle = NULL;
    } else {
        S_ERROR_DEFAULT("Already freed");
        ret = S_FAIL;
    }
    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    na_mpi_mem_handle_serialize
 *
 * Purpose:     Serialize memory handle for exchange over the network
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int na_mpi_mem_handle_serialize(void *buf, na_size_t buf_len,
        na_mem_handle_t mem_handle)
{
    int ret = S_SUCCESS;
    mpi_mem_handle_t *mpi_mem_handle = (mpi_mem_handle_t*) mem_handle;

    if (buf_len < sizeof(mpi_mem_handle_t)) {
        S_ERROR_DEFAULT("Buffer size too small for serializing parameter");
        ret = S_FAIL;
    } else {
        /* Here safe to do a simple memcpy */
        /* TODO may also want to add a checksum or something */
        memcpy(buf, mpi_mem_handle, sizeof(mpi_mem_handle_t));
    }
    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    na_mpi_mem_handle_deserialize
 *
 * Purpose:     Deserialize memory handle for exchange over the network
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int na_mpi_mem_handle_deserialize(na_mem_handle_t *mem_handle,
        const void *buf, na_size_t buf_len)
{
    int ret = S_SUCCESS;
    mpi_mem_handle_t *mpi_mem_handle;

    if (buf_len < sizeof(mpi_mem_handle_t)) {
        S_ERROR_DEFAULT("Buffer size too small for deserializing parameter");
        ret = S_FAIL;
    } else {
        mpi_mem_handle = malloc(sizeof(mpi_mem_handle_t));
        /* Here safe to do a simple memcpy */
        memcpy(mpi_mem_handle, buf, sizeof(mpi_mem_handle_t));
        *mem_handle = (na_mem_handle_t) mpi_mem_handle;
    }
    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    na_mpi_mem_handle_free
 *
 * Purpose:     Free memory handle created by deserialize
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int na_mpi_mem_handle_free(na_mem_handle_t mem_handle)
{
    int ret = S_SUCCESS;
    mpi_mem_handle_t *mpi_mem_handle = (mpi_mem_handle_t*) mem_handle;

    if (mpi_mem_handle) {
        free(mpi_mem_handle);
        mpi_mem_handle = NULL;
    } else {
        S_ERROR_DEFAULT("Already freed");
        ret = S_FAIL;
    }
    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    na_mpi_put
 *
 * Purpose:     Put data to remote target
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int na_mpi_put(na_mem_handle_t local_mem_handle, na_offset_t local_offset,
        na_mem_handle_t remote_mem_handle, na_offset_t remote_offset,
        na_size_t length, na_addr_t remote_addr, na_request_t *request)
{
    int mpi_ret, ret = S_SUCCESS;
    mpi_mem_handle_t *mpi_local_mem_handle = (mpi_mem_handle_t*) local_mem_handle;
    MPI_Aint mpi_local_offset = (MPI_Aint) local_offset;
    mpi_mem_handle_t *mpi_remote_mem_handle = (mpi_mem_handle_t*) remote_mem_handle;
    MPI_Aint mpi_remote_offset = (MPI_Aint) remote_offset;
    int mpi_length = (int) length; /* TODO careful here that we don't send more than 2GB */
    mpi_addr_t *mpi_remote_addr = (mpi_addr_t*) remote_addr;
    mpi_req_t *mpi_request;

    /* TODO check that local memory is registered */
    // ht_lookup(mem_map, mpi_local_mem_handle->base);

    if (mpi_remote_mem_handle->attr != NA_MEM_READWRITE) {
        S_ERROR_DEFAULT("Registered memory requires write permission");
        ret = S_FAIL;
        return ret;
    }

    mpi_request = malloc(sizeof(mpi_req_t));
    mpi_request->ack = 0;
    mpi_request->ack_request = MPI_REQUEST_NULL;
    mpi_request->request = MPI_REQUEST_NULL;

#if MPI_VERSION < 3
    /* Send to one-sided thread key to access mem_handle */
    mpi_onesided_info_t onesided_info;
    onesided_info.base = mpi_remote_mem_handle->base;
    onesided_info.disp = mpi_remote_offset;
    onesided_info.count = mpi_length;
    onesided_info.op = MPI_ONESIDED_PUT;

    MPI_Send(&onesided_info, sizeof(mpi_onesided_info_t), MPI_BYTE, mpi_remote_addr->rank,
            NA_MPI_ONESIDED_TAG, mpi_remote_addr->onesided_comm);

    /* Simply do an asynchronous send */
    mpi_ret = MPI_Isend(mpi_local_mem_handle->base + mpi_local_offset, mpi_length, MPI_BYTE,
            mpi_remote_addr->rank, NA_MPI_ONESIDED_TAG, mpi_remote_addr->onesided_comm, &mpi_request->request);
    if (mpi_ret != MPI_SUCCESS) {
        S_ERROR_DEFAULT("MPI_Isend() failed");
        free(mpi_request);
        mpi_request = NULL;
        ret = S_FAIL;
    }

    /* Pre-post an ack request */
    mpi_ret = MPI_Irecv(&mpi_request->ack, 1, MPI_UINT8_T, mpi_remote_addr->rank,
            NA_MPI_ONESIDED_ACK_TAG, mpi_remote_addr->onesided_comm, &mpi_request->ack_request);
    if (mpi_ret != MPI_SUCCESS) {
        S_ERROR_DEFAULT("MPI_Irecv() failed");
        free(mpi_request);
        mpi_request = NULL;
        ret = S_FAIL;
    }

#else
    MPI_Win_lock(MPI_LOCK_EXCLUSIVE, mpi_remote_addr->rank, 0, mpi_dynamic_win);

    mpi_ret = MPI_Rput(mpi_local_mem_handle->base + mpi_local_offset, mpi_length, MPI_BYTE,
            mpi_remote_addr->rank, mpi_remote_offset, mpi_length, MPI_BYTE, mpi_dynamic_win, mpi_request);
    if (mpi_ret != MPI_SUCCESS) {
        S_ERROR_DEFAULT("MPI_Rput() failed");
        free(mpi_request);
        mpi_request = NULL;
        ret = S_FAIL;
    }
#endif
    else {
        *request = (na_request_t) mpi_request;
    }
#if MPI_VERSION >= 3
    MPI_Win_unlock(mpi_remote_addr->rank, mpi_dynamic_win);
#endif

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    na_mpi_get
 *
 * Purpose:     Get data from remote target
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int na_mpi_get(na_mem_handle_t local_mem_handle, na_offset_t local_offset,
        na_mem_handle_t remote_mem_handle, na_offset_t remote_offset,
        na_size_t length, na_addr_t remote_addr, na_request_t *request)
{
    int mpi_ret, ret = S_SUCCESS;
    mpi_mem_handle_t *mpi_local_mem_handle = (mpi_mem_handle_t*) local_mem_handle;
    MPI_Aint mpi_local_offset = (MPI_Aint) local_offset;
    mpi_mem_handle_t *mpi_remote_mem_handle = (mpi_mem_handle_t*) remote_mem_handle;
    MPI_Aint mpi_remote_offset = (MPI_Aint) remote_offset;
    int mpi_length = (int) length; /* TODO careful here that we don't send more than 2GB */
    mpi_addr_t *mpi_remote_addr = (mpi_addr_t*) remote_addr;
    mpi_req_t *mpi_request;

    /* TODO check that local memory is registered */
    // ht_lookup(mem_map, mpi_local_mem_handle->base);

    mpi_request = malloc(sizeof(mpi_req_t));
    mpi_request->ack = 0;
    mpi_request->ack_request = MPI_REQUEST_NULL;
    mpi_request->request = MPI_REQUEST_NULL;

#if MPI_VERSION < 3
    /* Send to one-sided thread key to access mem_handle */
    mpi_onesided_info_t onesided_info;
    onesided_info.base = mpi_remote_mem_handle->base;
    onesided_info.disp = mpi_remote_offset;
    onesided_info.count = mpi_length;
    onesided_info.op = MPI_ONESIDED_GET;

    MPI_Send(&onesided_info, sizeof(mpi_onesided_info_t), MPI_BYTE, mpi_remote_addr->rank,
            NA_MPI_ONESIDED_TAG, mpi_remote_addr->onesided_comm);

    /* Simply do an asynchronous recv */
    mpi_ret = MPI_Irecv(mpi_local_mem_handle->base + mpi_local_offset, mpi_length, MPI_BYTE,
            mpi_remote_addr->rank, NA_MPI_ONESIDED_TAG, mpi_remote_addr->onesided_comm, &mpi_request->request);
    if (mpi_ret != MPI_SUCCESS) {
        S_ERROR_DEFAULT("MPI_Irecv() failed");
        free(mpi_request);
        mpi_request = NULL;
        ret = S_FAIL;
    }
#else
    MPI_Win_lock(MPI_LOCK_SHARED, mpi_remote_addr->rank, 0, mpi_dynamic_win);

    mpi_ret = MPI_Rget(mpi_local_mem_handle->base + mpi_local_offset, mpi_length, MPI_BYTE,
            mpi_remote_addr->rank, mpi_remote_offset, mpi_length, MPI_BYTE, mpi_dynamic_win, mpi_request);
    if (mpi_ret != MPI_SUCCESS) {
        S_ERROR_DEFAULT("MPI_Rget() failed");
        free(mpi_request);
        mpi_request = NULL;
        ret = S_FAIL;
    }
#endif
    else {
        *request = (na_request_t) mpi_request;
    }
#if MPI_VERSION >= 3
    MPI_Win_unlock(mpi_remote_addr->rank, mpi_dynamic_win);
#endif

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    na_mpi_wait
 *
 * Purpose:     Wait for a request to complete or until timeout (ms) is reached
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
static int na_mpi_wait(na_request_t request, unsigned int timeout,
        na_status_t *status)
{
    int mpi_ret, ret = S_SUCCESS;
    mpi_req_t *mpi_request = (mpi_req_t*) request;
    MPI_Status mpi_status;

    if (!mpi_request) {
        S_ERROR_DEFAULT("NULL request");
        ret = S_FAIL;
        return ret;
    }

    if (timeout == 0) {
        int mpi_flag = 0;
        mpi_ret = MPI_Test(&mpi_request->request, &mpi_flag, &mpi_status);
        if (mpi_ret != MPI_SUCCESS) {
            S_ERROR_DEFAULT("MPI_Test() failed");
            ret = S_FAIL;
            return ret;
        }
        if (!mpi_flag) {
            if (status && status != NA_STATUS_IGNORE) {
                status->completed = 0;
            }
            ret = S_SUCCESS;
            return ret;
        }
    } else {
        mpi_ret = MPI_Wait(&mpi_request->request, &mpi_status);
        if (mpi_ret != MPI_SUCCESS) {
            S_ERROR_DEFAULT("MPI_Wait() failed");
            ret = S_FAIL;
            return ret;
        }
    }
    if (status && status != NA_STATUS_IGNORE) {
        int count;
        MPI_Get_count(&mpi_status, MPI_BYTE, &count);
        status->completed = 1;
        status->count = (na_size_t) count;
    }

    if (mpi_request->ack_request != MPI_REQUEST_NULL) {
        mpi_ret = MPI_Wait(&mpi_request->ack_request, &mpi_status);
        if (mpi_ret != MPI_SUCCESS) {
            S_ERROR_DEFAULT("MPI_Wait() failed");
            ret = S_FAIL;
            return ret;
        }
    }
    free(mpi_request);
    mpi_request = NULL;

    return ret;
}
