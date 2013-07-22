/*
 * Copyright (C) 2013 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#include "na_mpi.h"
#include "na_private.h"
#include "na_error.h"

#include "mercury_hash_table.h"
#include "mercury_thread.h"
#include "mercury_thread_mutex.h"
#include "mercury_thread_condition.h"
#include "mercury_time.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int na_mpi_finalize(void);
static int na_mpi_addr_lookup(const char *name, na_addr_t *addr);
static int na_mpi_addr_free(na_addr_t addr);
static na_size_t na_mpi_msg_get_max_expected_size(void);
static na_size_t na_mpi_msg_get_max_unexpected_size(void);
static na_tag_t na_mpi_msg_get_max_tag(void);
static int na_mpi_msg_send_unexpected(const void *buf, na_size_t buf_size,
        na_addr_t dest, na_tag_t tag, na_request_t *request, void *op_arg);
static int na_mpi_msg_recv_unexpected(void *buf, na_size_t buf_size, na_size_t *actual_buf_size,
        na_addr_t *source, na_tag_t *tag, na_request_t *request, void *op_arg);
static int na_mpi_msg_send(const void *buf, na_size_t buf_size, na_addr_t dest,
        na_tag_t tag, na_request_t *request, void *op_arg);
static int na_mpi_msg_recv(void *buf, na_size_t buf_size, na_addr_t source,
        na_tag_t tag, na_request_t *request, void *op_arg);
static int na_mpi_mem_register(void *buf, na_size_t buf_size, unsigned long flags,
        na_mem_handle_t *mem_handle);
static int na_mpi_mem_deregister(na_mem_handle_t mem_handle);
static na_size_t na_mpi_mem_handle_get_serialize_size(na_mem_handle_t mem_handle);
static int na_mpi_mem_handle_serialize(void *buf, na_size_t buf_size, na_mem_handle_t mem_handle);
static int na_mpi_mem_handle_deserialize(na_mem_handle_t *mem_handle, const void *buf, na_size_t buf_size);
static int na_mpi_mem_handle_free(na_mem_handle_t mem_handle);
static int na_mpi_put(na_mem_handle_t local_mem_handle, na_offset_t local_offset,
        na_mem_handle_t remote_mem_handle, na_offset_t remote_offset,
        na_size_t length, na_addr_t remote_addr, na_request_t *request);
static int na_mpi_get(na_mem_handle_t local_mem_handle, na_offset_t local_offset,
        na_mem_handle_t remote_mem_handle, na_offset_t remote_offset,
        na_size_t length, na_addr_t remote_addr, na_request_t *request);
static int na_mpi_wait(na_request_t request, unsigned int timeout,
        na_status_t *status);
static int na_mpi_progress(unsigned int timeout, na_status_t *status);
static int na_mpi_request_free(na_request_t request);

static na_class_t na_mpi_g = {
        na_mpi_finalize,                      /* finalize */
        na_mpi_addr_lookup,                   /* addr_lookup */
        na_mpi_addr_free,                     /* addr_free */
        na_mpi_msg_get_max_expected_size,     /* msg_get_max_expected_size */
        na_mpi_msg_get_max_unexpected_size,   /* msg_get_max_expected_size */
        na_mpi_msg_get_max_tag,               /* msg_get_maximum_tag */
        na_mpi_msg_send_unexpected,           /* msg_send_unexpected */
        na_mpi_msg_recv_unexpected,           /* msg_recv_unexpected */
        na_mpi_msg_send,                      /* msg_send */
        na_mpi_msg_recv,                      /* msg_recv */
        na_mpi_mem_register,                  /* mem_register */
        NULL,                                 /* mem_register_segments */
        na_mpi_mem_deregister,                /* mem_deregister */
        na_mpi_mem_handle_get_serialize_size, /* mem_handle_get_serialize_size */
        na_mpi_mem_handle_serialize,          /* mem_handle_serialize */
        na_mpi_mem_handle_deserialize,        /* mem_handle_deserialize */
        na_mpi_mem_handle_free,               /* mem_handle_free */
        na_mpi_put,                           /* put */
        na_mpi_get,                           /* get */
        na_mpi_wait,                          /* wait */
        na_mpi_progress,                      /* progress */
        na_mpi_request_free                   /* request_free */
};

/* FIXME Force MPI version to 2 for now */
#undef MPI_VERSION
#define MPI_VERSION 2

/* Private structs */
typedef struct mpi_addr {
    MPI_Comm  comm;          /* Communicator */
    int       rank;          /* Rank in this communicator */
    na_bool_t is_reference;  /* Reference to existing address */
} mpi_addr_t;

typedef struct mpi_mem_handle {
    void *base;                /* Initial address of memory */
    /* MPI_Aint size; */       /* Size of memory, NB don't use it for now */
    unsigned attr;             /* Flag of operation access */
} mpi_mem_handle_t;

#if MPI_VERSION < 3
typedef enum mpi_onesided_op {
    MPI_ONESIDED_PUT,       /* Request a put operation */
    MPI_ONESIDED_GET        /* Request a get operation */
} mpi_onesided_op_t;

typedef struct mpi_onesided_info {
    void    *base;         /* Initial address of memory */
    MPI_Aint disp;         /* Offset from initial address */
    int      count;        /* Number of entries */
    mpi_onesided_op_t op;  /* Operation requested */
    na_tag_t tag;          /* Tag for the data transfer */
} mpi_onesided_info_t;
#endif

/* Used to differentiate Send requests from Recv requests */
typedef enum mpi_req_type {
    MPI_SEND_OP,
    MPI_RECV_OP
} mpi_req_type_t;

typedef struct mpi_req {
    mpi_req_type_t type;
    MPI_Request request;
#if MPI_VERSION < 3
    MPI_Request data_request;
#endif
} mpi_req_t;

/* Private variables */
static int mpi_ext_initialized;                 /* MPI initialized */
static MPI_Comm mpi_intra_comm = MPI_COMM_NULL; /* Private plugin intra-comm */
static char mpi_port_name[MPI_MAX_PORT_NAME];   /* Connection port */
static na_bool_t is_server = 0;                 /* Used in server mode */
static na_bool_t use_static_intercomm = 0;      /* Use static inter-communicator */
static mpi_addr_t *client_remote_addr = NULL;   /* Client remote address */
static mpi_addr_t server_remote_addr;           /* Server remote address */
static MPI_Comm mpi_onesided_comm = MPI_COMM_NULL;

static int is_mpi_testing = 0;
static hg_thread_cond_t mpi_test_cond;
static hg_thread_mutex_t mpi_test_mutex;

/* Mutex used for tag generation */
/* TODO use atomic increment instead */
static hg_thread_mutex_t mpi_tag_mutex;

#if MPI_VERSION < 3
static hg_hash_table_t *mem_handle_map = NULL;  /* Map mem addresses to mem handles */
static NA_INLINE int
pointer_equal(void *location1, void *location2)
{
    return location1 == location2;
}
static NA_INLINE unsigned int
pointer_hash(void *location)
{
    return (unsigned int) (unsigned long) location;
}
#else
static MPI_Win mpi_dynamic_win;                 /* Dynamic window */
#endif

#define NA_MPI_UNEXPECTED_SIZE 4096
#define NA_MPI_EXPECTED_SIZE   NA_MPI_UNEXPECTED_SIZE

/* Max tag */
#define NA_MPI_MAX_TAG (MPI_TAG_UB >> 2)

/* Default tag used for one-sided over two-sided emulation */
#define NA_MPI_ONESIDED_TAG (NA_MPI_MAX_TAG + 1)

#if MPI_VERSION < 3
#ifdef NA_HAS_CLIENT_THREAD
static hg_thread_mutex_t finalizing_mutex;
static na_bool_t         finalizing;
static hg_thread_t       progress_service;
#endif
hg_thread_mutex_t mem_map_mutex;

/*---------------------------------------------------------------------------*/
#ifdef NA_HAS_CLIENT_THREAD
static void *
na_mpi_progress_service(void NA_UNUSED *args)
{
    na_bool_t service_done = 0;

    while (!service_done) {
        int na_ret;

        hg_thread_mutex_lock(&finalizing_mutex);
        service_done = (finalizing) ? 1 : 0;
        hg_thread_mutex_unlock(&finalizing_mutex);

        na_ret = na_mpi_progress(0, NA_STATUS_IGNORE);
        if (na_ret != NA_SUCCESS) {
            NA_ERROR_DEFAULT("Could not make progress");
            break;
        }

        if (service_done) break;
    }

    return NULL;
}
#endif
#endif

/*---------------------------------------------------------------------------*/
static na_tag_t
na_mpi_gen_onesided_tag(void)
{
    static long int tag = NA_MPI_ONESIDED_TAG + 1;

    hg_thread_mutex_lock(&mpi_tag_mutex);
    tag++;
    if (tag == MPI_TAG_UB) tag = NA_MPI_ONESIDED_TAG + 1;
    hg_thread_mutex_unlock(&mpi_tag_mutex);

    return tag;
}

/*---------------------------------------------------------------------------*/
na_class_t *
NA_MPI_Init(MPI_Comm *intra_comm, int flags)
{
    /* Check flags */
    switch (flags) {
        case MPI_INIT_SERVER:
            is_server = 1;
            break;
        case MPI_INIT_SERVER_STATIC:
            is_server = 1;
            use_static_intercomm = 1;
            break;
        case MPI_INIT_STATIC:
            use_static_intercomm = 1;
            break;
        default:
            break;
    }

    /* MPI_Init */
    MPI_Initialized(&mpi_ext_initialized);

    if (!mpi_ext_initialized) {
#if MPI_VERSION < 3
        int provided;
        /* Need a MPI_THREAD_MULTIPLE level if onesided thread required */
        MPI_Init_thread(NULL, NULL, MPI_THREAD_MULTIPLE, &provided);
        if (provided != MPI_THREAD_MULTIPLE) {
            NA_ERROR_DEFAULT("MPI_THREAD_MULTIPLE cannot be set");
        }
#else
        MPI_Init(NULL, NULL);
#endif
    }

    /* Assign MPI intra comm */
    if (intra_comm && (*intra_comm != MPI_COMM_NULL)) {
        /* Assume that the application splits MPI_COMM_WORLD if necessary */
        MPI_Comm_dup(*intra_comm, &mpi_intra_comm);
    } else {
        if (use_static_intercomm) {
            int color;
            int global_rank;

            MPI_Comm_rank(MPI_COMM_WORLD, &global_rank);
            /* Color is 1 for server, 2 for client */
            color = (is_server) ? 1 : 2;
            MPI_Comm_split(MPI_COMM_WORLD, color, global_rank, &mpi_intra_comm);
        } else {
            MPI_Comm_dup(MPI_COMM_WORLD, &mpi_intra_comm);
        }
    }

#if MPI_VERSION < 3
    hg_thread_mutex_init(&mem_map_mutex);
    /* Create hash table for memory registration */
    mem_handle_map = hg_hash_table_new(pointer_hash, pointer_equal);
    /* Automatically free all the values with the hash map */
    hg_hash_table_register_free_functions(mem_handle_map, NULL, NULL);
#endif
    hg_thread_mutex_init(&mpi_test_mutex);
    hg_thread_cond_init(&mpi_test_cond);
    hg_thread_mutex_init(&mpi_tag_mutex);

    /* If server open a port */
    if (is_server) {
        if (use_static_intercomm) {
            int global_size, intra_size;

            MPI_Comm_size(MPI_COMM_WORLD, &global_size);
            MPI_Comm_size(mpi_intra_comm, &intra_size);
            MPI_Intercomm_create(mpi_intra_comm, 0, MPI_COMM_WORLD, global_size -
                    (global_size - intra_size), 0, &server_remote_addr.comm);
        } else {
            FILE *config;
            size_t nbytes;

            MPI_Open_port(MPI_INFO_NULL, mpi_port_name);
            config = fopen("port.cfg", "w+");
            nbytes = fwrite(mpi_port_name, sizeof(char), MPI_MAX_PORT_NAME, config);
            if (!nbytes) {
                NA_ERROR_DEFAULT("Could not write port name");
            }
            fclose(config);

            /* TODO server waits for connection here but that should be handled separately really */
            MPI_Comm_accept(mpi_port_name, MPI_INFO_NULL, 0, mpi_intra_comm, &server_remote_addr.comm);
        }
        server_remote_addr.is_reference = 0;
        server_remote_addr.rank = -1; /* the address returned does not bind to a specific process */

#if MPI_VERSION < 3
        /* To be thread-safe and create a new context, dup the remote comm to a new comm */
        MPI_Comm_dup(server_remote_addr.comm, &mpi_onesided_comm);
#else
        MPI_Intercomm_merge(server_remote_addr.comm, is_server, &mpi_onesided_comm);
        /* Create dynamic window */
        MPI_Win_create_dynamic(MPI_INFO_NULL, mpi_onesided_comm, &mpi_dynamic_win);
#endif
    }
    return &na_mpi_g;
}

/*---------------------------------------------------------------------------*/
static int
na_mpi_finalize(void)
{
    int mpi_ext_finalized, ret = NA_SUCCESS;

    /* If server opened a port */
    if (is_server) {
        MPI_Comm_free(&mpi_onesided_comm);

#if MPI_VERSION >= 3
        /* Destroy dynamic window */
        MPI_Win_free(&mpi_dynamic_win);
#endif

        if (use_static_intercomm) {
            MPI_Comm_free(&server_remote_addr.comm);
        } else {
            /* TODO Server disconnects here but that should be handled separately really */
            MPI_Comm_disconnect(&server_remote_addr.comm);
            MPI_Close_port(mpi_port_name);
        }
    } else {
        /* Automatically free addr */
        if (client_remote_addr) na_mpi_addr_free(client_remote_addr);
    }

    hg_thread_mutex_destroy(&mpi_tag_mutex);
    hg_thread_mutex_destroy(&mpi_test_mutex);
    hg_thread_cond_destroy(&mpi_test_cond);
#if MPI_VERSION < 3
    /* Free hash table for memory registration */
    hg_hash_table_free(mem_handle_map);
    hg_thread_mutex_destroy(&mem_map_mutex);
#endif

    /* Free the private dup'ed comm */
    MPI_Comm_free(&mpi_intra_comm);

    /* MPI_Finalize */
    MPI_Finalized(&mpi_ext_finalized);
    if (mpi_ext_finalized) {
        NA_ERROR_DEFAULT("MPI already finalized");
        ret = NA_FAIL;
    }
    if (!mpi_ext_initialized && !mpi_ext_finalized) {
        MPI_Finalize();
    }

    return ret;
}

/*---------------------------------------------------------------------------*/
static int
na_mpi_addr_lookup(const char *name, na_addr_t *addr)
{
    int mpi_ret, ret = NA_SUCCESS;
    char *port_name = (char*) name;
    mpi_addr_t *mpi_addr = NULL;

    if (client_remote_addr) {
        /* Already connected (TODO only allow connection to one server at this time) */
        if (addr) *addr = (na_addr_t) client_remote_addr;
        return ret;
    }

    /* Allocate the addr */
    mpi_addr = (mpi_addr_t*) malloc(sizeof(mpi_addr_t));
    if (!mpi_addr) {
        NA_ERROR_DEFAULT("Could not allocate addr");
        ret = NA_FAIL;
        return ret;
    }

    mpi_addr->comm = MPI_COMM_NULL;
    mpi_addr->is_reference = 0;
    mpi_addr->rank = 0; /* TODO Only one rank for server but this may need to be improved */

    /* Try to connect */
    if (use_static_intercomm) {
        mpi_ret = MPI_Intercomm_create(mpi_intra_comm, 0, MPI_COMM_WORLD, 0,
                0, &mpi_addr->comm);
    } else {
        mpi_ret = MPI_Comm_connect(port_name, MPI_INFO_NULL, 0, mpi_intra_comm,
                &mpi_addr->comm);
    }

    if (mpi_ret != MPI_SUCCESS) {
        NA_ERROR_DEFAULT("Could not connect");
        free(mpi_addr);
        ret = NA_FAIL;
        return ret;
    } else {
        int remote_size;
        MPI_Comm_remote_size(mpi_addr->comm, &remote_size);
        if (remote_size != 1) {
            NA_ERROR_DEFAULT("Connected to more than one server?");
        }
        if (addr) *addr = (na_addr_t) mpi_addr;
        client_remote_addr = mpi_addr;
    }

#if MPI_VERSION < 3
#ifdef NA_HAS_CLIENT_THREAD
    /* To be thread-safe and create a new context, dup the remote comm to a new comm */
    MPI_Comm_dup(mpi_addr->comm, &mpi_onesided_comm);
    hg_thread_mutex_init(&finalizing_mutex);
    /* TODO temporary to handle one-sided exchanges with remote server */
    hg_thread_create(&progress_service, (hg_thread_func_t) &na_mpi_progress_service, NULL);
#endif
#else
    MPI_Intercomm_merge(mpi_addr->comm, is_server, &mpi_onesided_comm);
    /* Create dynamic window */
    MPI_Win_create_dynamic(MPI_INFO_NULL, mpi_onesided_comm, &mpi_dynamic_win);
#endif
    return ret;
}

/*---------------------------------------------------------------------------*/
static int
na_mpi_addr_free(na_addr_t addr)
{
    mpi_addr_t *mpi_addr = (mpi_addr_t*) addr;
    int ret = NA_SUCCESS;

    if (!mpi_addr) {
        NA_ERROR_DEFAULT("Already freed");
        ret = NA_FAIL;
        return ret;
    }

    if (!mpi_addr->is_reference) {
#if MPI_VERSION < 3
#ifdef NA_HAS_CLIENT_THREAD
    if (!is_server) {
        hg_thread_mutex_lock(&finalizing_mutex);
        finalizing = 1;
        hg_thread_mutex_unlock(&finalizing_mutex);
        /* Wait for one-sided thread to complete */
        hg_thread_join(progress_service);
    }
    hg_thread_mutex_destroy(&finalizing_mutex);
#endif
#else
        /* Destroy dynamic window */
        MPI_Win_free(&mpi_dynamic_win);
#endif
        MPI_Comm_free(&mpi_onesided_comm);

        if (use_static_intercomm) {
            MPI_Comm_free(&mpi_addr->comm);
        } else {
            MPI_Comm_disconnect(&mpi_addr->comm);
        }
        /* We're disconnected now */
        client_remote_addr = NULL;
    }
    free(mpi_addr);
    mpi_addr = NULL;

    return ret;
}

/*---------------------------------------------------------------------------*/
static na_size_t
na_mpi_msg_get_max_expected_size(void)
{
    na_size_t max_expected_size = NA_MPI_EXPECTED_SIZE;

    return max_expected_size;
}

/*---------------------------------------------------------------------------*/
static na_size_t
na_mpi_msg_get_max_unexpected_size(void)
{
    na_size_t max_unexpected_size = NA_MPI_UNEXPECTED_SIZE;

    return max_unexpected_size;
}

/*---------------------------------------------------------------------------*/
static na_tag_t
na_mpi_msg_get_max_tag(void)
{
    na_tag_t max_tag = NA_MPI_MAX_TAG;

    return max_tag;
}

/*---------------------------------------------------------------------------*/
static int
na_mpi_msg_send_unexpected(const void *buf, na_size_t buf_size,
        na_addr_t dest, na_tag_t tag, na_request_t *request, void *op_arg)
{
    /* There should not be any difference for MPI */
    return na_mpi_msg_send(buf, buf_size, dest, tag, request, op_arg);
}

/*---------------------------------------------------------------------------*/
static int
na_mpi_msg_recv_unexpected(void *buf, na_size_t buf_size, na_size_t *actual_buf_size,
        na_addr_t *source, na_tag_t *tag, na_request_t *request, void NA_UNUSED *op_arg)
{
    int mpi_ret, ret = NA_SUCCESS;
    MPI_Status mpi_status;
    int flag = 0;

    int mpi_buf_size;
    int mpi_source;
    int mpi_tag;
    MPI_Comm mpi_unexpected_comm;
    mpi_req_t *mpi_request = NULL;
    mpi_addr_t *peer_addr = NULL;

    if (!buf) {
        NA_ERROR_DEFAULT("NULL buffer");
        ret = NA_FAIL;
        goto done;
    }

    /* TODO do that for now until addresses are better handled */
    if (is_server) {
        mpi_unexpected_comm = server_remote_addr.comm;
    } else {
#if MPI_VERSION < 3
        mpi_unexpected_comm = mpi_onesided_comm;
#else
        NA_ERROR_DEFAULT("Unexpected receive on client not allowed");
        ret = NA_FAIL;
        goto done;
#endif
    }

    mpi_ret = MPI_Iprobe(MPI_ANY_SOURCE, MPI_ANY_TAG, mpi_unexpected_comm,
            &flag, &mpi_status);
    if (mpi_ret != MPI_SUCCESS) {
        NA_ERROR_DEFAULT("MPI_Iprobe() failed");
        ret = NA_FAIL;
        goto done;
    }

    if (!flag) goto done;

    MPI_Get_count(&mpi_status, MPI_BYTE, &mpi_buf_size);
    if (mpi_buf_size > (int) buf_size) {
        NA_ERROR_DEFAULT("Buffer too small to recv unexpected data");
        ret = NA_FAIL;
        goto done;
    }

    mpi_source = mpi_status.MPI_SOURCE;
    mpi_tag = mpi_status.MPI_TAG;

    mpi_request = (mpi_req_t*) malloc(sizeof(mpi_req_t));
    if (!mpi_request) {
        NA_ERROR_DEFAULT("Could not allocate request");
        ret = NA_FAIL;
        goto done;
    }

    mpi_request->type = MPI_RECV_OP;
#if MPI_VERSION < 3
    mpi_request->data_request = MPI_REQUEST_NULL;
#endif

    mpi_ret = MPI_Irecv(buf, mpi_buf_size, MPI_BYTE, mpi_source,
            mpi_tag, mpi_unexpected_comm, &mpi_request->request);
    if (mpi_ret != MPI_SUCCESS) {
        NA_ERROR_DEFAULT("MPI_Irecv() failed");
        ret = NA_FAIL;
        goto done;
    }

    /* Fill info */
    if (actual_buf_size) *actual_buf_size = (na_size_t) mpi_buf_size;
    if (source) {
        mpi_addr_t **peer_addr_ptr = (mpi_addr_t**) source;
        peer_addr = (mpi_addr_t*) malloc(sizeof(mpi_addr_t));
        if (!peer_addr) {
            NA_ERROR_DEFAULT("Could not allocate peer addr");
            ret = NA_FAIL;
            goto done;
        }
        peer_addr->comm = mpi_unexpected_comm;
        peer_addr->rank = mpi_source;
        peer_addr->is_reference = 1;
        *peer_addr_ptr = peer_addr;
    }
    if (tag) *tag = mpi_tag;
    *request = (na_request_t) mpi_request;

done:
    if (ret != NA_SUCCESS) {
        free(mpi_request);
        free(peer_addr);
    }
    return ret;
}

/*---------------------------------------------------------------------------*/
static int
na_mpi_msg_send(const void *buf, na_size_t buf_size, na_addr_t dest,
        na_tag_t tag, na_request_t *request, void NA_UNUSED *op_arg)
{
    int mpi_ret, ret = NA_SUCCESS;
    void *mpi_buf = (void*) buf;
    int mpi_buf_size = (int) buf_size;
    int mpi_tag = (int) tag;
    mpi_addr_t *mpi_addr = (mpi_addr_t*) dest;
    mpi_req_t *mpi_request;

    mpi_request = (mpi_req_t*) malloc(sizeof(mpi_req_t));
    if (!mpi_request) {
        NA_ERROR_DEFAULT("Could not allocate request");
        ret = NA_FAIL;
        return ret;
    }
    mpi_request->type = MPI_SEND_OP;
#if MPI_VERSION < 3
    mpi_request->data_request = MPI_REQUEST_NULL;
#endif

    mpi_ret = MPI_Isend(mpi_buf, mpi_buf_size, MPI_BYTE, mpi_addr->rank,
            mpi_tag, mpi_addr->comm, &mpi_request->request);
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

/*---------------------------------------------------------------------------*/
static int
na_mpi_msg_recv(void *buf, na_size_t buf_size, na_addr_t source,
        na_tag_t tag, na_request_t *request, void NA_UNUSED *op_arg)
{
    int mpi_ret, ret = NA_SUCCESS;
    void *mpi_buf = (void*) buf;
    int mpi_buf_size = (int) buf_size;
    int mpi_tag = (int) tag;
    mpi_addr_t *mpi_addr = (mpi_addr_t*) source;
    mpi_req_t *mpi_request;

    mpi_request = (mpi_req_t*) malloc(sizeof(mpi_req_t));
    if (!mpi_request) {
        NA_ERROR_DEFAULT("Could not allocate request");
        ret = NA_FAIL;
        return ret;
    }
    mpi_request->type = MPI_RECV_OP;
#if MPI_VERSION < 3
    mpi_request->data_request = MPI_REQUEST_NULL;
#endif

    mpi_ret = MPI_Irecv(mpi_buf, mpi_buf_size, MPI_BYTE, mpi_addr->rank,
            mpi_tag, mpi_addr->comm, &mpi_request->request);
    if (mpi_ret != MPI_SUCCESS) {
        NA_ERROR_DEFAULT("MPI_Irecv() failed");
        free(mpi_request);
        mpi_request = NULL;
        ret = NA_FAIL;
    } else {
        *request = (na_request_t) mpi_request;
    }
    return ret;
}

/*---------------------------------------------------------------------------*/
static int
na_mpi_mem_register(void *buf, na_size_t NA_UNUSED buf_size, unsigned long flags,
        na_mem_handle_t *mem_handle)
{
    int ret = NA_SUCCESS;
    void *mpi_buf_base = buf;
    mpi_mem_handle_t *mpi_mem_handle;
    /* MPI_Aint mpi_buf_size = (MPI_Aint) buf_size; */

    mpi_mem_handle = (mpi_mem_handle_t*) malloc(sizeof(mpi_mem_handle_t));
    if (!mpi_mem_handle) {
        NA_ERROR_DEFAULT("Could not allocate memory handle");
        ret = NA_FAIL;
        return ret;
    }
    mpi_mem_handle->base = mpi_buf_base;
    /* mpi_mem_handle->size = mpi_buf_size; */
    mpi_mem_handle->attr = flags;

    *mem_handle = (na_mem_handle_t) mpi_mem_handle;

#if MPI_VERSION < 3
    hg_thread_mutex_lock(&mem_map_mutex);
    /* store this handle */
    if (!hg_hash_table_insert(mem_handle_map, mpi_mem_handle->base, mpi_mem_handle)) {
        NA_ERROR_DEFAULT("Could not register memory handle");
        ret = NA_FAIL;
    }
    hg_thread_mutex_unlock(&mem_map_mutex);
#else
    int mpi_ret;

    mpi_ret = MPI_Win_attach(mpi_dynamic_win, mpi_mem_handle->base, mpi_mem_handle->size);
    if (mpi_ret != MPI_SUCCESS) {
        NA_ERROR_DEFAULT("MPI_Win_attach() failed");
        ret = NA_FAIL;
    }
#endif
    return ret;
}

/*---------------------------------------------------------------------------*/
static int
na_mpi_mem_deregister(na_mem_handle_t mem_handle)
{
    int ret = NA_SUCCESS;
    mpi_mem_handle_t *mpi_mem_handle = (mpi_mem_handle_t*) mem_handle;

#if MPI_VERSION < 3
    hg_thread_mutex_lock(&mem_map_mutex);
    /* remove the handle */
    if (!hg_hash_table_remove(mem_handle_map, mpi_mem_handle->base)) {
        NA_ERROR_DEFAULT("Could not deregister memory handle");
        ret = NA_FAIL;
    }
    hg_thread_mutex_unlock(&mem_map_mutex);
#else
    int mpi_ret;

    mpi_ret = MPI_Win_detach(mpi_dynamic_win, mpi_mem_handle->base);
    if (mpi_ret != MPI_SUCCESS) {
        NA_ERROR_DEFAULT("MPI_Win_detach() failed");
        ret = NA_FAIL;
    }
#endif
    if (mpi_mem_handle) {
        free(mpi_mem_handle);
        mpi_mem_handle = NULL;
    } else {
        NA_ERROR_DEFAULT("Already freed");
        ret = NA_FAIL;
    }
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_size_t
na_mpi_mem_handle_get_serialize_size(na_mem_handle_t NA_UNUSED mem_handle)
{
    return sizeof(mpi_mem_handle_t);
}

/*---------------------------------------------------------------------------*/
static int
na_mpi_mem_handle_serialize(void *buf, na_size_t buf_size,
        na_mem_handle_t mem_handle)
{
    int ret = NA_SUCCESS;
    mpi_mem_handle_t *mpi_mem_handle = (mpi_mem_handle_t*) mem_handle;

    if (buf_size < sizeof(mpi_mem_handle_t)) {
        NA_ERROR_DEFAULT("Buffer size too small for serializing parameter");
        ret = NA_FAIL;
    } else {
        /* Here safe to do a simple memcpy */
        /* TODO may also want to add a checksum or something */
        memcpy(buf, mpi_mem_handle, sizeof(mpi_mem_handle_t));
    }
    return ret;
}

/*---------------------------------------------------------------------------*/
static int
na_mpi_mem_handle_deserialize(na_mem_handle_t *mem_handle,
        const void *buf, na_size_t buf_size)
{
    int ret = NA_SUCCESS;
    mpi_mem_handle_t *mpi_mem_handle;

    if (buf_size < sizeof(mpi_mem_handle_t)) {
        NA_ERROR_DEFAULT("Buffer size too small for deserializing parameter");
        ret = NA_FAIL;
        return ret;
    }

    mpi_mem_handle = (mpi_mem_handle_t*) malloc(sizeof(mpi_mem_handle_t));
    if (!mpi_mem_handle) {
        NA_ERROR_DEFAULT("Could not allocate memory handle");
        ret = NA_FAIL;
        return ret;
    }

    /* Here safe to do a simple memcpy */
    memcpy(mpi_mem_handle, buf, sizeof(mpi_mem_handle_t));
    *mem_handle = (na_mem_handle_t) mpi_mem_handle;

    return ret;
}

/*---------------------------------------------------------------------------*/
static int
na_mpi_mem_handle_free(na_mem_handle_t mem_handle)
{
    int ret = NA_SUCCESS;
    mpi_mem_handle_t *mpi_mem_handle = (mpi_mem_handle_t*) mem_handle;

    if (mpi_mem_handle) {
        free(mpi_mem_handle);
        mpi_mem_handle = NULL;
    } else {
        NA_ERROR_DEFAULT("Already freed");
        ret = NA_FAIL;
    }
    return ret;
}

/*---------------------------------------------------------------------------*/
static int
na_mpi_put(na_mem_handle_t local_mem_handle, na_offset_t local_offset,
        na_mem_handle_t remote_mem_handle, na_offset_t remote_offset,
        na_size_t length, na_addr_t remote_addr, na_request_t *request)
{
    int mpi_ret, ret = NA_SUCCESS;
    mpi_mem_handle_t *mpi_local_mem_handle = (mpi_mem_handle_t*) local_mem_handle;
    MPI_Aint mpi_local_offset = (MPI_Aint) local_offset;
    mpi_mem_handle_t *mpi_remote_mem_handle = (mpi_mem_handle_t*) remote_mem_handle;
    MPI_Aint mpi_remote_offset = (MPI_Aint) remote_offset;
    int mpi_length = (int) length; /* TODO careful here that we don't send more than 2GB */
    mpi_addr_t *mpi_remote_addr = (mpi_addr_t*) remote_addr;
    mpi_req_t *mpi_request = NULL;

#if MPI_VERSION < 3
    mpi_onesided_info_t onesided_info;

    /* Check that local memory is registered */
    if (!hg_hash_table_lookup(mem_handle_map, mpi_local_mem_handle->base)) {
        NA_ERROR_DEFAULT("Could not find memory handle, registered?");
        ret = NA_FAIL;
        return ret;
    }
#endif

    if (mpi_remote_mem_handle->attr != NA_MEM_READWRITE) {
        NA_ERROR_DEFAULT("Registered memory requires write permission");
        ret = NA_FAIL;
        return ret;
    }

    mpi_request = (mpi_req_t*) malloc(sizeof(mpi_req_t));
    if (!mpi_request) {
        NA_ERROR_DEFAULT("Could not allocate request");
        ret = NA_FAIL;
        return ret;
    }
    mpi_request->type = MPI_SEND_OP;
    mpi_request->request = MPI_REQUEST_NULL;

#if MPI_VERSION < 3
    mpi_request->data_request = MPI_REQUEST_NULL;

    /* Send to one-sided thread key to access mem_handle */
    onesided_info.base = mpi_remote_mem_handle->base;
    onesided_info.disp = mpi_remote_offset;
    onesided_info.count = mpi_length;
    onesided_info.op = MPI_ONESIDED_PUT;
    onesided_info.tag = na_mpi_gen_onesided_tag();

    MPI_Isend(&onesided_info, sizeof(mpi_onesided_info_t), MPI_BYTE, mpi_remote_addr->rank,
            NA_MPI_ONESIDED_TAG, mpi_onesided_comm, &mpi_request->request);

    /* Simply do a non blocking synchronous send */
    mpi_ret = MPI_Issend((char*) mpi_local_mem_handle->base + mpi_local_offset, mpi_length, MPI_BYTE,
            mpi_remote_addr->rank, onesided_info.tag, mpi_onesided_comm, &mpi_request->data_request);
    if (mpi_ret != MPI_SUCCESS) {
        NA_ERROR_DEFAULT("MPI_Isend() failed");
        free(mpi_request);
        mpi_request = NULL;
        ret = NA_FAIL;
    }

#else
    MPI_Win_lock(MPI_LOCK_EXCLUSIVE, mpi_remote_addr->rank, 0, mpi_dynamic_win);

    mpi_ret = MPI_Rput((char*) mpi_local_mem_handle->base + mpi_local_offset, mpi_length, MPI_BYTE,
            mpi_remote_addr->rank, mpi_remote_offset, mpi_length, MPI_BYTE, mpi_dynamic_win, &mpi_request->request);
    if (mpi_ret != MPI_SUCCESS) {
        NA_ERROR_DEFAULT("MPI_Rput() failed");
        free(mpi_request);
        mpi_request = NULL;
        ret = NA_FAIL;
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

/*---------------------------------------------------------------------------*/
static int
na_mpi_get(na_mem_handle_t local_mem_handle, na_offset_t local_offset,
        na_mem_handle_t remote_mem_handle, na_offset_t remote_offset,
        na_size_t length, na_addr_t remote_addr, na_request_t *request)
{
    int mpi_ret, ret = NA_SUCCESS;
    mpi_mem_handle_t *mpi_local_mem_handle = (mpi_mem_handle_t*) local_mem_handle;
    MPI_Aint mpi_local_offset = (MPI_Aint) local_offset;
    mpi_mem_handle_t *mpi_remote_mem_handle = (mpi_mem_handle_t*) remote_mem_handle;
    MPI_Aint mpi_remote_offset = (MPI_Aint) remote_offset;
    int mpi_length = (int) length; /* TODO careful here that we don't send more than 2GB */
    mpi_addr_t *mpi_remote_addr = (mpi_addr_t*) remote_addr;
    mpi_req_t *mpi_request = NULL;

#if MPI_VERSION < 3
    mpi_onesided_info_t onesided_info;

    /* Check that local memory is registered */
    if (!hg_hash_table_lookup(mem_handle_map, mpi_local_mem_handle->base)) {
        NA_ERROR_DEFAULT("Could not find memory handle, registered?");
        ret = NA_FAIL;
        return ret;
    }
#endif

    mpi_request = (mpi_req_t*) malloc(sizeof(mpi_req_t));
    if (!mpi_request) {
        NA_ERROR_DEFAULT("Could not allocate request");
        ret = NA_FAIL;
        return ret;
    }
    mpi_request->type = MPI_RECV_OP;
    mpi_request->request = MPI_REQUEST_NULL;

#if MPI_VERSION < 3
    mpi_request->data_request = MPI_REQUEST_NULL;

    /* Send to one-sided thread key to access mem_handle */
    onesided_info.base = mpi_remote_mem_handle->base;
    onesided_info.disp = mpi_remote_offset;
    onesided_info.count = mpi_length;
    onesided_info.op = MPI_ONESIDED_GET;
    onesided_info.tag = na_mpi_gen_onesided_tag();

    MPI_Isend(&onesided_info, sizeof(mpi_onesided_info_t), MPI_BYTE, mpi_remote_addr->rank,
            NA_MPI_ONESIDED_TAG, mpi_onesided_comm, &mpi_request->request);

    /* Simply do an asynchronous recv */
    mpi_ret = MPI_Irecv((char*) mpi_local_mem_handle->base + mpi_local_offset, mpi_length, MPI_BYTE,
            mpi_remote_addr->rank, onesided_info.tag, mpi_onesided_comm, &mpi_request->data_request);
    if (mpi_ret != MPI_SUCCESS) {
        NA_ERROR_DEFAULT("MPI_Irecv() failed");
        free(mpi_request);
        mpi_request = NULL;
        ret = NA_FAIL;
    }
#else
    MPI_Win_lock(MPI_LOCK_SHARED, mpi_remote_addr->rank, 0, mpi_dynamic_win);

    mpi_ret = MPI_Rget((char*) mpi_local_mem_handle->base + mpi_local_offset, mpi_length, MPI_BYTE,
            mpi_remote_addr->rank, mpi_remote_offset, mpi_length, MPI_BYTE, mpi_dynamic_win, &mpi_request->request);
    if (mpi_ret != MPI_SUCCESS) {
        NA_ERROR_DEFAULT("MPI_Rget() failed");
        free(mpi_request);
        mpi_request = NULL;
        ret = NA_FAIL;
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

/*---------------------------------------------------------------------------*/
static int
na_mpi_wait(na_request_t request, unsigned int timeout, na_status_t *status)
{
    int mpi_ret, ret = NA_SUCCESS;
    mpi_req_t *mpi_request = (mpi_req_t*) request;
    double remaining = timeout / 1000; /* Timeout in milliseconds */
    MPI_Status mpi_status;

    if (!mpi_request) {
        NA_ERROR_DEFAULT("NULL request");
        ret = NA_FAIL;
        return ret;
    }

    do {
        int hg_thread_cond_ret = 0;
        int mpi_flag = 0;
        hg_time_t t1, t2;

        hg_time_get_current(&t1);

        hg_thread_mutex_lock(&mpi_test_mutex);
        while (is_mpi_testing) {
            /*
            hg_thread_cond_ret = hg_thread_cond_timedwait(&testcontext_cond,
                    &testcontext_mutex, remaining);
             */
            hg_thread_cond_ret = hg_thread_cond_wait(&mpi_test_cond,
                    &mpi_test_mutex);
        }
        is_mpi_testing = 1;
        hg_thread_mutex_unlock(&mpi_test_mutex);

        if (hg_thread_cond_ret < 0) {
            NA_ERROR_DEFAULT("hg_thread_cond_timedwait failed");
            ret = NA_FAIL;
            break;
        }

        hg_thread_mutex_lock(&mpi_test_mutex);
        /* Test main request */
        if (mpi_request->request != MPI_REQUEST_NULL) {
            mpi_ret = MPI_Test(&mpi_request->request, &mpi_flag, &mpi_status);
            if (mpi_ret != MPI_SUCCESS) {
                NA_ERROR_DEFAULT("MPI_Test() failed");
                ret = NA_FAIL;
                return ret;
            }
            if (mpi_flag) mpi_request->request = MPI_REQUEST_NULL;
        }

#if MPI_VERSION < 3
        /* Test data request if exists */
        if (mpi_request->data_request != MPI_REQUEST_NULL) {
            mpi_ret = MPI_Test(&mpi_request->data_request, &mpi_flag, &mpi_status);
            if (mpi_ret != MPI_SUCCESS) {
                NA_ERROR_DEFAULT("MPI_Test() failed");
                ret = NA_FAIL;
                return ret;
            }
            if (mpi_flag) mpi_request->data_request = MPI_REQUEST_NULL;
        }
#endif

        is_mpi_testing = 0;
        hg_thread_cond_signal(&mpi_test_cond);
        hg_thread_mutex_unlock(&mpi_test_mutex);

        hg_time_get_current(&t2);
        remaining -= hg_time_to_double(hg_time_subtract(t2, t1));

    } while (( (mpi_request->request != MPI_REQUEST_NULL) ||
#if MPI_VERSION < 3
               (mpi_request->data_request != MPI_REQUEST_NULL)
#endif
             ) && remaining > 0);

    /* If the request has not completed return */
    if ( (mpi_request->request != MPI_REQUEST_NULL) ||
#if MPI_VERSION < 3
         (mpi_request->data_request != MPI_REQUEST_NULL)
#endif
         ) {
        if (status && status != NA_STATUS_IGNORE) {
            status->completed = 0;
        }
        ret = NA_SUCCESS;
        return ret;
    }

    /* If the request has completed free the request */
    if (status && status != NA_STATUS_IGNORE) {
        if (mpi_request->type == MPI_RECV_OP) {
            int count = 0;
            MPI_Get_count(&mpi_status, MPI_BYTE, &count);
            status->count = (na_size_t) count;
        } else {
            status->count = 0;
        }
        status->completed = 1;
    }

    free(mpi_request);
    mpi_request = NULL;

    return ret;
}

/*---------------------------------------------------------------------------*/
#if MPI_VERSION < 3
static int
na_mpi_progress(unsigned int timeout, na_status_t *status)
{
    double time_remaining = timeout / 1000; /* Timeout in milliseconds */
    int ret = NA_SUCCESS;
    int mpi_ret;

    /* TODO may want to have it dynamically allocated if multiple threads call
     * progress on the client but should that happen? */
    static mpi_onesided_info_t onesided_info;
    static na_size_t onesided_actual_size = 0;
    static na_addr_t remote_addr = NA_ADDR_NULL;
    static na_tag_t remote_tag = 0;
    static na_request_t onesided_request = NA_REQUEST_NULL;
    mpi_addr_t *mpi_addr;
    na_status_t onesided_status;
    mpi_mem_handle_t *mpi_mem_handle = NULL;

    /* Wait for an initial request from client */
    if (onesided_request == NA_REQUEST_NULL) {
        do {
            hg_time_t t1, t2;

            onesided_actual_size = 0;
            remote_addr = NA_ADDR_NULL;
            remote_tag = 0;

            hg_time_get_current(&t1);

            ret = na_mpi_msg_recv_unexpected(&onesided_info, sizeof(mpi_onesided_info_t),
                    &onesided_actual_size, &remote_addr,
                    &remote_tag, &onesided_request, NULL);
            if (ret != NA_SUCCESS) {
                NA_ERROR_DEFAULT("Could not recv buffer");
                ret = NA_FAIL;
                return ret;
            }

            hg_time_get_current(&t2);
            time_remaining -= hg_time_to_double(hg_time_subtract(t2, t1));

        } while (time_remaining > 0 && !onesided_actual_size);
        if (!onesided_actual_size) {
            /* Timeout reached and has still not received anything */
            if (status && status != NA_STATUS_IGNORE) {
                status->completed = 0;
                status->count = 0;
            }
            ret = NA_SUCCESS;
            return ret;
        }
        if (onesided_actual_size != sizeof(onesided_info)) {
            NA_ERROR_DEFAULT("recv_buf_size does not match onesided_info");
            ret = NA_FAIL;
            return ret;
        }
    }

    ret = na_mpi_wait(onesided_request, timeout, &onesided_status);
    if (ret != NA_SUCCESS) {
        NA_ERROR_DEFAULT("Error while waiting");
        ret = NA_FAIL;
        return ret;
    }

    if (!onesided_status.completed) {
        if (status && status != NA_STATUS_IGNORE) {
            status->completed = 0;
            status->count = 0;
        }
        ret = NA_SUCCESS;
        return ret;
    } else {
        onesided_request = NA_REQUEST_NULL;
    }

    if (remote_tag != NA_MPI_ONESIDED_TAG) {
        NA_ERROR_DEFAULT("Bad remote tag");
        ret = NA_FAIL;
        return ret;
    }

    /* fprintf(stderr, "Treating request: base %lu, count %lu, disp %lu\n",
            (unsigned long)onesided_info.base, (unsigned long)onesided_info.count,
            (unsigned long)onesided_info.disp); */

    /* Here better to keep the mutex locked the time we operate on
     * mpi_mem_handle since it's a pointer to a mem_handle */
    hg_thread_mutex_lock(&mem_map_mutex);

    mpi_mem_handle = (mpi_mem_handle_t*) hg_hash_table_lookup(mem_handle_map, onesided_info.base);

    if (!mpi_mem_handle) {
        NA_ERROR_DEFAULT("Could not find memory handle, registered?");
        hg_thread_mutex_unlock(&mem_map_mutex);
        ret = NA_FAIL;
        return ret;
    }

    mpi_addr = (mpi_addr_t*) remote_addr;

    switch (onesided_info.op) {

        /* Remote wants to do a put so wait in a recv */
        case MPI_ONESIDED_PUT:
            mpi_ret = MPI_Recv((char*) mpi_mem_handle->base + onesided_info.disp,
                    onesided_info.count, MPI_BYTE, mpi_addr->rank,
                    onesided_info.tag, mpi_onesided_comm, MPI_STATUS_IGNORE);
            if (mpi_ret != MPI_SUCCESS) {
                NA_ERROR_DEFAULT("Could not recv data");
                ret = NA_FAIL;
            }
            break;

            /* Remote wants to do a get so do a send */
        case MPI_ONESIDED_GET:
            mpi_ret = MPI_Send((char*) mpi_mem_handle->base + onesided_info.disp,
                    onesided_info.count, MPI_BYTE, mpi_addr->rank,
                    onesided_info.tag, mpi_onesided_comm);
            if (mpi_ret != MPI_SUCCESS) {
                NA_ERROR_DEFAULT("Could not send data");
                ret = NA_FAIL;
            }
            break;

        default:
            NA_ERROR_DEFAULT("Operation not supported");
            break;
    }

    hg_thread_mutex_unlock(&mem_map_mutex);

    if (status && status != NA_STATUS_IGNORE) {
        status->completed = 1;
        status->count = onesided_info.count;
    }
    na_mpi_addr_free(remote_addr);
    remote_addr = NA_ADDR_NULL;

    return ret;
}
#else
static int
na_mpi_progress(unsigned int timeout, na_status_t *status)
{
    NA_ERROR_DEFAULT("Not implemented");
    return NA_FAIL;
}
#endif

/*---------------------------------------------------------------------------*/
static int
na_mpi_request_free(na_request_t request)
{
    mpi_req_t *mpi_request = (mpi_req_t*) request;
    int ret = NA_SUCCESS;

    /* Do not want to free the request if another thread is testing it */
    hg_thread_mutex_lock(&mpi_test_mutex);

    if (!mpi_request) {
        NA_ERROR_DEFAULT("NULL request");
        ret = NA_FAIL;
    } else {
        if (mpi_request->request != MPI_REQUEST_NULL) {
            MPI_Request_free(&mpi_request->request);
        }
        if (mpi_request->data_request != MPI_REQUEST_NULL) {
            MPI_Request_free(&mpi_request->data_request);
        }
        free(mpi_request);
        mpi_request = NULL;
        /* TODO may need to do extra things here */
    }

    hg_thread_mutex_unlock(&mpi_test_mutex);

    return ret;
}
