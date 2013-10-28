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
#include "mercury_list.h"
#include "mercury_thread.h"
#include "mercury_thread_mutex.h"
#include "mercury_thread_condition.h"
#include "mercury_time.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static na_bool_t na_mpi_verify(const char *protocol);
static na_class_t *na_mpi_initialize(const struct na_host_buffer *na_buffer,
        na_bool_t listen);

static int na_mpi_finalize(void);

static int na_mpi_addr_lookup(const char *name, na_addr_t *addr);
static int na_mpi_addr_free(na_addr_t addr);
static int na_mpi_addr_to_string(char *buf, na_size_t buf_size, na_addr_t addr);

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
        na_mpi_addr_to_string,                /* addr_to_string */
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

/* Private structs */
struct na_mpi_addr {
    MPI_Comm  comm;              /* Communicator */
    MPI_Comm  onesided_comm;     /* Communicator used for one sided emulation */
    int       rank;              /* Rank in this communicator */
    na_bool_t is_unexpected : 1; /* Address generated from unexpected recv */
    char      port_name[MPI_MAX_PORT_NAME]; /* String version of addr */
};

struct na_mpi_mem_handle {
    void *base;                /* Initial address of memory */
    /* MPI_Aint size; */       /* Size of memory, NB don't use it for now */
    unsigned attr;             /* Flag of operation access */
};

typedef enum na_mpi_onesided_op {
    MPI_ONESIDED_PUT,       /* Request a put operation */
    MPI_ONESIDED_GET        /* Request a get operation */
} na_mpi_onesided_op_t;

struct na_mpi_onesided_info {
    void    *base;         /* Initial address of memory */
    MPI_Aint disp;         /* Offset from initial address */
    int      count;        /* Number of entries */
    na_mpi_onesided_op_t op;  /* Operation requested */
    na_tag_t tag;          /* Tag for the data transfer */
};

/* Used to differentiate Send requests from Recv requests */
typedef enum na_mpi_req_type {
    MPI_SEND_OP,
    MPI_RECV_OP
} na_mpi_req_type_t;

struct na_mpi_req {
    na_mpi_req_type_t type;
    MPI_Request request;
    MPI_Request data_request;
};

/* Private variables */

/* Class description */
static const char na_mpi_name_g[] = "mpi";
const struct na_class_describe na_mpi_describe_g = {
    na_mpi_name_g,
    na_mpi_verify,
    na_mpi_initialize
};
static int       na_mpi_ext_initialized_g; /* MPI initialized */
static MPI_Comm  na_mpi_intra_comm_g = MPI_COMM_NULL; /* Private plugin intra-comm */
static na_bool_t na_mpi_is_server_g = 0; /* Used in server mode */
static na_bool_t na_mpi_use_static_intercomm_g = 0; /* Use static inter-communicator */
static char      na_mpi_port_name_g[MPI_MAX_PORT_NAME]; /* Server local port name used for
                                                           dynamic connection */

/* Mutex used for tag generation (TODO use atomic increment instead) */
static hg_thread_mutex_t  na_mpi_tag_mutex_g;

/* For na_mpi_wait() */
static na_bool_t          na_mpi_is_testing_g = 0;
static hg_thread_cond_t   na_mpi_test_cond_g;
static hg_thread_mutex_t  na_mpi_test_mutex_g;

/* To finalize service threads */
static na_bool_t          na_mpi_is_finalizing_g = 0;
static hg_thread_mutex_t  na_mpi_finalize_mutex_g;

/* Accept service */
static hg_thread_t        na_mpi_accept_thread_g;
static hg_thread_mutex_t  na_mpi_accept_mutex_g;
static hg_thread_cond_t   na_mpi_accept_cond_g;
static na_bool_t          na_mpi_is_accepting_g = 1;

static hg_thread_mutex_t  na_mpi_remote_list_mutex_g;
static hg_list_entry_t   *na_mpi_remote_list_g = NULL;
static NA_INLINE int
na_mpi_remote_list_equal(void *location1, void *location2)
{
    return location1 == location2;
}

/* Onesided progress service */
static hg_thread_t        na_mpi_progress_thread_g;

/* Map mem addresses to mem handles */
static hg_thread_mutex_t  na_mpi_mem_map_mutex_g;
static hg_hash_table_t   *na_mpi_mem_handle_map_g = NULL;
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

#define NA_MPI_UNEXPECTED_SIZE 4096
/* Expected message size is the same as unexpected messages for now */
#define NA_MPI_EXPECTED_SIZE   NA_MPI_UNEXPECTED_SIZE

/* Max tag */
#define NA_MPI_MAX_TAG (MPI_TAG_UB >> 2)

/* Default tag used for one-sided over two-sided emulation */
#define NA_MPI_ONESIDED_TAG (NA_MPI_MAX_TAG + 1)

/*---------------------------------------------------------------------------*/
static int
na_mpi_addr_free_(struct na_mpi_addr *mpi_addr)
{
    int ret = NA_SUCCESS;

    if (mpi_addr && !mpi_addr->is_unexpected) {
        if (na_mpi_use_static_intercomm_g || na_mpi_is_server_g) {
            MPI_Comm_free(&mpi_addr->comm);
        } else {
            MPI_Comm_disconnect(&mpi_addr->comm);
        }
        MPI_Comm_free(&mpi_addr->onesided_comm);
    }
    free(mpi_addr);

    return ret;
}

static int
na_mpi_open_port(void)
{
    char mpi_port_name[MPI_MAX_PORT_NAME];
    int my_rank;
    int mpi_ret;
    int ret = NA_SUCCESS;

    memset(na_mpi_port_name_g, '\0', MPI_MAX_PORT_NAME);

    MPI_Comm_rank(na_mpi_intra_comm_g, &my_rank);
    if (my_rank == 0) {
        mpi_ret = MPI_Open_port(MPI_INFO_NULL, mpi_port_name);
        if (mpi_ret != MPI_SUCCESS) {
            NA_ERROR_DEFAULT("MPI_Open_port failed");
            ret = NA_FAIL;
            goto done;
        }
    }
    MPI_Bcast(mpi_port_name, MPI_MAX_PORT_NAME, MPI_BYTE, 0, na_mpi_intra_comm_g);

    strcpy(na_mpi_port_name_g, mpi_port_name);

done:
    return ret;
}

static int
na_mpi_accept(void)
{
    MPI_Comm new_comm;
    MPI_Comm new_onesided_comm;
    struct na_mpi_addr *remote_addr;
    int ret = NA_SUCCESS;

    hg_thread_mutex_lock(&na_mpi_accept_mutex_g);

    if (na_mpi_use_static_intercomm_g) {
        int global_size, intra_size, mpi_ret;

        MPI_Comm_size(MPI_COMM_WORLD, &global_size);
        MPI_Comm_size(na_mpi_intra_comm_g, &intra_size);
        mpi_ret = MPI_Intercomm_create(na_mpi_intra_comm_g, 0, MPI_COMM_WORLD,
                global_size - (global_size - intra_size), 0, &new_comm);
        if (mpi_ret != MPI_SUCCESS) {
            NA_ERROR_DEFAULT("MPI_Intercomm_create failed");
            ret = NA_FAIL;
            goto done;
        }
    } else {
        int mpi_ret;

        mpi_ret = MPI_Comm_accept(na_mpi_port_name_g, MPI_INFO_NULL, 0,
            na_mpi_intra_comm_g, &new_comm);
        if (mpi_ret != MPI_SUCCESS) {
            NA_ERROR_DEFAULT("MPI_Comm_accept failed");
            ret = NA_FAIL;
            goto done;
        }
    }

    /* To be thread-safe and create a new context, dup the remote comm to a new comm */
    MPI_Comm_dup(new_comm, &new_onesided_comm);

    na_mpi_is_accepting_g = 0;
    hg_thread_cond_signal(&na_mpi_accept_cond_g);
    hg_thread_mutex_unlock(&na_mpi_accept_mutex_g);

    remote_addr = (struct na_mpi_addr *) malloc(sizeof(struct na_mpi_addr));
    if (!remote_addr) {
        NA_ERROR_DEFAULT("Could not allocate remote_addr");
        ret = NA_FAIL;
        goto done;
    }
    remote_addr->comm = new_comm;
    remote_addr->onesided_comm = new_onesided_comm;
    remote_addr->rank = MPI_ANY_SOURCE;
    remote_addr->is_unexpected = 0;
    memset(remote_addr->port_name, '\0', MPI_MAX_PORT_NAME);

    /* Add comms to list of connected remotes */
    hg_thread_mutex_lock(&na_mpi_remote_list_mutex_g);
    hg_list_append(&na_mpi_remote_list_g, (hg_list_value_t) remote_addr);
    hg_thread_mutex_unlock(&na_mpi_remote_list_mutex_g);

done:
    return ret;
}

static HG_THREAD_RETURN_TYPE
na_mpi_accept_service(void NA_UNUSED *args)
{
    hg_thread_ret_t ret = 0;
    int na_ret;

    na_ret = na_mpi_accept();
    if (na_ret != NA_SUCCESS) {
        NA_ERROR_DEFAULT("Could not accept connection");
    }

    return ret;
}

static HG_THREAD_RETURN_TYPE
na_mpi_progress_service(void NA_UNUSED *args)
{
    hg_thread_ret_t ret = 0;
    na_bool_t service_done = 0;

    while (!service_done) {
        int na_ret;

        hg_thread_mutex_lock(&na_mpi_finalize_mutex_g);
        service_done = (na_mpi_is_finalizing_g) ? 1 : 0;
        hg_thread_mutex_unlock(&na_mpi_finalize_mutex_g);

        na_ret = na_mpi_progress(0, NA_STATUS_IGNORE);
        if (na_ret != NA_SUCCESS) {
            NA_ERROR_DEFAULT("Could not make progress");
            break;
        }

        if (service_done) break;
    }

    return ret;
}

static int
na_mpi_remote_list_remove(struct na_mpi_addr *mpi_addr)
{
    int ret = NA_SUCCESS;
    hg_list_entry_t *entry = NULL;

    /* Process list of remotes */
    hg_thread_mutex_lock(&na_mpi_remote_list_mutex_g);

    /* Append handle to list if not found */
    entry = hg_list_find_data(na_mpi_remote_list_g, na_mpi_remote_list_equal,
            (hg_list_value_t)mpi_addr);
    if (entry) {
        if (!hg_list_remove_entry(&na_mpi_remote_list_g, entry)) {
            NA_ERROR_DEFAULT("Could not remove entry");
            ret = NA_FAIL;
        }
    }

    hg_thread_mutex_unlock(&na_mpi_remote_list_mutex_g);

    return ret;
}

static int
na_mpi_remote_comm_free(void)
{
    int ret = NA_SUCCESS;

    /* Process list of communicators */
    hg_thread_mutex_lock(&na_mpi_remote_list_mutex_g);

    if (hg_list_length(na_mpi_remote_list_g)) {
        hg_list_entry_t *entry = na_mpi_remote_list_g;

        while (entry) {
            hg_list_entry_t *next_entry = hg_list_next(entry);
            struct na_mpi_addr *mpi_addr = (struct na_mpi_addr*) hg_list_data(entry);

            na_mpi_addr_free_(mpi_addr);

            if (!hg_list_remove_entry(&na_mpi_remote_list_g, entry)) {
                NA_ERROR_DEFAULT("Could not remove entry");
                ret = NA_FAIL;
                goto done;
            }

            entry = next_entry;
        }
    }

 done:
    hg_thread_mutex_unlock(&na_mpi_remote_list_mutex_g);

    return ret;
}

static int
na_mpi_extract_port_name_info(const char *name, char *mpi_port_name, int *mpi_rank)
{
    char *port_string = NULL, *rank_string = NULL, *rank_value = NULL;
    int ret = NA_SUCCESS;

    port_string = strdup(name);

    /* Get mpi port name */
    port_string = strtok_r(port_string, ":", &rank_string);
    strcpy(mpi_port_name, port_string);

    /* Get rank info */
    if (strlen(rank_string)) {
        rank_string = strtok_r(rank_string, "$", &rank_value);
        rank_string = strtok_r(rank_string, "#", &rank_value);

        if (strcmp(rank_string, "rank") == 0) {
            if (mpi_rank) *mpi_rank = atoi(rank_value);
        } else {
            if (mpi_rank) *mpi_rank = 0;
        }
    }

    free(port_string);

    return ret;
}

/*---------------------------------------------------------------------------*/
static na_tag_t
na_mpi_gen_onesided_tag(void)
{
    static long int tag = NA_MPI_ONESIDED_TAG + 1;

    hg_thread_mutex_lock(&na_mpi_tag_mutex_g);
    tag++;
    if (tag == MPI_TAG_UB) tag = NA_MPI_ONESIDED_TAG + 1;
    hg_thread_mutex_unlock(&na_mpi_tag_mutex_g);

    return tag;
}

/*---------------------------------------------------------------------------*/
static na_bool_t
na_mpi_verify(const char NA_UNUSED *protocol)
{
    return NA_TRUE;
}

/*---------------------------------------------------------------------------*/
static na_class_t*
na_mpi_initialize(const struct na_host_buffer NA_UNUSED *na_buffer,
        na_bool_t listen)
{
    return NA_MPI_Init(NULL, listen);
}

/*---------------------------------------------------------------------------*/
na_class_t *
NA_MPI_Init(MPI_Comm *intra_comm, int flags)
{
    na_class_t *ret = NULL;
    int mpi_ret;

    /* Check flags */
    switch (flags) {
        case MPI_INIT_SERVER:
            na_mpi_is_server_g = 1;
            na_mpi_use_static_intercomm_g = 0;
            break;
        case MPI_INIT_SERVER_STATIC:
            na_mpi_is_server_g = 1;
            na_mpi_use_static_intercomm_g = 1;
            break;
        case MPI_INIT_STATIC:
            na_mpi_is_server_g = 0;
            na_mpi_use_static_intercomm_g = 1;
            break;
        default:
            break;
    }

    /* MPI_Init */
    mpi_ret = MPI_Initialized(&na_mpi_ext_initialized_g);
    if (mpi_ret != MPI_SUCCESS) {
        NA_ERROR_DEFAULT("MPI_Initialized failed");
        goto done;
    }

    if (!na_mpi_ext_initialized_g) {
        int provided;

        /* Need a MPI_THREAD_MULTIPLE level if onesided thread required */
        mpi_ret = MPI_Init_thread(NULL, NULL, MPI_THREAD_MULTIPLE, &provided);
        if (mpi_ret != MPI_SUCCESS) {
            NA_ERROR_DEFAULT("Could not initialize MPI");
            goto done;
        }
        if (provided != MPI_THREAD_MULTIPLE) {
            NA_ERROR_DEFAULT("MPI_THREAD_MULTIPLE cannot be set");
            goto done;
        }
    }

    /* Assign MPI intra comm */
    if (intra_comm || (!intra_comm && !na_mpi_use_static_intercomm_g)) {
        MPI_Comm comm = (intra_comm && (*intra_comm != MPI_COMM_NULL)) ?
                *intra_comm : MPI_COMM_WORLD;

        mpi_ret = MPI_Comm_dup(comm, &na_mpi_intra_comm_g);
        if (mpi_ret != MPI_SUCCESS) {
            NA_ERROR_DEFAULT("Could not duplicate communicator");
            goto done;
        }
    } else if (na_mpi_use_static_intercomm_g) {
        int color;
        int global_rank;

        MPI_Comm_rank(MPI_COMM_WORLD, &global_rank);
        /* Color is 1 for server, 2 for client */
        color = (na_mpi_is_server_g) ? 1 : 2;

        /* Assume that the application did not split MPI_COMM_WORLD already */
        mpi_ret = MPI_Comm_split(MPI_COMM_WORLD, color, global_rank, &na_mpi_intra_comm_g);
        if (mpi_ret != MPI_SUCCESS) {
            NA_ERROR_DEFAULT("Could not split communicator");
            goto done;
        }
    }

    /* Tag generation mutex */
    hg_thread_mutex_init(&na_mpi_tag_mutex_g);

    /* For na_mpi_wait() */
    hg_thread_cond_init(&na_mpi_test_cond_g);
    hg_thread_mutex_init(&na_mpi_test_mutex_g);

    /* To finalize service threads */
    hg_thread_mutex_init(&na_mpi_finalize_mutex_g);

    /* Accept service */
    hg_thread_cond_init(&na_mpi_accept_cond_g);
    hg_thread_mutex_init(&na_mpi_accept_mutex_g);
    hg_thread_mutex_init(&na_mpi_remote_list_mutex_g);

    /* Map mem addresses to mem handles */
    hg_thread_mutex_init(&na_mpi_mem_map_mutex_g);
    na_mpi_mem_handle_map_g = hg_hash_table_new(pointer_hash, pointer_equal);
    hg_hash_table_register_free_functions(na_mpi_mem_handle_map_g, NULL, NULL);

    /* If server opens a port */
    if (na_mpi_is_server_g) {
        if (na_mpi_use_static_intercomm_g) {
            /* Do not launch any thread, just accept */
            if (na_mpi_accept() != NA_SUCCESS) goto done;
        } else {
            if (na_mpi_open_port() != NA_SUCCESS) goto done;

            hg_thread_create(&na_mpi_accept_thread_g, na_mpi_accept_service, NULL);
        }
    }

    /* Start a progress thread for onesided communication emulation
     * TODO this will be removed from the plugin and left to the user*/
    hg_thread_create(&na_mpi_progress_thread_g,
            (hg_thread_func_t) &na_mpi_progress_service, NULL);

    ret = &na_mpi_g;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
const char *
NA_MPI_Get_port_name(na_class_t NA_UNUSED *network_class)
{
    int my_rank;
    MPI_Comm_rank(na_mpi_intra_comm_g, &my_rank);
    static char port_name[MPI_MAX_PORT_NAME];

    sprintf(port_name, "%s:rank#%d$", na_mpi_port_name_g, my_rank);
    /* Global variable for now but it should be part of the network class */
    return port_name;
}

/*---------------------------------------------------------------------------*/
static int
na_mpi_finalize(void)
{
    int mpi_ext_finalized, ret = NA_SUCCESS;

    /* Start shutting down */
    hg_thread_mutex_lock(&na_mpi_finalize_mutex_g);
    na_mpi_is_finalizing_g = 1;
    hg_thread_mutex_unlock(&na_mpi_finalize_mutex_g);

    /* If server opened a port */
    if (na_mpi_is_server_g && !na_mpi_use_static_intercomm_g) {
        /* No more connection accepted after this point */
        hg_thread_join(na_mpi_accept_thread_g);
    }

    /* Wait for one-sided thread to complete */
    hg_thread_join(na_mpi_progress_thread_g);

    /* Process list of communicators */
    na_mpi_remote_comm_free();

    /* If server opened a port */
    if (na_mpi_is_server_g && !na_mpi_use_static_intercomm_g) {
        /* Close port */
        MPI_Close_port(na_mpi_port_name_g);
    }

    /* Tag generation mutex */
    hg_thread_mutex_destroy(&na_mpi_tag_mutex_g);

    /* For na_mpi_wait() */
    hg_thread_cond_destroy(&na_mpi_test_cond_g);
    hg_thread_mutex_destroy(&na_mpi_test_mutex_g);

    /* To finalize service threads */
    hg_thread_mutex_destroy(&na_mpi_finalize_mutex_g);

    /* Accept service */
    hg_thread_cond_destroy(&na_mpi_accept_cond_g);
    hg_thread_mutex_destroy(&na_mpi_accept_mutex_g);
    hg_thread_mutex_destroy(&na_mpi_remote_list_mutex_g);

    /* Map mem addresses to mem handles */
    hg_hash_table_free(na_mpi_mem_handle_map_g);
    hg_thread_mutex_destroy(&na_mpi_mem_map_mutex_g);

    /* Free the private dup'ed comm */
    MPI_Comm_free(&na_mpi_intra_comm_g);

    /* MPI_Finalize */
    MPI_Finalized(&mpi_ext_finalized);
    if (mpi_ext_finalized) {
        NA_ERROR_DEFAULT("MPI already finalized");
        ret = NA_FAIL;
    }
    if (!na_mpi_ext_initialized_g && !mpi_ext_finalized) {
        MPI_Finalize();
    }

    return ret;
}

/*---------------------------------------------------------------------------*/
static int
na_mpi_addr_lookup(const char *name, na_addr_t *addr)
{
    int mpi_ret, ret = NA_SUCCESS;
    struct na_mpi_addr *mpi_addr = NULL;

    /* TODO Lookup addr list to see if we are already connected */

    /* Allocate the addr */
    mpi_addr = (struct na_mpi_addr*) malloc(sizeof(struct na_mpi_addr));
    if (!mpi_addr) {
        NA_ERROR_DEFAULT("Could not allocate addr");
        ret = NA_FAIL;
        return ret;
    }

    mpi_addr->comm = MPI_COMM_NULL;
    mpi_addr->onesided_comm = MPI_COMM_NULL;
    mpi_addr->is_unexpected = 0;
    memset(mpi_addr->port_name, '\0', MPI_MAX_PORT_NAME);
    /* get port_name and remote server rank */
    na_mpi_extract_port_name_info(name, mpi_addr->port_name, &mpi_addr->rank);

    /* Try to connect, must prevent concurrent threads to create new communicators */
    hg_thread_mutex_lock(&na_mpi_accept_mutex_g);

    if (na_mpi_is_server_g) {
        while (na_mpi_is_accepting_g) {
            hg_thread_cond_wait(&na_mpi_accept_cond_g, &na_mpi_accept_mutex_g);
        }
        mpi_ret = MPI_Comm_dup(na_mpi_intra_comm_g, &mpi_addr->comm);
    } else {
        if (na_mpi_use_static_intercomm_g) {
            mpi_ret = MPI_Intercomm_create(na_mpi_intra_comm_g, 0, MPI_COMM_WORLD,
                    0, 0, &mpi_addr->comm);
        } else {
            mpi_ret = MPI_Comm_connect(mpi_addr->port_name, MPI_INFO_NULL, 0,
                    na_mpi_intra_comm_g, &mpi_addr->comm);
        }
        if (mpi_ret != MPI_SUCCESS) {
            NA_ERROR_DEFAULT("Could not connect");
            ret = NA_FAIL;
            goto done;
        }
    }

    /* To be thread-safe and create a new context, dup the remote comm to a new comm */
    MPI_Comm_dup(mpi_addr->comm, &mpi_addr->onesided_comm);

    hg_thread_mutex_unlock(&na_mpi_accept_mutex_g);

    /* Add addr to list of addresses */
    hg_thread_mutex_lock(&na_mpi_remote_list_mutex_g);
    hg_list_append(&na_mpi_remote_list_g, (hg_list_value_t) mpi_addr);
    hg_thread_mutex_unlock(&na_mpi_remote_list_mutex_g);

    if (addr) *addr = (na_addr_t) mpi_addr;

done:
    if (ret != NA_SUCCESS) {
        free(mpi_addr);
    }

    return ret;
}

/*---------------------------------------------------------------------------*/
static int
na_mpi_addr_free(na_addr_t addr)
{
    struct na_mpi_addr *mpi_addr = (struct na_mpi_addr*) addr;
    int ret = NA_SUCCESS;

    if (!mpi_addr) {
        NA_ERROR_DEFAULT("Already freed");
        ret = NA_FAIL;
        return ret;
    }

    /* Remove addr from list of addresses */
    na_mpi_remote_list_remove(mpi_addr);

    /* Free addr */
    na_mpi_addr_free_(mpi_addr);
    mpi_addr = NULL;

    return ret;
}

/*---------------------------------------------------------------------------*/
static int
na_mpi_addr_to_string(char *buf, na_size_t buf_size, na_addr_t addr)
{
    struct na_mpi_addr *mpi_addr = NULL;
    int ret = NA_SUCCESS;

    mpi_addr = (struct na_mpi_addr*) addr;

    if (strlen(mpi_addr->port_name) > buf_size) {
        NA_ERROR_DEFAULT("Buffer size too small to copy addr");
        ret = NA_FAIL;
        return ret;
    }

    strcpy(buf, mpi_addr->port_name);

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
na_mpi_msg_recv_unexpected_class(void *buf, na_size_t buf_size,
        na_bool_t do_onesided_progress, na_size_t *actual_buf_size,
        na_addr_t *source, na_tag_t *tag, na_request_t *request,
        void NA_UNUSED *op_arg)
{
    int mpi_ret, ret = NA_SUCCESS;
    MPI_Status mpi_status;
    int flag = 0;
    int mpi_buf_size, mpi_source, mpi_tag;
    MPI_Comm probe_comm;
    struct na_mpi_req *mpi_request = NULL;
    struct na_mpi_addr *unexpected_addr = NULL;
    struct na_mpi_addr *remote_addr_any = NULL;

    if (!buf) {
        NA_ERROR_DEFAULT("NULL buffer");
        ret = NA_FAIL;
        goto done;
    }

    /* Process list of communicators */
    hg_thread_mutex_lock(&na_mpi_remote_list_mutex_g);

    if (hg_list_length(na_mpi_remote_list_g)) {
        hg_list_entry_t *entry = na_mpi_remote_list_g;

        while (entry) {
            hg_list_entry_t *next_entry = hg_list_next(entry);

            remote_addr_any = (struct na_mpi_addr*) hg_list_data(entry);

            probe_comm = do_onesided_progress ? remote_addr_any->onesided_comm :
                    remote_addr_any->comm;

            mpi_ret = MPI_Iprobe(MPI_ANY_SOURCE, MPI_ANY_TAG, probe_comm,
                    &flag, &mpi_status);
            if (mpi_ret != MPI_SUCCESS) {
                NA_ERROR_DEFAULT("MPI_Iprobe() failed");
                ret = NA_FAIL;
                break;
            }

            if (flag) break;

            entry = next_entry;
        }
    }

    hg_thread_mutex_unlock(&na_mpi_remote_list_mutex_g);

    if (!remote_addr_any || !flag) goto done;

    MPI_Get_count(&mpi_status, MPI_BYTE, &mpi_buf_size);
    if (mpi_buf_size > (int) buf_size) {
        NA_ERROR_DEFAULT("Buffer too small to recv unexpected data");
        ret = NA_FAIL;
        goto done;
    }

    mpi_source = mpi_status.MPI_SOURCE;
    mpi_tag = mpi_status.MPI_TAG;

    mpi_request = (struct na_mpi_req*) malloc(sizeof(struct na_mpi_req));
    if (!mpi_request) {
        NA_ERROR_DEFAULT("Could not allocate request");
        ret = NA_FAIL;
        goto done;
    }

    mpi_request->type = MPI_RECV_OP;
    mpi_request->data_request = MPI_REQUEST_NULL;

    mpi_ret = MPI_Irecv(buf, mpi_buf_size, MPI_BYTE, mpi_source,
            mpi_tag, probe_comm, &mpi_request->request);
    if (mpi_ret != MPI_SUCCESS) {
        NA_ERROR_DEFAULT("MPI_Irecv() failed");
        ret = NA_FAIL;
        goto done;
    }

    /* Fill info */
    if (actual_buf_size) *actual_buf_size = (na_size_t) mpi_buf_size;
    if (source) {
        unexpected_addr = (struct na_mpi_addr*) malloc(sizeof(struct na_mpi_addr));
        if (!unexpected_addr) {
            NA_ERROR_DEFAULT("Could not allocate peer addr");
            ret = NA_FAIL;
            goto done;
        }

        unexpected_addr->comm = remote_addr_any->comm;
        unexpected_addr->onesided_comm = remote_addr_any->onesided_comm;
        unexpected_addr->rank = mpi_source;
        unexpected_addr->is_unexpected = 1;
        memset(unexpected_addr->port_name, '\0', MPI_MAX_PORT_NAME);
        /* Can only write debug info here */
        sprintf(unexpected_addr->port_name, "comm: %d rank:%d\n",
                (int) unexpected_addr->comm, unexpected_addr->rank);

        *((struct na_mpi_addr**) source) = unexpected_addr;
    }
    if (tag) *tag = mpi_tag;
    *request = (na_request_t) mpi_request;

done:
    if (ret != NA_SUCCESS) {
        free(mpi_request);
        free(unexpected_addr);
    }
    return ret;
}

static int
na_mpi_msg_recv_unexpected(void *buf, na_size_t buf_size, na_size_t *actual_buf_size,
        na_addr_t *source, na_tag_t *tag, na_request_t *request, void *op_arg)
{
    return na_mpi_msg_recv_unexpected_class(buf, buf_size, 0, actual_buf_size,
            source, tag, request, op_arg);
}

/*---------------------------------------------------------------------------*/
static int
na_mpi_msg_send(const void *buf, na_size_t buf_size, na_addr_t dest,
        na_tag_t tag, na_request_t *request, void NA_UNUSED *op_arg)
{
    int mpi_ret, ret = NA_SUCCESS;
    const void *mpi_buf = buf;
    int mpi_buf_size = (int) buf_size;
    int mpi_tag = (int) tag;
    struct na_mpi_addr *mpi_addr = (struct na_mpi_addr*) dest;
    struct na_mpi_req *mpi_request;

    mpi_request = (struct na_mpi_req*) malloc(sizeof(struct na_mpi_req));
    if (!mpi_request) {
        NA_ERROR_DEFAULT("Could not allocate request");
        ret = NA_FAIL;
        return ret;
    }
    mpi_request->type = MPI_SEND_OP;
    mpi_request->data_request = MPI_REQUEST_NULL;

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
    struct na_mpi_addr *mpi_addr = (struct na_mpi_addr*) source;
    struct na_mpi_req *mpi_request;

    mpi_request = (struct na_mpi_req*) malloc(sizeof(struct na_mpi_req));
    if (!mpi_request) {
        NA_ERROR_DEFAULT("Could not allocate request");
        ret = NA_FAIL;
        return ret;
    }
    mpi_request->type = MPI_RECV_OP;
    mpi_request->data_request = MPI_REQUEST_NULL;

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
    struct na_mpi_mem_handle *mpi_mem_handle;
    /* MPI_Aint mpi_buf_size = (MPI_Aint) buf_size; */

    mpi_mem_handle = (struct na_mpi_mem_handle*)
            malloc(sizeof(struct na_mpi_mem_handle));
    if (!mpi_mem_handle) {
        NA_ERROR_DEFAULT("Could not allocate memory handle");
        ret = NA_FAIL;
        return ret;
    }
    mpi_mem_handle->base = mpi_buf_base;
    /* mpi_mem_handle->size = mpi_buf_size; */
    mpi_mem_handle->attr = flags;

    *mem_handle = (na_mem_handle_t) mpi_mem_handle;

    hg_thread_mutex_lock(&na_mpi_mem_map_mutex_g);
    /* store this handle */
    if (!hg_hash_table_insert(na_mpi_mem_handle_map_g,
            mpi_mem_handle->base, mpi_mem_handle)) {
        NA_ERROR_DEFAULT("Could not register memory handle");
        ret = NA_FAIL;
    }
    hg_thread_mutex_unlock(&na_mpi_mem_map_mutex_g);

    return ret;
}

/*---------------------------------------------------------------------------*/
static int
na_mpi_mem_deregister(na_mem_handle_t mem_handle)
{
    int ret = NA_SUCCESS;
    struct na_mpi_mem_handle *mpi_mem_handle = (struct na_mpi_mem_handle*) mem_handle;

    hg_thread_mutex_lock(&na_mpi_mem_map_mutex_g);
    /* remove the handle */
    if (!hg_hash_table_remove(na_mpi_mem_handle_map_g, mpi_mem_handle->base)) {
        NA_ERROR_DEFAULT("Could not deregister memory handle");
        ret = NA_FAIL;
    }
    hg_thread_mutex_unlock(&na_mpi_mem_map_mutex_g);

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
    return sizeof(struct na_mpi_mem_handle);
}

/*---------------------------------------------------------------------------*/
static int
na_mpi_mem_handle_serialize(void *buf, na_size_t buf_size,
        na_mem_handle_t mem_handle)
{
    int ret = NA_SUCCESS;
    struct na_mpi_mem_handle *mpi_mem_handle = (struct na_mpi_mem_handle*) mem_handle;

    if (buf_size < sizeof(struct na_mpi_mem_handle)) {
        NA_ERROR_DEFAULT("Buffer size too small for serializing parameter");
        ret = NA_FAIL;
    } else {
        /* Here safe to do a simple memcpy */
        memcpy(buf, mpi_mem_handle, sizeof(struct na_mpi_mem_handle));
    }
    return ret;
}

/*---------------------------------------------------------------------------*/
static int
na_mpi_mem_handle_deserialize(na_mem_handle_t *mem_handle,
        const void *buf, na_size_t buf_size)
{
    int ret = NA_SUCCESS;
    struct na_mpi_mem_handle *mpi_mem_handle;

    if (buf_size < sizeof(struct na_mpi_mem_handle)) {
        NA_ERROR_DEFAULT("Buffer size too small for deserializing parameter");
        ret = NA_FAIL;
        return ret;
    }

    mpi_mem_handle = (struct na_mpi_mem_handle*) malloc(sizeof(struct na_mpi_mem_handle));
    if (!mpi_mem_handle) {
        NA_ERROR_DEFAULT("Could not allocate memory handle");
        ret = NA_FAIL;
        return ret;
    }

    /* Here safe to do a simple memcpy */
    memcpy(mpi_mem_handle, buf, sizeof(struct na_mpi_mem_handle));
    *mem_handle = (na_mem_handle_t) mpi_mem_handle;

    return ret;
}

/*---------------------------------------------------------------------------*/
static int
na_mpi_mem_handle_free(na_mem_handle_t mem_handle)
{
    int ret = NA_SUCCESS;
    struct na_mpi_mem_handle *mpi_mem_handle = (struct na_mpi_mem_handle*) mem_handle;

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
    struct na_mpi_mem_handle *mpi_local_mem_handle = (struct na_mpi_mem_handle*) local_mem_handle;
    MPI_Aint mpi_local_offset = (MPI_Aint) local_offset;
    struct na_mpi_mem_handle *mpi_remote_mem_handle = (struct na_mpi_mem_handle*) remote_mem_handle;
    MPI_Aint mpi_remote_offset = (MPI_Aint) remote_offset;
    int mpi_length = (int) length; /* TODO careful here that we don't send more than 2GB */
    struct na_mpi_addr *mpi_remote_addr = (struct na_mpi_addr*) remote_addr;
    struct na_mpi_req *mpi_request = NULL;

    struct na_mpi_onesided_info onesided_info;

    /* Check that local memory is registered */
    if (!hg_hash_table_lookup(na_mpi_mem_handle_map_g, mpi_local_mem_handle->base)) {
        NA_ERROR_DEFAULT("Could not find memory handle, registered?");
        ret = NA_FAIL;
        return ret;
    }

    if (mpi_remote_mem_handle->attr != NA_MEM_READWRITE) {
        NA_ERROR_DEFAULT("Registered memory requires write permission");
        ret = NA_FAIL;
        return ret;
    }

    mpi_request = (struct na_mpi_req*) malloc(sizeof(struct na_mpi_req));
    if (!mpi_request) {
        NA_ERROR_DEFAULT("Could not allocate request");
        ret = NA_FAIL;
        return ret;
    }
    mpi_request->type = MPI_SEND_OP;
    mpi_request->request = MPI_REQUEST_NULL;
    mpi_request->data_request = MPI_REQUEST_NULL;

    /* Send to one-sided thread key to access mem_handle */
    onesided_info.base = mpi_remote_mem_handle->base;
    onesided_info.disp = mpi_remote_offset;
    onesided_info.count = mpi_length;
    onesided_info.op = MPI_ONESIDED_PUT;
    onesided_info.tag = na_mpi_gen_onesided_tag();

    MPI_Isend(&onesided_info, sizeof(struct na_mpi_onesided_info), MPI_BYTE,
            mpi_remote_addr->rank, NA_MPI_ONESIDED_TAG,
            mpi_remote_addr->onesided_comm, &mpi_request->request);

    /* Simply do a non blocking synchronous send */
    mpi_ret = MPI_Issend((char*) mpi_local_mem_handle->base + mpi_local_offset,
            mpi_length, MPI_BYTE, mpi_remote_addr->rank, onesided_info.tag,
            mpi_remote_addr->onesided_comm, &mpi_request->data_request);
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
na_mpi_get(na_mem_handle_t local_mem_handle, na_offset_t local_offset,
        na_mem_handle_t remote_mem_handle, na_offset_t remote_offset,
        na_size_t length, na_addr_t remote_addr, na_request_t *request)
{
    int mpi_ret, ret = NA_SUCCESS;
    struct na_mpi_mem_handle *mpi_local_mem_handle = (struct na_mpi_mem_handle*) local_mem_handle;
    MPI_Aint mpi_local_offset = (MPI_Aint) local_offset;
    struct na_mpi_mem_handle *mpi_remote_mem_handle = (struct na_mpi_mem_handle*) remote_mem_handle;
    MPI_Aint mpi_remote_offset = (MPI_Aint) remote_offset;
    int mpi_length = (int) length; /* TODO careful here that we don't send more than 2GB */
    struct na_mpi_addr *mpi_remote_addr = (struct na_mpi_addr*) remote_addr;
    struct na_mpi_req *mpi_request = NULL;

    struct na_mpi_onesided_info onesided_info;

    /* Check that local memory is registered */
    if (!hg_hash_table_lookup(na_mpi_mem_handle_map_g, mpi_local_mem_handle->base)) {
        NA_ERROR_DEFAULT("Could not find memory handle, registered?");
        ret = NA_FAIL;
        return ret;
    }

    mpi_request = (struct na_mpi_req*) malloc(sizeof(struct na_mpi_req));
    if (!mpi_request) {
        NA_ERROR_DEFAULT("Could not allocate request");
        ret = NA_FAIL;
        return ret;
    }
    mpi_request->type = MPI_RECV_OP;
    mpi_request->request = MPI_REQUEST_NULL;
    mpi_request->data_request = MPI_REQUEST_NULL;

    /* Send to one-sided thread key to access mem_handle */
    onesided_info.base = mpi_remote_mem_handle->base;
    onesided_info.disp = mpi_remote_offset;
    onesided_info.count = mpi_length;
    onesided_info.op = MPI_ONESIDED_GET;
    onesided_info.tag = na_mpi_gen_onesided_tag();

    MPI_Isend(&onesided_info, sizeof(struct na_mpi_onesided_info), MPI_BYTE,
            mpi_remote_addr->rank, NA_MPI_ONESIDED_TAG,
            mpi_remote_addr->onesided_comm, &mpi_request->request);

    /* Simply do an asynchronous recv */
    mpi_ret = MPI_Irecv((char*) mpi_local_mem_handle->base + mpi_local_offset,
            mpi_length, MPI_BYTE, mpi_remote_addr->rank, onesided_info.tag,
            mpi_remote_addr->onesided_comm, &mpi_request->data_request);
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
na_mpi_wait(na_request_t request, unsigned int timeout, na_status_t *status)
{
    int mpi_ret, ret = NA_SUCCESS;
    struct na_mpi_req *mpi_request = (struct na_mpi_req*) request;
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

        hg_thread_mutex_lock(&na_mpi_test_mutex_g);
        while (na_mpi_is_testing_g) {
            /*
            hg_thread_cond_ret = hg_thread_cond_timedwait(&testcontext_cond,
                    &testcontext_mutex, remaining);
             */
            hg_thread_cond_ret = hg_thread_cond_wait(&na_mpi_test_cond_g,
                    &na_mpi_test_mutex_g);
        }
        na_mpi_is_testing_g = 1;
        hg_thread_mutex_unlock(&na_mpi_test_mutex_g);

        if (hg_thread_cond_ret < 0) {
            NA_ERROR_DEFAULT("hg_thread_cond_timedwait failed");
            ret = NA_FAIL;
            break;
        }

        hg_thread_mutex_lock(&na_mpi_test_mutex_g);
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

        na_mpi_is_testing_g = 0;
        hg_thread_cond_signal(&na_mpi_test_cond_g);
        hg_thread_mutex_unlock(&na_mpi_test_mutex_g);

        hg_time_get_current(&t2);
        remaining -= hg_time_to_double(hg_time_subtract(t2, t1));

    } while (( (mpi_request->request != MPI_REQUEST_NULL) ||
               (mpi_request->data_request != MPI_REQUEST_NULL)
             ) && remaining > 0);

    /* If the request has not completed return */
    if ( (mpi_request->request != MPI_REQUEST_NULL) ||
         (mpi_request->data_request != MPI_REQUEST_NULL)
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
static int
na_mpi_progress(unsigned int timeout, na_status_t *status)
{
    double time_remaining = timeout / 1000; /* Timeout in milliseconds */
    int ret = NA_SUCCESS;
    int mpi_ret;

    /* TODO progress will be better handled with callbacks */
    static struct na_mpi_onesided_info onesided_info;
    static na_size_t onesided_actual_size = 0;
    static na_addr_t remote_addr = NA_ADDR_NULL;
    static na_tag_t remote_tag = 0;
    static na_request_t onesided_request = NA_REQUEST_NULL;
    struct na_mpi_addr *mpi_addr;
    na_status_t onesided_status;
    struct na_mpi_mem_handle *mpi_mem_handle = NULL;

    /* Wait for an initial request from client */
    if (onesided_request == NA_REQUEST_NULL) {
        do {
            hg_time_t t1, t2;

            onesided_actual_size = 0;
            remote_addr = NA_ADDR_NULL;
            remote_tag = 0;

            hg_time_get_current(&t1);

            ret = na_mpi_msg_recv_unexpected_class(&onesided_info,
                    sizeof(struct na_mpi_onesided_info), 1, &onesided_actual_size,
                    &remote_addr, &remote_tag, &onesided_request, NULL);
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
    hg_thread_mutex_lock(&na_mpi_mem_map_mutex_g);

    mpi_mem_handle = (struct na_mpi_mem_handle*)
            hg_hash_table_lookup(na_mpi_mem_handle_map_g, onesided_info.base);

    if (!mpi_mem_handle) {
        NA_ERROR_DEFAULT("Could not find memory handle, registered?");
        hg_thread_mutex_unlock(&na_mpi_mem_map_mutex_g);
        ret = NA_FAIL;
        return ret;
    }

    mpi_addr = (struct na_mpi_addr*) remote_addr;

    switch (onesided_info.op) {
        /* Remote wants to do a put so wait in a recv */
        case MPI_ONESIDED_PUT:
            mpi_ret = MPI_Recv((char*) mpi_mem_handle->base + onesided_info.disp,
                    onesided_info.count, MPI_BYTE, mpi_addr->rank,
                    onesided_info.tag, mpi_addr->onesided_comm, MPI_STATUS_IGNORE);
            if (mpi_ret != MPI_SUCCESS) {
                NA_ERROR_DEFAULT("Could not recv data");
                ret = NA_FAIL;
            }
            break;

            /* Remote wants to do a get so do a send */
        case MPI_ONESIDED_GET:
            mpi_ret = MPI_Send((char*) mpi_mem_handle->base + onesided_info.disp,
                    onesided_info.count, MPI_BYTE, mpi_addr->rank,
                    onesided_info.tag, mpi_addr->onesided_comm);
            if (mpi_ret != MPI_SUCCESS) {
                NA_ERROR_DEFAULT("Could not send data");
                ret = NA_FAIL;
            }
            break;

        default:
            NA_ERROR_DEFAULT("Operation not supported");
            break;
    }

    hg_thread_mutex_unlock(&na_mpi_mem_map_mutex_g);

    if (status && status != NA_STATUS_IGNORE) {
        status->completed = 1;
        status->count = onesided_info.count;
    }
    na_mpi_addr_free(remote_addr);
    remote_addr = NA_ADDR_NULL;

    return ret;
}

/*---------------------------------------------------------------------------*/
static int
na_mpi_request_free(na_request_t request)
{
    struct na_mpi_req *mpi_request = (struct na_mpi_req*) request;
    int ret = NA_SUCCESS;

    /* Do not want to free the request if another thread is testing it */
    hg_thread_mutex_lock(&na_mpi_test_mutex_g);

    if (!mpi_request) {
        NA_ERROR_DEFAULT("NULL request");
        ret = NA_FAIL;
        goto done;
    }

    if (mpi_request->request != MPI_REQUEST_NULL) {
        MPI_Request_free(&mpi_request->request);
    }
    if (mpi_request->data_request != MPI_REQUEST_NULL) {
        MPI_Request_free(&mpi_request->data_request);
    }
    free(mpi_request);
    mpi_request = NULL;

done:
    hg_thread_mutex_unlock(&na_mpi_test_mutex_g);

    return ret;
}
