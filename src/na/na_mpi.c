/*
 * Copyright (C) 2013-2014 Argonne National Laboratory, Department of Energy,
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

#include "mercury_list.h"
#include "mercury_queue.h"
#include "mercury_thread.h"
#include "mercury_thread_mutex.h"
#include "mercury_thread_condition.h"
#include "mercury_time.h"
#include "mercury_atomic.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef NA_MPI_HAS_GNI_SETUP
#include <gni_pub.h>
#endif

/****************/
/* Local Macros */
/****************/

/* MPI initialization flags */
#define MPI_INIT_SERVER 0x01 /* set up to listen for unexpected messages */
#define MPI_INIT_STATIC 0x10 /* set up static inter-communicator */

/* Msg sizes */
#define NA_MPI_UNEXPECTED_SIZE 4096
#define NA_MPI_EXPECTED_SIZE   NA_MPI_UNEXPECTED_SIZE

/* Max tag */
#define NA_MPI_MAX_TAG (MPI_TAG_UB >> 2)

/* Default tag used for one-sided over two-sided */
#define NA_MPI_RMA_REQUEST_TAG (NA_MPI_MAX_TAG + 1)
#define NA_MPI_RMA_TAG (NA_MPI_RMA_REQUEST_TAG + 1)
#define NA_MPI_MAX_RMA_TAG (MPI_TAG_UB >> 1)

#define NA_MPI_PRIVATE_DATA(na_class) \
    ((struct na_mpi_private_data *)(na_class->private_data))

#ifdef _WIN32
#  define strtok_r strtok_s
#endif

/************************************/
/* Local Type and Struct Definition */
/************************************/

/* na_mpi_addr */
struct na_mpi_addr {
    MPI_Comm  comm;              /* Communicator */
    MPI_Comm  rma_comm;          /* Communicator used for one sided emulation */
    int       rank;              /* Rank in this communicator */
    na_bool_t unexpected;        /* Address generated from unexpected recv */
    na_bool_t self;              /* Boolean for self */
    na_bool_t dynamic;           /* Address generated using MPI DPM routines */
    char      port_name[MPI_MAX_PORT_NAME]; /* String version of addr */
};

/* na_mpi_mem_handle */
struct na_mpi_mem_handle {
    na_ptr_t base;     /* Initial address of memory */
    MPI_Aint size;    /* Size of memory */
    na_uint8_t attr;   /* Flag of operation access */
};

/* na_mpi_rma_op */
typedef enum na_mpi_rma_op {
    NA_MPI_RMA_PUT,       /* Request a put operation */
    NA_MPI_RMA_GET        /* Request a get operation */
} na_mpi_rma_op_t;

/* na_mpi_rma_info */
struct na_mpi_rma_info {
    na_mpi_rma_op_t op; /* Operation requested */
    na_ptr_t base;      /* Initial address of memory */
    MPI_Aint disp;      /* Offset from initial address */
    int      count;     /* Number of entries */
    na_tag_t tag;       /* Tag used for the data transfer */
};

/* na_mpi_info_lookup */
struct na_mpi_info_lookup {
    na_addr_t addr;
};

/* na_mpi_info_send_unexpected */
struct na_mpi_info_send_unexpected {
    MPI_Request data_request;
};

/* na_mpi_info_recv_unexpected */
struct na_mpi_info_recv_unexpected {
    void *buf;
    int buf_size;
    struct na_mpi_addr *remote_addr;
    MPI_Status status;
};

/* na_mpi_info_send_expected */
struct na_mpi_info_send_expected {
    MPI_Request data_request;
};

/* na_mpi_info_recv_expected */
struct na_mpi_info_recv_expected {
    MPI_Request data_request;
    int buf_size;
    int actual_size;
    MPI_Status status;
};

/* na_mpi_info_put */
struct na_mpi_info_put {
    MPI_Request rma_request;
    MPI_Request data_request;
    struct na_mpi_rma_info *rma_info;
    na_bool_t internal_progress; /* Used for internal RMA emulation */
};

/* na_mpi_info_get */
struct na_mpi_info_get {
    MPI_Request rma_request;
    MPI_Request data_request;
    struct na_mpi_rma_info *rma_info;
    na_bool_t internal_progress; /* Used for internal RMA emulation */
};

struct na_mpi_op_id {
    na_context_t *context;
    na_cb_type_t type;
    na_cb_t callback; /* Callback */
    void *arg;
    na_bool_t completed; /* Operation completed */
    union {
      struct na_mpi_info_lookup lookup;
      struct na_mpi_info_send_unexpected send_unexpected;
      struct na_mpi_info_recv_unexpected recv_unexpected;
      struct na_mpi_info_send_expected send_expected;
      struct na_mpi_info_recv_expected recv_expected;
      struct na_mpi_info_put put;
      struct na_mpi_info_get get;
    } info;
};

struct na_mpi_private_data {
    na_bool_t listening;                    /* Used in server mode */
    na_bool_t mpi_ext_initialized;          /* MPI externally initialized */
    na_bool_t use_static_inter_comm;         /* Use static inter-communicator */
    char port_name[MPI_MAX_PORT_NAME];      /* Server local port name used for
                                               dynamic connection */
    MPI_Comm intra_comm;                    /* MPI intra-communicator */

    hg_thread_t        accept_thread; /* Thread for accepting new connections */
    hg_thread_mutex_t  accept_mutex;  /* Mutex */
    hg_thread_cond_t   accept_cond;   /* Cond */
    na_bool_t          accepting;     /* Is in MPI_Comm_accept */

    hg_list_entry_t   *remote_list;       /* List of connected remotes */
    hg_thread_mutex_t  remote_list_mutex; /* Mutex */

    hg_queue_t        *unexpected_op_queue;        /* Unexpected op queue */
    hg_thread_mutex_t  unexpected_op_queue_mutex;  /* Mutex */

    hg_atomic_int32_t  rma_tag;              /* Atomic RMA tag value */

    hg_list_entry_t   *op_id_list;        /* List of na_mpi_op_ids */
    hg_thread_mutex_t  op_id_list_mutex;  /* Mutex */
};

/********************/
/* Local Prototypes */
/********************/

/* accept_service */
static HG_THREAD_RETURN_TYPE
na_mpi_accept_service(
        void *args
        );

/* open_port */
static na_return_t
na_mpi_open_port(
        na_class_t *na_class
        );

/* get_port_info */
static na_return_t
na_mpi_get_port_info(
        const char *name,
        char       *mpi_port_name,
        int        *mpi_rank);

/* accept */
static na_return_t
na_mpi_accept(
        na_class_t *na_class
        );

/* disconnect */
static na_return_t
na_mpi_disconnect(
        na_class_t         *na_class,
        struct na_mpi_addr *na_mpi_addr
        );

/* remote_list_append */
static na_return_t
na_mpi_remote_list_append(
        na_class_t         *na_class,
        struct na_mpi_addr *na_mpi_addr
        );

/* remote_list_remove */
static na_return_t
na_mpi_remote_list_remove(
        na_class_t         *na_class,
        struct na_mpi_addr *na_mpi_addr
        );

/* remote_list_disconnect */
static na_return_t
na_mpi_remote_list_disconnect(
        na_class_t *na_class
        );

/* op_id_list_add */
static na_return_t
na_mpi_op_id_list_append(
        na_class_t          *na_class,
        struct na_mpi_op_id *na_mpi_op_id
        );

/* msg_unexpected_op_push */
static na_return_t
na_mpi_msg_unexpected_op_push(
        na_class_t          *na_class,
        struct na_mpi_op_id *na_mpi_op_id
        );

/* msg_unexpected_op_pop */
static struct na_mpi_op_id *
na_mpi_msg_unexpected_op_pop(
        na_class_t *na_class
        );

/* gen_rma_tag */
static NA_INLINE na_tag_t
na_mpi_gen_rma_tag(
        na_class_t *na_class
        );

/* verify */
static na_bool_t
na_mpi_check_protocol(
        const char *protocol_name
        );

/* initialize */
static na_return_t
na_mpi_initialize(
        na_class_t *na_class,
        const struct na_info *na_info,
        na_bool_t listen
        );

/* finalize */
static na_return_t
na_mpi_finalize(
        na_class_t *na_class
        );

/* addr_lookup */
static na_return_t
na_mpi_addr_lookup(
        na_class_t   *na_class,
        na_context_t *context,
        na_cb_t       callback,
        void         *arg,
        const char   *name,
        na_op_id_t   *op_id
        );

/* addr_self */
static na_return_t
na_mpi_addr_self(
        na_class_t *na_class,
        na_addr_t  *addr
        );

/* addr_free */
static na_return_t
na_mpi_addr_free(
        na_class_t *na_class,
        na_addr_t   addr
        );

/* addr_is_self */
static na_bool_t
na_mpi_addr_is_self(
        na_class_t *na_class,
        na_addr_t   addr
        );

/* addr_to_string */
static na_return_t
na_mpi_addr_to_string(
        na_class_t *na_class,
        char       *buf,
        na_size_t   buf_size,
        na_addr_t   addr
        );

/* msg_get_max */
static na_size_t
na_mpi_msg_get_max_expected_size(
        na_class_t *na_class
        );

static na_size_t
na_mpi_msg_get_max_unexpected_size(
        na_class_t *na_class
        );

static na_tag_t
na_mpi_msg_get_max_tag(
        na_class_t *na_class
        );

/* msg_send_unexpected */
static na_return_t
na_mpi_msg_send_unexpected(
        na_class_t   *na_class,
        na_context_t *context,
        na_cb_t       callback,
        void         *arg,
        const void   *buf,
        na_size_t     buf_size,
        na_addr_t     dest,
        na_tag_t      tag,
        na_op_id_t   *op_id
        );

/* msg_recv_unexpected */
static na_return_t
na_mpi_msg_recv_unexpected(
        na_class_t   *na_class,
        na_context_t *context,
        na_cb_t       callback,
        void         *arg,
        void         *buf,
        na_size_t     buf_size,
        na_op_id_t   *op_id
        );

/* msg_send_expected */
static na_return_t
na_mpi_msg_send_expected(
        na_class_t   *na_class,
        na_context_t *context,
        na_cb_t       callback,
        void         *arg,
        const void   *buf,
        na_size_t     buf_size,
        na_addr_t     dest,
        na_tag_t      tag,
        na_op_id_t   *op_id
        );

/* msg_recv_expected */
static na_return_t
na_mpi_msg_recv_expected(
        na_class_t   *na_class,
        na_context_t *context,
        na_cb_t       callback,
        void         *arg,
        void         *buf,
        na_size_t     buf_size,
        na_addr_t     source,
        na_tag_t      tag,
        na_op_id_t   *op_id
        );

/* mem_handle */
static na_return_t
na_mpi_mem_handle_create(
        na_class_t      *na_class,
        void            *buf,
        na_size_t        buf_size,
        unsigned long    flags,
        na_mem_handle_t *mem_handle
        );

static na_return_t
na_mpi_mem_handle_free(
        na_class_t      *na_class,
        na_mem_handle_t  mem_handle
        );

static na_return_t
na_mpi_mem_register(
        na_class_t      *na_class,
        na_mem_handle_t  mem_handle
        );

static na_return_t
na_mpi_mem_deregister(
        na_class_t      *na_class,
        na_mem_handle_t  mem_handle
        );

/* mem_handle serialization */
static na_size_t
na_mpi_mem_handle_get_serialize_size(
        na_class_t      *na_class,
        na_mem_handle_t  mem_handle
        );

static na_return_t
na_mpi_mem_handle_serialize(
        na_class_t      *na_class,
        void            *buf,
        na_size_t        buf_size,
        na_mem_handle_t  mem_handle
        );

static na_return_t
na_mpi_mem_handle_deserialize(
        na_class_t      *na_class,
        na_mem_handle_t *mem_handle,
        const void      *buf,
        na_size_t        buf_size
        );

/* put */
static na_return_t
na_mpi_put(
        na_class_t      *na_class,
        na_context_t    *context,
        na_cb_t          callback,
        void            *arg,
        na_mem_handle_t local_mem_handle,
        na_offset_t     local_offset,
        na_mem_handle_t remote_mem_handle,
        na_offset_t     remote_offset,
        na_size_t       length,
        na_addr_t       remote_addr,
        na_op_id_t     *op_id
        );

/* get */
static na_return_t
na_mpi_get(
        na_class_t      *na_class,
        na_context_t    *context,
        na_cb_t          callback,
        void            *arg,
        na_mem_handle_t  local_mem_handle,
        na_offset_t      local_offset,
        na_mem_handle_t  remote_mem_handle,
        na_offset_t      remote_offset,
        na_size_t        length,
        na_addr_t        remote_addr,
        na_op_id_t      *op_id
        );

/* progress */
static na_return_t
na_mpi_progress(
        na_class_t   *na_class,
        na_context_t *context,
        unsigned int  timeout
        );

/* na_mpi_progress_unexpected */
static na_return_t
na_mpi_progress_unexpected(
        na_class_t   *na_class,
        na_context_t *context,
        unsigned int  timeout,
        na_bool_t    *progressed
        );

/* na_mpi_progress_unexpected_rma */
static na_return_t
na_mpi_progress_unexpected_msg(
        na_class_t         *na_class,
        na_context_t       *context,
        struct na_mpi_addr *na_mpi_addr,
        const MPI_Status   *status,
        na_bool_t          *progressed
        );

/* na_mpi_progress_unexpected_rma */
static na_return_t
na_mpi_progress_unexpected_rma(
        na_class_t         *na_class,
        na_context_t       *context,
        struct na_mpi_addr *na_mpi_addr,
        const MPI_Status   *status,
        na_bool_t          *progressed
        );

/* na_mpi_progress_expected */
static na_return_t
na_mpi_progress_expected(
        na_class_t   *na_class,
        na_context_t *context,
        unsigned int  timeout,
        na_bool_t    *progressed
        );

/* na_mpi_complete */
static na_return_t
na_mpi_complete(
        struct na_mpi_op_id *na_mpi_op_id
        );

/* na_mpi_release */
static void
na_mpi_release(
        struct na_cb_info *callback_info,
        void              *arg
        );

/* cancel */
static na_return_t
na_mpi_cancel(
        na_class_t   *na_class,
        na_context_t *context,
        na_op_id_t    op_id
        );

/*******************/
/* Local Variables */
/*******************/

const na_class_t na_mpi_class_g = {
        NULL,                                 /* private_data */
        "mpi",                                /* name */
        na_mpi_check_protocol,                /* check_protocol */
        na_mpi_initialize,                    /* initialize */
        na_mpi_finalize,                      /* finalize */
        NULL,                                 /* context_create */
        NULL,                                 /* context_destroy */
        na_mpi_addr_lookup,                   /* addr_lookup */
        na_mpi_addr_free,                     /* addr_free */
        na_mpi_addr_self,                     /* addr_self */
        NULL,                                 /* addr_dup */
        na_mpi_addr_is_self,                  /* addr_is_self */
        na_mpi_addr_to_string,                /* addr_to_string */
        na_mpi_msg_get_max_expected_size,     /* msg_get_max_expected_size */
        na_mpi_msg_get_max_unexpected_size,   /* msg_get_max_expected_size */
        na_mpi_msg_get_max_tag,               /* msg_get_max_tag */
        na_mpi_msg_send_unexpected,           /* msg_send_unexpected */
        na_mpi_msg_recv_unexpected,           /* msg_recv_unexpected */
        na_mpi_msg_send_expected,             /* msg_send_expected */
        na_mpi_msg_recv_expected,             /* msg_recv_expected */
        na_mpi_mem_handle_create,             /* mem_handle_create */
        NULL,                                 /* mem_handle_create_segment */
        na_mpi_mem_handle_free,               /* mem_handle_free */
        na_mpi_mem_register,                  /* mem_register */
        na_mpi_mem_deregister,                /* mem_deregister */
        NULL,                                 /* mem_publish */
        NULL,                                 /* mem_unpublish */
        na_mpi_mem_handle_get_serialize_size, /* mem_handle_get_serialize_size */
        na_mpi_mem_handle_serialize,          /* mem_handle_serialize */
        na_mpi_mem_handle_deserialize,        /* mem_handle_deserialize */
        na_mpi_put,                           /* put */
        na_mpi_get,                           /* get */
        na_mpi_progress,                      /* progress */
        na_mpi_cancel                         /* cancel */
};

static MPI_Comm na_mpi_init_comm_g = MPI_COMM_NULL; /* MPI comm used at init */

#ifdef NA_MPI_HAS_GNI_SETUP
const uint8_t ptag_value = 20;
const uint32_t key_value = GNI_PKEY_USER_START + 1;
#endif

/********************/
/* Plugin callbacks */
/********************/

/*---------------------------------------------------------------------------*/
static NA_INLINE int
pointer_equal(void *location1, void *location2)
{
    return location1 == location2;
}

/*---------------------------------------------------------------------------*/
static HG_THREAD_RETURN_TYPE
na_mpi_accept_service(void *args)
{
    hg_thread_ret_t ret = 0;
    na_class_t *na_class = (na_class_t *) args;
    na_return_t na_ret;

    na_ret = na_mpi_accept(na_class);
    if (na_ret != NA_SUCCESS) {
        NA_LOG_ERROR("Could not accept connection");
    }

    hg_thread_exit(ret);
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_mpi_open_port(na_class_t *na_class)
{
    char mpi_port_name[MPI_MAX_PORT_NAME];
    int my_rank;
    int mpi_ret;
    na_return_t ret = NA_SUCCESS;

    memset(NA_MPI_PRIVATE_DATA(na_class)->port_name, '\0', MPI_MAX_PORT_NAME);
    memset(mpi_port_name, '\0', MPI_MAX_PORT_NAME);

    MPI_Comm_rank(NA_MPI_PRIVATE_DATA(na_class)->intra_comm, &my_rank);
    if (my_rank == 0) {
        mpi_ret = MPI_Open_port(MPI_INFO_NULL, mpi_port_name);
        if (mpi_ret != MPI_SUCCESS) {
            NA_LOG_ERROR("MPI_Open_port failed");
            ret = NA_PROTOCOL_ERROR;
            goto done;
        }
    }
    mpi_ret = MPI_Bcast(mpi_port_name, MPI_MAX_PORT_NAME, MPI_BYTE, 0,
            NA_MPI_PRIVATE_DATA(na_class)->intra_comm);
    if (mpi_ret != MPI_SUCCESS) {
        NA_LOG_ERROR("MPI_Bcast() failed");
        ret = NA_PROTOCOL_ERROR;
        goto done;
    }

    strcpy(NA_MPI_PRIVATE_DATA(na_class)->port_name, mpi_port_name);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_mpi_get_port_info(const char *name, char *mpi_port_name, int *mpi_rank)
{
    char *port_string = NULL, *rank_string = NULL, *rank_value = NULL;
    na_return_t ret = NA_SUCCESS;

    port_string = strdup(name);
    if (!port_string) {
        NA_LOG_ERROR("Cannot dup name");
        ret = NA_NOMEM_ERROR;
        goto done;
    }

    /* Get mpi port name */
    port_string = strtok_r(port_string, ";", &rank_string);
    strcpy(mpi_port_name, port_string);

    if (!rank_string) {
        NA_LOG_ERROR("Cannot get rank from port name info");
        ret = NA_INVALID_PARAM;
        goto done;
    }

    /* Get rank info */
    if (strlen(rank_string)) {
        rank_string = strtok_r(rank_string, "$", &rank_value);
        rank_string = strtok_r(rank_string, "#", &rank_value);

        if (rank_value && strcmp(rank_string, "rank") == 0) {
            if (mpi_rank) *mpi_rank = atoi(rank_value);
        } else {
            if (mpi_rank) *mpi_rank = 0;
        }
    }

done:
    free(port_string);
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_mpi_accept(na_class_t *na_class)
{
    MPI_Comm new_comm;
    MPI_Comm new_rma_comm;
    struct na_mpi_addr *na_mpi_addr = NULL;
    na_return_t ret = NA_SUCCESS;
    int mpi_ret;

    hg_thread_mutex_lock(&NA_MPI_PRIVATE_DATA(na_class)->accept_mutex);

    if (NA_MPI_PRIVATE_DATA(na_class)->use_static_inter_comm) {
        int global_size, intra_size;

        MPI_Comm_size(MPI_COMM_WORLD, &global_size);
        MPI_Comm_size(NA_MPI_PRIVATE_DATA(na_class)->intra_comm, &intra_size);
        mpi_ret = MPI_Intercomm_create(
                NA_MPI_PRIVATE_DATA(na_class)->intra_comm, 0, MPI_COMM_WORLD,
                global_size - (global_size - intra_size), 0, &new_comm);
        if (mpi_ret != MPI_SUCCESS) {
            NA_LOG_ERROR("MPI_Intercomm_create failed");
            ret = NA_PROTOCOL_ERROR;
            goto done;
        }
    } else {
        mpi_ret = MPI_Comm_accept(NA_MPI_PRIVATE_DATA(na_class)->port_name,
                MPI_INFO_NULL, 0, NA_MPI_PRIVATE_DATA(na_class)->intra_comm,
                &new_comm);
        if (mpi_ret != MPI_SUCCESS) {
            NA_LOG_ERROR("MPI_Comm_accept failed");
            ret = NA_PROTOCOL_ERROR;
            goto done;
        }
    }

    /* To be thread-safe and create a new context, dup the remote comm to a
     * new comm */
    mpi_ret = MPI_Comm_dup(new_comm, &new_rma_comm);
    if (mpi_ret != MPI_SUCCESS) {
        NA_LOG_ERROR("MPI_Comm_dup() failed");
        ret = NA_PROTOCOL_ERROR;
        goto done;
    }

    NA_MPI_PRIVATE_DATA(na_class)->accepting = NA_FALSE;
    hg_thread_cond_signal(&NA_MPI_PRIVATE_DATA(na_class)->accept_cond);

    hg_thread_mutex_unlock(&NA_MPI_PRIVATE_DATA(na_class)->accept_mutex);

    na_mpi_addr = (struct na_mpi_addr *) malloc(sizeof(struct na_mpi_addr));
    if (!na_mpi_addr) {
        NA_LOG_ERROR("Could not allocate mpi_addr");
        ret = NA_NOMEM_ERROR;
        goto done;
    }
    na_mpi_addr->comm = new_comm;
    na_mpi_addr->rma_comm = new_rma_comm;
    na_mpi_addr->rank = MPI_ANY_SOURCE;
    na_mpi_addr->unexpected = NA_FALSE;
    na_mpi_addr->dynamic = (na_bool_t)
            (!NA_MPI_PRIVATE_DATA(na_class)->use_static_inter_comm);
    memset(na_mpi_addr->port_name, '\0', MPI_MAX_PORT_NAME);

    /* Add comms to list of connected remotes */
    ret = na_mpi_remote_list_append(na_class, na_mpi_addr);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_mpi_disconnect(na_class_t NA_UNUSED *na_class,
        struct na_mpi_addr *na_mpi_addr)
{
    na_return_t ret = NA_SUCCESS;

    if (na_mpi_addr && !na_mpi_addr->unexpected) {
        MPI_Comm_free(&na_mpi_addr->rma_comm);

        if (na_mpi_addr->dynamic) {
            int mpi_ret;

            mpi_ret = MPI_Comm_disconnect(&na_mpi_addr->comm);
            if (mpi_ret != MPI_SUCCESS) {
                NA_LOG_ERROR("MPI_Comm_disconnect() failed");
                ret = NA_PROTOCOL_ERROR;
                goto done;
            }
        } else {
            MPI_Comm_free(&na_mpi_addr->comm);
        }
    }
    free(na_mpi_addr);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_mpi_remote_list_append(na_class_t *na_class, struct na_mpi_addr *na_mpi_addr)
{
    na_return_t ret = NA_SUCCESS;
    hg_list_entry_t *new_entry = NULL;

    hg_thread_mutex_lock(&NA_MPI_PRIVATE_DATA(na_class)->remote_list_mutex);

    new_entry = hg_list_append(&NA_MPI_PRIVATE_DATA(na_class)->remote_list,
            (hg_list_value_t) na_mpi_addr);
    if (!new_entry) {
        NA_LOG_ERROR("Could not append entry");
        ret = NA_NOMEM_ERROR;
    }

    hg_thread_mutex_unlock(&NA_MPI_PRIVATE_DATA(na_class)->remote_list_mutex);

    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_mpi_remote_list_remove(na_class_t *na_class, struct na_mpi_addr *na_mpi_addr)
{
    na_return_t ret = NA_SUCCESS;
    hg_list_entry_t *entry = NULL;

    /* Process list of remotes */
    hg_thread_mutex_lock(&NA_MPI_PRIVATE_DATA(na_class)->remote_list_mutex);

    /* Remove handle from list if not found */
    entry = hg_list_find_data(NA_MPI_PRIVATE_DATA(na_class)->remote_list,
            pointer_equal, (hg_list_value_t) na_mpi_addr);
    if (entry && !hg_list_remove_entry(
            &NA_MPI_PRIVATE_DATA(na_class)->remote_list, entry)) {
        NA_LOG_ERROR("Could not remove entry");
        ret = NA_PROTOCOL_ERROR;
    }

    hg_thread_mutex_unlock(&NA_MPI_PRIVATE_DATA(na_class)->remote_list_mutex);

    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_mpi_remote_list_disconnect(na_class_t *na_class)
{
    na_return_t ret = NA_SUCCESS;

    /* Process list of communicators */
    hg_thread_mutex_lock(&NA_MPI_PRIVATE_DATA(na_class)->remote_list_mutex);

    if (hg_list_length(NA_MPI_PRIVATE_DATA(na_class)->remote_list)) {
        hg_list_entry_t *entry = NA_MPI_PRIVATE_DATA(na_class)->remote_list;

        while (entry) {
            hg_list_entry_t *next_entry = hg_list_next(entry);
            struct na_mpi_addr *na_mpi_addr =
                    (struct na_mpi_addr *) hg_list_data(entry);

            ret = na_mpi_disconnect(na_class, na_mpi_addr);
            if (ret != NA_SUCCESS) {
                goto done;
            }

            if (!hg_list_remove_entry(
                    &NA_MPI_PRIVATE_DATA(na_class)->remote_list, entry)) {
                NA_LOG_ERROR("Could not remove entry");
                ret = NA_PROTOCOL_ERROR;
                goto done;
            }

            entry = next_entry;
        }
    }

 done:
    hg_thread_mutex_unlock(&NA_MPI_PRIVATE_DATA(na_class)->remote_list_mutex);

    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_mpi_op_id_list_append(na_class_t *na_class,
        struct na_mpi_op_id *na_mpi_op_id)
{
    na_return_t ret = NA_SUCCESS;
    hg_list_entry_t *new_entry = NULL;

    hg_thread_mutex_lock(&NA_MPI_PRIVATE_DATA(na_class)->op_id_list_mutex);

    new_entry = hg_list_append(&NA_MPI_PRIVATE_DATA(na_class)->op_id_list,
            (hg_list_value_t) na_mpi_op_id);
    if (!new_entry) {
        NA_LOG_ERROR("Could not append entry");
        ret = NA_NOMEM_ERROR;
    }

    hg_thread_mutex_unlock(&NA_MPI_PRIVATE_DATA(na_class)->op_id_list_mutex);

    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_mpi_msg_unexpected_op_push(na_class_t *na_class,
        struct na_mpi_op_id *na_mpi_op_id)
{
    na_return_t ret = NA_SUCCESS;

    hg_thread_mutex_lock(
            &NA_MPI_PRIVATE_DATA(na_class)->unexpected_op_queue_mutex);

    if (!hg_queue_push_head(NA_MPI_PRIVATE_DATA(na_class)->unexpected_op_queue,
            (hg_queue_value_t) na_mpi_op_id)) {
        NA_LOG_ERROR("Could not push ID to unexpected op queue");
        ret = NA_NOMEM_ERROR;
    }

    hg_thread_mutex_unlock(
            &NA_MPI_PRIVATE_DATA(na_class)->unexpected_op_queue_mutex);

    return ret;
}

/*---------------------------------------------------------------------------*/
static struct na_mpi_op_id *
na_mpi_msg_unexpected_op_pop(na_class_t *na_class)
{
    struct na_mpi_op_id *na_mpi_op_id;
    hg_queue_value_t queue_value;

    hg_thread_mutex_lock(
            &NA_MPI_PRIVATE_DATA(na_class)->unexpected_op_queue_mutex);

    queue_value = hg_queue_pop_tail(
            NA_MPI_PRIVATE_DATA(na_class)->unexpected_op_queue);
    na_mpi_op_id = (queue_value != HG_QUEUE_NULL) ?
            (struct na_mpi_op_id *) queue_value : NULL;

    hg_thread_mutex_unlock(
            &NA_MPI_PRIVATE_DATA(na_class)->unexpected_op_queue_mutex);

    return na_mpi_op_id;
}

/*---------------------------------------------------------------------------*/
static NA_INLINE na_tag_t
na_mpi_gen_rma_tag(na_class_t *na_class)
{
    na_tag_t tag;

    /* Compare and swap tag if reached max tag */
    if (hg_atomic_cas32(&NA_MPI_PRIVATE_DATA(na_class)->rma_tag,
            NA_MPI_MAX_RMA_TAG, NA_MPI_RMA_TAG)) {
        tag = NA_MPI_RMA_TAG;
    } else {
        /* Increment tag */
        tag = hg_atomic_incr32(&NA_MPI_PRIVATE_DATA(na_class)->rma_tag);
    }

    return tag;
}

/*---------------------------------------------------------------------------*/
na_return_t
NA_MPI_Set_init_intra_comm(MPI_Comm intra_comm)
{
    na_mpi_init_comm_g = intra_comm;

    return NA_SUCCESS;
}

/*---------------------------------------------------------------------------*/
const char *
NA_MPI_Get_port_name(na_class_t *na_class)
{
    int my_rank;
    static char port_name[MPI_MAX_PORT_NAME];

    MPI_Comm_rank(NA_MPI_PRIVATE_DATA(na_class)->intra_comm, &my_rank);

    /* Append rank info to port name */
    if (NA_MPI_PRIVATE_DATA(na_class)->use_static_inter_comm)
        sprintf(port_name, "rank#%d$", my_rank);
    else
        sprintf(port_name, "%s;rank#%d$",
            NA_MPI_PRIVATE_DATA(na_class)->port_name, my_rank);

    return port_name;
}

/*---------------------------------------------------------------------------*/
#ifdef NA_MPI_HAS_GNI_SETUP
static na_return_t
gni_job_setup(uint8_t ptag, uint32_t cookie)
{
    gni_return_t grc;
    gni_job_limits_t limits;
    na_return_t ret = NA_SUCCESS;

    /* Do not apply any resource limits */
    limits.a.mrt_limit = GNI_JOB_INVALID_LIMIT;
    limits.b.gart_limit = GNI_JOB_INVALID_LIMIT;
    limits.mdd_limit = GNI_JOB_INVALID_LIMIT;
    limits.fma_limit = GNI_JOB_INVALID_LIMIT;
    limits.bte_limit = GNI_JOB_INVALID_LIMIT;
    limits.cq_limit = GNI_JOB_INVALID_LIMIT;

    /* Do not use NTT */
    limits.ntt_size = 0;

    /* GNI_ConfigureJob():
     * -device_id should be 0 for XC since we only have 1 NIC/node
     * -job_id should always be 0 (meaning "no job container created")
     */
    grc = GNI_ConfigureJob(0, 0, ptag, cookie, &limits);
    if(grc == GNI_RC_PERMISSION_ERROR) {
        NA_LOG_ERROR("GNI_ConfigureJob(...) requires root privileges.");
        ret = NA_PERMISSION_ERROR;
    }
    NA_LOG_DEBUG("GNI_ConfigureJob returned %s", gni_err_str[grc]);

    return ret;
}

/*---------------------------------------------------------------------------*/
na_return_t
NA_MPI_Gni_job_setup(void)
{
    char ptag_string[128];
    char cookie_string[128];
    uint32_t cookie_value = GNI_JOB_CREATE_COOKIE(key_value,0);
    na_return_t ret;

    if ((key_value < GNI_PKEY_USER_START)
            && (key_value >= GNI_PKEY_USER_END)) {
        NA_LOG_ERROR("Invalid key value");
        ret = NA_INVALID_PARAM;
        goto done;
    }
    if ((ptag_value < GNI_PTAG_USER_START)
            && (ptag_value >= GNI_PTAG_USER_END)) {
        NA_LOG_ERROR("Invalid ptag value");
        ret = NA_INVALID_PARAM;
        goto done;
    }

    /*
     * setup ptag/pcookie  env variables for MPI
     */
    sprintf(ptag_string,"PMI_GNI_PTAG=%d", ptag_value);
    putenv(ptag_string);
    sprintf(cookie_string,"PMI_GNI_COOKIE=%d", cookie_value);
    putenv(cookie_string);

    NA_LOG_DEBUG("Setting ptag to %d and cookie to 0x%x", ptag_value,
            cookie_value);
    NA_LOG_DEBUG("sanity check PMI_GNI_PTAG = %s", getenv("PMI_GNI_PTAG"));
    NA_LOG_DEBUG("sanity check PMI_GNI_COOKIE = %s", getenv("PMI_GNI_COOKIE"));

    /*
     * setup the Aries NIC resources for the job (this can be done multiple
     * times for the same ptag/cookie combination on the same node), so it
     * doesn't matter if there are multiple MPI ranks per node.
     */
    ret = gni_job_setup(ptag_value, cookie_value);

done:
    return ret;
}
#endif

/*---------------------------------------------------------------------------*/
static na_bool_t
na_mpi_check_protocol(const char NA_UNUSED *protocol_name)
{
    return NA_TRUE;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_mpi_initialize(na_class_t *na_class, const struct na_info *na_info,
        na_bool_t listen)
{
    int mpi_ext_initialized = 0;
    na_bool_t listening, use_static_inter_comm;
    hg_queue_t *unexpected_op_queue = NULL;
    int flags = (listen) ? MPI_INIT_SERVER : 0;
    int mpi_ret;
    na_return_t ret = NA_SUCCESS;

    na_class->private_data = malloc(sizeof(struct na_mpi_private_data));
    if (!na_class->private_data) {
        NA_LOG_ERROR("Could not allocate NA private data class");
        ret = NA_NOMEM_ERROR;
        goto done;
    }

    /* Check flags */
    if (strcmp(na_info->protocol_name, "static") == 0)
        flags |= MPI_INIT_STATIC;
    listening = (na_bool_t) (flags & MPI_INIT_SERVER);
    NA_MPI_PRIVATE_DATA(na_class)->listening = listening;

    use_static_inter_comm = (na_bool_t) (flags & MPI_INIT_STATIC);
    NA_MPI_PRIVATE_DATA(na_class)->use_static_inter_comm = use_static_inter_comm;

    /* Initialize MPI */
    mpi_ret = MPI_Initialized(&mpi_ext_initialized);
    if (mpi_ret != MPI_SUCCESS) {
        NA_LOG_ERROR("MPI_Initialized failed");
        ret = NA_PROTOCOL_ERROR;
        goto done;
    }
    NA_MPI_PRIVATE_DATA(na_class)->mpi_ext_initialized =
            (na_bool_t) mpi_ext_initialized;

    if (!mpi_ext_initialized) {
#ifdef NA_MPI_HAS_GNI_SETUP
        /* Setup GNI job before initializing MPI */
        if (NA_MPI_Gni_job_setup() != NA_SUCCESS) {
            NA_LOG_ERROR("Could not setup GNI job");
            error_occurred = NA_TRUE;
            goto done;
        }
#endif
        if (listening) {
            int provided;
            /* Listening implies creation of listening thread so use that to
             * be safe */
            mpi_ret = MPI_Init_thread(NULL, NULL, MPI_THREAD_MULTIPLE,
                    &provided);
            if (provided != MPI_THREAD_MULTIPLE) {
                NA_LOG_ERROR("MPI_THREAD_MULTIPLE cannot be set");
                ret = NA_PROTOCOL_ERROR;
                goto done;
            }
        } else {
            /* Here we assume that the application is not using threads
             * TODO add an option for init_thread ? */
            mpi_ret = MPI_Init(NULL, NULL);
        }
        if (mpi_ret != MPI_SUCCESS) {
            NA_LOG_ERROR("Could not initialize MPI");
            ret = NA_PROTOCOL_ERROR;
            goto done;
        }
    }

    /* Assign MPI intra comm */
    if ((na_mpi_init_comm_g != MPI_COMM_NULL) || !use_static_inter_comm) {
        MPI_Comm comm = (na_mpi_init_comm_g != MPI_COMM_NULL) ?
                na_mpi_init_comm_g : MPI_COMM_WORLD;

        mpi_ret = MPI_Comm_dup(comm, &NA_MPI_PRIVATE_DATA(na_class)->intra_comm);
        if (mpi_ret != MPI_SUCCESS) {
            NA_LOG_ERROR("Could not duplicate communicator");
            ret = NA_PROTOCOL_ERROR;
            goto done;
        }
    } else if (use_static_inter_comm) {
        int color;
        int global_rank;

        MPI_Comm_rank(MPI_COMM_WORLD, &global_rank);
        /* Color is 1 for server, 2 for client */
        color = (listening) ? 1 : 2;

        /* Assume that the application did not split MPI_COMM_WORLD already */
        mpi_ret = MPI_Comm_split(MPI_COMM_WORLD, color, global_rank,
                &NA_MPI_PRIVATE_DATA(na_class)->intra_comm);
        if (mpi_ret != MPI_SUCCESS) {
            NA_LOG_ERROR("Could not split communicator");
            ret = NA_PROTOCOL_ERROR;
            goto done;
        }
    }

    /* Initialize lists */
    NA_MPI_PRIVATE_DATA(na_class)->remote_list = NULL;
    NA_MPI_PRIVATE_DATA(na_class)->op_id_list = NULL;

    /* Create queue for making progress on unexpected operation IDs */
    unexpected_op_queue = hg_queue_new();
    if (!unexpected_op_queue) {
        NA_LOG_ERROR("Could not create unexpected op queue");
        ret = NA_NOMEM_ERROR;
        goto done;
    }
    NA_MPI_PRIVATE_DATA(na_class)->unexpected_op_queue = unexpected_op_queue;

    /* Initialize mutex/cond */
    hg_thread_mutex_init(&NA_MPI_PRIVATE_DATA(na_class)->accept_mutex);
    hg_thread_cond_init(&NA_MPI_PRIVATE_DATA(na_class)->accept_cond);
    hg_thread_mutex_init(&NA_MPI_PRIVATE_DATA(na_class)->remote_list_mutex);
    hg_thread_mutex_init(&NA_MPI_PRIVATE_DATA(na_class)->op_id_list_mutex);
    hg_thread_mutex_init(
            &NA_MPI_PRIVATE_DATA(na_class)->unexpected_op_queue_mutex);

    /* Initialize atomic op */
    hg_atomic_set32(&NA_MPI_PRIVATE_DATA(na_class)->rma_tag, NA_MPI_RMA_TAG);

    /* If server opens a port */
    if (listening) {
        NA_MPI_PRIVATE_DATA(na_class)->accepting = NA_TRUE;
        if (!use_static_inter_comm && (ret = na_mpi_open_port(na_class)) != NA_SUCCESS) {
            NA_LOG_ERROR("Cannot open port");
            goto done;
        }

        /* We need to create a thread here if we want to allow
         * connection / disconnection since MPI does not provide any
         * service for that and MPI_Comm_accept is blocking */
        hg_thread_create(&NA_MPI_PRIVATE_DATA(na_class)->accept_thread,
                &na_mpi_accept_service,
                (void *) na_class);
    } else {
        NA_MPI_PRIVATE_DATA(na_class)->accepting = NA_FALSE;
    }

done:
    if (ret != NA_SUCCESS) {
       na_mpi_finalize(na_class);
    }

    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_mpi_finalize(na_class_t *na_class)
{
    na_return_t ret = NA_SUCCESS;
    int mpi_ext_finalized = 0;
    int mpi_ret;

    if (NA_MPI_PRIVATE_DATA(na_class)->listening) {
        /* No more connection accepted after this point */
        hg_thread_join(NA_MPI_PRIVATE_DATA(na_class)->accept_thread);

        /* If server opened a port */
        if (!NA_MPI_PRIVATE_DATA(na_class)->use_static_inter_comm) {
            mpi_ret = MPI_Close_port(NA_MPI_PRIVATE_DATA(na_class)->port_name);
            if (mpi_ret != MPI_SUCCESS) {
                NA_LOG_ERROR("Could not close port");
                ret = NA_PROTOCOL_ERROR;
                goto done;
            }
        }
    }
    /* Process list of communicators */
    na_mpi_remote_list_disconnect(na_class);

    /* Check that unexpected op queue is empty */
    if (!hg_queue_is_empty(
            NA_MPI_PRIVATE_DATA(na_class)->unexpected_op_queue)) {
        NA_LOG_ERROR("Unexpected op queue should be empty");
        ret = NA_PROTOCOL_ERROR;
    }

    /* Free unexpected op queue */
    hg_queue_free(NA_MPI_PRIVATE_DATA(na_class)->unexpected_op_queue);

    /* Free the private dup'ed comm */
    mpi_ret = MPI_Comm_free(&NA_MPI_PRIVATE_DATA(na_class)->intra_comm);
    if (mpi_ret != MPI_SUCCESS) {
        NA_LOG_ERROR("Could not free intra_comm");
        ret = NA_PROTOCOL_ERROR;
        goto done;
    }

    /* MPI_Finalize */
    MPI_Finalized(&mpi_ext_finalized);
    if (mpi_ext_finalized) {
        NA_LOG_ERROR("MPI already finalized");
        ret = NA_PROTOCOL_ERROR;
        goto done;
    }

    if (!NA_MPI_PRIVATE_DATA(na_class)->mpi_ext_initialized &&
            !mpi_ext_finalized) {
        mpi_ret = MPI_Finalize();
        if (mpi_ret != MPI_SUCCESS) {
            NA_LOG_ERROR("Could not finalize MPI");
            ret = NA_PROTOCOL_ERROR;
            goto done;
        }
    }

    /* Destroy mutex/cond */
    hg_thread_mutex_destroy(&NA_MPI_PRIVATE_DATA(na_class)->accept_mutex);
    hg_thread_cond_destroy(&NA_MPI_PRIVATE_DATA(na_class)->accept_cond);
    hg_thread_mutex_destroy(&NA_MPI_PRIVATE_DATA(na_class)->remote_list_mutex);
    hg_thread_mutex_destroy(&NA_MPI_PRIVATE_DATA(na_class)->op_id_list_mutex);
    hg_thread_mutex_destroy(
            &NA_MPI_PRIVATE_DATA(na_class)->unexpected_op_queue_mutex);

    free(na_class->private_data);

 done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_mpi_addr_lookup(na_class_t *na_class, na_context_t *context,
        na_cb_t callback, void *arg, const char *name, na_op_id_t *op_id)
{
    struct na_mpi_op_id *na_mpi_op_id = NULL;
    struct na_mpi_addr *na_mpi_addr = NULL;
    na_return_t ret = NA_SUCCESS;
    int mpi_ret;

    /* Allocate op_id */
    na_mpi_op_id = (struct na_mpi_op_id *) malloc(sizeof(struct na_mpi_op_id));
    if (!na_mpi_op_id) {
        NA_LOG_ERROR("Could not allocate NA MPI operation ID");
        ret = NA_NOMEM_ERROR;
        goto done;
    }
    na_mpi_op_id->context = context;
    na_mpi_op_id->type = NA_CB_LOOKUP;
    na_mpi_op_id->callback = callback;
    na_mpi_op_id->arg = arg;
    na_mpi_op_id->completed = NA_FALSE;

    /* Allocate addr */
    na_mpi_addr = (struct na_mpi_addr *) malloc(sizeof(struct na_mpi_addr));
    if (!na_mpi_addr) {
        NA_LOG_ERROR("Could not allocate addr");
        ret = NA_NOMEM_ERROR;
        goto done;
    }
    na_mpi_addr->rank = 0;
    na_mpi_addr->comm = MPI_COMM_NULL;
    na_mpi_addr->rma_comm = MPI_COMM_NULL;
    na_mpi_addr->unexpected = NA_FALSE;
    na_mpi_addr->self = NA_FALSE;
    na_mpi_addr->dynamic = NA_FALSE;
    na_mpi_op_id->info.lookup.addr = (na_addr_t) na_mpi_addr;
    memset(na_mpi_addr->port_name, '\0', MPI_MAX_PORT_NAME);
    /* get port_name and remote server rank */
    na_mpi_get_port_info(name, na_mpi_addr->port_name, &na_mpi_addr->rank);

    /* Try to connect, must prevent concurrent threads to
     * create new communicators */
    hg_thread_mutex_lock(&NA_MPI_PRIVATE_DATA(na_class)->accept_mutex);

    /* TODO A listening process can only "connect" to one of his pairs ? */
    if (NA_MPI_PRIVATE_DATA(na_class)->listening) {
        while (NA_MPI_PRIVATE_DATA(na_class)->accepting) {
            hg_thread_cond_wait(&NA_MPI_PRIVATE_DATA(na_class)->accept_cond,
                    &NA_MPI_PRIVATE_DATA(na_class)->accept_mutex);
        }
        mpi_ret = MPI_Comm_dup(NA_MPI_PRIVATE_DATA(na_class)->intra_comm,
                &na_mpi_addr->comm);
        if (mpi_ret != MPI_SUCCESS) {
            NA_LOG_ERROR("MPI_Comm_dup() failed");
            ret = NA_PROTOCOL_ERROR;
            goto done;
        }
    } else {
        if (NA_MPI_PRIVATE_DATA(na_class)->use_static_inter_comm) {
            mpi_ret = MPI_Intercomm_create(
                    NA_MPI_PRIVATE_DATA(na_class)->intra_comm, 0,
                    MPI_COMM_WORLD, 0, 0, &na_mpi_addr->comm);
            if (mpi_ret != MPI_SUCCESS) {
                NA_LOG_ERROR("MPI_Intercomm_create() failed");
                ret = NA_PROTOCOL_ERROR;
                goto done;
            }
        } else {
            na_mpi_addr->dynamic = NA_TRUE;
            mpi_ret = MPI_Comm_connect(na_mpi_addr->port_name, MPI_INFO_NULL, 0,
                    NA_MPI_PRIVATE_DATA(na_class)->intra_comm,
                    &na_mpi_addr->comm);
            if (mpi_ret != MPI_SUCCESS) {
                NA_LOG_ERROR("MPI_Comm_connect() failed");
                ret = NA_PROTOCOL_ERROR;
                goto done;
            }
        }
    }

    /* To be thread-safe and create a new context,
     * dup the remote comm to a new comm */
    mpi_ret = MPI_Comm_dup(na_mpi_addr->comm, &na_mpi_addr->rma_comm);
    if (mpi_ret != MPI_SUCCESS) {
        NA_LOG_ERROR("MPI_Comm_dup() failed");
        ret = NA_PROTOCOL_ERROR;
        goto done;
    }

    hg_thread_mutex_unlock(&NA_MPI_PRIVATE_DATA(na_class)->accept_mutex);

    /* Add addr to list of addresses */
    ret = na_mpi_remote_list_append(na_class, na_mpi_addr);
    if (ret != NA_SUCCESS) {
        goto done;
    }

    /* TODO MPI calls are blocking and so is na_mpi_addr_lookup,
     * i.e. we always complete here for now */
    ret = na_mpi_complete(na_mpi_op_id);
    if (ret != NA_SUCCESS) {
        NA_LOG_ERROR("Could not complete operation");
        goto done;
    }

    /* Assign op_id */
    *op_id = (na_op_id_t) na_mpi_op_id;

done:
    if (ret != NA_SUCCESS) {
        free(na_mpi_addr);
        free(na_mpi_op_id);
    }

    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_mpi_addr_self(na_class_t NA_UNUSED *na_class, na_addr_t *addr)
{
    struct na_mpi_addr *na_mpi_addr = NULL;
    na_return_t ret = NA_SUCCESS;

    /* Allocate addr */
    na_mpi_addr = (struct na_mpi_addr *) malloc(sizeof(struct na_mpi_addr));
    if (!na_mpi_addr) {
        NA_LOG_ERROR("Could not allocate MPI addr");
        ret = NA_NOMEM_ERROR;
        goto done;
    }
    na_mpi_addr->comm = MPI_COMM_NULL;
    na_mpi_addr->rma_comm = MPI_COMM_NULL;
    na_mpi_addr->rank = 0;
    na_mpi_addr->unexpected = NA_FALSE;
    na_mpi_addr->self = NA_TRUE;
    na_mpi_addr->dynamic = NA_FALSE;
    memset(na_mpi_addr->port_name, '\0', MPI_MAX_PORT_NAME);

    *addr = (na_addr_t) na_mpi_addr;

done:
    if (ret != NA_SUCCESS) {
        free(na_mpi_addr);
    }
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_mpi_addr_free(na_class_t *na_class, na_addr_t addr)
{
    struct na_mpi_addr *na_mpi_addr = (struct na_mpi_addr *) addr;
    na_return_t ret = NA_SUCCESS;

    if (!na_mpi_addr) {
        NA_LOG_ERROR("Already freed");
        ret = NA_PROTOCOL_ERROR;
        return ret;
    }

    if (na_mpi_addr->self) {
        free(na_mpi_addr);
    } else {
        /* Remove addr from list of addresses */
        ret = na_mpi_remote_list_remove(na_class, na_mpi_addr);
        if (ret != NA_SUCCESS) goto done;

        /* Free addr */
        ret = na_mpi_disconnect(na_class, na_mpi_addr);
        if (ret != NA_SUCCESS) goto done;
    }

 done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_bool_t
na_mpi_addr_is_self(na_class_t NA_UNUSED *na_class, na_addr_t addr)
{
    struct na_mpi_addr *na_mpi_addr = (struct na_mpi_addr *) addr;

    return na_mpi_addr->self;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_mpi_addr_to_string(na_class_t NA_UNUSED *na_class, char *buf,
        na_size_t buf_size, na_addr_t addr)
{
    struct na_mpi_addr *mpi_addr = NULL;
    na_return_t ret = NA_SUCCESS;

    mpi_addr = (struct na_mpi_addr *) addr;

    if (strlen(mpi_addr->port_name) > buf_size) {
        NA_LOG_ERROR("Buffer size too small to copy addr");
        ret = NA_SIZE_ERROR;
        goto done;
    }

    sprintf(buf, "%s:rank#%d$", mpi_addr->port_name, mpi_addr->rank);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_size_t
na_mpi_msg_get_max_expected_size(na_class_t NA_UNUSED *na_class)
{
    na_size_t max_expected_size = NA_MPI_EXPECTED_SIZE;

    return max_expected_size;
}

/*---------------------------------------------------------------------------*/
static na_size_t
na_mpi_msg_get_max_unexpected_size(na_class_t NA_UNUSED *na_class)
{
    na_size_t max_unexpected_size = NA_MPI_UNEXPECTED_SIZE;

    return max_unexpected_size;
}

/*---------------------------------------------------------------------------*/
static na_tag_t
na_mpi_msg_get_max_tag(na_class_t NA_UNUSED *na_class)
{
    na_tag_t max_tag = NA_MPI_MAX_TAG;

    return max_tag;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_mpi_msg_send_unexpected(na_class_t *na_class, na_context_t *context,
        na_cb_t callback, void *arg, const void *buf, na_size_t buf_size,
        na_addr_t dest, na_tag_t tag, na_op_id_t *op_id)
{
    int mpi_buf_size = (int) buf_size;
    int mpi_tag = (int) tag;
    struct na_mpi_addr *mpi_addr = (struct na_mpi_addr *) dest;
    struct na_mpi_op_id *na_mpi_op_id = NULL;
    na_return_t ret = NA_SUCCESS;
    int mpi_ret;

    /* Allocate op_id */
    na_mpi_op_id = (struct na_mpi_op_id *) malloc(sizeof(struct na_mpi_op_id));
    if (!na_mpi_op_id) {
        NA_LOG_ERROR("Could not allocate NA MPI operation ID");
        ret = NA_NOMEM_ERROR;
        goto done;
    }
    na_mpi_op_id->context = context;
    na_mpi_op_id->type = NA_CB_SEND_UNEXPECTED;
    na_mpi_op_id->callback = callback;
    na_mpi_op_id->arg = arg;
    na_mpi_op_id->completed = NA_FALSE;
    na_mpi_op_id->info.send_unexpected.data_request = MPI_REQUEST_NULL;

    mpi_ret = MPI_Isend(buf, mpi_buf_size, MPI_BYTE, mpi_addr->rank,
            mpi_tag, mpi_addr->comm,
            &na_mpi_op_id->info.send_unexpected.data_request);
    if (mpi_ret != MPI_SUCCESS) {
        NA_LOG_ERROR("MPI_Isend() failed");
        ret = NA_PROTOCOL_ERROR;
        goto done;
    }

    /* Append op_id to op_id list and assign op_id */
    ret = na_mpi_op_id_list_append(na_class, na_mpi_op_id);
    *op_id = (na_op_id_t) na_mpi_op_id;

done:
    if (ret != NA_SUCCESS) {
        free(na_mpi_op_id);
    }
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_mpi_msg_recv_unexpected(na_class_t *na_class, na_context_t *context,
        na_cb_t callback, void *arg, void *buf, na_size_t buf_size,
        na_op_id_t *op_id)
{
    struct na_mpi_op_id *na_mpi_op_id = NULL;
    na_bool_t progressed = NA_FALSE;
    na_return_t ret = NA_SUCCESS;

    /* Allocate na_op_id */
    na_mpi_op_id = (struct na_mpi_op_id *) malloc(sizeof(struct na_mpi_op_id));
    if (!na_mpi_op_id) {
        NA_LOG_ERROR("Could not allocate NA MPI operation ID");
        ret = NA_NOMEM_ERROR;
        goto done;
    }
    na_mpi_op_id->context = context;
    na_mpi_op_id->type = NA_CB_RECV_UNEXPECTED;
    na_mpi_op_id->callback = callback;
    na_mpi_op_id->arg = arg;
    na_mpi_op_id->completed = NA_FALSE;
    na_mpi_op_id->info.recv_unexpected.buf = buf;
    na_mpi_op_id->info.recv_unexpected.buf_size = (int) buf_size;
    na_mpi_op_id->info.recv_unexpected.remote_addr = NULL;

    /* Add op_id to queue of pending unexpected recv ops and make some progress
     * in case messages are already arrived */
    ret = na_mpi_msg_unexpected_op_push(na_class, na_mpi_op_id);
    if (ret != NA_SUCCESS) {
        NA_LOG_ERROR("Could not push operation ID");
        goto done;
    }

    do {
        ret = na_mpi_progress_unexpected(na_class, context, 0, &progressed);
        if (ret != NA_SUCCESS) {
            NA_LOG_ERROR("Could not make unexpected progress");
            goto done;
        }
    } while (progressed);
    /* No guarantee here that ours has completed even if progressed is true,
     * we make progress here just in case we can complete the op at the same
     * time */

    /* Assign op_id */
    *op_id = (na_op_id_t) na_mpi_op_id;

done:
    if (ret != NA_SUCCESS) {
        free(na_mpi_op_id);
    }
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_mpi_msg_send_expected(na_class_t *na_class, na_context_t *context,
        na_cb_t callback, void *arg, const void *buf, na_size_t buf_size,
        na_addr_t dest, na_tag_t tag, na_op_id_t *op_id)
{
    int mpi_buf_size = (int) buf_size;
    int mpi_tag = (int) tag;
    struct na_mpi_addr *mpi_addr = (struct na_mpi_addr *) dest;
    struct na_mpi_op_id *na_mpi_op_id = NULL;
    na_return_t ret = NA_SUCCESS;
    int mpi_ret;

    /* Allocate op_id */
    na_mpi_op_id = (struct na_mpi_op_id *) malloc(sizeof(struct na_mpi_op_id));
    if (!na_mpi_op_id) {
        NA_LOG_ERROR("Could not allocate NA MPI operation ID");
        ret = NA_NOMEM_ERROR;
        goto done;
    }
    na_mpi_op_id->context = context;
    na_mpi_op_id->type = NA_CB_SEND_EXPECTED;
    na_mpi_op_id->callback = callback;
    na_mpi_op_id->arg = arg;
    na_mpi_op_id->completed = NA_FALSE;
    na_mpi_op_id->info.send_expected.data_request = MPI_REQUEST_NULL;

    mpi_ret = MPI_Isend(buf, mpi_buf_size, MPI_BYTE, mpi_addr->rank,
            mpi_tag, mpi_addr->comm,
            &na_mpi_op_id->info.send_expected.data_request);
    if (mpi_ret != MPI_SUCCESS) {
        NA_LOG_ERROR("MPI_Isend() failed");
        ret = NA_PROTOCOL_ERROR;
        goto done;
    }

    /* Append op_id to op_id list and assign op_id */
    ret = na_mpi_op_id_list_append(na_class, na_mpi_op_id);
    *op_id = (na_op_id_t) na_mpi_op_id;

done:
    if (ret != NA_SUCCESS) {
        free(na_mpi_op_id);
    }
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_mpi_msg_recv_expected(na_class_t *na_class, na_context_t *context,
        na_cb_t callback, void *arg, void *buf, na_size_t buf_size,
        na_addr_t source, na_tag_t tag, na_op_id_t *op_id)
{
    int mpi_buf_size = (int) buf_size;
    int mpi_tag = (int) tag;
    struct na_mpi_addr *mpi_addr = (struct na_mpi_addr *) source;
    struct na_mpi_op_id *na_mpi_op_id = NULL;
    na_return_t ret = NA_SUCCESS;
    int mpi_ret;

    /* Allocate op_id */
    na_mpi_op_id = (struct na_mpi_op_id *) malloc(sizeof(struct na_mpi_op_id));
    if (!na_mpi_op_id) {
        NA_LOG_ERROR("Could not allocate NA MPI operation ID");
        ret = NA_NOMEM_ERROR;
        goto done;
    }
    na_mpi_op_id->context = context;
    na_mpi_op_id->type = NA_CB_RECV_EXPECTED;
    na_mpi_op_id->callback = callback;
    na_mpi_op_id->arg = arg;
    na_mpi_op_id->completed = NA_FALSE;
    na_mpi_op_id->info.recv_expected.buf_size = mpi_buf_size;
    na_mpi_op_id->info.recv_expected.actual_size = 0;
    na_mpi_op_id->info.recv_expected.data_request = MPI_REQUEST_NULL;

    mpi_ret = MPI_Irecv(buf, mpi_buf_size, MPI_BYTE, mpi_addr->rank,
            mpi_tag, mpi_addr->comm,
            &na_mpi_op_id->info.recv_expected.data_request);
    if (mpi_ret != MPI_SUCCESS) {
        NA_LOG_ERROR("MPI_Irecv() failed");
        ret = NA_PROTOCOL_ERROR;
        goto done;
    }

    /* Append op_id to op_id list and assign op_id */
    ret = na_mpi_op_id_list_append(na_class, na_mpi_op_id);
    *op_id = (na_op_id_t) na_mpi_op_id;

done:
    if (ret != NA_SUCCESS) {
        free(na_mpi_op_id);
    }
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_mpi_mem_handle_create(na_class_t NA_UNUSED *na_class, void *buf,
        na_size_t buf_size, unsigned long flags, na_mem_handle_t *mem_handle)
{
    na_ptr_t mpi_buf_base = (na_ptr_t) buf;
    struct na_mpi_mem_handle *na_mpi_mem_handle = NULL;
    MPI_Aint mpi_buf_size = (MPI_Aint) buf_size;
    na_return_t ret = NA_SUCCESS;

    /* Allocate memory handle (use calloc to avoid uninitialized transfer) */
    na_mpi_mem_handle = (struct na_mpi_mem_handle *)
            calloc(1, sizeof(struct na_mpi_mem_handle));
    if (!na_mpi_mem_handle) {
          NA_LOG_ERROR("Could not allocate NA MPI memory handle");
          ret = NA_NOMEM_ERROR;
          goto done;
    }
    na_mpi_mem_handle->base = mpi_buf_base;
    na_mpi_mem_handle->size = mpi_buf_size;
    na_mpi_mem_handle->attr = flags;

    *mem_handle = (na_mem_handle_t) na_mpi_mem_handle;

done:
    return ret;

}

/*---------------------------------------------------------------------------*/
static na_return_t
na_mpi_mem_handle_free(na_class_t NA_UNUSED *na_class,
        na_mem_handle_t mem_handle)
{
    struct na_mpi_mem_handle *mpi_mem_handle =
            (struct na_mpi_mem_handle*) mem_handle;
    na_return_t ret = NA_SUCCESS;

    free(mpi_mem_handle);

    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_mpi_mem_register(na_class_t NA_UNUSED *na_class, na_mem_handle_t NA_UNUSED mem_handle)
{
    return NA_SUCCESS;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_mpi_mem_deregister(na_class_t NA_UNUSED *na_class, na_mem_handle_t NA_UNUSED mem_handle)
{
    return NA_SUCCESS;
}

/*---------------------------------------------------------------------------*/
static na_size_t
na_mpi_mem_handle_get_serialize_size(na_class_t NA_UNUSED *na_class,
        na_mem_handle_t NA_UNUSED mem_handle)
{
    return sizeof(struct na_mpi_mem_handle);
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_mpi_mem_handle_serialize(na_class_t NA_UNUSED *na_class, void *buf,
        na_size_t buf_size, na_mem_handle_t mem_handle)
{
    struct na_mpi_mem_handle *na_mpi_mem_handle =
            (struct na_mpi_mem_handle*) mem_handle;
    na_return_t ret = NA_SUCCESS;

    if (buf_size < sizeof(struct na_mpi_mem_handle)) {
        NA_LOG_ERROR("Buffer size too small for serializing handle");
        ret = NA_SIZE_ERROR;
        goto done;
    }

    /* Copy struct */
    memcpy(buf, na_mpi_mem_handle, sizeof(struct na_mpi_mem_handle));

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_mpi_mem_handle_deserialize(na_class_t NA_UNUSED *na_class,
        na_mem_handle_t *mem_handle, const void *buf, na_size_t buf_size)
{
    struct na_mpi_mem_handle *na_mpi_mem_handle = NULL;
    na_return_t ret = NA_SUCCESS;

    if (buf_size < sizeof(struct na_mpi_mem_handle)) {
        NA_LOG_ERROR("Buffer size too small for deserializing handle");
        ret = NA_SIZE_ERROR;
        goto done;
    }

    na_mpi_mem_handle = (struct na_mpi_mem_handle*)
            malloc(sizeof(struct na_mpi_mem_handle));
    if (!na_mpi_mem_handle) {
          NA_LOG_ERROR("Could not allocate NA MPI memory handle");
          ret = NA_NOMEM_ERROR;
          goto done;
    }

    /* Copy struct */
    memcpy(na_mpi_mem_handle, buf, sizeof(struct na_mpi_mem_handle));

    *mem_handle = (na_mem_handle_t) na_mpi_mem_handle;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_mpi_put(na_class_t *na_class, na_context_t *context, na_cb_t callback,
        void *arg, na_mem_handle_t local_mem_handle, na_offset_t local_offset,
        na_mem_handle_t remote_mem_handle, na_offset_t remote_offset,
        na_size_t length, na_addr_t remote_addr, na_op_id_t *op_id)
{
    struct na_mpi_mem_handle *mpi_local_mem_handle =
            (struct na_mpi_mem_handle *) local_mem_handle;
    MPI_Aint mpi_local_offset = (MPI_Aint) local_offset;
    struct na_mpi_mem_handle *mpi_remote_mem_handle =
            (struct na_mpi_mem_handle *) remote_mem_handle;
    MPI_Aint mpi_remote_offset = (MPI_Aint) remote_offset;
    struct na_mpi_addr *na_mpi_addr = (struct na_mpi_addr *) remote_addr;
    int mpi_length = (int) length; /* TODO careful here that we don't send more
                                    * than 2GB */
    struct na_mpi_op_id *na_mpi_op_id = NULL;
    struct na_mpi_rma_info *na_mpi_rma_info = NULL;
    na_return_t ret = NA_SUCCESS;
    int mpi_ret;

    if (mpi_remote_mem_handle->attr != NA_MEM_READWRITE) {
        NA_LOG_ERROR("Registered memory requires write permission");
        ret = NA_PERMISSION_ERROR;
        goto done;
    }

    /* Allocate op_id */
    na_mpi_op_id = (struct na_mpi_op_id *) malloc(sizeof(struct na_mpi_op_id));
    if (!na_mpi_op_id) {
        NA_LOG_ERROR("Could not allocate NA MPI operation ID");
        ret = NA_NOMEM_ERROR;
        goto done;
    }
    na_mpi_op_id->context = context;
    na_mpi_op_id->type = NA_CB_PUT;
    na_mpi_op_id->callback = callback;
    na_mpi_op_id->arg = arg;
    na_mpi_op_id->completed = NA_FALSE;
    na_mpi_op_id->info.put.rma_request = MPI_REQUEST_NULL;
    na_mpi_op_id->info.put.data_request = MPI_REQUEST_NULL;
    na_mpi_op_id->info.put.internal_progress = NA_FALSE;
    na_mpi_op_id->info.put.rma_info = NULL;

    /* Allocate rma info (use calloc to avoid uninitialized transfer) */
    na_mpi_rma_info =
            (struct na_mpi_rma_info *) calloc(1, sizeof(struct na_mpi_rma_info));
    if (!na_mpi_rma_info) {
        NA_LOG_ERROR("Could not allocate NA MPI RMA info");
        ret = NA_NOMEM_ERROR;
        goto done;
    }
    na_mpi_rma_info->op = NA_MPI_RMA_PUT;
    na_mpi_rma_info->base = mpi_remote_mem_handle->base;
    na_mpi_rma_info->disp = mpi_remote_offset;
    na_mpi_rma_info->count = mpi_length;
    na_mpi_rma_info->tag = na_mpi_gen_rma_tag(na_class);
    na_mpi_op_id->info.put.rma_info = na_mpi_rma_info;

    /* Post the MPI send request */
    mpi_ret = MPI_Isend(na_mpi_rma_info, sizeof(struct na_mpi_rma_info),
            MPI_BYTE, na_mpi_addr->rank, NA_MPI_RMA_REQUEST_TAG,
            na_mpi_addr->rma_comm, &na_mpi_op_id->info.put.rma_request);
    if (mpi_ret != MPI_SUCCESS) {
        NA_LOG_ERROR("MPI_Isend() failed");
        ret = NA_PROTOCOL_ERROR;
        goto done;
    }

    /* Simply do a non blocking synchronous send */
    mpi_ret = MPI_Issend((char*) mpi_local_mem_handle->base + mpi_local_offset,
            mpi_length, MPI_BYTE, na_mpi_addr->rank, na_mpi_rma_info->tag,
            na_mpi_addr->rma_comm, &na_mpi_op_id->info.put.data_request);
    if (mpi_ret != MPI_SUCCESS) {
        NA_LOG_ERROR("MPI_Issend() failed");
        ret = NA_PROTOCOL_ERROR;
        goto done;
    }

    /* Append op_id to op_id list and assign op_id */
    ret = na_mpi_op_id_list_append(na_class, na_mpi_op_id);
    *op_id = (na_op_id_t) na_mpi_op_id;

done:
    if (ret != NA_SUCCESS) {
        free(na_mpi_op_id);
        free(na_mpi_rma_info);
    }
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_mpi_get(na_class_t *na_class, na_context_t *context, na_cb_t callback,
        void *arg, na_mem_handle_t local_mem_handle, na_offset_t local_offset,
        na_mem_handle_t remote_mem_handle, na_offset_t remote_offset,
        na_size_t length, na_addr_t remote_addr, na_op_id_t *op_id)
{
    struct na_mpi_mem_handle *mpi_local_mem_handle =
            (struct na_mpi_mem_handle *) local_mem_handle;
    MPI_Aint mpi_local_offset = (MPI_Aint) local_offset;
    struct na_mpi_mem_handle *mpi_remote_mem_handle =
            (struct na_mpi_mem_handle *) remote_mem_handle;
    MPI_Aint mpi_remote_offset = (MPI_Aint) remote_offset;
    struct na_mpi_addr *na_mpi_addr = (struct na_mpi_addr *) remote_addr;
    int mpi_length = (int) length; /* TODO careful here that we don't send more
                                    * than 2GB */
    struct na_mpi_op_id *na_mpi_op_id = NULL;
    struct na_mpi_rma_info *na_mpi_rma_info = NULL;
    na_return_t ret = NA_SUCCESS;
    int mpi_ret;

    /* Allocate op_id */
    na_mpi_op_id = (struct na_mpi_op_id *) malloc(sizeof(struct na_mpi_op_id));
    if (!na_mpi_op_id) {
        NA_LOG_ERROR("Could not allocate NA MPI operation ID");
        ret = NA_NOMEM_ERROR;
        goto done;
    }
    na_mpi_op_id->context = context;
    na_mpi_op_id->type = NA_CB_GET;
    na_mpi_op_id->callback = callback;
    na_mpi_op_id->arg = arg;
    na_mpi_op_id->completed = NA_FALSE;
    na_mpi_op_id->info.get.rma_request = MPI_REQUEST_NULL;
    na_mpi_op_id->info.get.data_request = MPI_REQUEST_NULL;
    na_mpi_op_id->info.put.internal_progress = NA_FALSE;
    na_mpi_op_id->info.get.rma_info = NULL;

    /* Allocate rma info (use calloc to avoid uninitialized transfer) */
    na_mpi_rma_info =
            (struct na_mpi_rma_info *) calloc(1, sizeof(struct na_mpi_rma_info));
    if (!na_mpi_rma_info) {
        NA_LOG_ERROR("Could not allocate NA MPI RMA info");
        ret = NA_NOMEM_ERROR;
        goto done;
    }
    na_mpi_rma_info->op = NA_MPI_RMA_GET;
    na_mpi_rma_info->base = mpi_remote_mem_handle->base;
    na_mpi_rma_info->disp = mpi_remote_offset;
    na_mpi_rma_info->count = mpi_length;
    na_mpi_rma_info->tag = na_mpi_gen_rma_tag(na_class);
    na_mpi_op_id->info.get.rma_info = na_mpi_rma_info;

    /* Post the MPI send request */
    mpi_ret = MPI_Isend(na_mpi_rma_info, sizeof(struct na_mpi_rma_info),
            MPI_BYTE, na_mpi_addr->rank, NA_MPI_RMA_REQUEST_TAG,
            na_mpi_addr->rma_comm, &na_mpi_op_id->info.get.rma_request);
    if (mpi_ret != MPI_SUCCESS) {
        NA_LOG_ERROR("MPI_Isend() failed");
        ret = NA_PROTOCOL_ERROR;
        goto done;
    }

    /* Simply do an asynchronous recv */
    mpi_ret = MPI_Irecv((char*) mpi_local_mem_handle->base + mpi_local_offset,
            mpi_length, MPI_BYTE, na_mpi_addr->rank, na_mpi_rma_info->tag,
            na_mpi_addr->rma_comm, &na_mpi_op_id->info.get.data_request);
    if (mpi_ret != MPI_SUCCESS) {
        NA_LOG_ERROR("MPI_Irecv() failed");
        ret = NA_PROTOCOL_ERROR;
        goto done;
    }

    /* Append op_id to op_id list and assign op_id */
    ret = na_mpi_op_id_list_append(na_class, na_mpi_op_id);
    *op_id = (na_op_id_t) na_mpi_op_id;

done:
    if (ret != NA_SUCCESS) {
        free(na_mpi_op_id);
        free(na_mpi_rma_info);
    }
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_mpi_progress(na_class_t *na_class, na_context_t *context,
        unsigned int timeout)
{
    double remaining = timeout / 1000.0; /* Convert timeout in ms into seconds */
    na_return_t ret = NA_SUCCESS;

    do {
        hg_time_t t1, t2;
        na_bool_t progressed = NA_FALSE;

        hg_time_get_current(&t1);

        /* Try to make unexpected progress */
        ret = na_mpi_progress_unexpected(na_class, context, 0, &progressed);
        if (ret != NA_SUCCESS) {
            NA_LOG_ERROR("Could not make unexpected progress");
            goto done;
        }

        if (progressed) break;

        /* Try to make expected progress */
        ret = na_mpi_progress_expected(na_class, context,
                (unsigned int) (remaining * 1000), &progressed);
        if (ret != NA_SUCCESS) {
            NA_LOG_ERROR("Could not make expected progress");
            goto done;
        }

        if (progressed) break;

        hg_time_get_current(&t2);
        remaining -= hg_time_to_double(hg_time_subtract(t2, t1));
    } while (remaining > 0);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_mpi_progress_unexpected(na_class_t *na_class, na_context_t *context,
        unsigned int NA_UNUSED timeout, na_bool_t *progressed)
{
    struct na_mpi_addr *probe_addr = NULL;
    na_return_t ret = NA_SUCCESS;
    na_bool_t unexpected_progressed = NA_FALSE;
    int mpi_ret;

    /* Process list of communicators */
    hg_thread_mutex_lock(&NA_MPI_PRIVATE_DATA(na_class)->remote_list_mutex);

    if (hg_list_length(NA_MPI_PRIVATE_DATA(na_class)->remote_list)) {
        hg_list_entry_t *entry = NA_MPI_PRIVATE_DATA(na_class)->remote_list;

        while (entry) {
            MPI_Status status1, status2;
            int flag = 0;
            probe_addr = (struct na_mpi_addr *) hg_list_data(entry);

            /* First look for user unexpected message */
            mpi_ret = MPI_Iprobe(MPI_ANY_SOURCE, MPI_ANY_TAG, probe_addr->comm,
                    &flag, &status1);
            if (mpi_ret != MPI_SUCCESS) {
                NA_LOG_ERROR("MPI_Iprobe() failed");
                ret = NA_PROTOCOL_ERROR;
                goto done;
            }

            if (flag) {
                ret = na_mpi_progress_unexpected_msg(na_class, context,
                        probe_addr, &status1, &unexpected_progressed);
                if (ret != NA_SUCCESS) {
                    NA_LOG_ERROR("Could not make unexpected MSG progress");
                    goto done;
                }
                if (unexpected_progressed) break;
            }

            /* Look for internal unexpected RMA requests */
            mpi_ret = MPI_Iprobe(probe_addr->rank, NA_MPI_RMA_REQUEST_TAG,
                    probe_addr->rma_comm, &flag, &status2);
            if (mpi_ret != MPI_SUCCESS) {
                NA_LOG_ERROR("MPI_Iprobe() failed");
                ret = NA_PROTOCOL_ERROR;
                goto done;
            }

            if (flag) {
                ret = na_mpi_progress_unexpected_rma(na_class, context,
                        probe_addr, &status2, &unexpected_progressed);
                if (ret != NA_SUCCESS) {
                    NA_LOG_ERROR("Could not make unexpected RMA progress");
                    goto done;
                }
                if (unexpected_progressed) break;
            }

            entry = hg_list_next(entry);
        }
    }

    hg_thread_mutex_unlock(&NA_MPI_PRIVATE_DATA(na_class)->remote_list_mutex);

    *progressed = unexpected_progressed;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_mpi_progress_unexpected_msg(na_class_t *na_class, na_context_t NA_UNUSED *context,
        struct na_mpi_addr *na_mpi_addr, const MPI_Status *status,
        na_bool_t *progressed)
{
    struct na_mpi_op_id *na_mpi_op_id = NULL;
    int unexpected_buf_size = 0;
    na_return_t ret = NA_SUCCESS;
    int mpi_ret;

    MPI_Get_count(status, MPI_BYTE, &unexpected_buf_size);
    if (unexpected_buf_size > (int)
            na_mpi_msg_get_max_unexpected_size(na_class)) {
        NA_LOG_ERROR("Exceeding unexpected MSG size");
        ret = NA_SIZE_ERROR;
        goto done;
    }

    /* Try to pop an unexpected recv op id */
    na_mpi_op_id = na_mpi_msg_unexpected_op_pop(na_class);
    if (!na_mpi_op_id) {
        /* Can't process it since nobody has posted an unexpected recv yet */
        *progressed = NA_FALSE;
        goto done;
    }

    mpi_ret = MPI_Recv(na_mpi_op_id->info.recv_unexpected.buf,
            na_mpi_op_id->info.recv_unexpected.buf_size, MPI_BYTE,
            status->MPI_SOURCE, status->MPI_TAG, na_mpi_addr->comm,
            MPI_STATUS_IGNORE);
    if (mpi_ret != MPI_SUCCESS) {
        NA_LOG_ERROR("MPI_Recv() failed");
        ret = NA_PROTOCOL_ERROR;
        goto done;
    }

    na_mpi_op_id->info.recv_unexpected.remote_addr = na_mpi_addr;
    memcpy(&na_mpi_op_id->info.recv_unexpected.status, status,
            sizeof(MPI_Status));
    ret = na_mpi_complete(na_mpi_op_id);
    if (ret != NA_SUCCESS) goto done;

    *progressed = NA_TRUE;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_mpi_progress_unexpected_rma(na_class_t *na_class, na_context_t *context,
        struct na_mpi_addr *na_mpi_addr, const MPI_Status *status,
        na_bool_t *progressed)
{
    struct na_mpi_rma_info *na_mpi_rma_info = NULL;
    struct na_mpi_op_id *na_mpi_op_id = NULL;
    int unexpected_buf_size = 0;
    na_return_t ret = NA_SUCCESS;
    int mpi_ret;

    MPI_Get_count(status, MPI_BYTE, &unexpected_buf_size);
    if (unexpected_buf_size != sizeof(struct na_mpi_rma_info)) {
        NA_LOG_ERROR("Unexpected message size does not match RMA info struct");
        ret = NA_SIZE_ERROR;
        goto done;
    }

    /* Allocate rma info */
    na_mpi_rma_info =
            (struct na_mpi_rma_info *) malloc(sizeof(struct na_mpi_rma_info));
    if (!na_mpi_rma_info) {
        NA_LOG_ERROR("Could not allocate NA MPI RMA info");
        ret = NA_NOMEM_ERROR;
        goto done;
    }

    /* Recv message (already arrived) */
    mpi_ret = MPI_Recv(na_mpi_rma_info, sizeof(struct na_mpi_rma_info),
            MPI_BYTE, status->MPI_SOURCE, status->MPI_TAG,
            na_mpi_addr->rma_comm, MPI_STATUS_IGNORE);
    if (mpi_ret != MPI_SUCCESS) {
        NA_LOG_ERROR("MPI_Recv() failed");
        ret = NA_PROTOCOL_ERROR;
        goto done;
    }

    /* Allocate na_op_id */
    na_mpi_op_id = (struct na_mpi_op_id *) malloc(sizeof(struct na_mpi_op_id));
    if (!na_mpi_op_id) {
        NA_LOG_ERROR("Could not allocate NA MPI operation ID");
        ret = NA_NOMEM_ERROR;
        goto done;
    }
    /* This is an internal operation so no user callback/arg */
    na_mpi_op_id->context = context;
    na_mpi_op_id->callback = NULL;
    na_mpi_op_id->arg = NULL;
    na_mpi_op_id->completed = NA_FALSE;

    switch (na_mpi_rma_info->op) {
        /* Remote wants to do a put so wait in a recv */
        case NA_MPI_RMA_PUT:
            na_mpi_op_id->type = NA_CB_PUT;
            na_mpi_op_id->info.put.rma_request = MPI_REQUEST_NULL;
            na_mpi_op_id->info.put.data_request = MPI_REQUEST_NULL;
            na_mpi_op_id->info.put.internal_progress = NA_TRUE;
            na_mpi_op_id->info.put.rma_info = na_mpi_rma_info;

            mpi_ret = MPI_Irecv(
                    (char*) na_mpi_rma_info->base + na_mpi_rma_info->disp,
                    na_mpi_rma_info->count, MPI_BYTE, na_mpi_addr->rank,
                    na_mpi_rma_info->tag, na_mpi_addr->rma_comm,
                    &na_mpi_op_id->info.put.data_request);
            if (mpi_ret != MPI_SUCCESS) {
                NA_LOG_ERROR("MPI_Irecv() failed");
                ret = NA_PROTOCOL_ERROR;
                goto done;
            }
            break;

            /* Remote wants to do a get so do a send */
        case NA_MPI_RMA_GET:
            na_mpi_op_id->type = NA_CB_GET;
            na_mpi_op_id->info.get.rma_request = MPI_REQUEST_NULL;
            na_mpi_op_id->info.get.data_request = MPI_REQUEST_NULL;
            na_mpi_op_id->info.get.internal_progress = NA_TRUE;
            na_mpi_op_id->info.get.rma_info = na_mpi_rma_info;

            mpi_ret = MPI_Isend(
                    (char*) na_mpi_rma_info->base + na_mpi_rma_info->disp,
                    na_mpi_rma_info->count, MPI_BYTE, na_mpi_addr->rank,
                    na_mpi_rma_info->tag, na_mpi_addr->rma_comm,
                    &na_mpi_op_id->info.get.data_request);
            if (mpi_ret != MPI_SUCCESS) {
                NA_LOG_ERROR("MPI_Isend() failed");
                ret = NA_PROTOCOL_ERROR;
                goto done;
            }
            break;

        default:
            NA_LOG_ERROR("Operation not supported");
            break;
    }

    /* Add op_id to list */
    ret = na_mpi_op_id_list_append(na_class, na_mpi_op_id);
    if (ret != NA_SUCCESS) {
        goto done;
    }
    *progressed = NA_TRUE;

done:
    if (ret != NA_SUCCESS) {
        free(na_mpi_op_id);
        free(na_mpi_rma_info);
    }
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_mpi_progress_expected(na_class_t *na_class, na_context_t NA_UNUSED *context,
        unsigned int NA_UNUSED timeout, na_bool_t *progressed)
{
    hg_list_entry_t *entry = NULL;
    struct na_mpi_op_id *na_mpi_op_id = NULL;
    MPI_Request *request = NULL;
    na_bool_t expected_progressed = NA_FALSE;
    na_return_t ret = NA_SUCCESS;
    int mpi_ret = 0;

    hg_thread_mutex_lock(&NA_MPI_PRIVATE_DATA(na_class)->op_id_list_mutex);

    if (!hg_list_length(NA_MPI_PRIVATE_DATA(na_class)->op_id_list)) {
        *progressed = NA_FALSE;
        goto done;
    }

    entry = NA_MPI_PRIVATE_DATA(na_class)->op_id_list;

    while (entry) {
        na_bool_t internal = NA_FALSE; /* Only used to complete internal ops */
        struct na_mpi_rma_info **rma_info = NULL;
        na_bool_t complete_op_id = NA_TRUE;
        int flag = 0;
        MPI_Status *status = MPI_STATUS_IGNORE;

        na_mpi_op_id = (struct na_mpi_op_id *) hg_list_data(entry);

        /* If the op_id is marked as completed, something is wrong */
        if (na_mpi_op_id->completed) {
            NA_LOG_ERROR("Op ID should not have completed yet");
            ret = NA_PROTOCOL_ERROR;
            goto done;
        }

        switch (na_mpi_op_id->type) {
            case NA_CB_LOOKUP:
                NA_LOG_ERROR("Should not complete lookup here");
                break;
            case NA_CB_RECV_UNEXPECTED:
                NA_LOG_ERROR("Should not complete unexpected recv here");
                break;
            case NA_CB_SEND_UNEXPECTED:
                request = &na_mpi_op_id->info.send_unexpected.data_request;
                break;
            case NA_CB_RECV_EXPECTED:
                status = &na_mpi_op_id->info.recv_expected.status;
                request = &na_mpi_op_id->info.recv_expected.data_request;
                break;
            case NA_CB_SEND_EXPECTED:
                request = &na_mpi_op_id->info.send_expected.data_request;
                break;
            case NA_CB_PUT:
                if (na_mpi_op_id->info.put.internal_progress) {
                    request = &na_mpi_op_id->info.put.data_request;
                    rma_info = &na_mpi_op_id->info.put.rma_info;
                    internal = NA_TRUE;
                } else {
                    request = &na_mpi_op_id->info.put.rma_request;
                    if (*request != MPI_REQUEST_NULL) {
                        complete_op_id = NA_FALSE;
                    } else {
                        request = &na_mpi_op_id->info.put.data_request;
                    }
                }
                break;
            case NA_CB_GET:
                if (na_mpi_op_id->info.get.internal_progress) {
                    request = &na_mpi_op_id->info.get.data_request;
                    rma_info = &na_mpi_op_id->info.get.rma_info;
                    internal = NA_TRUE;
                } else {
                    request = &na_mpi_op_id->info.get.rma_request;
                    if (*request != MPI_REQUEST_NULL) {
                        complete_op_id = NA_FALSE;
                    } else {
                        request = &na_mpi_op_id->info.get.data_request;
                    }
                }
                break;
            default:
                NA_LOG_ERROR("Unknown type of operation ID");
                ret = NA_PROTOCOL_ERROR;
                goto done;
        }

        /* If request is MPI_REQUEST_NULL, the operation should be completed */
        if (!request || (request && (*request == MPI_REQUEST_NULL))) {
            NA_LOG_ERROR("NULL request found");
            ret = NA_PROTOCOL_ERROR;
            goto done;
        }

        mpi_ret = MPI_Test(request, &flag, status);
        if (mpi_ret != MPI_SUCCESS) {
            NA_LOG_ERROR("MPI_Test() failed");
            ret = NA_PROTOCOL_ERROR;
            goto done;
        }
        if (!flag) {
            entry = hg_list_next(entry);
            continue;
        }

        *request = MPI_REQUEST_NULL;

        /* If internal operation call release directly otherwise add callback
         * to completion queue */
        if (internal) {
            na_mpi_op_id->completed = NA_TRUE;

            free(*rma_info);
            *rma_info = NULL;
            na_mpi_release(NULL, na_mpi_op_id);
        } else {
            if (!complete_op_id) {
                entry = hg_list_next(entry);
                continue;
            }
            ret = na_mpi_complete(na_mpi_op_id);
        }
        /* Remove entry from list */
        hg_list_remove_entry(&NA_MPI_PRIVATE_DATA(na_class)->op_id_list,
                entry);
        expected_progressed = NA_TRUE;
        break;
    }

    *progressed = expected_progressed;

done:
    hg_thread_mutex_unlock(&NA_MPI_PRIVATE_DATA(na_class)->op_id_list_mutex);
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_mpi_complete(struct na_mpi_op_id *na_mpi_op_id)
{
    struct na_cb_info *callback_info = NULL;
    na_return_t ret = NA_SUCCESS;
    int mpi_ret;

    /* Mark op id as completed */
    na_mpi_op_id->completed = NA_TRUE;

    /* Allocate callback info */
    callback_info = (struct na_cb_info *) malloc(sizeof(struct na_cb_info));
    if (!callback_info) {
        NA_LOG_ERROR("Could not allocate callback info");
        ret = NA_NOMEM_ERROR;
        goto done;
    }
    callback_info->arg = na_mpi_op_id->arg;
    callback_info->ret = ret;
    callback_info->type = na_mpi_op_id->type;

    switch (na_mpi_op_id->type) {
        case NA_CB_LOOKUP:
            callback_info->info.lookup.addr = na_mpi_op_id->info.lookup.addr;
            break;
        case NA_CB_SEND_UNEXPECTED:
            break;
        case NA_CB_RECV_UNEXPECTED:
        {
            struct na_mpi_addr *na_mpi_addr = NULL;
            struct na_mpi_addr *na_mpi_remote_addr = NULL;
            MPI_Status *status;
            int recv_size;

            na_mpi_remote_addr = na_mpi_op_id->info.recv_unexpected.remote_addr;
            status = &na_mpi_op_id->info.recv_unexpected.status;

            mpi_ret = MPI_Get_count(status, MPI_BYTE, &recv_size);
            if (mpi_ret != MPI_SUCCESS) {
                NA_LOG_ERROR("MPI_Get_count() failed");
                ret = NA_PROTOCOL_ERROR;
                goto done;
            }

            /* Allocate addr */
            na_mpi_addr = (struct na_mpi_addr *) malloc(
                    sizeof(struct na_mpi_addr));
            if (!na_mpi_addr) {
                NA_LOG_ERROR("Could not allocate MPI addr");
                ret = NA_NOMEM_ERROR;
                goto done;
            }
            na_mpi_addr->comm = na_mpi_remote_addr->comm;
            na_mpi_addr->rma_comm = na_mpi_remote_addr->rma_comm;
            na_mpi_addr->rank = status->MPI_SOURCE;
            na_mpi_addr->unexpected = NA_TRUE;
            na_mpi_addr->self = NA_FALSE;
            na_mpi_addr->dynamic = NA_TRUE;
            memset(na_mpi_addr->port_name, '\0', MPI_MAX_PORT_NAME);
            /* Can only write debug info here */
            sprintf(na_mpi_addr->port_name, "comm: %d rank:%d\n",
                    (int) na_mpi_addr->comm, na_mpi_addr->rank);

            /* Fill callback info */
            callback_info->info.recv_unexpected.actual_buf_size =
                    (na_size_t) recv_size;
            callback_info->info.recv_unexpected.source =
                    (na_addr_t) na_mpi_addr;
            callback_info->info.recv_unexpected.tag =
                    (na_tag_t) status->MPI_TAG;
        }
            break;
        case NA_CB_SEND_EXPECTED:
            break;
        case NA_CB_RECV_EXPECTED:
            /* Check buf_size and actual_size */
            mpi_ret = MPI_Get_count(&na_mpi_op_id->info.recv_expected.status,
                    MPI_BYTE, &na_mpi_op_id->info.recv_expected.actual_size);
            if (mpi_ret != MPI_SUCCESS) {
                NA_LOG_ERROR("MPI_Get_count() failed");
                ret = NA_PROTOCOL_ERROR;
                goto done;
            }
            if (na_mpi_op_id->info.recv_expected.actual_size
                    != na_mpi_op_id->info.recv_expected.buf_size) {
                NA_LOG_ERROR("Buffer size and actual transfer size do not match");
                ret = NA_SIZE_ERROR;
                goto done;
            }
            break;
        case NA_CB_PUT:
            /* Transfer is now done so free RMA info */
            free(na_mpi_op_id->info.put.rma_info);
            na_mpi_op_id->info.put.rma_info = NULL;
            break;
        case NA_CB_GET:
            /* Transfer is now done so free RMA info */
            free(na_mpi_op_id->info.get.rma_info);
            na_mpi_op_id->info.get.rma_info = NULL;
            break;
        default:
            NA_LOG_ERROR("Operation not supported");
            ret = NA_INVALID_PARAM;
            break;
    }

    ret = na_cb_completion_add(na_mpi_op_id->context, na_mpi_op_id->callback,
            callback_info, &na_mpi_release, na_mpi_op_id);
    if (ret != NA_SUCCESS) {
        NA_LOG_ERROR("Could not add callback to completion queue");
        goto done;
    }

done:
    if (ret != NA_SUCCESS) {
        free(callback_info);
    }
    return ret;
}

/*---------------------------------------------------------------------------*/
static void
na_mpi_release(struct na_cb_info *callback_info, void *arg)
{
    struct na_mpi_op_id *na_mpi_op_id = (struct na_mpi_op_id *) arg;

    if (na_mpi_op_id && !na_mpi_op_id->completed) {
        NA_LOG_ERROR("Releasing resources from an uncompleted operation");
    }
    free(callback_info);
    free(na_mpi_op_id);
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_mpi_cancel(na_class_t *na_class, na_context_t NA_UNUSED *context,
        na_op_id_t op_id)
{
    struct na_mpi_op_id *na_mpi_op_id = (struct na_mpi_op_id *) op_id;
    na_return_t ret = NA_SUCCESS;
    int mpi_ret;

    /* TODO make this atomic */
    if (na_mpi_op_id->completed) goto done;

    switch (na_mpi_op_id->type) {
        case NA_CB_LOOKUP:
            /* Nothing for now */
            break;
        case NA_CB_SEND_UNEXPECTED:
            mpi_ret = MPI_Cancel(&na_mpi_op_id->info.send_unexpected.data_request);
            if (mpi_ret != MPI_SUCCESS) {
                NA_LOG_ERROR("MPI_Cancel() failed");
                ret = NA_PROTOCOL_ERROR;
                goto done;
            }
            break;
        case NA_CB_RECV_UNEXPECTED:
        {
            struct na_mpi_op_id *na_mpi_pop_op_id = NULL;

            /* Must remove op_id from unexpected op_id queue */
            while (na_mpi_pop_op_id != na_mpi_op_id) {
                na_mpi_pop_op_id = na_mpi_msg_unexpected_op_pop(na_class);

                /* Push back unexpected op_id to queue if it does not match */
                if (na_mpi_pop_op_id != na_mpi_op_id) {
                    na_mpi_msg_unexpected_op_push(na_class, na_mpi_pop_op_id);
                }
            }
        }
            break;
        case NA_CB_SEND_EXPECTED:
            mpi_ret = MPI_Cancel(&na_mpi_op_id->info.send_expected.data_request);
            if (mpi_ret != MPI_SUCCESS) {
                NA_LOG_ERROR("MPI_Cancel() failed");
                ret = NA_PROTOCOL_ERROR;
                goto done;
            }
            break;
        case NA_CB_RECV_EXPECTED:
            mpi_ret = MPI_Cancel(&na_mpi_op_id->info.recv_expected.data_request);
            if (mpi_ret != MPI_SUCCESS) {
                NA_LOG_ERROR("MPI_Cancel() failed");
                ret = NA_PROTOCOL_ERROR;
                goto done;
            }
            break;
        case NA_CB_PUT:
            /* TODO */
            break;
        case NA_CB_GET:
            /* TODO */
            break;
        default:
            NA_LOG_ERROR("Operation not supported");
            ret = NA_INVALID_PARAM;
            break;
    }
    free(na_mpi_op_id);

done:
    return ret;
}
