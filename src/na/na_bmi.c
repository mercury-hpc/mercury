/*
 * Copyright (C) 2013-2017 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#include "na_private.h"
#include "na_error.h"

#include "mercury_queue.h"
#include "mercury_thread_mutex.h"
#include "mercury_time.h"
#include "mercury_atomic.h"

#include <bmi.h>

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

/****************/
/* Local Macros */
/****************/

/* Max addr name */
#define NA_BMI_MAX_ADDR_NAME 256

/* Default port */
#define NA_BMI_DEFAULT_PORT 22222
#define NA_BMI_DEFAULT_PORT_TRIES 128

/* Msg sizes */
#define NA_BMI_UNEXPECTED_SIZE 4096
#define NA_BMI_EXPECTED_SIZE   NA_BMI_UNEXPECTED_SIZE

/* Max tag */
#define NA_BMI_MAX_TAG (NA_TAG_UB >> 2)

/* Default tag used for one-sided over two-sided */
#define NA_BMI_RMA_REQUEST_TAG (NA_BMI_MAX_TAG + 1)
#define NA_BMI_RMA_TAG (NA_BMI_RMA_REQUEST_TAG + 1)
#define NA_BMI_MAX_RMA_TAG (NA_TAG_UB >> 1)

#define NA_BMI_PRIVATE_DATA(na_class) \
    ((struct na_bmi_private_data *)(na_class->private_data))

#define NA_BMI_CANCEL_R (1 << 0)
#define NA_BMI_CANCEL_C (1 << 1)

/************************************/
/* Local Type and Struct Definition */
/************************************/

/* na_bmi_addr */
struct na_bmi_addr {
    BMI_addr_t bmi_addr;   /* BMI addr */
    na_bool_t  unexpected; /* Address generated from unexpected recv */
    na_bool_t  self;       /* Boolean for self */
    hg_atomic_int32_t ref_count; /* Ref count */
};

struct na_bmi_unexpected_info {
    struct BMI_unexpected_info info;
    HG_QUEUE_ENTRY(na_bmi_unexpected_info) entry;
};

struct na_bmi_mem_handle {
    na_ptr_t base;     /* Initial address of memory */
    na_size_t size;    /* Size of memory */
    na_uint8_t attr;   /* Flag of operation access */
};

typedef enum na_bmi_rma_op {
    NA_BMI_RMA_PUT, /* Request a put operation */
    NA_BMI_RMA_GET  /* Request a get operation */
} na_bmi_rma_op_t;

struct na_bmi_rma_info {
    na_bmi_rma_op_t op;           /* Operation requested */
    na_ptr_t base;                /* Initial address of memory */
    bmi_size_t disp;              /* Offset from initial address */
    bmi_size_t count;             /* Number of entries */
    bmi_msg_tag_t transfer_tag;   /* Tag used for the data transfer */
    bmi_msg_tag_t completion_tag; /* Tag used for completion ack */
};

struct na_bmi_info_lookup {
    na_addr_t addr;
};

struct na_bmi_info_send_unexpected {
    bmi_op_id_t op_id; /* BMI operation ID */
};

struct na_bmi_info_recv_unexpected {
    void *buf;
    bmi_size_t buf_size;
    struct BMI_unexpected_info *unexpected_info;
};

struct na_bmi_info_send_expected {
    bmi_op_id_t op_id; /* BMI operation ID */
};

struct na_bmi_info_recv_expected {
    bmi_op_id_t op_id; /* BMI operation ID */
    bmi_size_t buf_size;
    bmi_size_t actual_size;
};

struct na_bmi_info_put {
    bmi_op_id_t request_op_id;
    bmi_op_id_t transfer_op_id;
    hg_atomic_int32_t transfer_completed;
    bmi_size_t  transfer_actual_size;
    bmi_op_id_t completion_op_id;
    na_bool_t   completion_flag;
    bmi_size_t  completion_actual_size;
    na_bool_t   internal_progress;
    BMI_addr_t  remote_addr;
    struct na_bmi_rma_info *rma_info;
};

struct na_bmi_info_get {
    bmi_op_id_t request_op_id;
    bmi_op_id_t transfer_op_id;
    bmi_size_t  transfer_actual_size;
    na_bool_t   internal_progress;
    BMI_addr_t  remote_addr;
    struct na_bmi_rma_info *rma_info;
};

struct na_bmi_op_id {
    na_context_t *context;
    na_cb_type_t type;
    na_cb_t callback;               /* Callback */
    void *arg;
    hg_atomic_int32_t ref_count;    /* Ref count */
    hg_atomic_int32_t completed;    /* Operation completed */
    uint64_t cancel;
    union {
      struct na_bmi_info_lookup lookup;
      struct na_bmi_info_send_unexpected send_unexpected;
      struct na_bmi_info_recv_unexpected recv_unexpected;
      struct na_bmi_info_send_expected send_expected;
      struct na_bmi_info_recv_expected recv_expected;
      struct na_bmi_info_put put;
      struct na_bmi_info_get get;
    } info;
    struct na_cb_completion_data completion_data;
    HG_QUEUE_ENTRY(na_bmi_op_id) entry;
};

struct na_bmi_private_data {
    char *listen_addr;                               /* Listen addr */
    hg_thread_mutex_t test_unexpected_mutex;         /* Mutex */
    HG_QUEUE_HEAD(na_bmi_unexpected_info) unexpected_msg_queue; /* Unexpected message queue */
    hg_thread_mutex_t unexpected_msg_queue_mutex;    /* Mutex */
    HG_QUEUE_HEAD(na_bmi_op_id) unexpected_op_queue; /* Unexpected op queue */
    hg_thread_mutex_t unexpected_op_queue_mutex;     /* Mutex */
    hg_atomic_int32_t rma_tag;                       /* Atomic RMA tag value */
};

/********************/
/* Local Prototypes */
/********************/

/* check_protocol */
static na_bool_t
na_bmi_check_protocol(
        const char *protocol_name
        );

/* initialize */
static na_return_t
na_bmi_initialize(
        na_class_t           *na_class,
        const struct na_info *na_info,
        na_bool_t             listen
        );

/**
 * initialize
 *
 * \param method_list [IN]      (Optional) list of available methods depend on
 *                              BMI configuration, e.g., "bmi_tcp", ...
 * \param listen_addr [IN]      (Optional) e.g., "tcp://127.0.0.1:22222"
 * \param flags [IN]            (Optional) supported flags:
 *                                - BMI_INIT_SERVER
 *                                - BMI_TCP_BIND_SPECIFIC
 *                                - BMI_AUTO_REF_COUNT
 *                                - ... see BMI header file
 */
static na_return_t
na_bmi_init(
        na_class_t *na_class,
        const char *method_list,
        const char *listen_addr,
        int         flags
        );

/* finalize */
static na_return_t
na_bmi_finalize(
        na_class_t *na_class
        );

static na_return_t
na_bmi_context_create(
        na_class_t          *na_class,
        void               **context
        );

static na_return_t
na_bmi_context_destroy(
        na_class_t          *na_class,
        void                *context
        );

/* op_create */
static na_op_id_t
na_bmi_op_create(
        na_class_t      *na_class
        );

/* op_destroy */
static na_return_t
na_bmi_op_destroy(
        na_class_t      *na_class,
        na_op_id_t       op_id
        );

/* addr_lookup */
static na_return_t
na_bmi_addr_lookup(
        na_class_t   *na_class,
        na_context_t *context,
        na_cb_t       callback,
        void         *arg,
        const char   *name,
        na_op_id_t   *op_id
        );

/* addr_free */
static na_return_t
na_bmi_addr_free(
        na_class_t *na_class,
        na_addr_t   addr
        );

/* addr_self */
static na_return_t
na_bmi_addr_self(
        na_class_t *na_class,
        na_addr_t  *addr
        );

/* addr_dup */
static na_return_t
na_bmi_addr_dup(
        na_class_t *na_class,
        na_addr_t   addr,
        na_addr_t  *new_addr
        );

/* addr_is_self */
static na_bool_t
na_bmi_addr_is_self(
        na_class_t *na_class,
        na_addr_t   addr
        );

/* addr_to_string */
static na_return_t
na_bmi_addr_to_string(
        na_class_t *na_class,
        char       *buf,
        na_size_t  *buf_size,
        na_addr_t   addr
        );

/* msg_get_max */
static na_size_t
na_bmi_msg_get_max_unexpected_size(
        const na_class_t *na_class
        );

static na_size_t
na_bmi_msg_get_max_expected_size(
        const na_class_t *na_class
        );

static na_tag_t
na_bmi_msg_get_max_tag(
        const na_class_t *na_class
        );

/* msg_send_unexpected */
static na_return_t
na_bmi_msg_send_unexpected(
        na_class_t   *na_class,
        na_context_t *context,
        na_cb_t       callback,
        void         *arg,
        const void   *buf,
        na_size_t     buf_size,
        void         *plugin_data,
        na_addr_t     dest,
        na_tag_t      tag,
        na_op_id_t   *op_id
        );

/* msg_recv_unexpected */
static na_return_t
na_bmi_msg_recv_unexpected(
        na_class_t   *na_class,
        na_context_t *context,
        na_cb_t       callback,
        void         *arg,
        void         *buf,
        na_size_t     buf_size,
        void         *plugin_data,
        na_tag_t      mask,
        na_op_id_t   *op_id
        );

/* msg_send_expected */
static na_return_t
na_bmi_msg_send_expected(
        na_class_t   *na_class,
        na_context_t *context,
        na_cb_t       callback,
        void         *arg,
        const void   *buf,
        na_size_t     buf_size,
        void         *plugin_data,
        na_addr_t     dest,
        na_tag_t      tag,
        na_op_id_t   *op_id
        );

/* msg_recv_expected */
static na_return_t
na_bmi_msg_recv_expected(
        na_class_t   *na_class,
        na_context_t *context,
        na_cb_t       callback,
        void         *arg,
        void         *buf,
        na_size_t     buf_size,
        void         *plugin_data,
        na_addr_t     source,
        na_tag_t      tag,
        na_op_id_t   *op_id
        );

static na_return_t
na_bmi_msg_unexpected_push(
        na_class_t                    *na_class,
        struct na_bmi_unexpected_info *unexpected_info
        );

static struct na_bmi_unexpected_info *
na_bmi_msg_unexpected_pop(
        na_class_t *na_class);

static na_return_t
na_bmi_msg_unexpected_op_push(
        na_class_t          *na_class,
        struct na_bmi_op_id *na_bmi_op_id
        );

static struct na_bmi_op_id *
na_bmi_msg_unexpected_op_pop(
        na_class_t *na_class
        );

/* mem_handle */
static na_return_t
na_bmi_mem_handle_create(
        na_class_t      *na_class,
        void            *buf,
        na_size_t        buf_size,
        unsigned long    flags,
        na_mem_handle_t *mem_handle
        );

static na_return_t
na_bmi_mem_handle_free(
        na_class_t      *na_class,
        na_mem_handle_t  mem_handle
        );

static na_return_t
na_bmi_mem_register(
        na_class_t      *na_class,
        na_mem_handle_t  mem_handle
        );

static na_return_t
na_bmi_mem_deregister(
        na_class_t      *na_class,
        na_mem_handle_t  mem_handle
        );

/* mem_handle serialization */
static na_size_t
na_bmi_mem_handle_get_serialize_size(
        na_class_t      *na_class,
        na_mem_handle_t  mem_handle
        );

static na_return_t
na_bmi_mem_handle_serialize(
        na_class_t      *na_class,
        void            *buf,
        na_size_t        buf_size,
        na_mem_handle_t  mem_handle
        );

static na_return_t
na_bmi_mem_handle_deserialize(
        na_class_t      *na_class,
        na_mem_handle_t *mem_handle,
        const void      *buf,
        na_size_t        buf_size
        );

/* put */
static na_return_t
na_bmi_put(
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

/* get */
static na_return_t
na_bmi_get(
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
na_bmi_progress(
        na_class_t   *na_class,
        na_context_t *context,
        unsigned int  timeout
        );

static na_return_t
na_bmi_progress_unexpected(
        na_class_t   *na_class,
        na_context_t *context,
        unsigned int  timeout
        );

static na_return_t
na_bmi_progress_expected(
        na_class_t   *na_class,
        na_context_t *context,
        unsigned int  timeout
        );

static na_return_t
na_bmi_progress_rma(
        na_class_t                 *na_class,
        na_context_t               *context,
        struct BMI_unexpected_info *unexpected_info
        );

static na_return_t
na_bmi_progress_rma_completion(
        struct na_bmi_op_id *na_bmi_op_id
        );

static na_return_t
na_bmi_complete(
        struct na_bmi_op_id *na_bmi_op_id
        );

static void
na_bmi_release(
        void *arg
        );

/* cancel */
static na_return_t
na_bmi_cancel(
        na_class_t   *na_class,
        na_context_t *context,
        na_op_id_t    op_id
        );

/*******************/
/* Local Variables */
/*******************/

const na_class_t na_bmi_class_g = {
        NULL,                                 /* private_data */
        "bmi",                                /* name */
        na_bmi_check_protocol,                /* check_protocol */
        na_bmi_initialize,                    /* initialize */
        na_bmi_finalize,                      /* finalize */
        NULL,                                 /* cleanup */
        NULL,                                 /* check_feature */
        na_bmi_context_create,                /* context_create */
        na_bmi_context_destroy,               /* context_destroy */
        na_bmi_op_create,                     /* op_create */
        na_bmi_op_destroy,                    /* op_destroy */
        na_bmi_addr_lookup,                   /* addr_lookup */
        na_bmi_addr_free,                     /* addr_free */
        na_bmi_addr_self,                     /* addr_self */
        na_bmi_addr_dup,                      /* addr_dup */
        na_bmi_addr_is_self,                  /* addr_is_self */
        na_bmi_addr_to_string,                /* addr_to_string */
        na_bmi_msg_get_max_unexpected_size,   /* msg_get_max_unexpected_size */
        na_bmi_msg_get_max_expected_size,     /* msg_get_max_expected_size */
        NULL,                                 /* msg_get_unexpected_header_size */
        NULL,                                 /* msg_get_expected_header_size */
        na_bmi_msg_get_max_tag,               /* msg_get_max_tag */
        NULL,                                 /* msg_buf_alloc */
        NULL,                                 /* msg_buf_free */
        NULL,                                 /* msg_init_unexpected */
        na_bmi_msg_send_unexpected,           /* msg_send_unexpected */
        na_bmi_msg_recv_unexpected,           /* msg_recv_unexpected */
        NULL,                                 /* msg_init_expected */
        na_bmi_msg_send_expected,             /* msg_send_expected */
        na_bmi_msg_recv_expected,             /* msg_recv_expected */
        na_bmi_mem_handle_create,             /* mem_handle_create */
        NULL,                                 /* mem_handle_create_segment */
        na_bmi_mem_handle_free,               /* mem_handle_free */
        na_bmi_mem_register,                  /* mem_register */
        na_bmi_mem_deregister,                /* mem_deregister */
        NULL,                                 /* mem_publish */
        NULL,                                 /* mem_unpublish */
        na_bmi_mem_handle_get_serialize_size, /* mem_handle_get_serialize_size */
        na_bmi_mem_handle_serialize,          /* mem_handle_serialize */
        na_bmi_mem_handle_deserialize,        /* mem_handle_deserialize */
        na_bmi_put,                           /* put */
        na_bmi_get,                           /* get */
        NULL,                                 /* poll_get_fd */
        NULL,                                 /* poll_try_wait */
        na_bmi_progress,                      /* progress */
        na_bmi_cancel                         /* cancel */
};

/********************/
/* Plugin callbacks */
/********************/

/*---------------------------------------------------------------------------*/
static NA_INLINE bmi_msg_tag_t
na_bmi_gen_rma_tag(na_class_t *na_class)
{
    bmi_msg_tag_t tag;

    /* Compare and swap tag if reached max tag */
    if (hg_atomic_cas32(&NA_BMI_PRIVATE_DATA(na_class)->rma_tag,
            NA_BMI_MAX_RMA_TAG, NA_BMI_RMA_TAG)) {
        tag = NA_BMI_RMA_TAG;
    } else {
        /* Increment tag */
        tag = hg_atomic_incr32(&NA_BMI_PRIVATE_DATA(na_class)->rma_tag);
    }

    return tag;
}

/*---------------------------------------------------------------------------*/
static na_bool_t
na_bmi_check_protocol(const char *protocol_name)
{
    na_bool_t accept         = NA_FALSE;

    /* Note: BMI_SUPPORTS_TRANSPORT_METHOD_GETINFO is not defined
     *       anywhere.  This is a temporary way to disable this fully
     *       functional code to avoid incompatibility with older versions
     *       of BMI.  We will remove this #ifdef to always use the
     *       BMI_get_info API and find out the protocols supported by
     *       the BMI library.
     */
#ifdef BMI_SUPPORTS_TRANSPORT_METHOD_GETINFO
    int       string_length  = 0;
    char     *transport      = NULL;
    char     *transport_index = NULL;

    /* Obtain the list of transport protocols supported by BMI. */
    string_length = BMI_get_info(0, BMI_TRANSPORT_METHODS_STRING, &transport);
    
    if (string_length <= 0 || transport == NULL) {
        /* bmi is not configured with any plugins, transport is NULL */
        return NA_FALSE;
    }

    transport_index = strtok(transport, ",");

    while (transport_index != NULL) {
        /* check if bmi supports the protocol. */
        if (strcmp(transport_index, protocol_name) == 0) {
            accept = NA_TRUE;
            break;
        }

        transport_index = strtok(NULL, ",");
    }

    free(transport);
#else
    if ((strcmp(protocol_name, "tcp") == 0) ||
            (strcmp(protocol_name, "ib") == 0)) {
        accept = NA_TRUE;
    }
#endif

    return accept;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_bmi_initialize(na_class_t * na_class, const struct na_info *na_info,
        na_bool_t listen)
{
    char method_list[NA_BMI_MAX_ADDR_NAME];
    char listen_addr[NA_BMI_MAX_ADDR_NAME];
    char my_hostname[NA_BMI_MAX_ADDR_NAME] = {0};
    int flag;
    na_return_t ret = NA_SUCCESS;
    int i;

    flag = (listen) ? BMI_INIT_SERVER : 0;

    memset(method_list, '\0', NA_BMI_MAX_ADDR_NAME);
    strcpy(method_list, "bmi_");
    strncat(method_list, na_info->protocol_name,
        NA_BMI_MAX_ADDR_NAME - strlen(method_list));

    if (listen) {
        int desc_len = 0;
        if (na_info->host_name) {
            desc_len = snprintf(listen_addr, NA_BMI_MAX_ADDR_NAME, "%s://%s",
                na_info->protocol_name, na_info->host_name);
            if (desc_len > NA_BMI_MAX_ADDR_NAME) {
                NA_LOG_ERROR("Exceeding max addr name");
                ret = NA_SIZE_ERROR;
                goto done;
            }
            ret = na_bmi_init(na_class, method_list, listen_addr, flag);
        } else {
            /* Addr unspecified but we are in server mode; get local
             * hostname and then cycle through range of ports until we find
             * one that works.
             */
            ret = gethostname(my_hostname, NA_BMI_MAX_ADDR_NAME);
            if(ret < 0)
                sprintf(my_hostname, "localhost");

            ret = NA_ADDRINUSE_ERROR;
            for(i=0; (i<NA_BMI_DEFAULT_PORT_TRIES && ret == NA_ADDRINUSE_ERROR); i++) {
                desc_len = snprintf(listen_addr, NA_BMI_MAX_ADDR_NAME, "%s://%s:%d",
                    na_info->protocol_name, my_hostname, i+NA_BMI_DEFAULT_PORT);
                ret = na_bmi_init(na_class, method_list, listen_addr, flag);
            }
        }
    }
    else {
        ret = na_bmi_init(na_class, NULL, NULL, flag);
    }


done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_bmi_init(na_class_t *na_class, const char *method_list,
        const char *listen_addr, int flags)
{
    na_return_t ret = NA_SUCCESS;
    int bmi_ret;

    na_class->private_data = malloc(sizeof(struct na_bmi_private_data));
    if (!na_class->private_data) {
        NA_LOG_ERROR("Could not allocate NA private data class");
        ret = NA_NOMEM_ERROR;
        goto done;
    }
    NA_BMI_PRIVATE_DATA(na_class)->listen_addr = (listen_addr) ?
            strdup(listen_addr) : NULL;
    HG_QUEUE_INIT(&NA_BMI_PRIVATE_DATA(na_class)->unexpected_msg_queue);
    HG_QUEUE_INIT(&NA_BMI_PRIVATE_DATA(na_class)->unexpected_op_queue);

    /* Initialize BMI */
    bmi_ret = BMI_initialize(method_list, listen_addr, flags);
    if (bmi_ret < 0) {
        NA_LOG_ERROR("BMI_initialize() failed");
        if(bmi_ret == -BMI_EADDRINUSE)
            ret = NA_ADDRINUSE_ERROR;
        else
            ret = NA_PROTOCOL_ERROR;
        goto done;
    }

done:
    if (ret != NA_SUCCESS) {
        free(NA_BMI_PRIVATE_DATA(na_class)->listen_addr);
        free(na_class->private_data);
    }
    else
    {
        /* Initialize mutex/cond */
        hg_thread_mutex_init(&NA_BMI_PRIVATE_DATA(na_class)->test_unexpected_mutex);
        hg_thread_mutex_init(
                &NA_BMI_PRIVATE_DATA(na_class)->unexpected_msg_queue_mutex);
        hg_thread_mutex_init(
                &NA_BMI_PRIVATE_DATA(na_class)->unexpected_op_queue_mutex);

        /* Initialize atomic op */
        hg_atomic_set32(&NA_BMI_PRIVATE_DATA(na_class)->rma_tag, NA_BMI_RMA_TAG);
    }

    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_bmi_finalize(na_class_t *na_class)
{
    na_return_t ret = NA_SUCCESS;
    int bmi_ret;

    if (!na_class->private_data) {
        goto done;
    }

    /* Check that unexpected op queue is empty */
    if (!HG_QUEUE_IS_EMPTY(
            &NA_BMI_PRIVATE_DATA(na_class)->unexpected_op_queue)) {
        NA_LOG_ERROR("Unexpected op queue should be empty");
        ret = NA_PROTOCOL_ERROR;
    }

    /* Check that unexpected message queue is empty */
    if (!HG_QUEUE_IS_EMPTY(
            &NA_BMI_PRIVATE_DATA(na_class)->unexpected_msg_queue)) {
        NA_LOG_ERROR("Unexpected msg queue should be empty");
        ret = NA_PROTOCOL_ERROR;
    }

    /* Finalize BMI */
    bmi_ret = BMI_finalize();
    if (bmi_ret < 0) {
        NA_LOG_ERROR("BMI_finalize() failed");
        ret = NA_PROTOCOL_ERROR;
    }

    /* Destroy mutex/cond */
    hg_thread_mutex_destroy(
            &NA_BMI_PRIVATE_DATA(na_class)->test_unexpected_mutex);
    hg_thread_mutex_destroy(
            &NA_BMI_PRIVATE_DATA(na_class)->unexpected_msg_queue_mutex);
    hg_thread_mutex_destroy(
            &NA_BMI_PRIVATE_DATA(na_class)->unexpected_op_queue_mutex);

    free(NA_BMI_PRIVATE_DATA(na_class)->listen_addr);
    free(na_class->private_data);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_bmi_context_create(na_class_t NA_UNUSED *na_class, void **context)
{
    bmi_context_id *bmi_context = NULL;
    na_return_t ret = NA_SUCCESS;
    int bmi_ret;

    bmi_context = (bmi_context_id *) malloc(sizeof(bmi_context_id));
    if (!bmi_context) {
        NA_LOG_ERROR("Could not allocate BMI context ID");
        ret = NA_NOMEM_ERROR;
        goto done;
    }

    /* Create a new BMI context */
    bmi_ret = BMI_open_context(bmi_context);
    if (bmi_ret < 0) {
        NA_LOG_ERROR("BMI_open_context() failed");
        ret = NA_PROTOCOL_ERROR;
        goto done;
    }

    *context = bmi_context;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_bmi_context_destroy(na_class_t NA_UNUSED *na_class, void *context)
{
    bmi_context_id *bmi_context = (bmi_context_id *) context;
    na_return_t ret = NA_SUCCESS;

    /* Close BMI context */
    BMI_close_context(*bmi_context);
    free(bmi_context);

    return ret;
}

/*---------------------------------------------------------------------------*/
static na_op_id_t
na_bmi_op_create(na_class_t NA_UNUSED *na_class)
{
    struct na_bmi_op_id *na_bmi_op_id = NULL;

    na_bmi_op_id = (struct na_bmi_op_id *) malloc(sizeof(struct na_bmi_op_id));
    if (!na_bmi_op_id) {
        NA_LOG_ERROR("Could not allocate NA BMI operation ID");
        goto done;
    }
    memset(na_bmi_op_id, 0, sizeof(struct na_bmi_op_id));
    hg_atomic_set32(&na_bmi_op_id->ref_count, 1);
    /* Completed by default */
    hg_atomic_set32(&na_bmi_op_id->completed, 1);

done:
    return (na_op_id_t) na_bmi_op_id;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_bmi_op_destroy(na_class_t NA_UNUSED *na_class, na_op_id_t op_id)
{
    struct na_bmi_op_id *na_bmi_op_id = (struct na_bmi_op_id *) op_id;
    na_return_t ret = NA_SUCCESS;

    if (hg_atomic_decr32(&na_bmi_op_id->ref_count)) {
        /* Cannot free yet */
        goto done;
    }
    free(na_bmi_op_id);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_bmi_addr_lookup(na_class_t *na_class, na_context_t *context,
        na_cb_t callback, void *arg, const char *name, na_op_id_t *op_id)
{
    struct na_bmi_op_id *na_bmi_op_id = NULL;
    struct na_bmi_addr *na_bmi_addr = NULL;
    na_return_t ret = NA_SUCCESS;
    int bmi_ret;

    /* Allocate op_id if not provided */
    if (op_id && op_id != NA_OP_ID_IGNORE && *op_id != NA_OP_ID_NULL) {
        na_bmi_op_id = (struct na_bmi_op_id *) *op_id;
        hg_atomic_incr32(&na_bmi_op_id->ref_count);
    } else {
        na_bmi_op_id = (struct na_bmi_op_id *) na_bmi_op_create(na_class);
        if (!na_bmi_op_id) {
            NA_LOG_ERROR("Could not allocate NA BMI operation ID");
            ret = NA_NOMEM_ERROR;
            goto done;
        }
    }
    na_bmi_op_id->context = context;
    na_bmi_op_id->type = NA_CB_LOOKUP;
    na_bmi_op_id->callback = callback;
    na_bmi_op_id->arg = arg;
    hg_atomic_set32(&na_bmi_op_id->completed, 0);
    na_bmi_op_id->cancel = 0;

    /* Allocate addr */
    na_bmi_addr = (struct na_bmi_addr *) malloc(sizeof(struct na_bmi_addr));
    if (!na_bmi_addr) {
        NA_LOG_ERROR("Could not allocate BMI addr");
        ret = NA_NOMEM_ERROR;
        goto done;
    }
    na_bmi_addr->bmi_addr = 0;
    na_bmi_addr->unexpected = NA_FALSE;
    na_bmi_addr->self = NA_FALSE;
    hg_atomic_set32(&na_bmi_addr->ref_count, 1);
    na_bmi_op_id->info.lookup.addr = (na_addr_t) na_bmi_addr;

    /* Assign op_id */
    if (op_id && op_id != NA_OP_ID_IGNORE && *op_id == NA_OP_ID_NULL)
        *op_id = na_bmi_op_id;

    /* Perform an address lookup */
    bmi_ret = BMI_addr_lookup(&na_bmi_addr->bmi_addr, name);
    if (bmi_ret < 0) {
        NA_LOG_ERROR("BMI_addr_lookup() failed");
        ret = NA_PROTOCOL_ERROR;
        goto done;
    }

    /* TODO we always complete here for now as lookup is blocking */
    ret = na_bmi_complete(na_bmi_op_id);
    if (ret != NA_SUCCESS) {
        NA_LOG_ERROR("Could not complete operation");
        goto done;
    }

done:
    if (ret != NA_SUCCESS) {
        free(na_bmi_addr);
        na_bmi_op_destroy(na_class, (na_op_id_t) na_bmi_op_id);
    }
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_bmi_addr_self(na_class_t NA_UNUSED *na_class, na_addr_t *addr)
{
    struct na_bmi_addr *na_bmi_addr = NULL;
    na_return_t ret = NA_SUCCESS;

    /* Allocate addr */
    na_bmi_addr = (struct na_bmi_addr *) malloc(sizeof(struct na_bmi_addr));
    if (!na_bmi_addr) {
        NA_LOG_ERROR("Could not allocate BMI addr");
        ret = NA_NOMEM_ERROR;
        goto done;
    }
    na_bmi_addr->bmi_addr = 0;
    na_bmi_addr->unexpected = NA_FALSE;
    na_bmi_addr->self = NA_TRUE;
    hg_atomic_set32(&na_bmi_addr->ref_count, 1);

    *addr = (na_addr_t) na_bmi_addr;

done:
    if (ret != NA_SUCCESS) {
        free(na_bmi_addr);
    }
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_bmi_addr_dup(na_class_t NA_UNUSED *na_class, na_addr_t addr,
    na_addr_t *new_addr)
{
    struct na_bmi_addr *na_bmi_addr = (struct na_bmi_addr *) addr;

    /* Increment refcount */
    hg_atomic_incr32(&na_bmi_addr->ref_count);

    *new_addr = (na_addr_t) na_bmi_addr;

    return NA_SUCCESS;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_bmi_addr_free(na_class_t NA_UNUSED *na_class, na_addr_t addr)
{
    struct na_bmi_addr *na_bmi_addr = (struct na_bmi_addr *) addr;
    na_return_t ret = NA_SUCCESS;

    /* Cleanup peer_addr */
    if (!na_bmi_addr) {
        NA_LOG_ERROR("NULL BMI addr");
        ret = NA_INVALID_PARAM;
        return ret;
    }

    if (hg_atomic_decr32(&na_bmi_addr->ref_count)) {
        /* Cannot free yet */
        goto done;
    }

    free(na_bmi_addr);
    na_bmi_addr = NULL;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_bool_t
na_bmi_addr_is_self(na_class_t NA_UNUSED *na_class, na_addr_t addr)
{
    struct na_bmi_addr *na_bmi_addr = (struct na_bmi_addr *) addr;

    return na_bmi_addr->self;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_bmi_addr_to_string(na_class_t *na_class, char *buf,
        na_size_t *buf_size, na_addr_t addr)
{
    struct na_bmi_addr *na_bmi_addr = NULL;
    const char *bmi_rev_addr;
    na_size_t string_len;
    na_return_t ret = NA_SUCCESS;

    na_bmi_addr = (struct na_bmi_addr *) addr;

    if (na_bmi_addr->self) {
        bmi_rev_addr = NA_BMI_PRIVATE_DATA(na_class)->listen_addr;
        if (!bmi_rev_addr) {
            NA_LOG_ERROR("Cannot convert addr to string if not listening");
            ret = NA_PROTOCOL_ERROR;
            goto done;
        }
    } else {
        if (na_bmi_addr->unexpected) {
            bmi_rev_addr = BMI_addr_rev_lookup_unexpected(na_bmi_addr->bmi_addr);
        } else {
            bmi_rev_addr = BMI_addr_rev_lookup(na_bmi_addr->bmi_addr);
        }
    }

    string_len = strlen(bmi_rev_addr);
    if (buf) {
        if (string_len >= *buf_size) {
            NA_LOG_ERROR("Buffer size too small to copy addr");
            ret = NA_SIZE_ERROR;
        } else {
            strcpy(buf, bmi_rev_addr);
        }
    }
    *buf_size = string_len + 1;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_size_t
na_bmi_msg_get_max_unexpected_size(const na_class_t NA_UNUSED *na_class)
{
    na_size_t max_unexpected_size = NA_BMI_UNEXPECTED_SIZE;

    return max_unexpected_size;
}

/*---------------------------------------------------------------------------*/
static na_size_t
na_bmi_msg_get_max_expected_size(const na_class_t NA_UNUSED *na_class)
{
    na_size_t max_expected_size = NA_BMI_EXPECTED_SIZE;

    return max_expected_size;
}

/*---------------------------------------------------------------------------*/
static na_tag_t
na_bmi_msg_get_max_tag(const na_class_t NA_UNUSED *na_class)
{
    na_tag_t max_tag = NA_BMI_MAX_TAG;

    return max_tag;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_bmi_msg_send_unexpected(na_class_t *na_class,
        na_context_t *context, na_cb_t callback, void *arg, const void *buf,
        na_size_t buf_size, void NA_UNUSED *plugin_data, na_addr_t dest,
        na_tag_t tag, na_op_id_t *op_id)
{
    bmi_context_id *bmi_context = (bmi_context_id *) context->plugin_context;
    bmi_size_t bmi_buf_size = (bmi_size_t) buf_size;
    struct na_bmi_addr *na_bmi_addr = (struct na_bmi_addr*) dest;
    bmi_msg_tag_t bmi_tag = (bmi_msg_tag_t) tag;
    struct na_bmi_op_id *na_bmi_op_id = NULL;
    na_return_t ret = NA_SUCCESS;
    int bmi_ret;

    /* Allocate op_id if not provided */
    if (op_id && op_id != NA_OP_ID_IGNORE && *op_id != NA_OP_ID_NULL) {
        na_bmi_op_id = (struct na_bmi_op_id *) *op_id;
        hg_atomic_incr32(&na_bmi_op_id->ref_count);
    } else {
        na_bmi_op_id = (struct na_bmi_op_id *) na_bmi_op_create(na_class);
        if (!na_bmi_op_id) {
            NA_LOG_ERROR("Could not allocate NA BMI operation ID");
            ret = NA_NOMEM_ERROR;
            goto done;
        }
    }
    na_bmi_op_id->context = context;
    na_bmi_op_id->type = NA_CB_SEND_UNEXPECTED;
    na_bmi_op_id->callback = callback;
    na_bmi_op_id->arg = arg;
    hg_atomic_set32(&na_bmi_op_id->completed, 0);
    na_bmi_op_id->info.send_unexpected.op_id = 0;
    na_bmi_op_id->cancel = 0;

    /* Assign op_id */
    if (op_id && op_id != NA_OP_ID_IGNORE && *op_id == NA_OP_ID_NULL)
        *op_id = na_bmi_op_id;

    /* Post the BMI unexpected send request */
    bmi_ret = BMI_post_sendunexpected(
            &na_bmi_op_id->info.send_unexpected.op_id, na_bmi_addr->bmi_addr,
            buf, bmi_buf_size, BMI_EXT_ALLOC, bmi_tag, na_bmi_op_id,
            *bmi_context, NULL);
    if (bmi_ret < 0) {
        NA_LOG_ERROR("BMI_post_sendunexpected() failed");
        ret = NA_PROTOCOL_ERROR;
        goto done;
    }

    /* If immediate completion, directly add to completion queue */
    if (bmi_ret) {
        ret = na_bmi_complete(na_bmi_op_id);
        if (ret != NA_SUCCESS) {
            NA_LOG_ERROR("Could not complete operation");
            goto done;
        }
    }

done:
    if (ret != NA_SUCCESS) {
        na_bmi_op_destroy(na_class, (na_op_id_t) na_bmi_op_id);
    }
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_bmi_msg_recv_unexpected(na_class_t *na_class, na_context_t *context,
        na_cb_t callback, void *arg, void *buf, na_size_t buf_size,
        void NA_UNUSED *plugin_data, na_tag_t NA_UNUSED mask, na_op_id_t *op_id)
{
    struct na_bmi_unexpected_info *unexpected_info = NULL;
    struct na_bmi_op_id *na_bmi_op_id = NULL;
    na_return_t ret = NA_SUCCESS;

    /* Allocate op_id if not provided */
    if (op_id && op_id != NA_OP_ID_IGNORE && *op_id != NA_OP_ID_NULL) {
        na_bmi_op_id = (struct na_bmi_op_id *) *op_id;
        hg_atomic_incr32(&na_bmi_op_id->ref_count);
    } else {
        na_bmi_op_id = (struct na_bmi_op_id *) na_bmi_op_create(na_class);
        if (!na_bmi_op_id) {
            NA_LOG_ERROR("Could not allocate NA BMI operation ID");
            ret = NA_NOMEM_ERROR;
            goto done;
        }
    }
    na_bmi_op_id->context = context;
    na_bmi_op_id->type = NA_CB_RECV_UNEXPECTED;
    na_bmi_op_id->callback = callback;
    na_bmi_op_id->arg = arg;
    hg_atomic_set32(&na_bmi_op_id->completed, 0);
    na_bmi_op_id->info.recv_unexpected.buf = buf;
    na_bmi_op_id->info.recv_unexpected.buf_size = (bmi_size_t) buf_size;
    na_bmi_op_id->info.recv_unexpected.unexpected_info = NULL;
    na_bmi_op_id->cancel = 0;

    /* Assign op_id */
    if (op_id && op_id != NA_OP_ID_IGNORE && *op_id == NA_OP_ID_NULL)
        *op_id = na_bmi_op_id;

    /* Try to make progress here from the BMI unexpected queue */
    do {
        ret = na_bmi_progress_unexpected(na_class, context, 0);
        if (ret != NA_SUCCESS && ret != NA_TIMEOUT) {
            NA_LOG_ERROR("Could not check BMI unexpected message queue");
            goto done;
        }
    } while (ret == NA_SUCCESS);

    /* Look for an unexpected message already received */
    unexpected_info = na_bmi_msg_unexpected_pop(na_class);

    if (unexpected_info) {
        na_bmi_op_id->info.recv_unexpected.unexpected_info = &unexpected_info->info;
        ret = na_bmi_complete(na_bmi_op_id);
        if (ret != NA_SUCCESS) {
            NA_LOG_ERROR("Could not complete operation");
            goto done;
        }
    } else {
        /* Nothing has been received yet so add op_id to progress queue */
        ret = na_bmi_msg_unexpected_op_push(na_class, na_bmi_op_id);
        if (ret != NA_SUCCESS) {
            NA_LOG_ERROR("Could not push operation ID");
            goto done;
        }
    }

done:
    if (ret != NA_SUCCESS) {
        na_bmi_op_destroy(na_class, (na_op_id_t) na_bmi_op_id);
    }
    free(unexpected_info);
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_bmi_msg_unexpected_push(na_class_t *na_class,
        struct na_bmi_unexpected_info *unexpected_info)
{
    na_return_t ret = NA_SUCCESS;

    if (!unexpected_info) {
        NA_LOG_ERROR("NULL unexpected info");
        ret = NA_INVALID_PARAM;
        goto done;
    }

    hg_thread_mutex_lock(
            &NA_BMI_PRIVATE_DATA(na_class)->unexpected_msg_queue_mutex);

    HG_QUEUE_PUSH_TAIL(&NA_BMI_PRIVATE_DATA(na_class)->unexpected_msg_queue,
        unexpected_info, entry);

    hg_thread_mutex_unlock(
            &NA_BMI_PRIVATE_DATA(na_class)->unexpected_msg_queue_mutex);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static struct na_bmi_unexpected_info *
na_bmi_msg_unexpected_pop(na_class_t *na_class)
{
    struct na_bmi_unexpected_info *unexpected_info;

    hg_thread_mutex_lock(
            &NA_BMI_PRIVATE_DATA(na_class)->unexpected_msg_queue_mutex);

    unexpected_info = HG_QUEUE_FIRST(&NA_BMI_PRIVATE_DATA(na_class)->unexpected_msg_queue);
    HG_QUEUE_POP_HEAD(&NA_BMI_PRIVATE_DATA(na_class)->unexpected_msg_queue, entry);

    hg_thread_mutex_unlock(
            &NA_BMI_PRIVATE_DATA(na_class)->unexpected_msg_queue_mutex);

    return unexpected_info;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_bmi_msg_unexpected_op_push(na_class_t *na_class,
        struct na_bmi_op_id *na_bmi_op_id)
{
    na_return_t ret = NA_SUCCESS;

    if (!na_bmi_op_id) {
        NA_LOG_ERROR("NULL operation ID");
        ret = NA_INVALID_PARAM;
        goto done;
    }

    hg_thread_mutex_lock(&NA_BMI_PRIVATE_DATA(na_class)->unexpected_op_queue_mutex);

    HG_QUEUE_PUSH_TAIL(&NA_BMI_PRIVATE_DATA(na_class)->unexpected_op_queue,
        na_bmi_op_id, entry);

    hg_thread_mutex_unlock(
            &NA_BMI_PRIVATE_DATA(na_class)->unexpected_op_queue_mutex);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static struct na_bmi_op_id *
na_bmi_msg_unexpected_op_pop(na_class_t *na_class)
{
    struct na_bmi_op_id *na_bmi_op_id;

    hg_thread_mutex_lock(
        &NA_BMI_PRIVATE_DATA(na_class)->unexpected_op_queue_mutex);

    na_bmi_op_id = HG_QUEUE_FIRST(
        &NA_BMI_PRIVATE_DATA(na_class)->unexpected_op_queue);
    HG_QUEUE_POP_HEAD(&NA_BMI_PRIVATE_DATA(na_class)->unexpected_op_queue,
        entry);

    hg_thread_mutex_unlock(
        &NA_BMI_PRIVATE_DATA(na_class)->unexpected_op_queue_mutex);

    return na_bmi_op_id;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_bmi_msg_send_expected(na_class_t *na_class, na_context_t *context,
        na_cb_t callback, void *arg, const void *buf, na_size_t buf_size,
        void NA_UNUSED *plugin_data, na_addr_t dest, na_tag_t tag,
        na_op_id_t *op_id)
{
    bmi_context_id *bmi_context = (bmi_context_id *) context->plugin_context;
    bmi_size_t bmi_buf_size = (bmi_size_t) buf_size;
    struct na_bmi_addr *na_bmi_addr = (struct na_bmi_addr*) dest;
    bmi_msg_tag_t bmi_tag = (bmi_msg_tag_t) tag;
    struct na_bmi_op_id *na_bmi_op_id = NULL;
    na_return_t ret = NA_SUCCESS;
    int bmi_ret;

    /* Allocate op_id if not provided */
    if (op_id && op_id != NA_OP_ID_IGNORE && *op_id != NA_OP_ID_NULL) {
        na_bmi_op_id = (struct na_bmi_op_id *) *op_id;
        hg_atomic_incr32(&na_bmi_op_id->ref_count);
    } else {
        na_bmi_op_id = (struct na_bmi_op_id *) na_bmi_op_create(na_class);
        if (!na_bmi_op_id) {
            NA_LOG_ERROR("Could not allocate NA BMI operation ID");
            ret = NA_NOMEM_ERROR;
            goto done;
        }
    }
    na_bmi_op_id->context = context;
    na_bmi_op_id->type = NA_CB_SEND_EXPECTED;
    na_bmi_op_id->callback = callback;
    na_bmi_op_id->arg = arg;
    hg_atomic_set32(&na_bmi_op_id->completed, 0);
    na_bmi_op_id->info.send_expected.op_id = 0;
    na_bmi_op_id->cancel = 0;

    /* Assign op_id */
    if (op_id && op_id != NA_OP_ID_IGNORE && *op_id == NA_OP_ID_NULL)
        *op_id = na_bmi_op_id;

    /* Post the BMI send request */
    bmi_ret = BMI_post_send(&na_bmi_op_id->info.send_expected.op_id,
            na_bmi_addr->bmi_addr, buf, bmi_buf_size, BMI_EXT_ALLOC, bmi_tag,
            na_bmi_op_id, *bmi_context, NULL);
    if (bmi_ret < 0) {
        NA_LOG_ERROR("BMI_post_send() failed");
        ret = NA_PROTOCOL_ERROR;
        goto done;
    }

    /* If immediate completion, directly add to completion queue */
    if (bmi_ret) {
        ret = na_bmi_complete(na_bmi_op_id);
        if (ret != NA_SUCCESS) {
            NA_LOG_ERROR("Could not complete operation");
            goto done;
        }
    }

done:
    if (ret != NA_SUCCESS) {
        na_bmi_op_destroy(na_class, (na_op_id_t) na_bmi_op_id);
    }
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_bmi_msg_recv_expected(na_class_t *na_class, na_context_t *context,
        na_cb_t callback, void *arg, void *buf, na_size_t buf_size,
        void NA_UNUSED *plugin_data, na_addr_t source, na_tag_t tag,
        na_op_id_t *op_id)
{
    bmi_context_id *bmi_context = (bmi_context_id *) context->plugin_context;
    bmi_size_t bmi_buf_size = (bmi_size_t) buf_size;
    struct na_bmi_addr *na_bmi_addr = (struct na_bmi_addr*) source;
    bmi_msg_tag_t bmi_tag = (bmi_msg_tag_t) tag;
    struct na_bmi_op_id *na_bmi_op_id = NULL;
    na_return_t ret = NA_SUCCESS;
    int bmi_ret;

    /* Allocate op_id if not provided */
    if (op_id && op_id != NA_OP_ID_IGNORE && *op_id != NA_OP_ID_NULL) {
        na_bmi_op_id = (struct na_bmi_op_id *) *op_id;
        hg_atomic_incr32(&na_bmi_op_id->ref_count);
    } else {
        na_bmi_op_id = (struct na_bmi_op_id *) na_bmi_op_create(na_class);
        if (!na_bmi_op_id) {
            NA_LOG_ERROR("Could not allocate NA BMI operation ID");
            ret = NA_NOMEM_ERROR;
            goto done;
        }
    }
    na_bmi_op_id->context = context;
    na_bmi_op_id->type = NA_CB_RECV_EXPECTED;
    na_bmi_op_id->callback = callback;
    na_bmi_op_id->arg = arg;
    hg_atomic_set32(&na_bmi_op_id->completed, 0);
    na_bmi_op_id->info.recv_expected.op_id = 0;
    na_bmi_op_id->info.recv_expected.buf_size = bmi_buf_size;
    na_bmi_op_id->info.recv_expected.actual_size = 0;
    na_bmi_op_id->cancel = 0;

    /* Assign op_id */
    if (op_id && op_id != NA_OP_ID_IGNORE && *op_id == NA_OP_ID_NULL)
        *op_id = (na_op_id_t) na_bmi_op_id;

    /* Post the BMI recv request */
    bmi_ret = BMI_post_recv(&na_bmi_op_id->info.recv_expected.op_id,
            na_bmi_addr->bmi_addr, buf, bmi_buf_size,
            &na_bmi_op_id->info.recv_expected.actual_size, BMI_EXT_ALLOC,
            bmi_tag, na_bmi_op_id, *bmi_context, NULL);
    if (bmi_ret < 0) {
        NA_LOG_ERROR("BMI_post_recv() failed");
        ret = NA_PROTOCOL_ERROR;
        goto done;
    }

    /* If immediate completion, directly add to completion queue */
    if (bmi_ret) {
        ret = na_bmi_complete(na_bmi_op_id);
        if (ret != NA_SUCCESS) {
            NA_LOG_ERROR("Could not complete operation");
            goto done;
        }
    }

done:
    if (ret != NA_SUCCESS) {
        na_bmi_op_destroy(na_class, (na_op_id_t) na_bmi_op_id);
    }
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_bmi_mem_handle_create(na_class_t NA_UNUSED *na_class, void *buf,
        na_size_t buf_size, unsigned long flags, na_mem_handle_t *mem_handle)
{
    na_ptr_t bmi_buf_base = (na_ptr_t) buf;
    struct na_bmi_mem_handle *na_bmi_mem_handle = NULL;
    bmi_size_t bmi_buf_size = (bmi_size_t) buf_size;
    na_return_t ret = NA_SUCCESS;

    /* Allocate memory handle (use calloc to avoid uninitialized transfer) */
    na_bmi_mem_handle = (struct na_bmi_mem_handle*)
            calloc(1, sizeof(struct na_bmi_mem_handle));
    if (!na_bmi_mem_handle) {
          NA_LOG_ERROR("Could not allocate NA BMI memory handle");
          ret = NA_NOMEM_ERROR;
          goto done;
    }
    na_bmi_mem_handle->base = bmi_buf_base;
    na_bmi_mem_handle->size = (na_size_t) bmi_buf_size;
    na_bmi_mem_handle->attr = (na_uint8_t) flags;

    *mem_handle = (na_mem_handle_t) na_bmi_mem_handle;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_bmi_mem_handle_free(na_class_t NA_UNUSED *na_class,
        na_mem_handle_t mem_handle)
{
    struct na_bmi_mem_handle *bmi_mem_handle =
            (struct na_bmi_mem_handle*) mem_handle;
    na_return_t ret = NA_SUCCESS;

    free(bmi_mem_handle);

    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_bmi_mem_register(na_class_t NA_UNUSED *na_class, na_mem_handle_t NA_UNUSED mem_handle)
{
    return NA_SUCCESS;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_bmi_mem_deregister(na_class_t NA_UNUSED *na_class, na_mem_handle_t NA_UNUSED mem_handle)
{
    return NA_SUCCESS;
}

/*---------------------------------------------------------------------------*/
static na_size_t
na_bmi_mem_handle_get_serialize_size(na_class_t NA_UNUSED *na_class,
        na_mem_handle_t NA_UNUSED mem_handle)
{
    return sizeof(struct na_bmi_mem_handle);
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_bmi_mem_handle_serialize(na_class_t NA_UNUSED *na_class, void *buf,
        na_size_t buf_size, na_mem_handle_t mem_handle)
{
    struct na_bmi_mem_handle *na_bmi_mem_handle =
            (struct na_bmi_mem_handle*) mem_handle;
    na_return_t ret = NA_SUCCESS;

    if (buf_size < sizeof(struct na_bmi_mem_handle)) {
        NA_LOG_ERROR("Buffer size too small for serializing parameter");
        ret = NA_SIZE_ERROR;
        goto done;
    }

    /* Copy struct */
    memcpy(buf, na_bmi_mem_handle, sizeof(struct na_bmi_mem_handle));

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_bmi_mem_handle_deserialize(na_class_t NA_UNUSED *na_class,
        na_mem_handle_t *mem_handle, const void *buf, na_size_t buf_size)
{
    struct na_bmi_mem_handle *na_bmi_mem_handle = NULL;
    na_return_t ret = NA_SUCCESS;

    if (buf_size < sizeof(struct na_bmi_mem_handle)) {
        NA_LOG_ERROR("Buffer size too small for deserializing parameter");
        ret = NA_SIZE_ERROR;
        goto done;
    }

    na_bmi_mem_handle = (struct na_bmi_mem_handle*)
            malloc(sizeof(struct na_bmi_mem_handle));
    if (!na_bmi_mem_handle) {
          NA_LOG_ERROR("Could not allocate NA BMI memory handle");
          ret = NA_NOMEM_ERROR;
          goto done;
    }

    /* Copy struct */
    memcpy(na_bmi_mem_handle, buf, sizeof(struct na_bmi_mem_handle));

    *mem_handle = (na_mem_handle_t) na_bmi_mem_handle;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_bmi_put(na_class_t *na_class, na_context_t *context, na_cb_t callback,
        void *arg, na_mem_handle_t local_mem_handle, na_offset_t local_offset,
        na_mem_handle_t remote_mem_handle, na_offset_t remote_offset,
        na_size_t length, na_addr_t remote_addr, na_op_id_t *op_id)
{
    bmi_context_id *bmi_context = (bmi_context_id *) context->plugin_context;
    struct na_bmi_mem_handle *bmi_local_mem_handle =
            (struct na_bmi_mem_handle *) local_mem_handle;
    bmi_size_t bmi_local_offset = (bmi_size_t) local_offset;
    struct na_bmi_mem_handle *bmi_remote_mem_handle =
            (struct na_bmi_mem_handle *) remote_mem_handle;
    bmi_size_t bmi_remote_offset = (bmi_size_t) remote_offset;
    struct na_bmi_addr *na_bmi_addr = (struct na_bmi_addr *) remote_addr;
    bmi_size_t bmi_length = (bmi_size_t) length;
    struct na_bmi_op_id *na_bmi_op_id = NULL;
    struct na_bmi_rma_info *na_bmi_rma_info = NULL;
    na_return_t ret = NA_SUCCESS;
    int bmi_ret;

    switch (bmi_remote_mem_handle->attr) {
        case NA_MEM_READ_ONLY:
            NA_LOG_ERROR("Registered memory requires write permission");
            ret = NA_PERMISSION_ERROR;
            goto done;
        case NA_MEM_WRITE_ONLY:
        case NA_MEM_READWRITE:
            break;
        default:
            NA_LOG_ERROR("Invalid memory access flag");
            ret = NA_INVALID_PARAM;
            goto done;
    }

    /* Allocate op_id if not provided */
    if (op_id && op_id != NA_OP_ID_IGNORE && *op_id != NA_OP_ID_NULL) {
        na_bmi_op_id = (struct na_bmi_op_id *) *op_id;
        hg_atomic_incr32(&na_bmi_op_id->ref_count);
    } else {
        na_bmi_op_id = (struct na_bmi_op_id *) na_bmi_op_create(na_class);
        if (!na_bmi_op_id) {
            NA_LOG_ERROR("Could not allocate NA BMI operation ID");
            ret = NA_NOMEM_ERROR;
            goto done;
        }
    }
    na_bmi_op_id->context = context;
    na_bmi_op_id->type = NA_CB_PUT;
    na_bmi_op_id->callback = callback;
    na_bmi_op_id->arg = arg;
    hg_atomic_set32(&na_bmi_op_id->completed, 0);
    na_bmi_op_id->info.put.request_op_id = 0;
    na_bmi_op_id->info.put.transfer_op_id = 0;
    hg_atomic_set32(&na_bmi_op_id->info.put.transfer_completed, NA_FALSE);
    na_bmi_op_id->info.put.transfer_actual_size = 0;
    na_bmi_op_id->info.put.completion_op_id = 0;
    na_bmi_op_id->info.put.completion_flag = NA_FALSE;
    na_bmi_op_id->info.put.completion_actual_size = 0;
    na_bmi_op_id->info.put.internal_progress = NA_FALSE;
    na_bmi_op_id->info.put.remote_addr = na_bmi_addr->bmi_addr;
    na_bmi_op_id->info.put.rma_info = NULL;
    na_bmi_op_id->cancel = 0;

    /* Allocate rma info (use calloc to avoid uninitialized transfer) */
    na_bmi_rma_info =
            (struct na_bmi_rma_info *) calloc(1, sizeof(struct na_bmi_rma_info));
    if (!na_bmi_rma_info) {
        NA_LOG_ERROR("Could not allocate NA BMI RMA info");
        ret = NA_NOMEM_ERROR;
        goto done;
    }
    na_bmi_rma_info->op = NA_BMI_RMA_PUT;
    na_bmi_rma_info->base = bmi_remote_mem_handle->base;
    na_bmi_rma_info->disp = bmi_remote_offset;
    na_bmi_rma_info->count = bmi_length;
    na_bmi_rma_info->transfer_tag = na_bmi_gen_rma_tag(na_class);
    na_bmi_rma_info->completion_tag = na_bmi_gen_rma_tag(na_class);
    na_bmi_op_id->info.put.rma_info = na_bmi_rma_info;

    /* Assign op_id */
    if (op_id && op_id != NA_OP_ID_IGNORE && *op_id == NA_OP_ID_NULL)
        *op_id = (na_op_id_t) na_bmi_op_id;

    /* Post the BMI unexpected send request */
    bmi_ret = BMI_post_sendunexpected(
            &na_bmi_op_id->info.put.request_op_id, na_bmi_addr->bmi_addr,
            na_bmi_rma_info, sizeof(struct na_bmi_rma_info), BMI_EXT_ALLOC,
            NA_BMI_RMA_REQUEST_TAG, na_bmi_op_id, *bmi_context, NULL);
    if (bmi_ret < 0) {
        NA_LOG_ERROR("BMI_post_sendunexpected() failed");
        ret = NA_PROTOCOL_ERROR;
        goto done;
    }

    /* Post the BMI send request */
    bmi_ret = BMI_post_send(
            &na_bmi_op_id->info.put.transfer_op_id, na_bmi_addr->bmi_addr,
            (char *) bmi_local_mem_handle->base + bmi_local_offset, bmi_length,
            BMI_EXT_ALLOC, na_bmi_rma_info->transfer_tag, na_bmi_op_id,
            *bmi_context, NULL);
    if (bmi_ret < 0) {
        NA_LOG_ERROR("BMI_post_send() failed");
        ret = NA_PROTOCOL_ERROR;
        goto done;
    }

    /* Immediate completion */
    if (bmi_ret) {
        hg_atomic_set32(&na_bmi_op_id->info.put.transfer_completed, NA_TRUE);
    }

    /* Post the BMI recv request */
    bmi_ret = BMI_post_recv(
            &na_bmi_op_id->info.put.completion_op_id, na_bmi_addr->bmi_addr,
            &na_bmi_op_id->info.put.completion_flag, sizeof(na_bool_t),
            &na_bmi_op_id->info.put.completion_actual_size,
            BMI_EXT_ALLOC, na_bmi_rma_info->completion_tag, na_bmi_op_id,
            *bmi_context, NULL);
    if (bmi_ret < 0) {
        NA_LOG_ERROR("BMI_post_recv() failed");
        ret = NA_PROTOCOL_ERROR;
        goto done;
    }

    /* If immediate completion, directly add to completion queue */
    if (bmi_ret) {
        ret = na_bmi_complete(na_bmi_op_id);
        if (ret != NA_SUCCESS) {
            NA_LOG_ERROR("Could not complete operation");
            goto done;
        }
    }

done:
    if (ret != NA_SUCCESS) {
        na_bmi_op_destroy(na_class, (na_op_id_t) na_bmi_op_id);
        free(na_bmi_rma_info);
    }
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_bmi_get(na_class_t *na_class, na_context_t *context, na_cb_t callback,
        void *arg, na_mem_handle_t local_mem_handle, na_offset_t local_offset,
        na_mem_handle_t remote_mem_handle, na_offset_t remote_offset,
        na_size_t length, na_addr_t remote_addr, na_op_id_t *op_id)
{
    bmi_context_id *bmi_context = (bmi_context_id *) context->plugin_context;
    struct na_bmi_mem_handle *bmi_local_mem_handle =
            (struct na_bmi_mem_handle *) local_mem_handle;
    bmi_size_t bmi_local_offset = (bmi_size_t) local_offset;
    struct na_bmi_mem_handle *bmi_remote_mem_handle =
            (struct na_bmi_mem_handle *) remote_mem_handle;
    bmi_size_t bmi_remote_offset = (bmi_size_t) remote_offset;
    struct na_bmi_addr *na_bmi_addr = (struct na_bmi_addr *) remote_addr;
    bmi_size_t bmi_length = (bmi_size_t) length;
    struct na_bmi_op_id *na_bmi_op_id = NULL;
    struct na_bmi_rma_info *na_bmi_rma_info = NULL;
    na_return_t ret = NA_SUCCESS;
    int bmi_ret;

    switch (bmi_remote_mem_handle->attr) {
        case NA_MEM_WRITE_ONLY:
            NA_LOG_ERROR("Registered memory requires read permission");
            ret = NA_PERMISSION_ERROR;
            goto done;
        case NA_MEM_READ_ONLY:
        case NA_MEM_READWRITE:
            break;
        default:
            NA_LOG_ERROR("Invalid memory access flag");
            ret = NA_INVALID_PARAM;
            goto done;
    }

    /* Allocate op_id if not provided */
    if (op_id && op_id != NA_OP_ID_IGNORE && *op_id != NA_OP_ID_NULL) {
        na_bmi_op_id = (struct na_bmi_op_id *) *op_id;
        hg_atomic_incr32(&na_bmi_op_id->ref_count);
    } else {
        na_bmi_op_id = (struct na_bmi_op_id *) na_bmi_op_create(na_class);
        if (!na_bmi_op_id) {
            NA_LOG_ERROR("Could not allocate NA BMI operation ID");
            ret = NA_NOMEM_ERROR;
            goto done;
        }
    }
    na_bmi_op_id->context = context;
    na_bmi_op_id->type = NA_CB_GET;
    na_bmi_op_id->callback = callback;
    na_bmi_op_id->arg = arg;
    hg_atomic_set32(&na_bmi_op_id->completed, 0);
    na_bmi_op_id->info.get.request_op_id = 0;
    na_bmi_op_id->info.get.transfer_op_id = 0;
    na_bmi_op_id->info.get.transfer_actual_size = 0;
    na_bmi_op_id->info.get.internal_progress = NA_FALSE;
    na_bmi_op_id->info.get.remote_addr = na_bmi_addr->bmi_addr;
    na_bmi_op_id->info.get.rma_info = NULL;
    na_bmi_op_id->cancel = 0;

    /* Allocate rma info (use calloc to avoid uninitialized transfer) */
    na_bmi_rma_info =
            (struct na_bmi_rma_info *) calloc(1, sizeof(struct na_bmi_rma_info));
    if (!na_bmi_rma_info) {
        NA_LOG_ERROR("Could not allocate NA BMI RMA info");
        ret = NA_NOMEM_ERROR;
        goto done;
    }
    na_bmi_rma_info->op = NA_BMI_RMA_GET;
    na_bmi_rma_info->base = bmi_remote_mem_handle->base;
    na_bmi_rma_info->disp = bmi_remote_offset;
    na_bmi_rma_info->count = bmi_length;
    na_bmi_rma_info->transfer_tag = na_bmi_gen_rma_tag(na_class);
    na_bmi_rma_info->completion_tag = 0; /* not used */
    na_bmi_op_id->info.get.rma_info = na_bmi_rma_info;

    /* Assign op_id */
    if (op_id && op_id != NA_OP_ID_IGNORE && *op_id == NA_OP_ID_NULL)
        *op_id = na_bmi_op_id;

    /* Post the BMI unexpected send request */
    bmi_ret = BMI_post_sendunexpected(
            &na_bmi_op_id->info.get.request_op_id, na_bmi_addr->bmi_addr,
            na_bmi_rma_info, sizeof(struct na_bmi_rma_info), BMI_EXT_ALLOC,
            NA_BMI_RMA_REQUEST_TAG, na_bmi_op_id, *bmi_context, NULL);
    if (bmi_ret < 0) {
        NA_LOG_ERROR("BMI_post_sendunexpected() failed");
        ret = NA_PROTOCOL_ERROR;
        goto done;
    }

    /* Post the BMI recv request */
    bmi_ret = BMI_post_recv(
            &na_bmi_op_id->info.get.transfer_op_id, na_bmi_addr->bmi_addr,
            (char *) bmi_local_mem_handle->base + bmi_local_offset, bmi_length,
            &na_bmi_op_id->info.get.transfer_actual_size, BMI_EXT_ALLOC,
            na_bmi_rma_info->transfer_tag, na_bmi_op_id, *bmi_context, NULL);
    if (bmi_ret < 0) {
        NA_LOG_ERROR("BMI_post_recv() failed");
        ret = NA_PROTOCOL_ERROR;
        goto done;
    }

    /* If immediate completion, directly add to completion queue */
    if (bmi_ret) {
        ret = na_bmi_complete(na_bmi_op_id);
        if (ret != NA_SUCCESS) {
            NA_LOG_ERROR("Could not complete operation");
            goto done;
        }
    }

done:
    if (ret != NA_SUCCESS) {
        na_bmi_op_destroy(na_class, (na_op_id_t) na_bmi_op_id);
        free(na_bmi_rma_info);
    }
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_bmi_progress(na_class_t *na_class, na_context_t *context,
        unsigned int timeout)
{
    double remaining = timeout / 1000.0; /* Convert timeout in ms into seconds */
    na_return_t ret = NA_SUCCESS;

    do {
        hg_time_t t1, t2;

        if (timeout)
            hg_time_get_current(&t1);

        /* Try to make progress here from the BMI unexpected queue */
        ret = na_bmi_progress_unexpected(na_class, context, 0);
        if (ret != NA_SUCCESS) {
            if (ret != NA_TIMEOUT) {
                NA_LOG_ERROR("Could not make unexpected progress");
                goto done;
            }
        } else
            break; /* Progressed */

        /* The rule is that the timeout should be passed to testcontext, and
         * that testcontext will return if there is an unexpected message.
         * (And, that as long as there are unexpected messages pending,
         * testcontext will ignore the timeout and immediately return).
         * [verified this in the source] */
        ret = na_bmi_progress_expected(na_class, context,
                (unsigned int) (remaining * 1000.0));
        if (ret != NA_SUCCESS) {
            if (ret != NA_TIMEOUT) {
                NA_LOG_ERROR("Could not make expected progress");
                goto done;
            }
        } else
            break; /* Progressed */

        if (timeout) {
            hg_time_get_current(&t2);
            remaining -= hg_time_to_double(hg_time_subtract(t2, t1));
        }
    } while (remaining > 0);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_bmi_progress_unexpected(na_class_t *na_class, na_context_t *context,
        unsigned int timeout)
{
    int outcount = 0;
    struct BMI_unexpected_info test_unexpected_info;
    struct na_bmi_unexpected_info *unexpected_info = NULL;
    struct na_bmi_op_id *na_bmi_op_id = NULL;
    na_return_t ret = NA_SUCCESS;
    int bmi_ret;

    /* Prevent multiple threads from calling BMI_testunexpected concurrently */
    hg_thread_mutex_lock(&NA_BMI_PRIVATE_DATA(na_class)->test_unexpected_mutex);

    /* Test unexpected message */
    bmi_ret = BMI_testunexpected(1, &outcount, &test_unexpected_info,
            (int) timeout);

    hg_thread_mutex_unlock(
            &NA_BMI_PRIVATE_DATA(na_class)->test_unexpected_mutex);

    if (bmi_ret < 0) {
        NA_LOG_ERROR("BMI_testunexpected failed");
        ret = NA_PROTOCOL_ERROR;
        goto done;
    }

    if (outcount) {
        if (test_unexpected_info.error_code != 0) {
            NA_LOG_ERROR("BMI_testunexpected failed, error code set");
            ret = NA_PROTOCOL_ERROR;
            goto done;
        }
        /* If no error and message arrived, keep a copy of the struct in
         * the unexpected message queue */
        unexpected_info = (struct na_bmi_unexpected_info *)
                            malloc(sizeof(struct na_bmi_unexpected_info));
        if (!unexpected_info) {
            NA_LOG_ERROR("Could not allocate unexpected info");
            ret = NA_NOMEM_ERROR;
            goto done;
        }

        memcpy(&unexpected_info->info, &test_unexpected_info,
                sizeof(struct BMI_unexpected_info));

        if (unexpected_info->info.tag == NA_BMI_RMA_REQUEST_TAG) {
            /* Make RMA progress */
            ret = na_bmi_progress_rma(na_class, context, &unexpected_info->info);
            if (ret != NA_SUCCESS) {
                NA_LOG_ERROR("Could not make RMA progress");
                goto done;
            }
        } else {
            na_bmi_op_id = na_bmi_msg_unexpected_op_pop(na_class);

            if (na_bmi_op_id) {
                /* If an op id was pushed, associate unexpected info to this
                 * operation ID and complete operation */
                na_bmi_op_id->info.recv_unexpected.unexpected_info =
                        &unexpected_info->info;
                ret = na_bmi_complete(na_bmi_op_id);
                if (ret != NA_SUCCESS) {
                    NA_LOG_ERROR("Could not complete operation");
                    goto done;
                }
            } else {
                /* Otherwise push the unexpected message into our
                 * unexpected queue so that we can treat it later when a
                 * recv_unexpected is posted */
                ret = na_bmi_msg_unexpected_push(na_class, unexpected_info);
                if (ret != NA_SUCCESS) {
                    NA_LOG_ERROR("Could not push unexpected info");
                    goto done;
                }
                /* It's pushed now and we don't want to free it */
                unexpected_info = NULL;
            }
        }
    } else {
        ret = NA_TIMEOUT; /* No progress */
    }

done:
    free(unexpected_info);
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_bmi_progress_expected(na_class_t NA_UNUSED *na_class, na_context_t *context,
        unsigned int timeout)
{
    bmi_op_id_t bmi_op_id = 0;
    int outcount = 0;
    bmi_error_code_t error_code = 0;
    bmi_size_t  bmi_actual_size = 0;
    struct na_bmi_op_id *na_bmi_op_id = NULL;
    bmi_context_id *bmi_context = (bmi_context_id *) context->plugin_context;
    na_return_t ret = NA_SUCCESS;
    int bmi_ret = 0;

    /* Return as soon as something completes or timeout is reached */
    bmi_ret = BMI_testcontext(1, &bmi_op_id, &outcount, &error_code,
            &bmi_actual_size, (void **) &na_bmi_op_id, (int) timeout,
            *bmi_context);

    /* TODO Sometimes bmi_ret is weird so check error_code as well */
    if (bmi_ret < 0 && (error_code != 0)) {
        NA_LOG_ERROR("BMI_testcontext failed");
        ret = NA_PROTOCOL_ERROR;
        goto done;
    }

    if (outcount && na_bmi_op_id) {
        if ((error_code != 0) &&
            (error_code != -BMI_ECANCEL)) {
            NA_LOG_ERROR("BMI_testcontext failed, error code set");
            ret = NA_PROTOCOL_ERROR;
            goto done;
        }

        if (error_code == -BMI_ECANCEL) {
            na_bmi_op_id->cancel |= NA_BMI_CANCEL_C;
        }

        switch (na_bmi_op_id->type) {
            case NA_CB_LOOKUP:
                NA_LOG_ERROR("Should not complete lookup here");
                break;
            case NA_CB_RECV_UNEXPECTED:
                NA_LOG_ERROR("Should not complete unexpected recv here");
                break;
            case NA_CB_SEND_UNEXPECTED:
                ret = na_bmi_complete(na_bmi_op_id);
                break;
            case NA_CB_RECV_EXPECTED:
                /* Set the actual size */
                na_bmi_op_id->info.recv_expected.actual_size = bmi_actual_size;
                ret = na_bmi_complete(na_bmi_op_id);
                break;
            case NA_CB_SEND_EXPECTED:
                ret = na_bmi_complete(na_bmi_op_id);
                break;
            case NA_CB_PUT:
                if (!hg_atomic_get32(&na_bmi_op_id->info.put.transfer_completed)
                    && na_bmi_op_id->info.put.transfer_op_id == bmi_op_id) {
                    if (na_bmi_op_id->info.put.internal_progress) {
                        hg_atomic_set32(&na_bmi_op_id->info.put.transfer_completed, NA_TRUE);
                        /* Progress completion and send an ack after the put */
                        ret = na_bmi_progress_rma_completion(na_bmi_op_id);
                    } else {
                        /* Nothing */
                    }
                }
                else if (na_bmi_op_id->info.put.completion_op_id == bmi_op_id) {
                    if (na_bmi_op_id->info.put.internal_progress) {
                        hg_atomic_set32(&na_bmi_op_id->completed, 1);

                        /* Transfer is now done so free RMA info */
                        free(na_bmi_op_id->info.put.rma_info);
                        na_bmi_op_id->info.put.rma_info = NULL;
                        na_bmi_release(na_bmi_op_id);
                    } else {
                        /* Check ack completion flag */
                        if (!na_bmi_op_id->info.put.completion_flag) {
                            NA_LOG_ERROR("Error during transfer, ack received is %u",
                                na_bmi_op_id->info.put.completion_flag);
                            ret = NA_PROTOCOL_ERROR;
                            goto done;
                        }
                        /* No internal progress but actual put */
                        ret = na_bmi_complete(na_bmi_op_id);
                    }
                }
                else if (na_bmi_op_id->info.put.request_op_id == bmi_op_id) {
                    /* If request just completed, nothing to do, just ignore */
                } else {
                    NA_LOG_ERROR("Unexpected operation ID");
                    ret = NA_PROTOCOL_ERROR;
                    goto done;
                }
                break;
            case NA_CB_GET:
                if (na_bmi_op_id->info.get.transfer_op_id == bmi_op_id) {
                    if (na_bmi_op_id->info.get.internal_progress) {
                        hg_atomic_set32(&na_bmi_op_id->completed, 1);

                        /* Transfer is now done so free RMA info */
                        free(na_bmi_op_id->info.get.rma_info);
                        na_bmi_op_id->info.get.rma_info = NULL;
                        na_bmi_release(na_bmi_op_id);
                    } else {
                        /* No internal progress but actual get */
                        ret = na_bmi_complete(na_bmi_op_id);
                    }
                }
                else if (na_bmi_op_id->info.get.request_op_id == bmi_op_id) {
                    /* If request just completed, nothing to do, just ignore */
                } else {
                    NA_LOG_ERROR("Unexpected operation ID");
                    ret = NA_PROTOCOL_ERROR;
                    goto done;
                }
                break;
            default:
                NA_LOG_ERROR("Unknown type of operation ID");
                ret = NA_PROTOCOL_ERROR;
                goto done;
        }
    } else {
        ret = NA_TIMEOUT; /* No progress */
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_bmi_progress_rma(na_class_t NA_UNUSED *na_class, na_context_t *context,
        struct BMI_unexpected_info *unexpected_info)
{
    struct na_bmi_rma_info *na_bmi_rma_info = NULL;
    struct na_bmi_op_id *na_bmi_op_id = NULL;
    bmi_context_id *bmi_context = (bmi_context_id *) context->plugin_context;
    na_return_t ret = NA_SUCCESS;
    int bmi_ret;

    if (unexpected_info->size != sizeof(struct na_bmi_rma_info)) {
        NA_LOG_ERROR("Unexpected message size does not match RMA info struct");
        ret = NA_SIZE_ERROR;
        goto done;
    }
    /* Allocate rma info */
    na_bmi_rma_info =
            (struct na_bmi_rma_info *) malloc(sizeof(struct na_bmi_rma_info));
    if (!na_bmi_rma_info) {
        NA_LOG_ERROR("Could not allocate NA BMI RMA info");
        ret = NA_NOMEM_ERROR;
        goto done;
    }
    memcpy(na_bmi_rma_info, unexpected_info->buffer, (size_t) unexpected_info->size);

    /* Allocate na_op_id */
    na_bmi_op_id = (struct na_bmi_op_id *) na_bmi_op_create(na_class);
    if (!na_bmi_op_id) {
        NA_LOG_ERROR("Could not allocate NA BMI operation ID");
        ret = NA_NOMEM_ERROR;
        goto done;
    }
    /* This is an internal operation so no user callback/arg */
    na_bmi_op_id->context = context;
    na_bmi_op_id->callback = NULL;
    na_bmi_op_id->arg = NULL;
    hg_atomic_set32(&na_bmi_op_id->completed, 0);

    switch (na_bmi_rma_info->op) {
        /* Remote wants to do a put so wait in a recv */
        case NA_BMI_RMA_PUT:
            na_bmi_op_id->type = NA_CB_PUT;
            na_bmi_op_id->info.put.request_op_id = 0;
            na_bmi_op_id->info.put.transfer_op_id = 0;
            hg_atomic_set32(&na_bmi_op_id->info.put.transfer_completed, NA_FALSE);
            na_bmi_op_id->info.put.transfer_actual_size = 0;
            na_bmi_op_id->info.put.completion_op_id = 0;
            na_bmi_op_id->info.put.completion_flag = NA_FALSE;
            na_bmi_op_id->info.put.completion_actual_size = 0;
            na_bmi_op_id->info.put.internal_progress = NA_TRUE;
            na_bmi_op_id->info.put.remote_addr = unexpected_info->addr;
            na_bmi_op_id->info.put.rma_info = na_bmi_rma_info;
            na_bmi_op_id->cancel = 0;

            /* Start receiving data */
            bmi_ret = BMI_post_recv(&na_bmi_op_id->info.put.transfer_op_id,
                    na_bmi_op_id->info.put.remote_addr,
                    (char *) na_bmi_rma_info->base + na_bmi_rma_info->disp,
                    na_bmi_rma_info->count,
                    &na_bmi_op_id->info.put.transfer_actual_size,
                    BMI_EXT_ALLOC, na_bmi_rma_info->transfer_tag, na_bmi_op_id,
                    *bmi_context, NULL);
            if (bmi_ret < 0) {
                NA_LOG_ERROR("BMI_post_recv() failed");
                ret = NA_PROTOCOL_ERROR;
                goto done;
            }

            /* Immediate completion */
            if (bmi_ret) {
                hg_atomic_set32(&na_bmi_op_id->info.put.transfer_completed, NA_TRUE);
                ret = na_bmi_progress_rma_completion(na_bmi_op_id);
            }
            break;
            /* Remote wants to do a get so do a send */
        case NA_BMI_RMA_GET:
            na_bmi_op_id->type = NA_CB_GET;
            na_bmi_op_id->info.get.request_op_id = 0;
            na_bmi_op_id->info.get.transfer_op_id = 0;
            na_bmi_op_id->info.get.transfer_actual_size = 0;
            na_bmi_op_id->info.get.internal_progress = NA_TRUE;
            na_bmi_op_id->info.get.remote_addr = unexpected_info->addr;
            na_bmi_op_id->info.get.rma_info = na_bmi_rma_info;
            na_bmi_op_id->cancel = 0;

            /* Start sending data */
            bmi_ret = BMI_post_send(&na_bmi_op_id->info.get.transfer_op_id,
                    na_bmi_op_id->info.get.remote_addr,
                    (char *) na_bmi_rma_info->base + na_bmi_rma_info->disp,
                    na_bmi_rma_info->count, BMI_EXT_ALLOC,
                    na_bmi_rma_info->transfer_tag, na_bmi_op_id,
                    *bmi_context, NULL);
            if (bmi_ret < 0) {
                NA_LOG_ERROR("BMI_post_send() failed");
                ret = NA_PROTOCOL_ERROR;
                goto done;
            }

            if (bmi_ret) {
                hg_atomic_set32(&na_bmi_op_id->completed, 1);

                free(na_bmi_op_id->info.get.rma_info);
                na_bmi_op_id->info.get.rma_info = NULL;
                na_bmi_release(na_bmi_op_id);
            }
            break;
        default:
            NA_LOG_ERROR("Operation not supported");
            ret = NA_INVALID_PARAM;
            break;
    }

    BMI_unexpected_free(unexpected_info->addr, unexpected_info->buffer);

done:
    if (ret != NA_SUCCESS) {
        free(na_bmi_op_id);
        free(na_bmi_rma_info);
    }
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_bmi_progress_rma_completion(struct na_bmi_op_id *na_bmi_op_id)
{
    na_return_t ret = NA_SUCCESS;
    struct na_bmi_rma_info *na_bmi_rma_info = NULL;
    bmi_context_id *bmi_context =
            (bmi_context_id *) na_bmi_op_id->context->plugin_context;
    int bmi_ret;
    na_bool_t completed = NA_TRUE;

    /* Only use this to send an ack when the put completes */
    if (na_bmi_op_id->type != NA_CB_PUT) {
        NA_LOG_ERROR("Invalid operation ID type");
        ret = NA_INVALID_PARAM;
        goto done;
    }

    na_bmi_rma_info = na_bmi_op_id->info.put.rma_info;

    /* Send an ack to tell the server that the data is here */
    bmi_ret = BMI_post_send(&na_bmi_op_id->info.put.completion_op_id,
            na_bmi_op_id->info.put.remote_addr, &completed, sizeof(na_bool_t),
            BMI_EXT_ALLOC, na_bmi_rma_info->completion_tag, na_bmi_op_id,
            *bmi_context, NULL);
    if (bmi_ret < 0) {
        NA_LOG_ERROR("BMI_post_send() failed");
        ret = NA_PROTOCOL_ERROR;
        goto done;
    }
    if (bmi_ret) {
        hg_atomic_set32(&na_bmi_op_id->completed, 1);

        free(na_bmi_op_id->info.put.rma_info);
        na_bmi_op_id->info.put.rma_info = NULL;
        na_bmi_release(na_bmi_op_id);
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_bmi_complete(struct na_bmi_op_id *na_bmi_op_id)
{
    struct na_cb_info *callback_info = NULL;
    na_return_t ret = NA_SUCCESS;

    /* Mark op id as completed */
    hg_atomic_set32(&na_bmi_op_id->completed, 1);

    /* Init callback info */
    callback_info = &na_bmi_op_id->completion_data.callback_info;
    callback_info->arg = na_bmi_op_id->arg;
    callback_info->ret = ((na_bmi_op_id->cancel & NA_BMI_CANCEL_R) ? NA_CANCELED : ret);
    callback_info->type = na_bmi_op_id->type;

    switch (na_bmi_op_id->type) {
        case NA_CB_LOOKUP:
            callback_info->info.lookup.addr = na_bmi_op_id->info.lookup.addr;
            break;
        case NA_CB_SEND_UNEXPECTED:
            break;
        case NA_CB_RECV_UNEXPECTED:
        {
            struct BMI_unexpected_info *unexpected_info = NULL;
 
            unexpected_info =
                    na_bmi_op_id->info.recv_unexpected.unexpected_info;

            if (unexpected_info) {
                struct na_bmi_addr *na_bmi_addr = NULL;

                /* Allocate addr */
                na_bmi_addr = (struct na_bmi_addr *) malloc(
                        sizeof(struct na_bmi_addr));
                if (!na_bmi_addr) {
                    NA_LOG_ERROR("Could not allocate BMI addr");
                    ret = NA_NOMEM_ERROR;
                    goto done;
                }

                /* Copy buffer from bmi_unexpected_info */
                if (unexpected_info->size
                      > na_bmi_op_id->info.recv_unexpected.buf_size) {
                    NA_LOG_ERROR("Buffer too small to recv unexpected data");
                    free(na_bmi_addr);
                    ret = NA_SIZE_ERROR;
                    goto done;
                }
                memcpy(na_bmi_op_id->info.recv_unexpected.buf,
                    unexpected_info->buffer, (size_t) unexpected_info->size);

                na_bmi_addr->self = NA_FALSE;
                na_bmi_addr->unexpected = NA_TRUE;
                na_bmi_addr->bmi_addr = unexpected_info->addr;
                hg_atomic_set32(&na_bmi_addr->ref_count, 1);

                /* Fill callback info */
                callback_info->info.recv_unexpected.actual_buf_size =
                    (na_size_t) unexpected_info->size;
                callback_info->info.recv_unexpected.source =
                    (na_addr_t) na_bmi_addr;
                callback_info->info.recv_unexpected.tag =
                    (na_tag_t) unexpected_info->tag;

                BMI_unexpected_free(unexpected_info->addr, unexpected_info->buffer);
            } else {
                /* In case of cancellation where no recv'd data */
                callback_info->info.recv_unexpected.actual_buf_size = 0;
                callback_info->info.recv_unexpected.source = NA_ADDR_NULL;
                callback_info->info.recv_unexpected.tag = 0;
            }
        }
            break;
        case NA_CB_SEND_EXPECTED:
            break;
        case NA_CB_RECV_EXPECTED:
            /* Check buf_size and actual_size */
            if (!(na_bmi_op_id->cancel & NA_BMI_CANCEL_R) &&
                 (na_bmi_op_id->info.recv_expected.actual_size >
                    na_bmi_op_id->info.recv_expected.buf_size)) {
                NA_LOG_ERROR("Expected recv size too large for buffer");
                ret = NA_SIZE_ERROR;
                goto done;
            }
            break;
        case NA_CB_PUT:
            /* Transfer is now done so free RMA info */
            free(na_bmi_op_id->info.put.rma_info);
            na_bmi_op_id->info.put.rma_info = NULL;
            break;
        case NA_CB_GET:
            /* Transfer is now done so free RMA info */
            free(na_bmi_op_id->info.get.rma_info);
            na_bmi_op_id->info.get.rma_info = NULL;
            break;
        default:
            NA_LOG_ERROR("Operation not supported");
            ret = NA_INVALID_PARAM;
            break;
    }

    na_bmi_op_id->completion_data.callback = na_bmi_op_id->callback;
    na_bmi_op_id->completion_data.plugin_callback = na_bmi_release;
    na_bmi_op_id->completion_data.plugin_callback_args = na_bmi_op_id;

    ret = na_cb_completion_add(na_bmi_op_id->context,
        &na_bmi_op_id->completion_data);
    if (ret != NA_SUCCESS) {
        NA_LOG_ERROR("Could not add callback to completion queue");
        goto done;
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static void
na_bmi_release(void *arg)
{
    struct na_bmi_op_id *na_bmi_op_id = (struct na_bmi_op_id *) arg;

    if (na_bmi_op_id && !hg_atomic_get32(&na_bmi_op_id->completed)) {
        NA_LOG_WARNING("Releasing resources from an uncompleted operation");
    }
    na_bmi_op_destroy(NULL, (na_op_id_t) na_bmi_op_id);
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_bmi_cancel(na_class_t *na_class, na_context_t *context, na_op_id_t op_id)
{
    struct na_bmi_op_id *na_bmi_op_id = (struct na_bmi_op_id *) op_id;
    bmi_context_id *bmi_context = (bmi_context_id *) context->plugin_context;
    na_return_t ret = NA_SUCCESS;
    int bmi_ret;

    if (hg_atomic_get32(&na_bmi_op_id->completed))
        goto done;

    switch (na_bmi_op_id->type) {
        case NA_CB_LOOKUP:
            /* Nothing for now */
            break;
        case NA_CB_SEND_UNEXPECTED:
            bmi_ret = BMI_cancel(na_bmi_op_id->info.send_unexpected.op_id,
                    *bmi_context);
            if (bmi_ret < 0) {
                NA_LOG_ERROR("BMI_cancel() failed");
                ret = NA_PROTOCOL_ERROR;
            }
            na_bmi_op_id->cancel = NA_BMI_CANCEL_R;
            break;
        case NA_CB_RECV_UNEXPECTED:
        {
            struct na_bmi_op_id *na_bmi_pop_op_id = NULL;

            /* Must remove op_id from unexpected op_id queue */
            while (na_bmi_pop_op_id != na_bmi_op_id) {
                na_bmi_pop_op_id = na_bmi_msg_unexpected_op_pop(na_class);

                /* Push back unexpected op_id to queue if it does not match */
                if (na_bmi_pop_op_id != na_bmi_op_id) {
                    na_bmi_msg_unexpected_op_push(na_class, na_bmi_pop_op_id);
                } else {
                    na_bmi_op_id->cancel = NA_BMI_CANCEL_R;
                    na_bmi_complete(na_bmi_op_id);
                }
            }
        }
            break;
        case NA_CB_SEND_EXPECTED:
            bmi_ret = BMI_cancel(na_bmi_op_id->info.send_expected.op_id,
                    *bmi_context);
            if (bmi_ret < 0) {
                NA_LOG_ERROR("BMI_cancel() failed");
                ret = NA_PROTOCOL_ERROR;
            }
            na_bmi_op_id->cancel = NA_BMI_CANCEL_R;
            break;
        case NA_CB_RECV_EXPECTED:
            bmi_ret = BMI_cancel(na_bmi_op_id->info.recv_expected.op_id,
                    *bmi_context);
            if (bmi_ret < 0) {
                NA_LOG_ERROR("BMI_cancel() failed");
                ret = NA_PROTOCOL_ERROR;
            }
            na_bmi_op_id->cancel = NA_BMI_CANCEL_R;
            break;
        case NA_CB_PUT:
            /* cancel request (unexpected send) */
            bmi_ret = 0;
            bmi_ret |= BMI_cancel(na_bmi_op_id->info.put.request_op_id,
                                 *bmi_context);

            /* cancel put (expected send) */
            bmi_ret |= BMI_cancel(na_bmi_op_id->info.put.transfer_op_id,
                                 *bmi_context);

            /* cancel ack (expected recv) */
            bmi_ret |= BMI_cancel(na_bmi_op_id->info.put.completion_op_id,
                                 *bmi_context);
            if (bmi_ret < 0) {
                NA_LOG_ERROR("BMI_cancel() failed");
                ret = NA_PROTOCOL_ERROR;
            }
            na_bmi_op_id->cancel = NA_BMI_CANCEL_R;
            break;
        case NA_CB_GET:
            /* cancel request (unexpected send) */
            bmi_ret = 0;

            bmi_ret |= BMI_cancel(na_bmi_op_id->info.get.request_op_id,
                                  *bmi_context);

            /* cancel get (expected recv) */
            bmi_ret |= BMI_cancel(na_bmi_op_id->info.get.transfer_op_id,
                                  *bmi_context);
            if (bmi_ret < 0) {
                NA_LOG_ERROR("BMI_cancel() failed");
                ret = NA_PROTOCOL_ERROR;
            }
            na_bmi_op_id->cancel = NA_BMI_CANCEL_R;
            break;
        default:
            NA_LOG_ERROR("Operation not supported");
            ret = NA_INVALID_PARAM;
            break;
    }

done:
    return ret;
}
