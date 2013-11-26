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
#include "na_private.h"
#include "na_error.h"

#include "mercury_hash_table.h"
#include "mercury_queue.h"
#include "mercury_thread.h"
#include "mercury_thread_mutex.h"
#include "mercury_time.h"
#include "mercury_atomic.h"

#include <stdlib.h>
#include <string.h>

/****************/
/* Local Macros */
/****************/
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

/************************************/
/* Local Type and Struct Definition */
/************************************/

/* na_bmi_addr */
struct na_bmi_addr {
    BMI_addr_t bmi_addr;   /* BMI addr */
    na_bool_t  unexpected; /* Address generated from unexpected recv */
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
    bmi_size_t  transfer_actual_size;
    bmi_op_id_t completion_op_id;
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

/* na_bmi_op_id  TODO uint64_t cookie for cancel ?*/
struct na_bmi_op_id {
    na_cb_type_t type;
    na_cb_t callback; /* Callback */
    void *arg;
    na_bool_t completed; /* Operation completed */
    union {
      struct na_bmi_info_lookup lookup;
      struct na_bmi_info_send_unexpected send_unexpected;
      struct na_bmi_info_recv_unexpected recv_unexpected;
      struct na_bmi_info_send_expected send_expected;
      struct na_bmi_info_recv_expected recv_expected;
      struct na_bmi_info_put put;
      struct na_bmi_info_get get;
    } info;
};

struct na_bmi_private_data {
    na_bool_t listening;                          /* Used in server mode */
    char *listen_addr;                            /* Server listen_addr */
    bmi_context_id bmi_context;                   /* BMI Context */
    hg_thread_mutex_t test_unexpected_mutex;      /* Mutex */
    hg_queue_t *unexpected_msg_queue;             /* Unexpected message queue */
    hg_thread_mutex_t unexpected_msg_queue_mutex; /* Mutex */
    hg_queue_t *unexpected_op_queue;              /* Unexpected op queue */
    hg_thread_mutex_t unexpected_op_queue_mutex;  /* Mutex */
    hg_hash_table_t  *mem_handle_map;             /* Map to memory handles */
    hg_thread_mutex_t mem_handle_map_mutex;       /* Mutex */
    hg_atomic_int32_t rma_tag;                    /* Atomic RMA tag value */
};

/********************/
/* Local Prototypes */
/********************/
/* verify */
static na_bool_t na_bmi_verify(const char *protocol);

/* initialize */
static na_class_t *na_bmi_initialize(const struct na_host_buffer *na_buffer,
        na_bool_t listen);

/* finalize */
static na_return_t na_bmi_finalize(na_class_t *na_class);

/* addr_lookup */
static na_return_t na_bmi_addr_lookup(na_class_t *na_class, na_cb_t callback,
        void *arg, const char *name, na_op_id_t *op_id);

/* addr_free */
static na_return_t na_bmi_addr_free(na_class_t *na_class, na_addr_t addr);

/* addr_to_string */
static na_return_t na_bmi_addr_to_string(na_class_t *na_class, char *buf,
        na_size_t buf_size, na_addr_t addr);

/* msg_get_max */
static na_size_t na_bmi_msg_get_max_expected_size(na_class_t *na_class);
static na_size_t na_bmi_msg_get_max_unexpected_size(na_class_t *na_class);
static na_tag_t na_bmi_msg_get_max_tag(na_class_t *na_class);

/* msg_send_unexpected */
static na_return_t na_bmi_msg_send_unexpected(na_class_t *na_class,
        na_cb_t callback, void *arg, const void *buf, na_size_t buf_size,
        na_addr_t dest, na_tag_t tag, na_op_id_t *op_id);

/* msg_recv_unexpected */
static na_return_t na_bmi_msg_recv_unexpected(na_class_t *na_class,
        na_cb_t callback, void *arg, void *buf, na_size_t buf_size,
        na_op_id_t *op_id);

/* msg_send_expected */
static na_return_t na_bmi_msg_send_expected(na_class_t *na_class,
        na_cb_t callback, void *arg, const void *buf, na_size_t buf_size,
        na_addr_t dest, na_tag_t tag, na_op_id_t *op_id);

/* msg_recv_expected */
static na_return_t na_bmi_msg_recv_expected(na_class_t *na_class,
        na_cb_t callback, void *arg, void *buf, na_size_t buf_size,
        na_addr_t source, na_tag_t tag, na_op_id_t *op_id);
static na_return_t na_bmi_msg_unexpected_push(na_class_t *na_class,
        struct BMI_unexpected_info *unexpected_info);
static struct BMI_unexpected_info *na_bmi_msg_unexpected_pop(
        na_class_t *na_class);
static na_return_t na_bmi_msg_unexpected_op_push(na_class_t *na_class,
        struct na_bmi_op_id *na_bmi_op_id);
static struct na_bmi_op_id *na_bmi_msg_unexpected_op_pop(na_class_t *na_class);

/* mem_handle */
static na_return_t na_bmi_mem_handle_create(na_class_t *na_class, void *buf,
        na_size_t buf_size, unsigned long flags, na_mem_handle_t *mem_handle);
static na_return_t na_bmi_mem_handle_free(na_class_t *na_class,
        na_mem_handle_t mem_handle);
static na_return_t na_bmi_mem_register(na_class_t *na_class,
        na_mem_handle_t mem_handle);
static na_return_t na_bmi_mem_deregister(na_class_t *na_class,
        na_mem_handle_t mem_handle);

/* mem_handle serialization */
static na_size_t na_bmi_mem_handle_get_serialize_size(na_class_t *na_class,
        na_mem_handle_t mem_handle);
static na_return_t na_bmi_mem_handle_serialize(na_class_t *na_class, void *buf,
        na_size_t buf_size, na_mem_handle_t mem_handle);
static na_return_t na_bmi_mem_handle_deserialize(na_class_t *na_class,
        na_mem_handle_t *mem_handle, const void *buf, na_size_t buf_size);

/* put */
static na_return_t na_bmi_put(na_class_t *na_class, na_cb_t callback, void *arg,
        na_mem_handle_t local_mem_handle, na_offset_t local_offset,
        na_mem_handle_t remote_mem_handle, na_offset_t remote_offset,
        na_size_t length, na_addr_t remote_addr, na_op_id_t *op_id);

/* get */
static na_return_t na_bmi_get(na_class_t *na_class, na_cb_t callback, void *arg,
        na_mem_handle_t local_mem_handle, na_offset_t local_offset,
        na_mem_handle_t remote_mem_handle, na_offset_t remote_offset,
        na_size_t length, na_addr_t remote_addr, na_op_id_t *op_id);

/* progress */
static na_return_t na_bmi_progress(na_class_t *na_class, unsigned int timeout);
static na_return_t na_bmi_progress_unexpected(na_class_t *na_class,
        unsigned int timeout, na_bool_t *progressed);
static na_return_t na_bmi_progress_expected(na_class_t *na_class,
        unsigned int timeout, na_bool_t *progressed);
static na_return_t na_bmi_progress_rma(na_class_t *na_class,
        struct BMI_unexpected_info *unexpected_info);
static na_return_t na_bmi_progress_rma_completion(na_class_t *na_class,
        struct na_bmi_op_id *na_bmi_op_id);
static na_return_t na_bmi_complete(struct na_bmi_op_id *na_bmi_op_id);
static void na_bmi_release(struct na_cb_info *callback_info, void *arg);

/* cancel */
static na_return_t na_bmi_cancel(na_class_t *na_class, na_op_id_t op_id);

/*******************/
/* Local Variables */
/*******************/
static const na_class_t na_bmi_class_g = {
        NULL,                                 /* private_data */
        na_bmi_finalize,                      /* finalize */
        na_bmi_addr_lookup,                   /* addr_lookup */
        na_bmi_addr_free,                     /* addr_free */
        na_bmi_addr_to_string,                /* addr_to_string */
        na_bmi_msg_get_max_expected_size,     /* msg_get_max_expected_size */
        na_bmi_msg_get_max_unexpected_size,   /* msg_get_max_expected_size */
        na_bmi_msg_get_max_tag,               /* msg_get_maximum_tag */
        na_bmi_msg_send_unexpected,           /* msg_send_unexpected */
        na_bmi_msg_recv_unexpected,           /* msg_recv_unexpected */
        na_bmi_msg_send_expected,             /* msg_send_expected */
        na_bmi_msg_recv_expected,             /* msg_recv_expected */
        na_bmi_mem_handle_create,             /* mem_handle_create */
        NULL,                                 /* mem_handle_create_segment */
        na_bmi_mem_handle_free,               /* mem_handle_free */
        na_bmi_mem_register,                  /* mem_register */
        na_bmi_mem_deregister,                /* mem_deregister */
        na_bmi_mem_handle_get_serialize_size, /* mem_handle_get_serialize_size */
        na_bmi_mem_handle_serialize,          /* mem_handle_serialize */
        na_bmi_mem_handle_deserialize,        /* mem_handle_deserialize */
        na_bmi_put,                           /* put */
        na_bmi_get,                           /* get */
        na_bmi_progress,                      /* progress */
        na_bmi_cancel                         /* cancel */
};

static const char na_bmi_name_g[] = "bmi";

const struct na_class_describe na_bmi_describe_g  = {
    na_bmi_name_g,
    na_bmi_verify,
    na_bmi_initialize
};

/********************/
/* Plugin callbacks */
/********************/

static NA_INLINE int
pointer_equal(void *location1, void *location2)
{
    return location1 == location2;
}

/*---------------------------------------------------------------------------*/
static NA_INLINE unsigned int
pointer_hash(void *location)
{
    return (unsigned int) (unsigned long) location;
}

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
na_bmi_verify(const char *protocol)
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
    char     *index          = NULL;

    /* Obtain the list of transport protocols supported by BMI. */
    string_length = BMI_get_info(0, BMI_TRANSPORT_METHODS_STRING, &transport);
    
    if (string_length <= 0 || transport == NULL) {
        /* bmi is not configured with any plugins, transport is NULL */
        return NA_FALSE;
    }

    index = strtok(transport, ",");

    while (index != NULL) {
        /* check if bmi supports the protocol. */
        if (strcmp(index, protocol) == 0) {
            accept = NA_TRUE;
            break;
        }

        index = strtok(NULL, ",");
    }

    free(transport);
#else
    if (strcmp(protocol, "tcp") == 0) {
        accept = NA_TRUE;
    }
#endif

    return accept;
}

/*---------------------------------------------------------------------------*/
static na_class_t *
na_bmi_initialize(const struct na_host_buffer *na_buffer, na_bool_t listen)
{
    char *method_list = NULL;
    int flag;
    size_t method_list_len;
    na_class_t *na_class = NULL;

    flag = (listen) ? BMI_INIT_SERVER : 0;

    method_list_len = strlen("bmi_") + strlen(na_buffer->na_protocol) + 1;
    method_list = (char *) malloc(method_list_len);
    if (!method_list) {
        NA_LOG_ERROR("Could not allocate method_list");
        return NULL;
    }

    memset(method_list, '\0', method_list_len);

    strcpy(method_list, "bmi_");
    strcat(method_list, na_buffer->na_protocol);

    na_class = NA_BMI_Init((listen) ? method_list : NULL,
                                (listen) ? na_buffer->na_host_string : NULL,
                                flag);

    free(method_list);

    return na_class;
}

/*---------------------------------------------------------------------------*/
na_class_t *
NA_BMI_Init(const char *method_list, const char *listen_addr, int flags)
{
    na_class_t *na_class = NULL;
    na_bool_t listening;
    hg_hash_table_t *mem_handle_map = NULL;
    hg_queue_t *unexpected_msg_queue = NULL;
    hg_queue_t *unexpected_op_queue = NULL;
    na_bool_t error_occurred = NA_FALSE;
    int bmi_ret;

    na_class = (na_class_t *) malloc(sizeof(na_class_t));
    if (!na_class) {
        NA_LOG_ERROR("Could not allocate NA class");
        error_occurred = NA_TRUE;
        goto done;
    }
    *na_class = na_bmi_class_g;
    na_class->private_data = malloc(sizeof(struct na_bmi_private_data));
    if (!na_class->private_data) {
        NA_LOG_ERROR("Could not allocate NA private data class");
        error_occurred = NA_TRUE;
        goto done;
    }

    /* Initialize BMI */
    bmi_ret = BMI_initialize(method_list, listen_addr, flags);
    if (bmi_ret < 0) {
        NA_LOG_ERROR("BMI_initialize() failed");
        error_occurred = NA_TRUE;
        goto done;
    }

    listening = (flags == BMI_INIT_SERVER) ? NA_TRUE : NA_FALSE;
    NA_BMI_PRIVATE_DATA(na_class)->listening = listening;
    NA_BMI_PRIVATE_DATA(na_class)->listen_addr =
            (listening) ? strdup(listen_addr) : NULL;

    /* Create a new BMI context */
    bmi_ret = BMI_open_context(&NA_BMI_PRIVATE_DATA(na_class)->bmi_context);
    if (bmi_ret < 0) {
        NA_LOG_ERROR("BMI_open_context() failed");
        error_occurred = NA_TRUE;
        goto done;
    }

    /* Create hash table for memory registration */
    mem_handle_map = hg_hash_table_new(pointer_hash, pointer_equal);
    if (!mem_handle_map) {
        NA_LOG_ERROR("Could not create memory handle map");
        error_occurred = NA_TRUE;
        goto done;
    }
    /* Automatically free all the values with the hash map */
    hg_hash_table_register_free_functions(mem_handle_map, NULL, NULL);
    NA_BMI_PRIVATE_DATA(na_class)->mem_handle_map = mem_handle_map;

    /* Create queue for unexpected messages */
    unexpected_msg_queue = hg_queue_new();
    if (!unexpected_msg_queue) {
        NA_LOG_ERROR("Could not create unexpected message queue");
        error_occurred = NA_TRUE;
        goto done;
    }
    NA_BMI_PRIVATE_DATA(na_class)->unexpected_msg_queue = unexpected_msg_queue;

    /* Create queue for making progress on operation IDs */
    unexpected_op_queue = hg_queue_new();
    if (!unexpected_op_queue) {
        NA_LOG_ERROR("Could not create unexpected op queue");
        error_occurred = NA_TRUE;
        goto done;
    }
    NA_BMI_PRIVATE_DATA(na_class)->unexpected_op_queue = unexpected_op_queue;

    /* Initialize mutex/cond */
    hg_thread_mutex_init(&NA_BMI_PRIVATE_DATA(na_class)->test_unexpected_mutex);
    hg_thread_mutex_init(&NA_BMI_PRIVATE_DATA(na_class)->mem_handle_map_mutex);
    hg_thread_mutex_init(
            &NA_BMI_PRIVATE_DATA(na_class)->unexpected_msg_queue_mutex);
    hg_thread_mutex_init(
            &NA_BMI_PRIVATE_DATA(na_class)->unexpected_op_queue_mutex);

    /* Initialize atomic op */
    hg_atomic_set32(&NA_BMI_PRIVATE_DATA(na_class)->rma_tag, NA_BMI_RMA_TAG);

done:
    if (error_occurred) {
        /* TODO clean stuff */
    }

    return na_class;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_bmi_finalize(na_class_t *na_class)
{
    na_return_t ret = NA_SUCCESS;
    int bmi_ret;

    /* Check that unexpected op queue is empty */
    if (!hg_queue_is_empty(
            NA_BMI_PRIVATE_DATA(na_class)->unexpected_op_queue)) {
        NA_LOG_ERROR("Unexpected op queue should be empty");
        ret = NA_PROTOCOL_ERROR;
    }

    /* Free unexpected op queue */
    hg_queue_free(NA_BMI_PRIVATE_DATA(na_class)->unexpected_op_queue);

    /* Check that unexpected message queue is empty */
    if (!hg_queue_is_empty(
            NA_BMI_PRIVATE_DATA(na_class)->unexpected_msg_queue)) {
        NA_LOG_ERROR("Unexpected msg queue should be empty");
        ret = NA_PROTOCOL_ERROR;
    }

    /* Free unexpected message queue */
    hg_queue_free(NA_BMI_PRIVATE_DATA(na_class)->unexpected_msg_queue);

    /* Free hash table for memory registration */
    hg_hash_table_free(NA_BMI_PRIVATE_DATA(na_class)->mem_handle_map);

    /* Close BMI context */
    BMI_close_context(NA_BMI_PRIVATE_DATA(na_class)->bmi_context);

    /* Free dupp'ed listen addr */
    free(NA_BMI_PRIVATE_DATA(na_class)->listen_addr);

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
            &NA_BMI_PRIVATE_DATA(na_class)->mem_handle_map_mutex);
    hg_thread_mutex_destroy(
            &NA_BMI_PRIVATE_DATA(na_class)->unexpected_msg_queue_mutex);
    hg_thread_mutex_destroy(
            &NA_BMI_PRIVATE_DATA(na_class)->unexpected_op_queue_mutex);

    free(na_class->private_data);
    free(na_class);

    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_bmi_addr_lookup(na_class_t NA_UNUSED *na_class, na_cb_t callback, void *arg,
        const char *name, na_op_id_t *op_id)
{
    struct na_bmi_op_id *na_bmi_op_id = NULL;
    struct na_bmi_addr *na_bmi_addr = NULL;
    na_return_t ret = NA_SUCCESS;
    int bmi_ret;

    /* Allocate op_id */
    na_bmi_op_id = (struct na_bmi_op_id *) malloc(sizeof(struct na_bmi_op_id));
    if (!na_bmi_op_id) {
        NA_LOG_ERROR("Could not allocate NA BMI operation ID");
        ret = NA_NOMEM_ERROR;
        goto done;
    }
    na_bmi_op_id->type = NA_CB_LOOKUP;
    na_bmi_op_id->callback = callback;
    na_bmi_op_id->arg = arg;
    na_bmi_op_id->completed = NA_FALSE;

    /* Allocate addr */
    na_bmi_addr = (struct na_bmi_addr *) malloc(sizeof(struct na_bmi_addr));
    if (!na_bmi_addr) {
        NA_LOG_ERROR("Could not allocate BMI addr");
        ret = NA_NOMEM_ERROR;
        goto done;
    }
    na_bmi_addr->bmi_addr = 0;
    na_bmi_addr->unexpected = NA_FALSE;
    na_bmi_op_id->info.lookup.addr = (na_addr_t) na_bmi_addr;

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

    /* Assign op_id */
    *op_id = (na_op_id_t) na_bmi_op_id;

done:
    if (ret != NA_SUCCESS) {
        free(na_bmi_addr);
        free(na_bmi_op_id);
    }
    return ret;
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

    free(na_bmi_addr);
    na_bmi_addr = NULL;

    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_bmi_addr_to_string(na_class_t NA_UNUSED *na_class, char *buf,
        na_size_t buf_size, na_addr_t addr)
{
    struct na_bmi_addr *na_bmi_addr = NULL;
    const char *bmi_rev_addr;
    na_return_t ret = NA_SUCCESS;

    na_bmi_addr = (struct na_bmi_addr *) addr;

    if (na_bmi_addr->unexpected) {
        bmi_rev_addr = BMI_addr_rev_lookup_unexpected(na_bmi_addr->bmi_addr);
    } else {
        bmi_rev_addr = BMI_addr_rev_lookup(na_bmi_addr->bmi_addr);
    }

    if (strlen(bmi_rev_addr) > buf_size) {
        NA_LOG_ERROR("Buffer size too small to copy addr");
        ret = NA_SIZE_ERROR;
        return ret;
    }

    strcpy(buf, bmi_rev_addr);

    return ret;
}

/*---------------------------------------------------------------------------*/
static na_size_t
na_bmi_msg_get_max_expected_size(na_class_t NA_UNUSED *na_class)
{
    na_size_t max_expected_size = NA_BMI_EXPECTED_SIZE;

    return max_expected_size;
}

/*---------------------------------------------------------------------------*/
static na_size_t
na_bmi_msg_get_max_unexpected_size(na_class_t NA_UNUSED *na_class)
{
    na_size_t max_unexpected_size = NA_BMI_UNEXPECTED_SIZE;

    return max_unexpected_size;
}

/*---------------------------------------------------------------------------*/
static na_tag_t
na_bmi_msg_get_max_tag(na_class_t NA_UNUSED *na_class)
{
    na_tag_t max_tag = NA_BMI_MAX_TAG;

    return max_tag;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_bmi_msg_send_unexpected(na_class_t *na_class, na_cb_t callback, void *arg,
        const void *buf, na_size_t buf_size, na_addr_t dest, na_tag_t tag,
        na_op_id_t *op_id)
{
    bmi_size_t bmi_buf_size = (bmi_size_t) buf_size;
    struct na_bmi_addr *na_bmi_addr = (struct na_bmi_addr*) dest;
    bmi_msg_tag_t bmi_tag = (bmi_msg_tag_t) tag;
    struct na_bmi_op_id *na_bmi_op_id = NULL;
    na_return_t ret = NA_SUCCESS;
    int bmi_ret;

    /* Allocate op_id */
    na_bmi_op_id = (struct na_bmi_op_id *) malloc(sizeof(struct na_bmi_op_id));
    if (!na_bmi_op_id) {
        NA_LOG_ERROR("Could not allocate NA BMI operation ID");
        ret = NA_NOMEM_ERROR;
        goto done;
    }
    na_bmi_op_id->type = NA_CB_SEND_UNEXPECTED;
    na_bmi_op_id->callback = callback;
    na_bmi_op_id->arg = arg;
    na_bmi_op_id->completed = NA_FALSE;
    na_bmi_op_id->info.send_unexpected.op_id = 0;

    /* Post the BMI unexpected send request */
    bmi_ret = BMI_post_sendunexpected(
            &na_bmi_op_id->info.send_unexpected.op_id, na_bmi_addr->bmi_addr,
            buf, bmi_buf_size, BMI_EXT_ALLOC, bmi_tag, na_bmi_op_id,
            NA_BMI_PRIVATE_DATA(na_class)->bmi_context, NULL);
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

    /* Assign op_id */
    *op_id = (na_op_id_t) na_bmi_op_id;

done:
    if (ret != NA_SUCCESS) {
        free(na_bmi_op_id);
    }
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_bmi_msg_recv_unexpected(na_class_t *na_class, na_cb_t callback, void *arg,
        void *buf, na_size_t buf_size, na_op_id_t *op_id)
{
    struct BMI_unexpected_info *unexpected_info = NULL;
    struct na_bmi_op_id *na_bmi_op_id = NULL;
    na_bool_t progressed = NA_FALSE;
    na_return_t ret = NA_SUCCESS;

    /* Allocate na_op_id */
    na_bmi_op_id = (struct na_bmi_op_id *) malloc(sizeof(struct na_bmi_op_id));
    if (!na_bmi_op_id) {
        NA_LOG_ERROR("Could not allocate NA BMI operation ID");
        ret = NA_NOMEM_ERROR;
        goto done;
    }
    na_bmi_op_id->type = NA_CB_RECV_UNEXPECTED;
    na_bmi_op_id->callback = callback;
    na_bmi_op_id->arg = arg;
    na_bmi_op_id->completed = NA_FALSE;
    na_bmi_op_id->info.recv_unexpected.buf = buf;
    na_bmi_op_id->info.recv_unexpected.buf_size = (bmi_size_t) buf_size;
    na_bmi_op_id->info.recv_unexpected.unexpected_info = NULL;

    /* Try to make progress here from the BMI unexpected queue */
    do {
        ret = na_bmi_progress_unexpected(na_class, 0, &progressed);
        if (ret != NA_SUCCESS) {
            NA_LOG_ERROR("Could not check BMI unexpected message queue");
            goto done;
        }
    } while (progressed);

    /* Look for an unexpected message already received */
    unexpected_info = na_bmi_msg_unexpected_pop(na_class);

    if (unexpected_info) {
        na_bmi_op_id->info.recv_unexpected.unexpected_info = unexpected_info;
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

    /* Assign op_id */
    *op_id = (na_op_id_t) na_bmi_op_id;

done:
    if (ret != NA_SUCCESS) {
        free(na_bmi_op_id);
    }
    free(unexpected_info);
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_bmi_msg_unexpected_push(na_class_t *na_class,
        struct BMI_unexpected_info *unexpected_info)
{
    na_return_t ret = NA_SUCCESS;

    if (!unexpected_info) {
        NA_LOG_ERROR("NULL unexpected info");
        ret = NA_INVALID_PARAM;
        goto done;
    }

    hg_thread_mutex_lock(
            &NA_BMI_PRIVATE_DATA(na_class)->unexpected_msg_queue_mutex);

    if (!hg_queue_push_head(NA_BMI_PRIVATE_DATA(na_class)->unexpected_msg_queue,
            (hg_queue_value_t) unexpected_info)) {
        NA_LOG_ERROR("Could not push unexpected info to unexpected msg queue");
        ret = NA_NOMEM_ERROR;
    }

    hg_thread_mutex_unlock(
            &NA_BMI_PRIVATE_DATA(na_class)->unexpected_msg_queue_mutex);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static struct BMI_unexpected_info *
na_bmi_msg_unexpected_pop(na_class_t *na_class)
{
    struct BMI_unexpected_info *unexpected_info;
    hg_queue_value_t queue_value;

    hg_thread_mutex_lock(
            &NA_BMI_PRIVATE_DATA(na_class)->unexpected_msg_queue_mutex);

    queue_value = hg_queue_pop_tail(
            NA_BMI_PRIVATE_DATA(na_class)->unexpected_msg_queue);
    unexpected_info = (queue_value != HG_QUEUE_NULL) ?
            (struct BMI_unexpected_info *) queue_value : NULL;

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

    if (!hg_queue_push_head(NA_BMI_PRIVATE_DATA(na_class)->unexpected_op_queue,
            (hg_queue_value_t) na_bmi_op_id)) {
        NA_LOG_ERROR("Could not push ID to unexpected op queue");
        ret = NA_NOMEM_ERROR;
    }

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
    hg_queue_value_t queue_value;

    hg_thread_mutex_lock(&NA_BMI_PRIVATE_DATA(na_class)->unexpected_op_queue_mutex);

    queue_value = hg_queue_pop_tail(
            NA_BMI_PRIVATE_DATA(na_class)->unexpected_op_queue);
    na_bmi_op_id = (queue_value != HG_QUEUE_NULL) ?
            (struct na_bmi_op_id *) queue_value : NULL;

    hg_thread_mutex_unlock(
            &NA_BMI_PRIVATE_DATA(na_class)->unexpected_op_queue_mutex);

    return na_bmi_op_id;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_bmi_msg_send_expected(na_class_t *na_class, na_cb_t callback, void *arg,
        const void *buf, na_size_t buf_size, na_addr_t dest, na_tag_t tag,
        na_op_id_t *op_id)
{
    bmi_size_t bmi_buf_size = (bmi_size_t) buf_size;
    struct na_bmi_addr *na_bmi_addr = (struct na_bmi_addr*) dest;
    bmi_msg_tag_t bmi_tag = (bmi_msg_tag_t) tag;
    struct na_bmi_op_id *na_bmi_op_id = NULL;
    na_return_t ret = NA_SUCCESS;
    int bmi_ret;

    /* Allocate op_id */
    na_bmi_op_id = (struct na_bmi_op_id *) malloc(sizeof(struct na_bmi_op_id));
    if (!na_bmi_op_id) {
        NA_LOG_ERROR("Could not allocate NA BMI operation ID");
        ret = NA_NOMEM_ERROR;
        goto done;
    }
    na_bmi_op_id->type = NA_CB_SEND_EXPECTED;
    na_bmi_op_id->callback = callback;
    na_bmi_op_id->arg = arg;
    na_bmi_op_id->completed = NA_FALSE;
    na_bmi_op_id->info.send_expected.op_id = 0;

    /* Post the BMI send request */
    bmi_ret = BMI_post_send(&na_bmi_op_id->info.send_expected.op_id,
            na_bmi_addr->bmi_addr, buf, bmi_buf_size, BMI_EXT_ALLOC, bmi_tag,
            na_bmi_op_id, NA_BMI_PRIVATE_DATA(na_class)->bmi_context, NULL);
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

    /* Assign op_id */
    *op_id = (na_op_id_t) na_bmi_op_id;

done:
    if (ret != NA_SUCCESS) {
        free(na_bmi_op_id);
    }
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_bmi_msg_recv_expected(na_class_t *na_class, na_cb_t callback, void *arg,
        void *buf, na_size_t buf_size, na_addr_t source, na_tag_t tag,
        na_op_id_t *op_id)
{
    bmi_size_t bmi_buf_size = (bmi_size_t) buf_size;
    struct na_bmi_addr *na_bmi_addr = (struct na_bmi_addr*) source;
    bmi_msg_tag_t bmi_tag = (bmi_msg_tag_t) tag;
    struct na_bmi_op_id *na_bmi_op_id = NULL;
    na_return_t ret = NA_SUCCESS;
    int bmi_ret;

    /* Allocate na_op_id */
    na_bmi_op_id = (struct na_bmi_op_id *) malloc(sizeof(struct na_bmi_op_id));
    if (!na_bmi_op_id) {
        NA_LOG_ERROR("Could not allocate NA BMI operation ID");
        ret = NA_NOMEM_ERROR;
        goto done;
    }
    na_bmi_op_id->type = NA_CB_RECV_EXPECTED;
    na_bmi_op_id->callback = callback;
    na_bmi_op_id->arg = arg;
    na_bmi_op_id->completed = NA_FALSE;
    na_bmi_op_id->info.recv_expected.op_id = 0;
    na_bmi_op_id->info.recv_expected.buf_size = bmi_buf_size;
    na_bmi_op_id->info.recv_expected.actual_size = 0;

    /* Post the BMI recv request */
    bmi_ret = BMI_post_recv(&na_bmi_op_id->info.recv_expected.op_id,
            na_bmi_addr->bmi_addr, buf, bmi_buf_size,
            &na_bmi_op_id->info.recv_expected.actual_size, BMI_EXT_ALLOC,
            bmi_tag, na_bmi_op_id, NA_BMI_PRIVATE_DATA(na_class)->bmi_context,
            NULL);
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

    /* Assign op_id */
    *op_id = (na_op_id_t) na_bmi_op_id;

done:
    if (ret != NA_SUCCESS) {
        free(na_bmi_op_id);
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
    na_bmi_mem_handle->size = bmi_buf_size;
    na_bmi_mem_handle->attr = flags;

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
na_bmi_mem_register(na_class_t *na_class, na_mem_handle_t mem_handle)
{
    struct na_bmi_mem_handle *na_bmi_mem_handle =
            (struct na_bmi_mem_handle *) mem_handle;
    na_return_t ret = NA_SUCCESS;

    hg_thread_mutex_lock(&NA_BMI_PRIVATE_DATA(na_class)->mem_handle_map_mutex);

    /* Store this handle */
    if (!hg_hash_table_insert(NA_BMI_PRIVATE_DATA(na_class)->mem_handle_map,
            (hg_hash_table_key_t) na_bmi_mem_handle->base,
            (hg_hash_table_value_t) na_bmi_mem_handle)) {
        NA_LOG_ERROR("Could not register memory handle");
        ret = NA_NOMEM_ERROR;
    }

    hg_thread_mutex_unlock(
            &NA_BMI_PRIVATE_DATA(na_class)->mem_handle_map_mutex);

    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_bmi_mem_deregister(na_class_t *na_class, na_mem_handle_t mem_handle)
{
    struct na_bmi_mem_handle *na_bmi_mem_handle =
            (struct na_bmi_mem_handle *) mem_handle;
    na_return_t ret = NA_SUCCESS;

    hg_thread_mutex_lock(&NA_BMI_PRIVATE_DATA(na_class)->mem_handle_map_mutex);

    /* Remove the handle */
    if (!hg_hash_table_remove(NA_BMI_PRIVATE_DATA(na_class)->mem_handle_map,
            (hg_hash_table_key_t) na_bmi_mem_handle->base)) {
        NA_LOG_ERROR("Could not deregister memory handle");
        ret = NA_INVALID_PARAM;
    }

    hg_thread_mutex_unlock(
            &NA_BMI_PRIVATE_DATA(na_class)->mem_handle_map_mutex);

    return ret;
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
na_bmi_put(na_class_t *na_class, na_cb_t callback, void *arg,
        na_mem_handle_t local_mem_handle, na_offset_t local_offset,
        na_mem_handle_t remote_mem_handle, na_offset_t remote_offset,
        na_size_t length, na_addr_t remote_addr, na_op_id_t *op_id)
{
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

    /* Check that local memory is registered */
    hg_thread_mutex_lock(&NA_BMI_PRIVATE_DATA(na_class)->mem_handle_map_mutex);

    if (!hg_hash_table_lookup(NA_BMI_PRIVATE_DATA(na_class)->mem_handle_map,
            (hg_hash_table_key_t) bmi_local_mem_handle->base)) {
        NA_LOG_ERROR("Could not find memory handle");
        ret = NA_INVALID_PARAM;
        goto done;
    }

    hg_thread_mutex_unlock(
            &NA_BMI_PRIVATE_DATA(na_class)->mem_handle_map_mutex);

    if (bmi_remote_mem_handle->attr != NA_MEM_READWRITE) {
        NA_LOG_ERROR("Registered memory requires write permission");
        ret = NA_PERMISSION_ERROR;
        goto done;
    }

    /* Allocate op_id */
    na_bmi_op_id = (struct na_bmi_op_id *) malloc(sizeof(struct na_bmi_op_id));
    if (!na_bmi_op_id) {
        NA_LOG_ERROR("Could not allocate NA BMI operation ID");
        ret = NA_NOMEM_ERROR;
        goto done;
    }
    na_bmi_op_id->type = NA_CB_PUT;
    na_bmi_op_id->callback = callback;
    na_bmi_op_id->arg = arg;
    na_bmi_op_id->completed = NA_FALSE;
    na_bmi_op_id->info.put.request_op_id = 0;
    na_bmi_op_id->info.put.transfer_op_id = 0;
    na_bmi_op_id->info.put.transfer_actual_size = 0;
    na_bmi_op_id->info.put.completion_op_id = 0;
    na_bmi_op_id->info.put.completion_actual_size = 0;
    na_bmi_op_id->info.put.internal_progress = NA_FALSE;
    na_bmi_op_id->info.put.remote_addr = na_bmi_addr->bmi_addr;
    na_bmi_op_id->info.put.rma_info = NULL;

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

    /* Post the BMI unexpected send request */
    bmi_ret = BMI_post_sendunexpected(
            &na_bmi_op_id->info.put.request_op_id, na_bmi_addr->bmi_addr,
            na_bmi_rma_info, sizeof(struct na_bmi_rma_info), BMI_EXT_ALLOC,
            NA_BMI_RMA_REQUEST_TAG, na_bmi_op_id,
            NA_BMI_PRIVATE_DATA(na_class)->bmi_context, NULL);
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
            NA_BMI_PRIVATE_DATA(na_class)->bmi_context, NULL);
    if (bmi_ret < 0) {
        NA_LOG_ERROR("BMI_post_send() failed");
        ret = NA_PROTOCOL_ERROR;
        goto done;
    }

    /* Post the BMI recv request */
    bmi_ret = BMI_post_recv(
            &na_bmi_op_id->info.put.completion_op_id, na_bmi_addr->bmi_addr,
            &na_bmi_op_id->completed, sizeof(na_bool_t),
            &na_bmi_op_id->info.put.completion_actual_size,
            BMI_EXT_ALLOC, na_bmi_rma_info->completion_tag, na_bmi_op_id,
            NA_BMI_PRIVATE_DATA(na_class)->bmi_context, NULL);

    /* If immediate completion, directly add to completion queue */
    if (bmi_ret) {
        ret = na_bmi_complete(na_bmi_op_id);
        if (ret != NA_SUCCESS) {
            NA_LOG_ERROR("Could not complete operation");
            goto done;
        }
    }

    /* Assign op_id */
    *op_id = (na_op_id_t) na_bmi_op_id;

done:
    if (ret != NA_SUCCESS) {
        free(na_bmi_op_id);
        free(na_bmi_rma_info);
    }
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_bmi_get(na_class_t *na_class, na_cb_t callback, void *arg,
        na_mem_handle_t local_mem_handle, na_offset_t local_offset,
        na_mem_handle_t remote_mem_handle, na_offset_t remote_offset,
        na_size_t length, na_addr_t remote_addr, na_op_id_t *op_id)
{
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

    /* Check that local memory is registered */
    hg_thread_mutex_lock(&NA_BMI_PRIVATE_DATA(na_class)->mem_handle_map_mutex);

    if (!hg_hash_table_lookup(NA_BMI_PRIVATE_DATA(na_class)->mem_handle_map,
            (hg_hash_table_key_t) bmi_local_mem_handle->base)) {
        NA_LOG_ERROR("Could not find memory handle");
        ret = NA_INVALID_PARAM;
        goto done;
    }

    hg_thread_mutex_unlock(
            &NA_BMI_PRIVATE_DATA(na_class)->mem_handle_map_mutex);

    /* Allocate op_id */
    na_bmi_op_id = (struct na_bmi_op_id *) malloc(sizeof(struct na_bmi_op_id));
    if (!na_bmi_op_id) {
        NA_LOG_ERROR("Could not allocate NA BMI operation ID");
        ret = NA_NOMEM_ERROR;
        goto done;
    }
    na_bmi_op_id->type = NA_CB_GET;
    na_bmi_op_id->callback = callback;
    na_bmi_op_id->arg = arg;
    na_bmi_op_id->completed = NA_FALSE;
    na_bmi_op_id->info.get.request_op_id = 0;
    na_bmi_op_id->info.get.transfer_op_id = 0;
    na_bmi_op_id->info.get.transfer_actual_size = 0;
    na_bmi_op_id->info.get.internal_progress = NA_FALSE;
    na_bmi_op_id->info.get.remote_addr = na_bmi_addr->bmi_addr;
    na_bmi_op_id->info.get.rma_info = NULL;

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

    /* Post the BMI unexpected send request */
    bmi_ret = BMI_post_sendunexpected(
            &na_bmi_op_id->info.get.request_op_id, na_bmi_addr->bmi_addr,
            na_bmi_rma_info, sizeof(struct na_bmi_rma_info), BMI_EXT_ALLOC,
            NA_BMI_RMA_REQUEST_TAG, na_bmi_op_id,
            NA_BMI_PRIVATE_DATA(na_class)->bmi_context, NULL);
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
            na_bmi_rma_info->transfer_tag, na_bmi_op_id,
            NA_BMI_PRIVATE_DATA(na_class)->bmi_context, NULL);
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

    /* Assign op_id */
    *op_id = (na_op_id_t) na_bmi_op_id;

done:
    if (ret != NA_SUCCESS) {
        free(na_bmi_op_id);
        free(na_bmi_rma_info);
    }
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_bmi_progress(na_class_t *na_class, unsigned int timeout)
{
    double remaining = timeout / 1000; /* Convert timeout in ms into seconds */
    na_return_t ret = NA_SUCCESS;

    do {
        hg_time_t t1, t2;
        na_bool_t progressed = NA_FALSE;

        hg_time_get_current(&t1);

        /* Try to make progress here from the BMI unexpected queue */
        ret = na_bmi_progress_unexpected(na_class, 0, &progressed);
        if (ret != NA_SUCCESS) {
            NA_LOG_ERROR("Could not make unexpected progress");
            goto done;
        }
        if (progressed) break;

        /* The rule is that the timeout should be passed to testcontext, and
         * that testcontext will return if there is an unexpected message.
         * (And, that as long as there are unexpected messages pending,
         * testcontext will ignore the timeout and immediately return).
         * [verified this in the source] */
        ret = na_bmi_progress_expected(na_class,
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
na_bmi_progress_unexpected(na_class_t *na_class, unsigned int timeout,
        na_bool_t *progressed)
{
    int outcount = 0;
    struct BMI_unexpected_info test_unexpected_info;
    struct BMI_unexpected_info *unexpected_info = NULL;
    na_return_t ret = NA_SUCCESS;
    int bmi_ret;

    /* Prevent multiple threads from calling BMI_testunexpected concurrently */
    hg_thread_mutex_lock(&NA_BMI_PRIVATE_DATA(na_class)->test_unexpected_mutex);

    /* Test unexpected message */
    bmi_ret = BMI_testunexpected(1, &outcount, &test_unexpected_info, timeout);

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
        unexpected_info = (struct BMI_unexpected_info*)
                            malloc(sizeof(struct BMI_unexpected_info));
        if (!unexpected_info) {
            NA_LOG_ERROR("Could not allocate unexpected info");
            ret = NA_NOMEM_ERROR;
            goto done;
        }

        memcpy(unexpected_info, &test_unexpected_info,
                sizeof(struct BMI_unexpected_info));

        if (unexpected_info->tag == NA_BMI_RMA_REQUEST_TAG) {
            /* Make RMA progress */
            ret = na_bmi_progress_rma(na_class, unexpected_info);
            if (ret != NA_SUCCESS) {
                NA_LOG_ERROR("Could not make RMA progress");
                goto done;
            }
        } else {
            struct na_bmi_op_id *na_bmi_op_id;

            na_bmi_op_id = na_bmi_msg_unexpected_op_pop(na_class);
            /* If an op id was pushed, associate unexpected
             * info to this operation ID and complete operation */
            if (na_bmi_op_id) {
                na_bmi_op_id->info.recv_unexpected.unexpected_info =
                        unexpected_info;
                ret = na_bmi_complete(na_bmi_op_id);
                if (ret != NA_SUCCESS) {
                    NA_LOG_ERROR("Could not complete operation");
                    goto done;
                }
            } else {
                ret = na_bmi_msg_unexpected_push(na_class, unexpected_info);
                if (ret != NA_SUCCESS) {
                    NA_LOG_ERROR("Could not push unexpected info");
                    goto done;
                }
                /* It's pushed now and we don't want to free it */
                unexpected_info = NULL;
            }
        }
    }

    if (progressed) *progressed = (outcount > 0);

done:
    free(unexpected_info);
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_bmi_progress_expected(na_class_t *na_class, unsigned int timeout,
        na_bool_t *progressed)
{
    bmi_op_id_t bmi_op_id = 0;
    int outcount = 0;
    bmi_error_code_t error_code = 0;
    bmi_size_t  bmi_actual_size = 0;
    struct na_bmi_op_id *na_bmi_op_id = NULL;
    na_return_t ret = NA_SUCCESS;
    int bmi_ret = 0;

    /* Return as soon as something completes or timeout is reached */
    bmi_ret = BMI_testcontext(1, &bmi_op_id, &outcount, &error_code,
            &bmi_actual_size, (void **) &na_bmi_op_id, timeout,
            NA_BMI_PRIVATE_DATA(na_class)->bmi_context);

    /* TODO Sometimes bmi_ret is weird so check error_code as well */
    if (bmi_ret < 0 && (error_code != 0)) {
        NA_LOG_ERROR("BMI_testcontext failed");
        ret = NA_PROTOCOL_ERROR;
        goto done;
    }

    if (outcount && na_bmi_op_id) {
        if (error_code != 0) {
            NA_LOG_ERROR("BMI_testcontext failed, error code set");
            ret = NA_PROTOCOL_ERROR;
            goto done;
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
                if (na_bmi_op_id->info.put.transfer_op_id == bmi_op_id) {
                    /* Progress completion and send an ack after the put */
                    ret = (na_bmi_op_id->info.put.internal_progress) ?
                            na_bmi_progress_rma_completion(na_class,
                                    na_bmi_op_id) : NA_SUCCESS;
                }
                else if (na_bmi_op_id->info.put.completion_op_id == bmi_op_id) {
                    if (na_bmi_op_id->info.put.internal_progress) {
                        na_bmi_op_id->completed = NA_TRUE;

                        /* Transfer is now done so free RMA info */
                        free(na_bmi_op_id->info.put.rma_info);
                        na_bmi_op_id->info.put.rma_info = NULL;
                        na_bmi_release(NULL, na_bmi_op_id);
                    } else {
                        /* No internal progress but actual put */
                        ret = na_bmi_complete(na_bmi_op_id);
                    }
                } else {
                    NA_LOG_ERROR("Unexpected operation ID");
                    ret = NA_PROTOCOL_ERROR;
                    goto done;
                }
                break;
            case NA_CB_GET:
                if (na_bmi_op_id->info.get.transfer_op_id == bmi_op_id) {
                    if (na_bmi_op_id->info.get.internal_progress) {
                        na_bmi_op_id->completed = NA_TRUE;

                        /* Transfer is now done so free RMA info */
                        free(na_bmi_op_id->info.get.rma_info);
                        na_bmi_op_id->info.get.rma_info = NULL;
                        na_bmi_release(NULL, na_bmi_op_id);
                    } else {
                        /* No internal progress but actual get */
                        ret = na_bmi_complete(na_bmi_op_id);
                    }
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
    }

    if (progressed) *progressed = (outcount > 0);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_bmi_progress_rma(na_class_t *na_class,
        struct BMI_unexpected_info *unexpected_info)
{
    struct na_bmi_mem_handle *na_bmi_mem_handle = NULL;
    struct na_bmi_rma_info *na_bmi_rma_info;
    struct na_bmi_op_id *na_bmi_op_id = NULL;
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
    memcpy(na_bmi_rma_info, unexpected_info->buffer, unexpected_info->size);

    /* Allocate na_op_id */
    na_bmi_op_id = (struct na_bmi_op_id *) malloc(sizeof(struct na_bmi_op_id));
    if (!na_bmi_op_id) {
        NA_LOG_ERROR("Could not allocate NA BMI operation ID");
        ret = NA_NOMEM_ERROR;
        goto done;
    }
    /* This is an internal operation so no user callback/arg */
    na_bmi_op_id->callback = NULL;
    na_bmi_op_id->arg = NULL;
    na_bmi_op_id->completed = NA_FALSE;

    /* Here better to keep the mutex locked the time we operate on
     * bmi_mem_handle since it's a pointer to a mem_handle */
    hg_thread_mutex_lock(&NA_BMI_PRIVATE_DATA(na_class)->mem_handle_map_mutex);

    na_bmi_mem_handle = (struct na_bmi_mem_handle *) hg_hash_table_lookup(
            NA_BMI_PRIVATE_DATA(na_class)->mem_handle_map,
            (hg_hash_table_key_t) na_bmi_rma_info->base);
    if (!na_bmi_mem_handle) {
        NA_LOG_ERROR("Could not find memory handle");
        ret = NA_INVALID_PARAM;
        hg_thread_mutex_unlock(
                &NA_BMI_PRIVATE_DATA(na_class)->mem_handle_map_mutex);
        goto done;
    }

    switch (na_bmi_rma_info->op) {
        /* Remote wants to do a put so wait in a recv */
        case NA_BMI_RMA_PUT:
            na_bmi_op_id->type = NA_CB_PUT;
            na_bmi_op_id->info.put.request_op_id = 0;
            na_bmi_op_id->info.put.transfer_op_id = 0;
            na_bmi_op_id->info.put.transfer_actual_size = 0;
            na_bmi_op_id->info.put.completion_op_id = 0;
            na_bmi_op_id->info.put.completion_actual_size = 0;
            na_bmi_op_id->info.put.internal_progress = NA_TRUE;
            na_bmi_op_id->info.put.remote_addr = unexpected_info->addr;
            na_bmi_op_id->info.put.rma_info = na_bmi_rma_info;

            /* Start receiving data */
            bmi_ret = BMI_post_recv(&na_bmi_op_id->info.put.transfer_op_id,
                    na_bmi_op_id->info.put.remote_addr,
                    (char *) na_bmi_mem_handle->base + na_bmi_rma_info->disp,
                    na_bmi_rma_info->count,
                    &na_bmi_op_id->info.put.transfer_actual_size,
                    BMI_EXT_ALLOC, na_bmi_rma_info->transfer_tag, na_bmi_op_id,
                    NA_BMI_PRIVATE_DATA(na_class)->bmi_context, NULL);
            if (bmi_ret < 0) {
                NA_LOG_ERROR("BMI_post_recv() failed");
                ret = NA_PROTOCOL_ERROR;
                goto done;
            }

            if (bmi_ret) {
                ret = na_bmi_progress_rma_completion(na_class, na_bmi_op_id);
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

            /* Start sending data */
            bmi_ret = BMI_post_send(&na_bmi_op_id->info.get.transfer_op_id,
                    na_bmi_op_id->info.get.remote_addr,
                    (char *) na_bmi_mem_handle->base + na_bmi_rma_info->disp,
                    na_bmi_rma_info->count, BMI_EXT_ALLOC,
                    na_bmi_rma_info->transfer_tag, na_bmi_op_id,
                    NA_BMI_PRIVATE_DATA(na_class)->bmi_context, NULL);
            if (bmi_ret < 0) {
                NA_LOG_ERROR("BMI_post_send() failed");
                ret = NA_PROTOCOL_ERROR;
                goto done;
            }

            if (bmi_ret) {
                na_bmi_op_id->completed = NA_TRUE;

                free(na_bmi_op_id->info.get.rma_info);
                na_bmi_op_id->info.get.rma_info = NULL;
                na_bmi_release(NULL, na_bmi_op_id);
            }
            break;
        default:
            NA_LOG_ERROR("Operation not supported");
            ret = NA_INVALID_PARAM;
            break;
    }

    hg_thread_mutex_unlock(
            &NA_BMI_PRIVATE_DATA(na_class)->mem_handle_map_mutex);

    BMI_unexpected_free(unexpected_info->addr, unexpected_info->buffer);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_bmi_progress_rma_completion(na_class_t *na_class,
        struct na_bmi_op_id *na_bmi_op_id)
{
    na_return_t ret = NA_SUCCESS;
    struct na_bmi_rma_info *na_bmi_rma_info = NULL;
    int bmi_ret;

    /* Only use this to send an ack when the put completes */
    if (na_bmi_op_id->type != NA_CB_PUT) {
        NA_LOG_ERROR("Invalid operation ID type");
        ret = NA_INVALID_PARAM;
        goto done;
    }

    na_bmi_rma_info = na_bmi_op_id->info.put.rma_info;

    /* Send an ack to tell the server that the data is here */
    bmi_ret = BMI_post_send(&na_bmi_op_id->info.put.completion_op_id,
            na_bmi_op_id->info.put.remote_addr, &na_bmi_op_id->completed,
            sizeof(na_bool_t), BMI_EXT_ALLOC, na_bmi_rma_info->completion_tag,
            na_bmi_op_id, NA_BMI_PRIVATE_DATA(na_class)->bmi_context, NULL);
    if (bmi_ret < 0) {
        NA_LOG_ERROR("BMI_post_send() failed");
        ret = NA_PROTOCOL_ERROR;
        goto done;
    }
    if (bmi_ret) {
        na_bmi_op_id->completed = NA_TRUE;

        free(na_bmi_op_id->info.put.rma_info);
        na_bmi_op_id->info.put.rma_info = NULL;
        na_bmi_release(NULL, na_bmi_op_id);
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
    na_bmi_op_id->completed = NA_TRUE;

    /* Allocate callback info */
    callback_info = (struct na_cb_info *) malloc(sizeof(struct na_cb_info));
    if (!callback_info) {
        NA_LOG_ERROR("Could not allocate callback info");
        ret = NA_NOMEM_ERROR;
        goto done;
    }
    callback_info->arg = na_bmi_op_id->arg;
    callback_info->ret = ret;
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
            struct na_bmi_addr *na_bmi_addr = NULL;

            unexpected_info =
                    na_bmi_op_id->info.recv_unexpected.unexpected_info;

            /* Copy buffer from bmi_unexpected_info */
            if (unexpected_info->size
                    > na_bmi_op_id->info.recv_unexpected.buf_size) {
                NA_LOG_ERROR("Buffer too small to recv unexpected data");
                ret = NA_SIZE_ERROR;
                goto done;
            }
            memcpy(na_bmi_op_id->info.recv_unexpected.buf,
                    unexpected_info->buffer, unexpected_info->size);

            /* Allocate addr */
            na_bmi_addr = (struct na_bmi_addr *) malloc(
                    sizeof(struct na_bmi_addr));
            if (!na_bmi_addr) {
                NA_LOG_ERROR("Could not allocate BMI addr");
                ret = NA_NOMEM_ERROR;
                goto done;
            }
            na_bmi_addr->unexpected = NA_TRUE;
            na_bmi_addr->bmi_addr = unexpected_info->addr;

            /* Fill callback info */
            callback_info->info.recv_unexpected.actual_buf_size =
                    (na_size_t) unexpected_info->size;
            callback_info->info.recv_unexpected.source =
                    (na_addr_t) na_bmi_addr;
            callback_info->info.recv_unexpected.tag =
                    (na_tag_t) unexpected_info->tag;

            BMI_unexpected_free(unexpected_info->addr, unexpected_info->buffer);
        }
            break;
        case NA_CB_SEND_EXPECTED:
            break;
        case NA_CB_RECV_EXPECTED:
            /* Check buf_size and actual_size */
            if (na_bmi_op_id->info.recv_expected.actual_size !=
                    na_bmi_op_id->info.recv_expected.buf_size) {
                NA_LOG_ERROR("Buffer size and actual transfer size do not match");
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

    ret = na_cb_completion_add(na_bmi_op_id->callback, callback_info,
            &na_bmi_release, na_bmi_op_id);
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
na_bmi_release(struct na_cb_info *callback_info, void *arg)
{
    struct na_bmi_op_id *na_bmi_op_id = (struct na_bmi_op_id *) arg;

    if (na_bmi_op_id && !na_bmi_op_id->completed) {
        NA_LOG_ERROR("Releasing resources from an uncompleted operation");
    }
    free(callback_info);
    free(na_bmi_op_id);
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_bmi_cancel(na_class_t *na_class, na_op_id_t op_id)
{
    struct na_bmi_op_id *na_bmi_op_id = (struct na_bmi_op_id *) op_id;
    na_return_t ret = NA_SUCCESS;

    /* TODO correct */
    BMI_cancel(na_bmi_op_id->info.send_expected.op_id,
            NA_BMI_PRIVATE_DATA(na_class)->bmi_context);

    return ret;
}
