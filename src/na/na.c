/*
 * Copyright (C) 2013 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#include "na_private.h"
#ifdef NA_HAS_MPI
#include "na_mpi.h"
#endif
#ifdef NA_HAS_BMI
#include "na_bmi.h"
#endif
#include "na_error.h"

#include "mercury_queue.h"
#include "mercury_thread_mutex.h"
#include "mercury_thread_condition.h"
#include "mercury_time.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

/* TODO check params in NA routines */

/****************/
/* Local Macros */
/****************/
/* Convert value to string */
#define NA_ERROR_STRING_MACRO(def, value, string) \
  if (value == def) string = #def

/************************************/
/* Local Type and Struct Definition */
/************************************/
/* NA class priority */
typedef enum na_class_priority {
  NA_CLASS_PRIORITY_INVALID  = 0,
  NA_CLASS_PRIORITY_LOW      = 1,
  NA_CLASS_PRIORITY_HIGH     = 2,
  NA_CLASS_PRIORITY_MAX      = 10
} na_class_priority_t;

/* Private context / do not expose private members to plugins */
struct na_private_context {
    struct na_context context; /* Must remain as first field */
    hg_queue_t *completion_queue;
    hg_thread_mutex_t completion_queue_mutex;
    hg_thread_cond_t completion_queue_cond;
    hg_thread_mutex_t progress_mutex;
    hg_thread_cond_t progress_cond;
    na_bool_t progressing;
};

/* Completion data stored in completion queue */
struct na_cb_completion_data {
    na_cb_t callback;
    struct na_cb_info *callback_info;
    na_plugin_cb_t plugin_callback;
    void *plugin_callback_args;
};

/********************/
/* Local Prototypes */
/********************/
/* NA_Lookup_wait callback */
static na_return_t
na_addr_lookup_cb(
        const struct na_cb_info *callback_info
        );

/*******************/
/* Local Variables */
/*******************/
#ifdef NA_HAS_SSM
extern struct na_class_describe na_ssm_describe_g;
#endif
#ifdef NA_HAS_BMI
extern struct na_class_describe na_bmi_describe_g;
#endif
#ifdef NA_HAS_MPI
extern struct na_class_describe na_mpi_describe_g;
#endif

static const struct na_class_describe *na_class_methods[] = {
#ifdef NA_HAS_BMI
    &na_bmi_describe_g,
#endif
#ifdef NA_HAS_MPI
    &na_mpi_describe_g,
#endif
#ifdef NA_HAS_SSM
    &na_ssm_describe_g,
#endif
    NULL
};

static hg_thread_mutex_t na_addr_lookup_mutex_g;

/*---------------------------------------------------------------------------*/
static void
NA_free_host_buffer(struct na_host_buffer *na_buffer)
{
    if (na_buffer) {
        free(na_buffer->na_class);
        na_buffer->na_class = NULL;
        free(na_buffer->na_protocol);
        na_buffer->na_protocol = NULL;
        free(na_buffer->na_host);
        na_buffer->na_host = NULL;
        free(na_buffer->na_host_string);
        na_buffer->na_host_string = NULL;
        free(na_buffer);
    }
}

/*---------------------------------------------------------------------------*/
static na_return_t
NA_parse_host_string(const char *host_string,
        struct na_host_buffer **in_na_buffer)
{
    char *input_string               = NULL;
    char *token                      = NULL;
    char *locator                    = NULL;
    struct na_host_buffer *na_buffer = *in_na_buffer;
    size_t na_host_string_len;
    na_return_t ret = NA_SUCCESS;

    input_string = (char*) malloc(strlen(host_string) + 1);
    if (!input_string) {
        NA_LOG_ERROR("Could not allocate string");
        ret = NA_NOMEM_ERROR;
        goto done;
    }

    strcpy(input_string, host_string);

    /* Strings can be of the format:
     *   tcp://localhost:3344
     *   tcp@ssm://localhost:3344
     */
    token = strtok_r(input_string, ":", &locator);

    if (strstr(token, "@") != NULL) {
        char *_locator = NULL;

        token = strtok_r(token, "@", &_locator);

        na_buffer->na_class = (char*) malloc(strlen(_locator) + 1);
        if (!na_buffer->na_class) {
            NA_LOG_ERROR("Could not allocate na_class");
            ret = NA_NOMEM_ERROR;
            goto done;
        }

        strcpy(na_buffer->na_class, _locator);
    } else {
        na_buffer->na_class = NULL;
    }

    na_buffer->na_protocol = (char*) malloc(strlen(token) + 1);
    if (!na_buffer->na_protocol) {
        NA_LOG_ERROR("Could not allocate na_protocol");
        ret = NA_NOMEM_ERROR;
        goto done;
    }

    strcpy(na_buffer->na_protocol, token);

    token = locator + 2;
    token = strtok_r(token, ":", &locator);

    na_buffer->na_host = (char*) malloc(strlen(token) + 1);
    if (!na_buffer->na_host) {
        NA_LOG_ERROR("Could not allocate na_host");
        ret = NA_NOMEM_ERROR;
        goto done;
    }

    strcpy(na_buffer->na_host, token);

    na_buffer->na_port = atoi(locator);

    na_host_string_len = strlen(na_buffer->na_protocol) + 1;
    na_host_string_len += strlen("://");
    na_host_string_len += strlen(na_buffer->na_host);
    na_host_string_len += strlen(":");
    na_host_string_len += strlen(locator);

    na_buffer->na_host_string = (char*) malloc(na_host_string_len);
    if (!na_buffer->na_host_string) {
        NA_LOG_ERROR("Could not allocate na_host_string");
        ret = NA_NOMEM_ERROR;
        goto done;
    }

    if (na_buffer->na_host_string != NULL) {
        memset(na_buffer->na_host_string, '\0', na_host_string_len);
        strcpy(na_buffer->na_host_string, na_buffer->na_protocol);
        strcat(na_buffer->na_host_string, "://");
        strcat(na_buffer->na_host_string, na_buffer->na_host);
        strcat(na_buffer->na_host_string, ":");
        strcat(na_buffer->na_host_string, locator);
    }

done:
    if (ret != NA_SUCCESS) {
        free(na_buffer->na_class);
        na_buffer->na_class = NULL;
        free(na_buffer->na_protocol);
        na_buffer->na_protocol = NULL;
        free(na_buffer->na_host);
        na_buffer->na_host = NULL;
        free(na_buffer->na_host_string);
        na_buffer->na_host_string = NULL;
    }
    free(input_string);

    return ret;
}

/*---------------------------------------------------------------------------*/
static na_class_priority_t
NA_get_priority(const struct na_host_buffer NA_UNUSED *na_buffer)
{
    /* TBD: */
    return NA_CLASS_PRIORITY_HIGH;
}

/*---------------------------------------------------------------------------*/
na_class_t *
NA_Initialize(const char *host_string, na_bool_t listen)
{
    na_class_t *na_class = NULL;
    na_bool_t accept = NA_FALSE;
    struct na_host_buffer *na_buffer = NULL;
    int class_index = 0;
    na_class_priority_t highest_priority = NA_CLASS_PRIORITY_INVALID;
    int i = 0;
    int plugin_count = 0;

    na_buffer = (struct na_host_buffer*) malloc(sizeof(struct na_host_buffer));
    if (!na_buffer) {
        NA_LOG_ERROR("Could not allocate na_buffer");
        return NULL;
    }

    plugin_count = sizeof(na_class_methods) / sizeof(na_class_methods[0]) - 1;

    NA_parse_host_string(host_string, &na_buffer);

    for (i = 0; i < plugin_count; ++i) {
        accept = na_class_methods[i]->verify(na_buffer->na_protocol);

        if (accept) {
            na_class_priority_t class_priority = NA_get_priority(na_buffer);

            if ((na_buffer->na_class && strcmp(na_class_methods[i]->class_name,
                                               na_buffer->na_class) == 0) ||
                    class_priority == NA_CLASS_PRIORITY_MAX) {
                class_index = i;
                break;
            } else {
                if (class_priority > highest_priority) {
                    highest_priority = class_priority;
                    class_index = i;
                }
            }
        }
    }

    /* Initialize lookup mutex */
    hg_thread_mutex_init(&na_addr_lookup_mutex_g);

    na_class = na_class_methods[class_index]->initialize(na_buffer, listen);

    NA_free_host_buffer(na_buffer);

    return na_class;
}

/*---------------------------------------------------------------------------*/
na_return_t
NA_Finalize(na_class_t *na_class)
{
    na_return_t ret = NA_SUCCESS;

    assert(na_class);

    ret = na_class->finalize(na_class);

    /* Destroy lookup mutex */
    hg_thread_mutex_destroy(&na_addr_lookup_mutex_g);

    return ret;
}

/*---------------------------------------------------------------------------*/
na_context_t *
NA_Context_create(na_class_t *na_class)
{
    na_return_t ret = NA_SUCCESS;
    struct na_private_context *na_private_context = NULL;

    assert(na_class);

    na_private_context = (struct na_private_context *) malloc(
            sizeof(struct na_private_context));
    if (!na_private_context) {
        NA_LOG_ERROR("Could not allocate context");
        ret = NA_NOMEM_ERROR;
        goto done;
    }

    if (na_class->context_create) {
        ret = na_class->context_create(na_class,
                &na_private_context->context.plugin_context);
        if (ret != NA_SUCCESS) {
            goto done;
        }
    }

    /* Initialize completion queue */
    na_private_context->completion_queue = hg_queue_new();
    if (!na_private_context->completion_queue) {
        NA_LOG_ERROR("Could not create completion queue");
        ret = NA_NOMEM_ERROR;
        goto done;
    }

    /* Initialize completion queue mutex/cond */
    hg_thread_mutex_init(&na_private_context->completion_queue_mutex);
    hg_thread_cond_init(&na_private_context->completion_queue_cond);

    /* Initialize progress mutex/cond */
    hg_thread_mutex_init(&na_private_context->progress_mutex);
    hg_thread_cond_init(&na_private_context->progress_cond);
    na_private_context->progressing = NA_FALSE;

done:
    if (ret != NA_SUCCESS) {
        free(na_private_context);
        na_private_context = NULL;
    }
    return (na_context_t *) na_private_context;
}

/*---------------------------------------------------------------------------*/
na_return_t
NA_Context_destroy(na_class_t *na_class, na_context_t *context)
{
    struct na_private_context *na_private_context =
            (struct na_private_context *) context;
    na_return_t ret = NA_SUCCESS;

    /* Check that completion queue is empty now */
    hg_thread_mutex_lock(&na_private_context->completion_queue_mutex);

    if (!hg_queue_is_empty(na_private_context->completion_queue)) {
        NA_LOG_ERROR("Completion queue should be empty");
        ret = NA_PROTOCOL_ERROR;
        hg_thread_mutex_unlock(&na_private_context->completion_queue_mutex);
        goto done;
    }

    if (na_class->context_destroy) {
        ret = na_class->context_destroy(na_class,
                na_private_context->context.plugin_context);
        if (ret != NA_SUCCESS) {
            goto done;
        }
    }

    /* Destroy completion queue */
    hg_queue_free(na_private_context->completion_queue);
    na_private_context->completion_queue = NULL;

    hg_thread_mutex_unlock(&na_private_context->completion_queue_mutex);

    /* Destroy completion queue mutex/cond */
    hg_thread_mutex_destroy(&na_private_context->completion_queue_mutex);
    hg_thread_cond_destroy(&na_private_context->completion_queue_cond);

    /* Destroy progress mutex/cond */
    hg_thread_mutex_destroy(&na_private_context->progress_mutex);
    hg_thread_cond_destroy(&na_private_context->progress_cond);

    free(na_private_context);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
na_return_t
NA_Addr_lookup(na_class_t *na_class, na_context_t *context, na_cb_t callback,
        void *arg, const char *name, na_op_id_t *op_id)
{
    na_op_id_t na_op_id;
    na_return_t ret;

    assert(na_class);

    if (!context) {
        NA_LOG_ERROR("NULL context");
        ret = NA_INVALID_PARAM;
        goto done;
    }

    ret = na_class->addr_lookup(na_class, context, callback, arg, name,
            &na_op_id);
    if (ret != NA_SUCCESS) {
        goto done;
    }

    if (op_id && op_id != NA_OP_ID_IGNORE) *op_id = na_op_id;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
na_return_t
NA_Addr_lookup_wait(na_class_t *na_class, const char *name, na_addr_t *addr)
{
    na_addr_t new_addr = NULL;
    na_bool_t lookup_completed = NA_FALSE;
    na_context_t *context = NULL;
    na_return_t ret = NA_SUCCESS;

    if (!addr) {
        NA_LOG_ERROR("NULL pointer to na_addr_t");
        ret = NA_INVALID_PARAM;
        goto done;
    }

    context = NA_Context_create(na_class);
    if (!context) {
        NA_LOG_ERROR("Could not create context");
        goto done;
    }

    ret = NA_Addr_lookup(na_class, context, &na_addr_lookup_cb, &new_addr, name,
            NA_OP_ID_IGNORE);
    if (ret != NA_SUCCESS) {
        NA_LOG_ERROR("Could not start NA_Addr_lookup");
        goto done;
    }

    while (!lookup_completed) {
        na_return_t trigger_ret;
        unsigned int actual_count = 0;

        do {
            trigger_ret = NA_Trigger(context, 0, 1, &actual_count);
        } while ((trigger_ret == NA_SUCCESS) && actual_count);

        hg_thread_mutex_lock(&na_addr_lookup_mutex_g);
        if (new_addr) {
            lookup_completed = NA_TRUE;
            *addr = new_addr;
        }
        hg_thread_mutex_unlock(&na_addr_lookup_mutex_g);

        if (lookup_completed) break;

        ret = NA_Progress(na_class, context, NA_MAX_IDLE_TIME);
        if (ret != NA_SUCCESS) {
            NA_LOG_ERROR("Could not make progress");
            goto done;
        }
    }

    ret = NA_Context_destroy(na_class, context);
    if (ret != NA_SUCCESS) {
        NA_LOG_ERROR("Could not destroy context");
        goto done;
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_addr_lookup_cb(const struct na_cb_info *callback_info)
{
    na_addr_t *addr_ptr = (na_addr_t *) callback_info->arg;
    na_return_t ret = NA_SUCCESS;

    if (callback_info->ret != NA_SUCCESS) {
        return ret;
    }

    hg_thread_mutex_lock(&na_addr_lookup_mutex_g);

    *addr_ptr = callback_info->info.lookup.addr;

    hg_thread_mutex_unlock(&na_addr_lookup_mutex_g);

    return ret;
}

/*---------------------------------------------------------------------------*/
na_return_t
NA_Addr_free(na_class_t *na_class, na_addr_t addr)
{
    assert(na_class);
    return na_class->addr_free(na_class, addr);
}

/*---------------------------------------------------------------------------*/
na_return_t
NA_Addr_to_string(na_class_t *na_class, char *buf, na_size_t buf_size,
        na_addr_t addr)
{
    na_return_t ret = NA_SUCCESS;

    assert(na_class);

    if (addr == NA_ADDR_NULL) {
        NA_LOG_ERROR("NULL addr");
        ret = NA_INVALID_PARAM;
        return ret;
    }

    ret = na_class->addr_to_string(na_class, buf, buf_size, addr);

    return ret;
}

/*---------------------------------------------------------------------------*/
na_size_t
NA_Msg_get_max_expected_size(na_class_t *na_class)
{
    assert(na_class);
    return na_class->msg_get_max_expected_size(na_class);
}

/*---------------------------------------------------------------------------*/
na_size_t
NA_Msg_get_max_unexpected_size(na_class_t *na_class)
{
    assert(na_class);
    return na_class->msg_get_max_unexpected_size(na_class);
}

/*---------------------------------------------------------------------------*/
na_tag_t
NA_Msg_get_max_tag(na_class_t *na_class)
{
    assert(na_class);
    return na_class->msg_get_max_tag(na_class);
}

/*---------------------------------------------------------------------------*/
na_return_t
NA_Msg_send_unexpected(na_class_t *na_class, na_context_t *context,
        na_cb_t callback, void *arg, const void *buf, na_size_t buf_size,
        na_addr_t dest, na_tag_t tag, na_op_id_t *op_id)
{
    na_op_id_t na_op_id;
    na_return_t ret;

    assert(na_class);

    if (!context) {
        NA_LOG_ERROR("NULL context");
        ret = NA_INVALID_PARAM;
        goto done;
    }

    ret = na_class->msg_send_unexpected(na_class, context, callback, arg, buf,
            buf_size, dest, tag, &na_op_id);
    if (ret != NA_SUCCESS) {
        goto done;
    }

    if (op_id && op_id != NA_OP_ID_IGNORE) *op_id = na_op_id;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
na_return_t
NA_Msg_recv_unexpected(na_class_t *na_class, na_context_t *context,
        na_cb_t callback, void *arg, void *buf, na_size_t buf_size,
        na_op_id_t *op_id)
{
    na_op_id_t na_op_id;
    na_return_t ret;

    assert(na_class);

    if (!context) {
        NA_LOG_ERROR("NULL context");
        ret = NA_INVALID_PARAM;
        goto done;
    }

    ret = na_class->msg_recv_unexpected(na_class, context, callback, arg, buf,
            buf_size, &na_op_id);
    if (ret != NA_SUCCESS) {
        goto done;
    }

    if (op_id && op_id != NA_OP_ID_IGNORE) *op_id = na_op_id;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
na_return_t
NA_Msg_send_expected(na_class_t *na_class, na_context_t *context,
        na_cb_t callback, void *arg, const void *buf, na_size_t buf_size,
        na_addr_t dest, na_tag_t tag, na_op_id_t *op_id)
{
    na_op_id_t na_op_id;
    na_return_t ret;

    assert(na_class);

    if (!context) {
        NA_LOG_ERROR("NULL context");
        ret = NA_INVALID_PARAM;
        goto done;
    }

    ret = na_class->msg_send_expected(na_class, context, callback, arg, buf,
            buf_size, dest, tag, &na_op_id);
    if (ret != NA_SUCCESS) {
        goto done;
    }

    if (op_id && op_id != NA_OP_ID_IGNORE) *op_id = na_op_id;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
na_return_t
NA_Msg_recv_expected(na_class_t *na_class, na_context_t *context,
        na_cb_t callback, void *arg, void *buf, na_size_t buf_size,
        na_addr_t source, na_tag_t tag, na_op_id_t *op_id)
{
    na_op_id_t na_op_id;
    na_return_t ret;

    assert(na_class);

    if (!context) {
        NA_LOG_ERROR("NULL context");
        ret = NA_INVALID_PARAM;
        goto done;
    }

    ret = na_class->msg_recv_expected(na_class, context, callback, arg, buf,
            buf_size, source, tag, &na_op_id);
    if (ret != NA_SUCCESS) {
        goto done;
    }

    if (op_id && op_id != NA_OP_ID_IGNORE) *op_id = na_op_id;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
na_return_t
NA_Mem_handle_create(na_class_t *na_class, void *buf, na_size_t buf_size,
        unsigned long flags, na_mem_handle_t *mem_handle)
{
    assert(na_class);
    return na_class->mem_handle_create(na_class, buf, buf_size, flags,
            mem_handle);
}

/*---------------------------------------------------------------------------*/
na_return_t
NA_Mem_handle_create_segments(na_class_t *na_class, struct na_segment *segments,
        na_size_t segment_count, unsigned long flags,
        na_mem_handle_t *mem_handle)
{
    assert(na_class);
    return na_class->mem_handle_create_segments(na_class, segments,
            segment_count, flags, mem_handle);
}

/*---------------------------------------------------------------------------*/
na_return_t
NA_Mem_handle_free(na_class_t *na_class, na_mem_handle_t mem_handle)
{
    assert(na_class);
    return na_class->mem_handle_free(na_class, mem_handle);
}

/*---------------------------------------------------------------------------*/
na_return_t
NA_Mem_register(na_class_t *na_class, na_mem_handle_t mem_handle)
{
    assert(na_class);
    return na_class->mem_register(na_class, mem_handle);
}

/*---------------------------------------------------------------------------*/
na_return_t
NA_Mem_deregister(na_class_t *na_class, na_mem_handle_t mem_handle)
{
    assert(na_class);
    return na_class->mem_deregister(na_class, mem_handle);
}

/*---------------------------------------------------------------------------*/
na_size_t
NA_Mem_handle_get_serialize_size(na_class_t *na_class,
        na_mem_handle_t mem_handle)
{
    assert(na_class);
    return na_class->mem_handle_get_serialize_size(na_class,
            mem_handle);
}

/*---------------------------------------------------------------------------*/
na_return_t
NA_Mem_handle_serialize(na_class_t *na_class, void *buf, na_size_t buf_size,
        na_mem_handle_t mem_handle)
{
    assert(na_class);
    return na_class->mem_handle_serialize(na_class, buf, buf_size,
            mem_handle);
}

/*---------------------------------------------------------------------------*/
na_return_t
NA_Mem_handle_deserialize(na_class_t *na_class, na_mem_handle_t *mem_handle,
        const void *buf, na_size_t buf_size)
{
    assert(na_class);
    return na_class->mem_handle_deserialize(na_class, mem_handle, buf,
            buf_size);
}

/*---------------------------------------------------------------------------*/
na_return_t
NA_Put(na_class_t *na_class, na_context_t *context, na_cb_t callback, void *arg,
        na_mem_handle_t local_mem_handle, na_offset_t local_offset,
        na_mem_handle_t remote_mem_handle, na_offset_t remote_offset,
        na_size_t data_size, na_addr_t remote_addr, na_op_id_t *op_id)
{
    na_op_id_t na_op_id;
    na_return_t ret;

    assert(na_class);

    if (!context) {
        NA_LOG_ERROR("NULL context");
        ret = NA_INVALID_PARAM;
        goto done;
    }

    ret = na_class->put(na_class, context, callback, arg, local_mem_handle,
            local_offset, remote_mem_handle, remote_offset, data_size,
            remote_addr, &na_op_id);
    if (ret != NA_SUCCESS) {
        goto done;
    }

    if (op_id && op_id != NA_OP_ID_IGNORE) *op_id = na_op_id;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
na_return_t
NA_Get(na_class_t *na_class, na_context_t *context, na_cb_t callback, void *arg,
        na_mem_handle_t local_mem_handle, na_offset_t local_offset,
        na_mem_handle_t remote_mem_handle, na_offset_t remote_offset,
        na_size_t data_size, na_addr_t remote_addr, na_op_id_t *op_id)
{
    na_op_id_t na_op_id;
    na_return_t ret;

    assert(na_class);

    if (!context) {
        NA_LOG_ERROR("NULL context");
        ret = NA_INVALID_PARAM;
        goto done;
    }

    ret = na_class->get(na_class, context, callback, arg, local_mem_handle,
            local_offset, remote_mem_handle, remote_offset, data_size,
            remote_addr, &na_op_id);
    if (ret != NA_SUCCESS) {
        goto done;
    }

    if (op_id && op_id != NA_OP_ID_IGNORE) *op_id = na_op_id;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
na_return_t
NA_Progress(na_class_t *na_class, na_context_t *context, unsigned int timeout)
{
    struct na_private_context *na_private_context =
            (struct na_private_context *) context;
    double remaining = timeout / 1000; /* Convert timeout in ms into seconds */
    na_return_t ret = NA_SUCCESS;

    assert(na_class);

    if (!context) {
        NA_LOG_ERROR("NULL context");
        ret = NA_INVALID_PARAM;
        goto done;
    }

    /* TODO option for concurrent progress */

    /* Prevent multiple threads from concurrently calling progress on the same
     * context */
    hg_thread_mutex_lock(&na_private_context->progress_mutex);

    while (na_private_context->progressing) {
        hg_time_t t1, t2;

        hg_time_get_current(&t1);

        if (hg_thread_cond_timedwait(&na_private_context->progress_cond,
                &na_private_context->progress_mutex,
                (unsigned int) (remaining * 1000)) != HG_UTIL_SUCCESS) {
            /* Timeout occurred so leave */
            hg_thread_mutex_unlock(&na_private_context->progress_mutex);
            ret = NA_TIMEOUT;
            goto done;
        }

        hg_time_get_current(&t2);
        remaining -= hg_time_to_double(hg_time_subtract(t2, t1));
        if (remaining < 0) {
            /* Give a chance to call progress with timeout of 0 if
             * progressing is NA_FALSE */
            remaining = 0;
        }
    }
    na_private_context->progressing = NA_TRUE;

    hg_thread_mutex_unlock(&na_private_context->progress_mutex);

    /* Try to make progress for remaining time */
    ret = na_class->progress(na_class, context,
            (unsigned int) (remaining * 1000));

    hg_thread_mutex_lock(&na_private_context->progress_mutex);

    /* At this point, either progress succeeded or failed with NA_TIMEOUT,
     * meaning remaining time is now 0, so wake up other threads waiting */
    na_private_context->progressing = NA_FALSE;
    hg_thread_cond_signal(&na_private_context->progress_cond);

    hg_thread_mutex_unlock(&na_private_context->progress_mutex);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
na_return_t
NA_Trigger(na_context_t *context, unsigned int timeout, unsigned int max_count,
        unsigned int *actual_count)
{
    struct na_private_context *na_private_context =
            (struct na_private_context *) context;
    na_return_t ret = NA_SUCCESS;
    na_bool_t completion_queue_empty = 0;
    struct na_cb_completion_data *completion_data = NULL;
    unsigned int count = 0;

    if (!context) {
        NA_LOG_ERROR("NULL context");
        ret = NA_INVALID_PARAM;
        goto done;
    }

    while (count < max_count) {
        hg_thread_mutex_lock(&na_private_context->completion_queue_mutex);

        /* Is completion queue empty */
        completion_queue_empty = (na_bool_t) hg_queue_is_empty(
                na_private_context->completion_queue);

        while (completion_queue_empty) {
            /* If queue is empty and already triggered something, just leave */
            if (count) {
                hg_thread_mutex_unlock(
                        &na_private_context->completion_queue_mutex);
                goto done;
            }

            /* Otherwise wait timeout ms */
            if (hg_thread_cond_timedwait(
                    &na_private_context->completion_queue_cond,
                    &na_private_context->completion_queue_mutex, timeout)
                    != HG_UTIL_SUCCESS) {
                /* Timeout occurred so leave */
                ret = NA_TIMEOUT;
                hg_thread_mutex_unlock(
                        &na_private_context->completion_queue_mutex);
                goto done;
            }
        }

        /* Completion queue should not be empty now */
        completion_data = (struct na_cb_completion_data *)
                    hg_queue_pop_tail(na_private_context->completion_queue);
        if (!completion_data) {
            NA_LOG_ERROR("NULL completion data");
            ret = NA_INVALID_PARAM;
            hg_thread_mutex_unlock(&na_private_context->completion_queue_mutex);
            goto done;
        }

        /* Unlock now so that other threads can eventually add callbacks
         * to the queue while callback gets executed */
        hg_thread_mutex_unlock(&na_private_context->completion_queue_mutex);

        /* Execute callback */
        if (completion_data->callback) {
            /* TODO should return error from callback ? */
            completion_data->callback(completion_data->callback_info);
        }

        /* Execute plugin callback (free resources etc) */
        if (completion_data->plugin_callback)
            completion_data->plugin_callback(completion_data->callback_info,
                    completion_data->plugin_callback_args);

        free(completion_data);
        count++;
    }

    if (actual_count) *actual_count = count;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
na_return_t
NA_Cancel(na_class_t *na_class, na_context_t *context, na_op_id_t op_id)
{
    na_return_t ret = NA_SUCCESS;

    assert(na_class);

    if (!context) {
        NA_LOG_ERROR("NULL context");
        ret = NA_INVALID_PARAM;
        goto done;
    }

    if (op_id != NA_OP_ID_NULL) {
        NA_LOG_ERROR("NULL operation ID");
        ret = NA_INVALID_PARAM;
        goto done;
    }

    ret = na_class->cancel(na_class, context, op_id);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
const char *
NA_Error_to_string(na_return_t errnum)
{
    const char *na_error_string = "UNDEFINED/UNRECOGNIZED NA ERROR";

    NA_ERROR_STRING_MACRO(NA_SUCCESS, errnum, na_error_string);
    NA_ERROR_STRING_MACRO(NA_CANCELED, errnum, na_error_string);
    NA_ERROR_STRING_MACRO(NA_TIMEOUT, errnum, na_error_string);
    NA_ERROR_STRING_MACRO(NA_INVALID_PARAM, errnum, na_error_string);
    NA_ERROR_STRING_MACRO(NA_SIZE_ERROR, errnum, na_error_string);
    NA_ERROR_STRING_MACRO(NA_ALIGNMENT_ERROR, errnum, na_error_string);
    NA_ERROR_STRING_MACRO(NA_PERMISSION_ERROR, errnum, na_error_string);
    NA_ERROR_STRING_MACRO(NA_NOMEM_ERROR, errnum, na_error_string);
    NA_ERROR_STRING_MACRO(NA_PROTOCOL_ERROR, errnum, na_error_string);

    return na_error_string;
}

/*---------------------------------------------------------------------------*/
na_return_t
na_cb_completion_add(na_context_t *context,
        na_cb_t callback, struct na_cb_info *callback_info,
        na_plugin_cb_t plugin_callback, void *plugin_callback_args)
{
    struct na_private_context *na_private_context =
            (struct na_private_context *) context;
    na_return_t ret = NA_SUCCESS;
    struct na_cb_completion_data *completion_data = NULL;

    assert(context);

    completion_data = (struct na_cb_completion_data *)
            malloc(sizeof(struct na_cb_completion_data));
    if (!completion_data) {
        NA_LOG_ERROR("Could not allocate completion data struct");
        ret = NA_NOMEM_ERROR;
        goto done;
    }

    completion_data->callback = callback;
    completion_data->callback_info = callback_info;
    completion_data->plugin_callback = plugin_callback;
    completion_data->plugin_callback_args = plugin_callback_args;

    hg_thread_mutex_lock(&na_private_context->completion_queue_mutex);

    if (!hg_queue_push_head(na_private_context->completion_queue,
            (hg_queue_value_t) completion_data)) {
        NA_LOG_ERROR("Could not push completion data to completion queue");
        ret = NA_NOMEM_ERROR;
        hg_thread_mutex_unlock(
                &na_private_context->completion_queue_mutex);
        goto done;
    }

    /* Callback is pushed to the completion queue when something completes
     * so wake up anyone waiting in the trigger */
    hg_thread_cond_signal(&na_private_context->completion_queue_cond);

    hg_thread_mutex_unlock(&na_private_context->completion_queue_mutex);

done:
    return ret;
}
