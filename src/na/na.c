/*
 * Copyright (C) 2013-2014 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
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
#include "mercury_thread_condition.h"
#include "mercury_time.h"

#include <stdlib.h>
#include <string.h>

/****************/
/* Local Macros */
/****************/
/* Convert value to string */
#define NA_ERROR_STRING_MACRO(def, value, string) \
  if (value == def) string = #def

#ifdef _WIN32
#  define strtok_r strtok_s
#endif

/************************************/
/* Local Type and Struct Definition */
/************************************/

struct na_private_class {
    struct na_class na_class; /* Must remain as first field */
    na_bool_t listen;
};

/* Private context / do not expose private members to plugins */
struct na_private_context {
    struct na_context context;  /* Must remain as first field */
    na_class_t *na_class;       /* Pointer to NA class */
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

/* Parse host string and fill info */
static na_return_t
na_info_parse(
        const char *host_string,
        struct na_info **na_info_ptr
        );

/* Free host info */
static void
na_info_free(
        struct na_info *na_info
        );

#ifdef NA_DEBUG
/* Print NA info */
static void
na_info_print(struct na_info *na_info);
#endif

/* NA_Lookup_wait callback */
static na_return_t
na_addr_lookup_cb(
        const struct na_cb_info *callback_info
        );

/*******************/
/* Local Variables */
/*******************/
#ifdef NA_HAS_BMI
extern na_class_t na_bmi_class_g;
#endif
#ifdef NA_HAS_MPI
extern na_class_t na_mpi_class_g;
#endif
#ifdef NA_HAS_SSM
extern na_class_t na_ssm_class_g;
#endif
#ifdef NA_HAS_CCI
extern na_class_t na_cci_class_g;
#endif

static const na_class_t *na_class_table[] = {
#ifdef NA_HAS_BMI
    &na_bmi_class_g,
#endif
#ifdef NA_HAS_MPI
    &na_mpi_class_g,
#endif
#ifdef NA_HAS_SSM
    &na_ssm_class_g,
#endif
#ifdef NA_HAS_CCI
    &na_cci_class_g,
#endif
    NULL
};

/*---------------------------------------------------------------------------*/
static na_return_t
na_info_parse(const char *info_string, struct na_info **na_info_ptr)
{
    struct na_info *na_info = NULL;
    na_return_t ret = NA_SUCCESS;

    char *input_string = NULL;
    char *token = NULL;
    char *locator = NULL;
    size_t port_name_len;

    na_info = (struct na_info *) malloc(sizeof(struct na_info));
    if (!na_info) {
        NA_LOG_ERROR("Could not allocate NA info struct");
        ret = NA_NOMEM_ERROR;
        goto done;
    }
    /* Initialize NA info */
    na_info->class_name = NULL;
    na_info->protocol_name = NULL;
    na_info->host_name = NULL;
    na_info->port = 0;
    na_info->port_name = NULL;

    /* Copy info string and work from that */
    input_string = strdup(info_string);
    if (!input_string) {
        NA_LOG_ERROR("Could not duplicate host string");
        ret = NA_NOMEM_ERROR;
        goto done;
    }

    /**
     * Strings can be of the format:
     *   tcp://localhost:3344
     *   ssm+tcp://localhost:3344
     */

    /* Get first part of string (i.e., class_name+protocol) */
    token = strtok_r(input_string, ":", &locator);

    /* Is class name specified */
    if (strstr(token, "+") != NULL) {
        char *_locator = NULL;

        token = strtok_r(token, "+", &_locator);

        /* Get NA class name */
        na_info->class_name = strdup(token);
        if (!na_info->class_name) {
            NA_LOG_ERROR("Could not duplicate NA info class name");
            ret = NA_NOMEM_ERROR;
            goto done;
        }

        /* Get protocol name */
        na_info->protocol_name = strdup(_locator);
        if (!na_info->protocol_name) {
            NA_LOG_ERROR("Could not duplicate NA info protocol name");
            ret = NA_NOMEM_ERROR;
            goto done;
        }
    } else {
        /* Get protocol name */
        na_info->protocol_name = strdup(token);
        if (!na_info->protocol_name) {
            NA_LOG_ERROR("Could not duplicate NA info protocol name");
            ret = NA_NOMEM_ERROR;
            goto done;
        }
    }

    /* Treat //hostname:port part */
    token = locator + 2; /* Skip // */
    token = strtok_r(token, ":", &locator); /* Get hostname */

    na_info->host_name = strdup(token);
    if (!na_info->host_name) {
        NA_LOG_ERROR("Could not duplicate NA info host name");
        ret = NA_NOMEM_ERROR;
        goto done;
    }

    /* Get port number */
    na_info->port = atoi(locator);

    /* Build port name that can be used by NA class */
    port_name_len = strlen(info_string);
    if (na_info->class_name) {
        /* Remove class_name+ */
        port_name_len -= (strlen(na_info->class_name) + 1);
    }

    /**
     * Strings can be of the format:
     *   tcp://localhost:3344
     */
    na_info->port_name = (char *) malloc(port_name_len + 1);
    if (!na_info->port_name) {
        NA_LOG_ERROR("Could not allocate NA info port name");
        ret = NA_NOMEM_ERROR;
        goto done;
    }

    memset(na_info->port_name, '\0', port_name_len + 1);
    strcpy(na_info->port_name, na_info->protocol_name);
    strcat(na_info->port_name, info_string +
            (strlen(info_string) - port_name_len) +
            strlen(na_info->protocol_name));

    *na_info_ptr = na_info;
done:
    if (ret != NA_SUCCESS) {
        na_info_free(na_info);
    }
    free(input_string);

    return ret;
}

/*---------------------------------------------------------------------------*/
static void
na_info_free(struct na_info *na_info)
{
    if (!na_info) return;

    free(na_info->class_name);
    free(na_info->protocol_name);
    free(na_info->host_name);
    free(na_info->port_name);
    free(na_info);
}

/*---------------------------------------------------------------------------*/
#ifdef NA_DEBUG
static void
na_info_print(struct na_info *na_info)
{
    if (!na_info) return;

    printf("Class: %s\n", na_info->class_name);
    printf("Protocol: %s\n", na_info->protocol_name);
    printf("Hostname: %s\n", na_info->host_name);
    printf("Port: %d\n", na_info->port);
    printf("Port name: %s\n", na_info->port_name);
}
#endif

/*---------------------------------------------------------------------------*/
na_class_t *
NA_Initialize(const char *info_string, na_bool_t listen)
{
    struct na_private_class *na_private_class = NULL;
    struct na_info *na_info = NULL;
    unsigned int plugin_index = 0;
    unsigned int plugin_count = 0;
    na_bool_t plugin_found = NA_FALSE;
    na_return_t ret = NA_SUCCESS;

    if (!info_string) {
        NA_LOG_ERROR("NULL info string");
        ret = NA_INVALID_PARAM;
        goto done;
    }

    na_private_class = (struct na_private_class *) malloc(
            sizeof(struct na_private_class));
    if (!na_private_class) {
        NA_LOG_ERROR("Could not allocate class");
        ret = NA_NOMEM_ERROR;
        goto done;
    }

    plugin_count = sizeof(na_class_table) / sizeof(na_class_table[0]) - 1;

    ret = na_info_parse(info_string, &na_info);
    if (ret != NA_SUCCESS) {
        NA_LOG_ERROR("Could not parse host string");
        goto done;
    }

#ifdef NA_DEBUG
    na_info_print(na_info);
#endif

    while (plugin_index < plugin_count) {
        na_bool_t verified = NA_FALSE;

        if (!na_class_table[plugin_index]->check_protocol) {
            NA_LOG_ERROR("check_protocol plugin callback is not defined");
            ret = NA_PROTOCOL_ERROR;
            goto done;
        }
        verified = na_class_table[plugin_index]->check_protocol(
                na_info->protocol_name);

        if (verified) {
            /* Take the first plugin that supports the protocol */
            if (!na_info->class_name) {
                plugin_found = NA_TRUE;
                break;
            }

            /* Otherwise try to use the plugin name */
            if (!na_class_table[plugin_index]->class_name) {
                NA_LOG_ERROR("class name is not defined");
                ret = NA_PROTOCOL_ERROR;
                goto done;
            }
            if (strcmp(na_class_table[plugin_index]->class_name,
                    na_info->class_name) == 0) {
                plugin_found = NA_TRUE;
                break;
            }
        }
        plugin_index++;
    }

    if (!plugin_found) {
        NA_LOG_ERROR("No suitable plugin was found");
        ret = NA_PROTOCOL_ERROR;
        goto done;
    }

    na_private_class->na_class = *na_class_table[plugin_index];
    if (!na_private_class->na_class.initialize) {
        NA_LOG_ERROR("initialize plugin callback is not defined");
        ret = NA_PROTOCOL_ERROR;
        goto done;
    }
    ret = na_private_class->na_class.initialize(&na_private_class->na_class,
            na_info, listen);
    if (ret != NA_SUCCESS) {
        NA_LOG_ERROR("Could not initialize plugin");
        goto done;
    }
    na_private_class->listen = listen;

done:
    if (ret != NA_SUCCESS) {
        free(na_private_class);
        na_private_class = NULL;
    }
    na_info_free(na_info);
    return (na_class_t *) na_private_class;
}

/*---------------------------------------------------------------------------*/
na_return_t
NA_Finalize(na_class_t *na_class)
{
    struct na_private_class *na_private_class =
            (struct na_private_class *) na_class;
    na_return_t ret = NA_SUCCESS;

    if (!na_private_class) goto done;
    if (!na_class->finalize) {
        NA_LOG_ERROR("finalize plugin callback is not defined");
        ret = NA_PROTOCOL_ERROR;
        goto done;
    }

    ret = na_private_class->na_class.finalize(&na_private_class->na_class);

    free(na_private_class);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
na_bool_t
NA_Is_listening(na_class_t *na_class)
{
    struct na_private_class *na_private_class =
            (struct na_private_class *) na_class;
    na_bool_t ret = NA_FALSE;

    if (!na_private_class) {
        NA_LOG_ERROR("NULL NA class");
        goto done;
    }

    ret = na_private_class->listen;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
na_context_t *
NA_Context_create(na_class_t *na_class)
{
    na_return_t ret = NA_SUCCESS;
    struct na_private_context *na_private_context = NULL;

    if (!na_class) {
        NA_LOG_ERROR("NULL NA class");
        ret = NA_INVALID_PARAM;
        goto done;
    }

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

    if (!na_class) {
        NA_LOG_ERROR("NULL NA class");
        ret = NA_INVALID_PARAM;
        goto done;
    }
    if (!context) goto done;

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
    char *name_string = NULL;
    char *short_name = NULL;
    na_op_id_t na_op_id;
    na_return_t ret = NA_SUCCESS;

    if (!na_class) {
        NA_LOG_ERROR("NULL NA class");
        ret = NA_INVALID_PARAM;
        goto done;
    }
    if (!context) {
        NA_LOG_ERROR("NULL context");
        ret = NA_INVALID_PARAM;
        goto done;
    }
    if (!name) {
        NA_LOG_ERROR("Lookup name is NULL");
        ret = NA_INVALID_PARAM;
        goto done;
    }
    if (!na_class->addr_lookup) {
        NA_LOG_ERROR("addr_lookup plugin callback is not defined");
        ret = NA_PROTOCOL_ERROR;
        goto done;
    }

    /* Copy name and work from that */
    name_string = strdup(name);
    if (!name_string) {
        NA_LOG_ERROR("Could not duplicate string");
        ret = NA_NOMEM_ERROR;
        goto done;
    }

    /* If NA class name was specified, we can remove the name here:
     * ie. bmi+tcp://hostname:port -> tcp://hostname:port */
    if (strstr(name_string, "+") != NULL)
        strtok_r(name_string, "+", &short_name);
    else
        short_name = name_string;

    ret = na_class->addr_lookup(na_class, context, callback, arg, short_name,
            &na_op_id);
    if (ret != NA_SUCCESS) {
        goto done;
    }

    if (op_id && op_id != NA_OP_ID_IGNORE) *op_id = na_op_id;

done:
    free(name_string);
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

    if (!na_class) {
        NA_LOG_ERROR("NULL NA class");
        ret = NA_INVALID_PARAM;
        goto done;
    }
    if (!name) {
        NA_LOG_ERROR("Lookup name is NULL");
        ret = NA_INVALID_PARAM;
        goto done;
    }
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

        if (new_addr) {
            lookup_completed = NA_TRUE;
            *addr = new_addr;
        }

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
        NA_LOG_ERROR("Return from callback with %s error code",
                NA_Error_to_string(callback_info->ret));
        return ret;
    }

    *addr_ptr = callback_info->info.lookup.addr;

    return ret;
}

/*---------------------------------------------------------------------------*/
na_return_t
NA_Addr_self(na_class_t *na_class, na_addr_t *addr)
{
    na_return_t ret = NA_SUCCESS;

    if (!na_class) {
        NA_LOG_ERROR("NULL NA class");
        ret = NA_INVALID_PARAM;
        goto done;
    }
    if (!addr) {
        NA_LOG_ERROR("NULL pointer to na_addr_t");
        ret = NA_INVALID_PARAM;
        goto done;
    }
    if (!na_class->addr_self) {
        NA_LOG_ERROR("addr_self plugin callback is not defined");
        ret = NA_PROTOCOL_ERROR;
        goto done;
    }

    ret = na_class->addr_self(na_class, addr);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
na_return_t
NA_Addr_dup(na_class_t *na_class, na_addr_t addr, na_addr_t *new_addr)
{
    na_return_t ret = NA_SUCCESS;

    if (!na_class) {
        NA_LOG_ERROR("NULL NA class");
        ret = NA_INVALID_PARAM;
        goto done;
    }
    if (addr == NA_ADDR_NULL) {
        NA_LOG_ERROR("NULL addr");
        ret = NA_INVALID_PARAM;
        goto done;
    }
    if (!new_addr) {
        NA_LOG_ERROR("NULL pointer to NA addr");
        ret = NA_INVALID_PARAM;
        goto done;
    }
    if (!na_class->addr_dup) {
        NA_LOG_ERROR("addr_dup plugin callback is not defined");
        ret = NA_PROTOCOL_ERROR;
        goto done;
    }

    ret = na_class->addr_dup(na_class, addr, new_addr);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
na_return_t
NA_Addr_free(na_class_t *na_class, na_addr_t addr)
{
    na_return_t ret = NA_SUCCESS;

    if (!na_class) {
        NA_LOG_ERROR("NULL NA class");
        ret = NA_INVALID_PARAM;
        goto done;
    }
    if (!na_class->addr_free) {
        NA_LOG_ERROR("addr_free plugin callback is not defined");
        ret = NA_PROTOCOL_ERROR;
        goto done;
    }

    ret = na_class->addr_free(na_class, addr);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
na_bool_t
NA_Addr_is_self(na_class_t *na_class, na_addr_t addr)
{
    na_bool_t ret = NA_FALSE;

    if (!na_class) {
        NA_LOG_ERROR("NULL NA class");
        goto done;
    }
    if (!na_class->addr_is_self) {
        NA_LOG_ERROR("addr_is_self plugin callback is not defined");
        goto done;
    }

    ret = na_class->addr_is_self(na_class, addr);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
na_return_t
NA_Addr_to_string(na_class_t *na_class, char *buf, na_size_t buf_size,
        na_addr_t addr)
{
    na_return_t ret = NA_SUCCESS;

    if (!na_class) {
        NA_LOG_ERROR("NULL NA class");
        ret = NA_INVALID_PARAM;
        goto done;
    }
    if (!buf) {
        NA_LOG_ERROR("NULL buffer");
        ret = NA_INVALID_PARAM;
        goto done;
    }
    if (!buf_size) {
        NA_LOG_ERROR("NULL buffer size");
        ret = NA_INVALID_PARAM;
        goto done;
    }
    if (addr == NA_ADDR_NULL) {
        NA_LOG_ERROR("NULL addr");
        ret = NA_INVALID_PARAM;
        goto done;
    }
    if (!na_class->addr_to_string) {
        NA_LOG_ERROR("addr_to_string plugin callback is not defined");
        ret = NA_PROTOCOL_ERROR;
        goto done;
    }

    ret = na_class->addr_to_string(na_class, buf, buf_size, addr);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
na_size_t
NA_Msg_get_max_expected_size(na_class_t *na_class)
{
    na_size_t ret = 0;

    if (!na_class) {
        NA_LOG_ERROR("NULL NA class");
        goto done;
    }
    if (!na_class->msg_get_max_expected_size) {
        NA_LOG_ERROR("msg_get_max_expected_size plugin callback is not defined");
        goto done;
    }

    ret = na_class->msg_get_max_expected_size(na_class);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
na_size_t
NA_Msg_get_max_unexpected_size(na_class_t *na_class)
{
    na_size_t ret = 0;

    if (!na_class) {
        NA_LOG_ERROR("NULL NA class");
        goto done;
    }
    if (!na_class->msg_get_max_unexpected_size) {
        NA_LOG_ERROR("msg_get_max_unexpected_size plugin callback is not defined");
        goto done;
    }

    ret = na_class->msg_get_max_unexpected_size(na_class);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
na_tag_t
NA_Msg_get_max_tag(na_class_t *na_class)
{
    na_tag_t ret = 0;

    if (!na_class) {
        NA_LOG_ERROR("NULL NA class");
        goto done;
    }
    if (!na_class->msg_get_max_tag) {
        NA_LOG_ERROR("msg_get_max_tag plugin callback is not defined");
        goto done;
    }

    ret = na_class->msg_get_max_tag(na_class);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
na_return_t
NA_Msg_send_unexpected(na_class_t *na_class, na_context_t *context,
        na_cb_t callback, void *arg, const void *buf, na_size_t buf_size,
        na_addr_t dest, na_tag_t tag, na_op_id_t *op_id)
{
    na_op_id_t na_op_id;
    na_return_t ret = NA_SUCCESS;

    if (!na_class) {
        NA_LOG_ERROR("NULL NA class");
        ret = NA_INVALID_PARAM;
        goto done;
    }
    if (!context) {
        NA_LOG_ERROR("NULL context");
        ret = NA_INVALID_PARAM;
        goto done;
    }
    if (!buf) {
        NA_LOG_ERROR("NULL buffer");
        ret = NA_INVALID_PARAM;
        goto done;
    }
    if (!buf_size) {
        NA_LOG_ERROR("NULL buffer size");
        ret = NA_INVALID_PARAM;
        goto done;
    }
    if (dest == NA_ADDR_NULL) {
        NA_LOG_ERROR("NULL NA address");
        ret = NA_INVALID_PARAM;
        goto done;
    }
    if (!na_class->msg_send_unexpected) {
        NA_LOG_ERROR("msg_send_unexpected plugin callback is not defined");
        ret = NA_PROTOCOL_ERROR;
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
    na_return_t ret = NA_SUCCESS;

    if (!na_class) {
        NA_LOG_ERROR("NULL NA class");
        ret = NA_INVALID_PARAM;
        goto done;
    }
    if (!context) {
        NA_LOG_ERROR("NULL context");
        ret = NA_INVALID_PARAM;
        goto done;
    }
    if (!buf) {
        NA_LOG_ERROR("NULL buffer");
        ret = NA_INVALID_PARAM;
        goto done;
    }
    if (!buf_size) {
        NA_LOG_ERROR("NULL buffer size");
        ret = NA_INVALID_PARAM;
        goto done;
    }
    if (!na_class->msg_recv_unexpected) {
        NA_LOG_ERROR("msg_recv_unexpected plugin callback is not defined");
        ret = NA_PROTOCOL_ERROR;
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
    na_return_t ret = NA_SUCCESS;

    if (!na_class) {
        NA_LOG_ERROR("NULL NA class");
        ret = NA_INVALID_PARAM;
        goto done;
    }
    if (!context) {
        NA_LOG_ERROR("NULL context");
        ret = NA_INVALID_PARAM;
        goto done;
    }
    if (!buf) {
        NA_LOG_ERROR("NULL buffer");
        ret = NA_INVALID_PARAM;
        goto done;
    }
    if (!buf_size) {
        NA_LOG_ERROR("NULL buffer size");
        ret = NA_INVALID_PARAM;
        goto done;
    }
    if (dest == NA_ADDR_NULL) {
        NA_LOG_ERROR("NULL NA address");
        ret = NA_INVALID_PARAM;
        goto done;
    }
    if (!na_class->msg_send_expected) {
        NA_LOG_ERROR("msg_send_expected plugin callback is not defined");
        ret = NA_PROTOCOL_ERROR;
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
    na_return_t ret = NA_SUCCESS;

    if (!na_class) {
        NA_LOG_ERROR("NULL NA class");
        ret = NA_INVALID_PARAM;
        goto done;
    }
    if (!context) {
        NA_LOG_ERROR("NULL context");
        ret = NA_INVALID_PARAM;
        goto done;
    }
    if (!buf) {
        NA_LOG_ERROR("NULL buffer");
        ret = NA_INVALID_PARAM;
        goto done;
    }
    if (!buf_size) {
        NA_LOG_ERROR("NULL buffer size");
        ret = NA_INVALID_PARAM;
        goto done;
    }
    if (source == NA_ADDR_NULL) {
        NA_LOG_ERROR("NULL NA address");
        ret = NA_INVALID_PARAM;
        goto done;
    }
    if (!na_class->msg_recv_expected) {
        NA_LOG_ERROR("msg_recv_expected plugin callback is not defined");
        ret = NA_PROTOCOL_ERROR;
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
    na_return_t ret = NA_SUCCESS;

    if (!na_class) {
        NA_LOG_ERROR("NULL NA class");
        ret = NA_INVALID_PARAM;
        goto done;
    }
    if (!buf) {
        NA_LOG_ERROR("NULL buffer");
        ret = NA_INVALID_PARAM;
        goto done;
    }
    if (!buf_size) {
        NA_LOG_ERROR("NULL buffer size");
        ret = NA_INVALID_PARAM;
        goto done;
    }
    if (!na_class->mem_handle_create) {
        NA_LOG_ERROR("mem_handle_create plugin callback is not defined");
        ret = NA_PROTOCOL_ERROR;
        goto done;
    }

    ret = na_class->mem_handle_create(na_class, buf, buf_size, flags,
            mem_handle);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
na_return_t
NA_Mem_handle_create_segments(na_class_t *na_class, struct na_segment *segments,
        na_size_t segment_count, unsigned long flags,
        na_mem_handle_t *mem_handle)
{
    na_return_t ret = NA_SUCCESS;

    if (!na_class) {
        NA_LOG_ERROR("NULL NA class");
        ret = NA_INVALID_PARAM;
        goto done;
    }
    if (!segments) {
        NA_LOG_ERROR("NULL pointer to segments");
        ret = NA_INVALID_PARAM;
        goto done;
    }
    if (!segment_count) {
        NA_LOG_ERROR("NULL segment count");
        ret = NA_INVALID_PARAM;
        goto done;
    }
    if (!na_class->mem_handle_create_segments) {
        NA_LOG_ERROR("mem_handle_create_segments plugin callback is not defined");
        ret = NA_PROTOCOL_ERROR;
        goto done;
    }

    ret = na_class->mem_handle_create_segments(na_class, segments,
            segment_count, flags, mem_handle);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
na_return_t
NA_Mem_handle_free(na_class_t *na_class, na_mem_handle_t mem_handle)
{
    na_return_t ret = NA_SUCCESS;

    if (!na_class) {
        NA_LOG_ERROR("NULL NA class");
        ret = NA_INVALID_PARAM;
        goto done;
    }
    if (mem_handle == NA_MEM_HANDLE_NULL) {
        NA_LOG_ERROR("NULL memory handle");
        ret = NA_INVALID_PARAM;
        goto done;
    }
    if (!na_class->mem_handle_free) {
        NA_LOG_ERROR("mem_handle_free plugin callback is not defined");
        ret = NA_PROTOCOL_ERROR;
        goto done;
    }

    ret = na_class->mem_handle_free(na_class, mem_handle);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
na_return_t
NA_Mem_register(na_class_t *na_class, na_mem_handle_t mem_handle)
{
    na_return_t ret = NA_SUCCESS;

    if (!na_class) {
        NA_LOG_ERROR("NULL NA class");
        ret = NA_INVALID_PARAM;
        goto done;
    }
    if (mem_handle == NA_MEM_HANDLE_NULL) {
        NA_LOG_ERROR("NULL memory handle");
        ret = NA_INVALID_PARAM;
        goto done;
    }

    if (na_class->mem_register) {
        /* Optional */
        ret = na_class->mem_register(na_class, mem_handle);
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
na_return_t
NA_Mem_deregister(na_class_t *na_class, na_mem_handle_t mem_handle)
{
    na_return_t ret = NA_SUCCESS;

    if (!na_class) {
        NA_LOG_ERROR("NULL NA class");
        ret = NA_INVALID_PARAM;
        goto done;
    }
    if (mem_handle == NA_MEM_HANDLE_NULL) {
        NA_LOG_ERROR("NULL memory handle");
        ret = NA_INVALID_PARAM;
        goto done;
    }

    if (na_class->mem_deregister) {
        /* Optional */
        ret = na_class->mem_deregister(na_class, mem_handle);
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
na_return_t
NA_Mem_publish(na_class_t *na_class, na_mem_handle_t mem_handle)
{
    na_return_t ret = NA_SUCCESS;

    if (!na_class) {
        NA_LOG_ERROR("NULL NA class");
        ret = NA_INVALID_PARAM;
        goto done;
    }
    if (mem_handle == NA_MEM_HANDLE_NULL) {
        NA_LOG_ERROR("NULL memory handle");
        ret = NA_INVALID_PARAM;
        goto done;
    }

    if (na_class->mem_publish) {
        /* Optional */
        ret = na_class->mem_publish(na_class, mem_handle);
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
na_return_t
NA_Mem_unpublish(na_class_t *na_class, na_mem_handle_t mem_handle)
{
    na_return_t ret = NA_SUCCESS;

    if (!na_class) {
        NA_LOG_ERROR("NULL NA class");
        ret = NA_INVALID_PARAM;
        goto done;
    }
    if (mem_handle == NA_MEM_HANDLE_NULL) {
        NA_LOG_ERROR("NULL memory handle");
        ret = NA_INVALID_PARAM;
        goto done;
    }

    if (na_class->mem_unpublish) {
        /* Optional */
        ret = na_class->mem_unpublish(na_class, mem_handle);
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
na_size_t
NA_Mem_handle_get_serialize_size(na_class_t *na_class,
        na_mem_handle_t mem_handle)
{
    na_size_t ret = 0;

    if (!na_class) {
        NA_LOG_ERROR("NULL NA class");
        goto done;
    }
    /* mem_handle parameter is optional */
    if (!na_class->mem_handle_get_serialize_size) {
        NA_LOG_ERROR("mem_handle_get_serialize_size plugin callback is not defined");
        goto done;
    }

    ret = na_class->mem_handle_get_serialize_size(na_class, mem_handle);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
na_return_t
NA_Mem_handle_serialize(na_class_t *na_class, void *buf, na_size_t buf_size,
        na_mem_handle_t mem_handle)
{
    na_return_t ret = NA_SUCCESS;

    if (!na_class) {
        NA_LOG_ERROR("NULL NA class");
        ret = NA_INVALID_PARAM;
        goto done;
    }
    if (!buf) {
        NA_LOG_ERROR("NULL buffer");
        ret = NA_INVALID_PARAM;
        goto done;
    }
    if (!buf_size) {
        NA_LOG_ERROR("NULL buffer size");
        ret = NA_INVALID_PARAM;
        goto done;
    }
    if (mem_handle == NA_MEM_HANDLE_NULL) {
        NA_LOG_ERROR("NULL memory handle");
        ret = NA_INVALID_PARAM;
        goto done;
    }
    if (!na_class->mem_handle_serialize) {
        NA_LOG_ERROR("mem_handle_serialize plugin callback is not defined");
        ret = NA_PROTOCOL_ERROR;
        goto done;
    }

    ret = na_class->mem_handle_serialize(na_class, buf, buf_size, mem_handle);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
na_return_t
NA_Mem_handle_deserialize(na_class_t *na_class, na_mem_handle_t *mem_handle,
        const void *buf, na_size_t buf_size)
{
    na_return_t ret = NA_SUCCESS;

    if (!na_class) {
        NA_LOG_ERROR("NULL NA class");
        ret = NA_INVALID_PARAM;
        goto done;
    }
    if (!mem_handle) {
        NA_LOG_ERROR("NULL pointer to memory handle");
        ret = NA_INVALID_PARAM;
        goto done;
    }
    if (!buf) {
        NA_LOG_ERROR("NULL buffer");
        ret = NA_INVALID_PARAM;
        goto done;
    }
    if (!buf_size) {
        NA_LOG_ERROR("NULL buffer size");
        ret = NA_INVALID_PARAM;
        goto done;
    }
    if (!na_class->mem_handle_deserialize) {
        NA_LOG_ERROR("mem_handle_deserialize plugin callback is not defined");
        ret = NA_PROTOCOL_ERROR;
        goto done;
    }

    ret = na_class->mem_handle_deserialize(na_class, mem_handle, buf, buf_size);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
na_return_t
NA_Put(na_class_t *na_class, na_context_t *context, na_cb_t callback, void *arg,
        na_mem_handle_t local_mem_handle, na_offset_t local_offset,
        na_mem_handle_t remote_mem_handle, na_offset_t remote_offset,
        na_size_t data_size, na_addr_t remote_addr, na_op_id_t *op_id)
{
    na_op_id_t na_op_id;
    na_return_t ret = NA_SUCCESS;

    if (!na_class) {
        NA_LOG_ERROR("NULL NA class");
        ret = NA_INVALID_PARAM;
        goto done;
    }
    if (!context) {
        NA_LOG_ERROR("NULL context");
        ret = NA_INVALID_PARAM;
        goto done;
    }
    if (local_mem_handle == NA_MEM_HANDLE_NULL) {
        NA_LOG_ERROR("NULL memory handle");
        ret = NA_INVALID_PARAM;
        goto done;
    }
    if (remote_mem_handle == NA_MEM_HANDLE_NULL) {
        NA_LOG_ERROR("NULL memory handle");
        ret = NA_INVALID_PARAM;
        goto done;
    }
    if (!data_size) {
        NA_LOG_ERROR("NULL data size");
        ret = NA_INVALID_PARAM;
        goto done;
    }
    if (remote_addr == NA_ADDR_NULL) {
        NA_LOG_ERROR("NULL addr");
        ret = NA_INVALID_PARAM;
        goto done;
    }
    if (!na_class->put) {
        NA_LOG_ERROR("put plugin callback is not defined");
        ret = NA_PROTOCOL_ERROR;
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
    na_return_t ret = NA_SUCCESS;

    if (!na_class) {
        NA_LOG_ERROR("NULL NA class");
        ret = NA_INVALID_PARAM;
        goto done;
    }
    if (!context) {
        NA_LOG_ERROR("NULL context");
        ret = NA_INVALID_PARAM;
        goto done;
    }
    if (local_mem_handle == NA_MEM_HANDLE_NULL) {
        NA_LOG_ERROR("NULL memory handle");
        ret = NA_INVALID_PARAM;
        goto done;
    }
    if (remote_mem_handle == NA_MEM_HANDLE_NULL) {
        NA_LOG_ERROR("NULL memory handle");
        ret = NA_INVALID_PARAM;
        goto done;
    }
    if (!data_size) {
        NA_LOG_ERROR("NULL data size");
        ret = NA_INVALID_PARAM;
        goto done;
    }
    if (remote_addr == NA_ADDR_NULL) {
        NA_LOG_ERROR("NULL addr");
        ret = NA_INVALID_PARAM;
        goto done;
    }
    if (!na_class->get) {
        NA_LOG_ERROR("get plugin callback is not defined");
        ret = NA_PROTOCOL_ERROR;
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
    double remaining = timeout / 1000.0; /* Convert timeout in ms into seconds */
    na_return_t ret = NA_SUCCESS;

    if (!na_class) {
        NA_LOG_ERROR("NULL NA class");
        ret = NA_INVALID_PARAM;
        goto done;
    }
    if (!context) {
        NA_LOG_ERROR("NULL context");
        ret = NA_INVALID_PARAM;
        goto done;
    }
    if (!na_class->progress) {
        NA_LOG_ERROR("progress plugin callback is not defined");
        ret = NA_PROTOCOL_ERROR;
        goto done;
    }

    /* TODO option for concurrent progress */

    /* Prevent multiple threads from concurrently calling progress on the same
     * context */
    hg_thread_mutex_lock(&na_private_context->progress_mutex);

    while (na_private_context->progressing) {
        hg_time_t t1, t2;

        if (remaining <= 0) {
            /* Timeout is 0 so leave */
            hg_thread_mutex_unlock(&na_private_context->progress_mutex);
            ret = NA_TIMEOUT;
            goto done;
        }

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
            /* TODO needed ? */
            /* If queue is empty and already triggered something, just leave */
            if (count) {
                hg_thread_mutex_unlock(
                        &na_private_context->completion_queue_mutex);
                goto done;
            }

            if (!timeout) {
                /* Timeout is 0 so leave */
                ret = NA_TIMEOUT;
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

    if (!na_class) {
        NA_LOG_ERROR("NULL NA class");
        ret = NA_INVALID_PARAM;
        goto done;
    }
    if (!context) {
        NA_LOG_ERROR("NULL context");
        ret = NA_INVALID_PARAM;
        goto done;
    }
    if (op_id == NA_OP_ID_NULL) {
        NA_LOG_ERROR("NULL operation ID");
        ret = NA_INVALID_PARAM;
        goto done;
    }
    if (!na_class->cancel) {
        NA_LOG_ERROR("cancel plugin callback is not defined");
        ret = NA_PROTOCOL_ERROR;
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
