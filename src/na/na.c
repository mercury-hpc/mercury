/*
 * Copyright (C) 2013-2016 Argonne National Laboratory, Department of Energy,
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
#  undef strdup
#  define strdup _strdup
#endif

/************************************/
/* Local Type and Struct Definition */
/************************************/

struct na_private_class {
    struct na_class na_class; /* Must remain as first field */
    char * protocol_name;
    na_bool_t listen;
};

/* NA completions queue */
TAILQ_HEAD(na_compqueue, na_cb_completion_data);
typedef struct na_compqueue na_compqueue_t;

/* Private context / do not expose private members to plugins */
struct na_private_context {
    struct na_context context;  /* Must remain as first field */
    na_class_t *na_class;       /* Pointer to NA class */
    na_compqueue_t completion_queue;
    hg_thread_mutex_t completion_queue_mutex;
    hg_thread_cond_t completion_queue_cond;
    hg_thread_mutex_t progress_mutex;
    hg_thread_cond_t progress_cond;
    na_bool_t progressing;
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

    /* Copy info string and work from that */
    input_string = strdup(info_string);
    if (!input_string) {
        NA_LOG_ERROR("Could not duplicate host string");
        ret = NA_NOMEM_ERROR;
        goto done;
    }

    /**
     * Strings can be of the format:
     *   [<class>+]<protocol>[://[<host string>]]
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

    /* Is the host string empty? */
    if (!locator || locator[0] == '\0') {
        goto done;
    }
    /* Format sanity check ("://") */
    else if (strncmp(locator, "//", 2) != 0) {
        NA_LOG_ERROR("Bad address string format");
        ret = NA_PROTOCOL_ERROR;
        goto done;
    }
    /* :// followed by empty hostname is allowed, explicitly check here */
    else if (locator[2] == '\0') {
        goto done;
    }
    else {
        na_info->host_name = strdup(locator+2);
        if (!na_info->host_name) {
            NA_LOG_ERROR("Could not duplicate NA info host name");
            ret = NA_NOMEM_ERROR;
        }
    }

done:
    if (ret == NA_SUCCESS) {
        *na_info_ptr = na_info;
    }
    else {
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
    na_private_class->protocol_name = NULL;

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
                /* While we're here, dup the class_name */
                na_info->class_name = strdup(
                        na_class_table[plugin_index]->class_name);
                if (!na_info->class_name) {
                    NA_LOG_ERROR("unable to dup class name string");
                    ret = NA_NOMEM_ERROR;
                    goto done;
                }
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
    na_private_class->protocol_name = strdup(na_info->protocol_name);
    if (!na_private_class->protocol_name) {
        NA_LOG_ERROR("Could not duplicate protocol name");
        ret = NA_NOMEM_ERROR;
        goto done;
    }
    na_private_class->listen = listen;

done:
    if (ret != NA_SUCCESS) {
        if (na_private_class) {
            free(na_private_class->protocol_name);
        }
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

    free(na_private_class->protocol_name);
    free(na_private_class);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
const char *
NA_Get_class_name(na_class_t *na_class)
{
    const char *ret = NULL;

    if (!na_class) {
        NA_LOG_ERROR("NULL NA class");
        goto done;
    }

    ret = na_class->class_name;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
const char *
NA_Get_class_protocol(na_class_t *na_class)
{
    const char *ret = NULL;
    struct na_private_class *na_private_class =
        (struct na_private_class *) na_class;

    if (!na_private_class) {
        NA_LOG_ERROR("NULL NA class");
        goto done;
    }

    ret = na_private_class->protocol_name;

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
    TAILQ_INIT(&na_private_context->completion_queue);

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

    if (!TAILQ_EMPTY(&na_private_context->completion_queue)) {
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
            op_id);
    if (ret != NA_SUCCESS) {
        goto done;
    }

done:
    free(name_string);
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
NA_Addr_to_string(na_class_t *na_class, char *buf, na_size_t *buf_size,
        na_addr_t addr)
{
    na_return_t ret = NA_SUCCESS;

    if (!na_class) {
        NA_LOG_ERROR("NULL NA class");
        ret = NA_INVALID_PARAM;
        goto done;
    }
    /* buf can be NULL */
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
NA_Prealloc_op_id(na_class_t *na_class, na_context_t *context,
        na_op_id_t *op_id)          
{
    na_return_t ret = NA_SUCCESS;

    *op_id = NULL;    /* ensure caller gets something valid */

    if (!na_class) {
        NA_LOG_ERROR("NULL NA class");
        ret = NA_INVALID_PARAM;
        goto done;
    }
    if (!na_class->prealloc_op_id) {
        /* optional prealloc_op_id not provided, so we skip it */
        goto done;
    }

    ret = na_class->prealloc_op_id(na_class, context, op_id);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
na_return_t
NA_Prealloc_op_id_free(na_class_t *na_class, na_context_t *context,
        na_op_id_t op_id)          
{
    na_return_t ret = NA_SUCCESS;

    if (!na_class) {
        NA_LOG_ERROR("NULL NA class");
        ret = NA_INVALID_PARAM;
        goto done;
    }
    if (!op_id || !na_class->prealloc_op_id_free) {
        /* no preallocated op_id or free function?  skip it */
        goto done;
    }

    ret = na_class->prealloc_op_id_free(na_class, context, op_id);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
na_return_t
NA_Msg_send_unexpected(na_class_t *na_class, na_context_t *context,
        na_cb_t callback, void *arg, const void *buf, na_size_t buf_size,
        na_addr_t dest, na_tag_t tag, na_op_id_t op_id_in, na_op_id_t *op_id)
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
                                        buf_size, dest, tag, op_id_in, op_id);
    if (ret != NA_SUCCESS) {
        goto done;
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
na_return_t
NA_Msg_recv_unexpected(na_class_t *na_class, na_context_t *context,
        na_cb_t callback, void *arg, void *buf, na_size_t buf_size,
        na_op_id_t op_id_in, na_op_id_t *op_id)
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
                                        buf_size, op_id_in, op_id);
    if (ret != NA_SUCCESS) {
        goto done;
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
na_return_t
NA_Msg_send_expected(na_class_t *na_class, na_context_t *context,
        na_cb_t callback, void *arg, const void *buf, na_size_t buf_size,
        na_addr_t dest, na_tag_t tag, na_op_id_t op_id_in,
        na_op_id_t *op_id)
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
                                      buf_size, dest, tag, op_id_in, op_id);
    if (ret != NA_SUCCESS) {
        goto done;
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
na_return_t
NA_Msg_recv_expected(na_class_t *na_class, na_context_t *context,
        na_cb_t callback, void *arg, void *buf, na_size_t buf_size,
        na_addr_t source, na_tag_t tag, na_op_id_t op_id_in, na_op_id_t *op_id)
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
                                      buf_size, source, tag, op_id_in, op_id);
    if (ret != NA_SUCCESS) {
        goto done;
    }

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
            remote_addr, op_id);
    if (ret != NA_SUCCESS) {
        goto done;
    }

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
            remote_addr, op_id);
    if (ret != NA_SUCCESS) {
        goto done;
    }

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
        completion_queue_empty =
            (TAILQ_EMPTY(&na_private_context->completion_queue)) ? NA_TRUE
            : NA_FALSE;

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
        completion_data = TAILQ_LAST(&na_private_context->completion_queue,
                                     na_compqueue);
        TAILQ_REMOVE(&na_private_context->completion_queue,
                     completion_data, q);
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
            completion_data->callback(&completion_data->callback_info);
        }

        /* Execute plugin callback (free resources etc) */
        if (completion_data->plugin_callback)
            completion_data->plugin_callback(&completion_data->callback_info,
                    completion_data->plugin_callback_args);

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
                     struct na_cb_completion_data *completion_data)
{
    struct na_private_context *na_private_context =
            (struct na_private_context *) context;
    na_return_t ret = NA_SUCCESS;

    hg_thread_mutex_lock(&na_private_context->completion_queue_mutex);

    TAILQ_INSERT_HEAD(&na_private_context->completion_queue,
                      completion_data, q);

    /* Callback is pushed to the completion queue when something completes
     * so wake up anyone waiting in the trigger */
    hg_thread_cond_signal(&na_private_context->completion_queue_cond);

    hg_thread_mutex_unlock(&na_private_context->completion_queue_mutex);

    return ret;
}
