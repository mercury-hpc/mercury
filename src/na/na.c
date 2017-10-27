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
#include "mercury_thread_condition.h"
#include "mercury_time.h"
#include "mercury_atomic.h"
#include "mercury_mem.h"
#include "mercury_atomic_queue.h"

#include <stdlib.h>
#include <string.h>

/****************/
/* Local Macros */
/****************/
/* Convert value to string */
#define NA_ERROR_STRING_MACRO(def, value, string) \
  if (value == def) string = #def

#define NA_CLASS_DELIMITER "+" /* e.g. "class+protocol" */

#ifdef _WIN32
#  define strtok_r strtok_s
#  undef strdup
#  define strdup _strdup
#endif

#define NA_ATOMIC_QUEUE_SIZE 1024   /* TODO make it configurable */

#define NA_PROGRESS_LOCK 0x80000000 /* 32-bit lock value for serial progress */

/************************************/
/* Local Type and Struct Definition */
/************************************/

struct na_private_class {
    struct na_class na_class;   /* Must remain as first field */
    char * protocol_name;       /* Name of protocol */
    na_bool_t listen;           /* Listen for connections */
};

/* Private context / do not expose private members to plugins */
struct na_private_context {
    struct na_context context;                  /* Must remain as first field */
    na_class_t *na_class;                       /* Pointer to NA class */
    struct hg_atomic_queue *completion_queue;   /* Default completion queue */
    HG_QUEUE_HEAD(na_cb_completion_data) backfill_queue; /* Backfill completion queue */
    hg_atomic_int32_t backfill_queue_count;     /* Number of entries in backfill queue */
    hg_thread_mutex_t completion_queue_mutex;   /* Completion queue mutex */
    hg_thread_cond_t  completion_queue_cond;    /* Completion queue cond */
    hg_atomic_int32_t trigger_waiting;          /* Polling/waiting in trigger */
#ifdef NA_HAS_MULTI_PROGRESS
    hg_thread_mutex_t progress_mutex;           /* Progress mutex */
    hg_thread_cond_t  progress_cond;            /* Progress cond */
    hg_atomic_int32_t progressing;              /* Progressing count */
#endif
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
#ifdef NA_HAS_SM
extern na_class_t na_sm_class_g;
#endif
#ifdef NA_HAS_BMI
extern na_class_t na_bmi_class_g;
#endif
#ifdef NA_HAS_MPI
extern na_class_t na_mpi_class_g;
#endif
#ifdef NA_HAS_CCI
extern na_class_t na_cci_class_g;
#endif
#ifdef NA_HAS_OFI
extern na_class_t na_ofi_class_g;
#endif

static const na_class_t *na_class_table[] = {
#ifdef NA_HAS_SM
    &na_sm_class_g, /* Keep NA SM first for protocol selection */
#endif
#ifdef NA_HAS_BMI
    &na_bmi_class_g,
#endif
#ifdef NA_HAS_MPI
    &na_mpi_class_g,
#endif
#ifdef NA_HAS_CCI
    &na_cci_class_g,
#endif
#ifdef NA_HAS_OFI
    &na_ofi_class_g,
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
    if (strstr(token, NA_CLASS_DELIMITER) != NULL) {
        char *_locator = NULL;

        token = strtok_r(token, NA_CLASS_DELIMITER, &_locator);

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
        na_info->host_name = strdup(locator + 2);
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

        if (!na_class_table[plugin_index]->class_name) {
            NA_LOG_ERROR("class name is not defined");
            ret = NA_PROTOCOL_ERROR;
            goto done;
        }

        if (!na_class_table[plugin_index]->check_protocol) {
            NA_LOG_ERROR("check_protocol plugin callback is not defined");
            ret = NA_PROTOCOL_ERROR;
            goto done;
        }

        /* Skip check protocol if class name does not match */
        if (na_info->class_name) {
            if (strcmp(na_class_table[plugin_index]->class_name,
                na_info->class_name) != 0) {
                plugin_index++;
                continue;
            }
        }

        /* Check that protocol is supported */
        verified = na_class_table[plugin_index]->check_protocol(
            na_info->protocol_name);
        if (!verified) {
            if (na_info->class_name) {
                NA_LOG_ERROR("Specified class name does not support request protocol");
                ret = NA_PROTOCOL_ERROR;
                goto done;
            }
            plugin_index++;
            continue;
        }

        /* If no class name specified, take the first plugin that supports
         * the protocol */
        if (!na_info->class_name) {
            /* While we're here, dup the class_name */
            na_info->class_name = strdup(
                na_class_table[plugin_index]->class_name);
            if (!na_info->class_name) {
                NA_LOG_ERROR("unable to dup class name string");
                ret = NA_NOMEM_ERROR;
                goto done;
            }
        }

        /* All checks have passed */
        plugin_found = NA_TRUE;
        break;
    }

    if (!plugin_found) {
        NA_LOG_ERROR("No suitable plugin found that matches %s", info_string);
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
void
NA_Cleanup(void)
{
    unsigned int plugin_count =
        sizeof(na_class_table) / sizeof(na_class_table[0]) - 1;
    unsigned int i;

    for (i = 0; i < plugin_count; i++) {
        if (!na_class_table[i]->cleanup)
            continue;

        na_class_table[i]->cleanup();
    }
}

/*---------------------------------------------------------------------------*/
const char *
NA_Get_class_name(const na_class_t *na_class)
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
NA_Get_class_protocol(const na_class_t *na_class)
{
    const char *ret = NULL;
    const struct na_private_class *na_private_class =
        (const struct na_private_class *) na_class;

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
NA_Is_listening(const na_class_t *na_class)
{
    const struct na_private_class *na_private_class =
        (const struct na_private_class *) na_class;
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
na_bool_t
NA_Check_feature(na_class_t *na_class, na_uint8_t feature)
{
    na_bool_t ret = NA_FALSE;

    if (!na_class) {
        NA_LOG_ERROR("NULL NA class");
        goto done;
    }

    if (na_class->check_feature)
        ret = na_class->check_feature(na_class, feature);

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
    na_private_context->completion_queue =
        hg_atomic_queue_alloc(NA_ATOMIC_QUEUE_SIZE);
    if (!na_private_context->completion_queue) {
        NA_LOG_ERROR("Could not allocate queue");
        ret = NA_NOMEM_ERROR;
        goto done;
    }
    HG_QUEUE_INIT(&na_private_context->backfill_queue);
    hg_atomic_init32(&na_private_context->backfill_queue_count, 0);

    /* Initialize completion queue mutex/cond */
    hg_thread_mutex_init(&na_private_context->completion_queue_mutex);
    hg_thread_cond_init(&na_private_context->completion_queue_cond);
    hg_atomic_init32(&na_private_context->trigger_waiting, 0);

#ifdef NA_HAS_MULTI_PROGRESS
    /* Initialize progress mutex/cond */
    hg_thread_mutex_init(&na_private_context->progress_mutex);
    hg_thread_cond_init(&na_private_context->progress_cond);
    hg_atomic_init32(&na_private_context->progressing, 0);
#endif

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
    if (!hg_atomic_queue_is_empty(na_private_context->completion_queue)) {
        NA_LOG_ERROR("Completion queue should be empty");
        ret = NA_PROTOCOL_ERROR;
        goto done;
    }
    hg_atomic_queue_free(na_private_context->completion_queue);

    /* Check that backfill completion queue is empty now */
    hg_thread_mutex_lock(&na_private_context->completion_queue_mutex);
    if (!HG_QUEUE_IS_EMPTY(&na_private_context->backfill_queue)) {
        NA_LOG_ERROR("Completion queue should be empty");
        ret = NA_PROTOCOL_ERROR;
        hg_thread_mutex_unlock(&na_private_context->completion_queue_mutex);
        goto done;
    }
    hg_thread_mutex_unlock(&na_private_context->completion_queue_mutex);

    /* Destroy completion queue mutex/cond */
    hg_thread_mutex_destroy(&na_private_context->completion_queue_mutex);
    hg_thread_cond_destroy(&na_private_context->completion_queue_cond);

    /* Destroy NA plugin context */
    if (na_class->context_destroy) {
        ret = na_class->context_destroy(na_class,
            na_private_context->context.plugin_context);
        if (ret != NA_SUCCESS) {
            goto done;
        }
    }

#ifdef NA_HAS_MULTI_PROGRESS
    /* Destroy progress mutex/cond */
    hg_thread_mutex_destroy(&na_private_context->progress_mutex);
    hg_thread_cond_destroy(&na_private_context->progress_cond);
#endif

    free(na_private_context);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
na_op_id_t
NA_Op_create(na_class_t *na_class)
{
    na_op_id_t ret = NA_OP_ID_NULL;

    if (!na_class) {
        NA_LOG_ERROR("NULL NA class");
        goto done;
    }
    if (!na_class->op_create) {
        /* Not provided */
        goto done;
    }

    ret = na_class->op_create(na_class);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
na_return_t
NA_Op_destroy(na_class_t *na_class, na_op_id_t op_id)
{
    na_return_t ret = NA_SUCCESS;

    if (!na_class) {
        NA_LOG_ERROR("NULL NA class");
        ret = NA_INVALID_PARAM;
        goto done;
    }
    if (op_id == NA_OP_ID_NULL) {
        /* Nothing to do */
        goto done;
    }
    if (!na_class->op_destroy) {
        /* Not provided */
        goto done;
    }

    ret = na_class->op_destroy(na_class, op_id);

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
    if (strstr(name_string, NA_CLASS_DELIMITER) != NULL)
        strtok_r(name_string, NA_CLASS_DELIMITER, &short_name);
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
    if (addr == NA_ADDR_NULL)
        /* Nothing to do */
        goto done;
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
    char *buf_ptr = buf;
    na_size_t buf_size_used, plugin_buf_size;
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

    /* Automatically prepend string by plugin name with class delimiter */
    buf_size_used = strlen(na_class->class_name) + 1;
    if (buf_ptr) {
        if (*buf_size > buf_size_used) {
            strcpy(buf_ptr, na_class->class_name);
            strcat(buf_ptr, NA_CLASS_DELIMITER);
            buf_ptr += buf_size_used;
            plugin_buf_size = *buf_size - buf_size_used;
        } else {
            NA_LOG_ERROR("Buffer size too small to copy addr");
            ret = NA_SIZE_ERROR;
            goto done;
        }
    } else {
        plugin_buf_size = 0;
    }

    ret = na_class->addr_to_string(na_class, buf_ptr, &plugin_buf_size, addr);

    *buf_size = buf_size_used + plugin_buf_size;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
na_size_t
NA_Msg_get_max_unexpected_size(const na_class_t *na_class)
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
na_size_t
NA_Msg_get_max_expected_size(const na_class_t *na_class)
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
NA_Msg_get_unexpected_header_size(const na_class_t *na_class)
{
    na_size_t ret = 0;

    if (!na_class) {
        NA_LOG_ERROR("NULL NA class");
        goto done;
    }

    if (na_class->msg_get_unexpected_header_size)
        ret = na_class->msg_get_unexpected_header_size(na_class);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
na_size_t
NA_Msg_get_expected_header_size(const na_class_t *na_class)
{
    na_size_t ret = 0;

    if (!na_class) {
        NA_LOG_ERROR("NULL NA class");
        goto done;
    }

    if (na_class->msg_get_expected_header_size)
        ret = na_class->msg_get_expected_header_size(na_class);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
na_tag_t
NA_Msg_get_max_tag(const na_class_t *na_class)
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
void *
NA_Msg_buf_alloc(na_class_t *na_class, na_size_t buf_size, void **plugin_data)
{
    void *ret = NULL;

    if (!na_class) {
        NA_LOG_ERROR("NULL NA class");
        goto done;
    }
    if (!buf_size) {
        NA_LOG_ERROR("NULL buffer size");
        goto done;
    }
    if (!plugin_data) {
        NA_LOG_ERROR("NULL pointer to plugin data");
        goto done;
    }

    if (na_class->msg_buf_alloc)
        ret = na_class->msg_buf_alloc(na_class, buf_size, plugin_data);
    else {
        na_size_t page_size = (na_size_t) hg_mem_get_page_size();

        ret = hg_mem_aligned_alloc(page_size, buf_size);
        if (!ret) {
            NA_LOG_ERROR("Could not allocate %d bytes", (int) buf_size);
            goto done;
        }
        memset(ret, 0, buf_size);
        *plugin_data = (void *)1; /* Sanity check on free */
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
na_return_t
NA_Msg_buf_free(na_class_t *na_class, void *buf, void *plugin_data)
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
    if (!plugin_data) {
        NA_LOG_ERROR("NULL pointer to plugin data");
        ret = NA_INVALID_PARAM;
        goto done;
    }

    if (na_class->msg_buf_free)
        ret = na_class->msg_buf_free(na_class, buf, plugin_data);
    else {
        if (plugin_data != (void *)1) {
            NA_LOG_ERROR("Invalid plugin data value");
            ret = NA_PROTOCOL_ERROR;
            goto done;
        }
        hg_mem_aligned_free(buf);
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
na_return_t
NA_Msg_init_unexpected(na_class_t *na_class, void *buf, na_size_t buf_size)
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

    if (na_class->msg_init_unexpected)
        ret = na_class->msg_init_unexpected(na_class, buf, buf_size);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
na_return_t
NA_Msg_send_unexpected(na_class_t *na_class, na_context_t *context,
    na_cb_t callback, void *arg, const void *buf, na_size_t buf_size,
    void *plugin_data, na_addr_t dest, na_tag_t tag, na_op_id_t *op_id)
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
        buf_size, plugin_data, dest, tag, op_id);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
na_return_t
NA_Msg_recv_unexpected(na_class_t *na_class, na_context_t *context,
    na_cb_t callback, void *arg, void *buf, na_size_t buf_size,
    void *plugin_data, na_tag_t mask, na_op_id_t *op_id)
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
        buf_size, plugin_data, mask, op_id);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
na_return_t
NA_Msg_init_expected(na_class_t *na_class, void *buf, na_size_t buf_size)
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

    if (na_class->msg_init_expected)
        ret = na_class->msg_init_expected(na_class, buf, buf_size);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
na_return_t
NA_Msg_send_expected(na_class_t *na_class, na_context_t *context,
    na_cb_t callback, void *arg, const void *buf, na_size_t buf_size,
    void *plugin_data, na_addr_t dest, na_tag_t tag, na_op_id_t *op_id)
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
        buf_size, plugin_data, dest, tag, op_id);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
na_return_t
NA_Msg_recv_expected(na_class_t *na_class, na_context_t *context,
    na_cb_t callback, void *arg, void *buf, na_size_t buf_size,
    void *plugin_data, na_addr_t source, na_tag_t tag, na_op_id_t *op_id)
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
        buf_size, plugin_data, source, tag, op_id);

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
    if (mem_handle == NA_MEM_HANDLE_NULL) {
        NA_LOG_ERROR("NULL memory handle");
        ret = NA_INVALID_PARAM;
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

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
int
NA_Poll_get_fd(na_class_t *na_class, na_context_t *context)
{
    int ret = 0;

    if (!na_class) {
        NA_LOG_ERROR("NULL NA class");
        goto done;
    }
    if (!context) {
        NA_LOG_ERROR("NULL context");
        goto done;
    }
    if (!na_class->na_poll_get_fd) {
        goto done;
    }

    ret = na_class->na_poll_get_fd(na_class, context);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
na_bool_t
NA_Poll_try_wait(na_class_t *na_class, na_context_t *context)
{
    struct na_private_context *na_private_context =
        (struct na_private_context *) context;

    if (!na_class) {
        NA_LOG_ERROR("NULL NA class");
        return NA_FALSE;
    }
    if (!context) {
        NA_LOG_ERROR("NULL context");
        return NA_FALSE;
    }

    /* Something is in one of the completion queues */
    if (!hg_atomic_queue_is_empty(na_private_context->completion_queue) ||
        hg_atomic_get32(&na_private_context->backfill_queue_count)) {
        return NA_FALSE;
    }

    /* Check plugin try wait */
    if (na_class->na_poll_try_wait)
        return na_class->na_poll_try_wait(na_class, context);

    return NA_TRUE;
}

/*---------------------------------------------------------------------------*/
na_return_t
NA_Progress(na_class_t *na_class, na_context_t *context, unsigned int timeout)
{
    struct na_private_context *na_private_context =
        (struct na_private_context *) context;
    double remaining = timeout / 1000.0; /* Convert timeout in ms into seconds */
#ifdef NA_HAS_MULTI_PROGRESS
    hg_util_int32_t old, num;
#endif
    na_return_t ret = NA_TIMEOUT;

    if (!na_class) {
        NA_LOG_ERROR("NULL NA class");
        ret = NA_INVALID_PARAM;
        goto done;
    }
    if (!na_private_context) {
        NA_LOG_ERROR("NULL context");
        ret = NA_INVALID_PARAM;
        goto done;
    }
    if (!na_class->progress) {
        NA_LOG_ERROR("progress plugin callback is not defined");
        ret = NA_PROTOCOL_ERROR;
        goto done;
    }

#ifdef NA_HAS_MULTI_PROGRESS
    hg_atomic_incr32(&na_private_context->progressing);
    for (;;) {
        hg_time_t t1, t2;

        old = hg_atomic_get32(&na_private_context->progressing)
            & (hg_util_int32_t) ~NA_PROGRESS_LOCK;
        num = old | (hg_util_int32_t) NA_PROGRESS_LOCK;
        if (hg_atomic_cas32(&na_private_context->progressing, old, num))
            break; /* No other thread is progressing */

        /* Timeout is 0 so leave */
        if (remaining <= 0) {
            hg_atomic_decr32(&na_private_context->progressing);
            goto done;
        }

        hg_time_get_current(&t1);

        /* Prevent multiple threads from concurrently calling progress on
         * the same context */
        hg_thread_mutex_lock(&na_private_context->progress_mutex);

        num = hg_atomic_get32(&na_private_context->progressing);
        /* Do not need to enter condition if lock is already released */
        if (((num & (hg_util_int32_t) NA_PROGRESS_LOCK) != 0)
            && (hg_thread_cond_timedwait(&na_private_context->progress_cond,
                &na_private_context->progress_mutex,
                (unsigned int) (remaining * 1000.0)) != HG_UTIL_SUCCESS)) {
            /* Timeout occurred so leave */
            hg_atomic_decr32(&na_private_context->progressing);
            hg_thread_mutex_unlock(&na_private_context->progress_mutex);
            goto done;
        }

        hg_thread_mutex_unlock(&na_private_context->progress_mutex);

        hg_time_get_current(&t2);
        remaining -= hg_time_to_double(hg_time_subtract(t2, t1));
        /* Give a chance to call progress with timeout of 0 */
        if (remaining < 0)
            remaining = 0;
    }
#endif

    /* Something is in one of the completion queues */
    if (!hg_atomic_queue_is_empty(na_private_context->completion_queue) ||
        hg_atomic_get32(&na_private_context->backfill_queue_count)) {
        ret = NA_SUCCESS; /* Progressed */
#ifdef NA_HAS_MULTI_PROGRESS
        goto unlock;
#else
        goto done;
#endif
    }

    /* Try to make progress for remaining time */
    ret = na_class->progress(na_class, context,
        (unsigned int) (remaining * 1000.0));

#ifdef NA_HAS_MULTI_PROGRESS
unlock:
    do {
        old = hg_atomic_get32(&na_private_context->progressing);
        num = (old - 1) ^ (hg_util_int32_t) NA_PROGRESS_LOCK;
    } while (!hg_atomic_cas32(&na_private_context->progressing, old, num));

    if (num > 0) {
        /* If there is another processes entered in progress, signal it */
        hg_thread_mutex_lock(&na_private_context->progress_mutex);
        hg_thread_cond_signal(&na_private_context->progress_cond);
        hg_thread_mutex_unlock(&na_private_context->progress_mutex);
    }
#endif

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
na_return_t
NA_Trigger(na_context_t *context, unsigned int timeout, unsigned int max_count,
    int callback_ret[], unsigned int *actual_count)
{
    double remaining = timeout / 1000.0; /* Convert timeout in ms into seconds */
    na_return_t ret = NA_SUCCESS;
    unsigned int count = 0;

    if (!context) {
        NA_LOG_ERROR("NULL context");
        ret = NA_INVALID_PARAM;
        goto done;
    }

    while (count < max_count) {
        struct na_cb_completion_data *completion_data = NULL;
        struct na_private_context *na_private_context =
            (struct na_private_context *) context;

        completion_data =
            hg_atomic_queue_pop_mc(na_private_context->completion_queue);
        if (!completion_data) {
            /* Check backfill queue */
            if (hg_atomic_get32(&na_private_context->backfill_queue_count)) {
                hg_thread_mutex_lock(
                    &na_private_context->completion_queue_mutex);
                completion_data =
                    HG_QUEUE_FIRST(&na_private_context->backfill_queue);
                HG_QUEUE_POP_HEAD(&na_private_context->backfill_queue, entry);
                hg_atomic_decr32(&na_private_context->backfill_queue_count);
                hg_thread_mutex_unlock(
                    &na_private_context->completion_queue_mutex);
                if (!completion_data)
                    continue; /* Give another change to grab it */
            } else {
                hg_time_t t1, t2;

                /* If something was already processed leave */
                if (count)
                    break;

                /* Timeout is 0 so leave */
                if ((int)(remaining * 1000.0) <= 0) {
                    ret = NA_TIMEOUT;
                    break;
                }

                hg_time_get_current(&t1);

                hg_atomic_incr32(&na_private_context->trigger_waiting);
                hg_thread_mutex_lock(
                    &na_private_context->completion_queue_mutex);
                /* Otherwise wait timeout ms */
                while (hg_atomic_queue_is_empty(
                    na_private_context->completion_queue)
                    && !hg_atomic_get32(
                        &na_private_context->backfill_queue_count)) {
                    if (hg_thread_cond_timedwait(
                        &na_private_context->completion_queue_cond,
                        &na_private_context->completion_queue_mutex, timeout)
                        != HG_UTIL_SUCCESS) {
                        /* Timeout occurred so leave */
                        ret = NA_TIMEOUT;
                        break;
                    }
                }
                hg_thread_mutex_unlock(
                    &na_private_context->completion_queue_mutex);
                hg_atomic_decr32(&na_private_context->trigger_waiting);
                if (ret == NA_TIMEOUT)
                    break;

                hg_time_get_current(&t2);
                remaining -= hg_time_to_double(hg_time_subtract(t2, t1));
                continue; /* Give another change to grab it */
            }
        }

        /* Completion queue should not be empty now */
        if (!completion_data) {
            NA_LOG_ERROR("NULL completion data");
            ret = NA_PROTOCOL_ERROR;
            goto done;
        }

        /* Execute callback */
        if (completion_data->callback) {
            int cb_ret =
                completion_data->callback(&completion_data->callback_info);
            if (callback_ret)
                callback_ret[count] = cb_ret;
        }

        /* Execute plugin callback (free resources etc) */
        if (completion_data->plugin_callback)
            completion_data->plugin_callback(
                completion_data->plugin_callback_args);

        count++;
    }

done:
    if ((ret == NA_SUCCESS || ret == NA_TIMEOUT) && actual_count)
        *actual_count = count;
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
    NA_ERROR_STRING_MACRO(NA_ADDRINUSE_ERROR, errnum, na_error_string);

    return na_error_string;
}

/*---------------------------------------------------------------------------*/
na_return_t
na_cb_completion_add(na_context_t *context,
    struct na_cb_completion_data *na_cb_completion_data)
{
    struct na_private_context *na_private_context =
        (struct na_private_context *) context;
    na_return_t ret = NA_SUCCESS;

    if (hg_atomic_queue_push(na_private_context->completion_queue,
        na_cb_completion_data) != HG_UTIL_SUCCESS) {
        /* Queue is full */
        hg_thread_mutex_lock(&na_private_context->completion_queue_mutex);
        HG_QUEUE_PUSH_TAIL(&na_private_context->backfill_queue,
            na_cb_completion_data, entry);
        hg_atomic_incr32(&na_private_context->backfill_queue_count);
        hg_thread_mutex_unlock(&na_private_context->completion_queue_mutex);
    }

    if (hg_atomic_get32(&na_private_context->trigger_waiting)) {
        hg_thread_mutex_lock(&na_private_context->completion_queue_mutex);
        /* Callback is pushed to the completion queue when something completes
         * so wake up anyone waiting in the trigger */
        hg_thread_cond_signal(&na_private_context->completion_queue_cond);
        hg_thread_mutex_unlock(&na_private_context->completion_queue_mutex);
    }

    return ret;
}
