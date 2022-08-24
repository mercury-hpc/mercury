/**
 * Copyright (c) 2013-2022 UChicago Argonne, LLC and The HDF Group.
 * Copyright (c) 2022 Intel Corporation.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "na_plugin.h"

#include "mercury_atomic_queue.h"
#include "mercury_mem.h"
#include "mercury_thread_spin.h"

#include <stdlib.h>
#include <string.h>

/****************/
/* Local Macros */
/****************/

/* Name of this subsystem */
#define NA_SUBSYS_NAME        na
#define NA_STRINGIFY(x)       HG_UTIL_STRINGIFY(x)
#define NA_SUBSYS_NAME_STRING NA_STRINGIFY(NA_SUBSYS_NAME)

#define NA_CLASS_DELIMITER     "+" /* e.g. "class+protocol" */
#define NA_CLASS_DELIMITER_LEN (1)

#ifdef _WIN32
#    define strtok_r strtok_s
#    undef strdup
#    define strdup _strdup
#endif

#define NA_ATOMIC_QUEUE_SIZE 1024 /* TODO make it configurable */

/************************************/
/* Local Type and Struct Definition */
/************************************/

/* Private class */
struct na_private_class {
    struct na_class na_class; /* Must remain as first field */
};

/* Completion queue */
struct na_completion_queue {
    HG_QUEUE_HEAD(na_cb_completion_data) queue; /* Completion queue */
    hg_thread_spin_t lock;                      /* Completion queue lock */
    hg_atomic_int32_t count;                    /* Number of entries */
};

/* Private context / do not expose private members to plugins */
struct na_private_context {
    struct na_context context;                 /* Must remain as first field */
    struct na_completion_queue backfill_queue; /* Backfill queue */
    struct hg_atomic_queue *completion_queue;  /* Default completion queue */
    na_class_t *na_class;                      /* Pointer to NA class */
};

/* NA address */
struct na_addr;

/* NA memory handle */
struct na_mem_handle;

/* NA op ID */
struct na_op_id;

/********************/
/* Local Prototypes */
/********************/

/* Parse host string and fill info */
static na_return_t
na_info_parse(
    const char *host_string, char **class_name_p, struct na_info **na_info_p);

/* Free host info */
static void
na_info_free(struct na_info *na_info);

/*******************/
/* Local Variables */
/*******************/

/* NA plugin class table */
static const struct na_class_ops *const na_class_table_g[] = {
#ifdef NA_HAS_SM
    &NA_PLUGIN_OPS(sm), /* Keep NA SM first for protocol selection */
#endif
#ifdef NA_HAS_OFI
    &NA_PLUGIN_OPS(ofi),
#endif
#ifdef NA_HAS_BMI
    &NA_PLUGIN_OPS(bmi),
#endif
#ifdef NA_HAS_MPI
    &NA_PLUGIN_OPS(mpi),
#endif
#ifdef NA_HAS_CCI
    &NA_PLUGIN_OPS(cci),
#endif
#ifdef NA_HAS_UCX
    &NA_PLUGIN_OPS(ucx),
#endif
#ifdef NA_HAS_PSM
    &NA_PLUGIN_OPS(psm),
#endif
#ifdef NA_HAS_PSM2
    &NA_PLUGIN_OPS(psm2),
#endif
    NULL};

/* Return code string table */
#define X(a) #a,
static const char *const na_return_name_g[] = {NA_RETURN_VALUES};
#undef X

/* Callback type string table */
#define X(a) #a,
static const char *const na_cb_type_name_g[] = {NA_CB_TYPES};
#undef X

/* NA_LOG_DEBUG_LESIZE: default number of debug log entries. */
#define NA_LOG_DEBUG_LESIZE (256)

/* Declare debug log for na */
static HG_LOG_DEBUG_DECL_LE(NA_SUBSYS_NAME, NA_LOG_DEBUG_LESIZE);
static HG_LOG_DEBUG_DECL_DLOG(NA_SUBSYS_NAME) = HG_LOG_DLOG_INITIALIZER(
    NA_SUBSYS_NAME, NA_LOG_DEBUG_LESIZE);

/* Default log outlets */
HG_LOG_SUBSYS_DLOG_DECL_REGISTER(NA_SUBSYS_NAME, hg);
HG_LOG_SUBSYS_DECL_STATE_REGISTER(fatal, NA_SUBSYS_NAME, HG_LOG_ON);

/* Specific log outlets */
HG_LOG_SUBSYS_DECL_REGISTER(cls, NA_SUBSYS_NAME);
HG_LOG_SUBSYS_DECL_REGISTER(ctx, NA_SUBSYS_NAME);
HG_LOG_SUBSYS_DECL_REGISTER(op, NA_SUBSYS_NAME);
HG_LOG_SUBSYS_DECL_REGISTER(addr, NA_SUBSYS_NAME);
HG_LOG_SUBSYS_DECL_REGISTER(msg, NA_SUBSYS_NAME);
HG_LOG_SUBSYS_DECL_REGISTER(mem, NA_SUBSYS_NAME);
HG_LOG_SUBSYS_DECL_REGISTER(rma, NA_SUBSYS_NAME);
HG_LOG_SUBSYS_DECL_REGISTER(poll, NA_SUBSYS_NAME);

/* Off by default because of potientally excessive logs */
HG_LOG_SUBSYS_DECL_STATE_REGISTER(poll_loop, NA_SUBSYS_NAME, HG_LOG_OFF);
HG_LOG_SUBSYS_DECL_STATE_REGISTER(ip, NA_SUBSYS_NAME, HG_LOG_OFF);
HG_LOG_SUBSYS_DECL_STATE_REGISTER(perf, NA_SUBSYS_NAME, HG_LOG_OFF);

/*---------------------------------------------------------------------------*/
static na_return_t
na_info_parse(
    const char *info_string, char **class_name_p, struct na_info **na_info_p)
{
    char *class_name = NULL;
    struct na_info *na_info = NULL;
    char *input_string = NULL, *token = NULL, *locator = NULL;
    na_return_t ret = NA_SUCCESS;

    na_info = (struct na_info *) malloc(sizeof(struct na_info));
    NA_CHECK_SUBSYS_ERROR(cls, na_info == NULL, error, ret, NA_NOMEM,
        "Could not allocate NA info struct");
    *na_info = (struct na_info){
        .host_name = NULL, .protocol_name = NULL, .na_init_info = NULL};

    /* Copy info string and work from that */
    input_string = strdup(info_string);
    NA_CHECK_SUBSYS_ERROR(cls, input_string == NULL, error, ret, NA_NOMEM,
        "Could not duplicate host string");

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
        class_name = strdup(token);
        NA_CHECK_SUBSYS_ERROR(cls, class_name == NULL, error, ret, NA_NOMEM,
            "Could not duplicate NA info class name");

        /* Get protocol name */
        na_info->protocol_name = strdup(_locator);
        NA_CHECK_SUBSYS_ERROR(cls, na_info->protocol_name == NULL, error, ret,
            NA_NOMEM, "Could not duplicate NA info protocol name");
    } else {
        /* Get protocol name */
        na_info->protocol_name = strdup(token);
        NA_CHECK_SUBSYS_ERROR(cls, na_info->protocol_name == NULL, error, ret,
            NA_NOMEM, "Could not duplicate NA info protocol name");
    }

    /* Is the host string empty? */
    if (!locator || locator[0] == '\0')
        goto done;

    /* Format sanity check ("://") */
    NA_CHECK_SUBSYS_ERROR(fatal, strncmp(locator, "//", 2) != 0, error, ret,
        NA_PROTONOSUPPORT, "Bad address string format");

    /* :// followed by empty hostname is allowed, explicitly check here */
    if (locator[2] == '\0')
        goto done;

    na_info->host_name = strdup(locator + 2);
    NA_CHECK_SUBSYS_ERROR(cls, na_info->host_name == NULL, error, ret, NA_NOMEM,
        "Could not duplicate NA info host name");

done:
    *class_name_p = class_name;
    *na_info_p = na_info;
    free(input_string);

    return ret;

error:
    free(class_name);
    na_info_free(na_info);
    free(input_string);

    return ret;
}

/*---------------------------------------------------------------------------*/
static void
na_info_free(struct na_info *na_info)
{
    if (!na_info)
        return;

    free(na_info->protocol_name);
    free(na_info->host_name);
    free(na_info);
}

/*---------------------------------------------------------------------------*/
void
NA_Version_get(unsigned int *major, unsigned int *minor, unsigned int *patch)
{
    if (major)
        *major = NA_VERSION_MAJOR;
    if (minor)
        *minor = NA_VERSION_MINOR;
    if (patch)
        *patch = NA_VERSION_PATCH;
}

/*---------------------------------------------------------------------------*/
na_class_t *
NA_Initialize(const char *info_string, bool listen)
{
    return NA_Initialize_opt(info_string, listen, NULL);
}

/*---------------------------------------------------------------------------*/
na_class_t *
NA_Initialize_opt(const char *info_string, bool listen,
    const struct na_init_info *na_init_info)
{
    struct na_private_class *na_private_class = NULL;
    char *class_name = NULL;
    struct na_info *na_info = NULL;
    const struct na_class_ops *ops = NULL;
    na_return_t ret;
    int i;

    NA_CHECK_SUBSYS_ERROR(cls, info_string == NULL, error, ret, NA_INVALID_ARG,
        "NULL info string");

    na_private_class =
        (struct na_private_class *) calloc(1, sizeof(*na_private_class));
    NA_CHECK_SUBSYS_ERROR(cls, na_private_class == NULL, error, ret, NA_NOMEM,
        "Could not allocate class");

    ret = na_info_parse(info_string, &class_name, &na_info);
    NA_CHECK_SUBSYS_NA_ERROR(cls, error, ret, "Could not parse host string");

    na_info->na_init_info = na_init_info;
    if (na_init_info)
        na_private_class->na_class.progress_mode = na_init_info->progress_mode;

    /* Print debug info */
    NA_LOG_SUBSYS_DEBUG(cls, "Class: %s, Protocol: %s, Hostname: %s",
        class_name, na_info->protocol_name, na_info->host_name);

    for (i = 0, ops = na_class_table_g[0]; ops != NULL;
         i++, ops = na_class_table_g[i]) {
        NA_CHECK_SUBSYS_ERROR(cls, ops->class_name == NULL, error, ret,
            NA_PROTONOSUPPORT, "class name is not defined");
        NA_CHECK_SUBSYS_ERROR(cls, ops->check_protocol == NULL, error, ret,
            NA_OPNOTSUPPORTED, "check_protocol plugin callback is not defined");

        /* Skip check protocol if class name does not match */
        if ((class_name != NULL) && (strcmp(ops->class_name, class_name) != 0))
            continue;

        /* Check that protocol is supported, if no class name specified, take
         * the first plugin that supports the protocol */
        if (ops->check_protocol(na_info->protocol_name))
            break;
        else
            NA_CHECK_SUBSYS_ERROR(fatal, class_name != NULL, error, ret,
                NA_PROTONOSUPPORT,
                "Specified class name \"%s\" does not support requested "
                "protocol",
                class_name);
    }
    NA_CHECK_SUBSYS_ERROR(fatal, ops == NULL, error, ret, NA_PROTONOSUPPORT,
        "No suitable plugin found that matches %s", info_string);

    na_private_class->na_class.protocol_name = strdup(na_info->protocol_name);
    NA_CHECK_SUBSYS_ERROR(cls, na_private_class->na_class.protocol_name == NULL,
        error, ret, NA_NOMEM, "Could not duplicate protocol name");

    na_private_class->na_class.ops = ops;
    NA_CHECK_SUBSYS_ERROR(cls, na_private_class->na_class.ops == NULL, error,
        ret, NA_INVALID_ARG, "NULL NA class ops");

    NA_CHECK_SUBSYS_ERROR(cls,
        na_private_class->na_class.ops->initialize == NULL, error, ret,
        NA_OPNOTSUPPORTED, "initialize plugin callback is not defined");

    ret = na_private_class->na_class.ops->initialize(
        &na_private_class->na_class, na_info, listen);
    NA_CHECK_SUBSYS_NA_ERROR(cls, error, ret, "Could not initialize plugin");

    na_private_class->na_class.listen = listen;

    free(class_name);
    na_info_free(na_info);

    return (na_class_t *) na_private_class;

error:
    free(class_name);
    na_info_free(na_info);
    if (na_private_class) {
        free(na_private_class->na_class.protocol_name);
        free(na_private_class);
    }
    return NULL;
}

/*---------------------------------------------------------------------------*/
na_return_t
NA_Finalize(na_class_t *na_class)
{
    struct na_private_class *na_private_class =
        (struct na_private_class *) na_class;
    na_return_t ret;

    if (na_private_class == NULL)
        return NA_SUCCESS;

    NA_CHECK_SUBSYS_ERROR(cls,
        na_class->ops == NULL || na_class->ops->finalize == NULL, error, ret,
        NA_OPNOTSUPPORTED, "finalize plugin callback is not defined");

    ret = na_class->ops->finalize(&na_private_class->na_class);
    NA_CHECK_SUBSYS_NA_ERROR(cls, error, ret, "Could not finalize plugin");

    free(na_private_class->na_class.protocol_name);
    free(na_private_class);

    return NA_SUCCESS;

error:
    return ret;
}

/*---------------------------------------------------------------------------*/
void
NA_Cleanup(void)
{
    const struct na_class_ops *ops = NULL;
    int i;

    for (i = 0, ops = na_class_table_g[0]; ops != NULL;
         i++, ops = na_class_table_g[i])
        if (ops->cleanup)
            ops->cleanup();
}

/*---------------------------------------------------------------------------*/
bool
NA_Has_opt_feature(na_class_t *na_class, unsigned long flags)
{
    if (na_class && na_class->ops && na_class->ops->has_opt_feature)
        return na_class->ops->has_opt_feature(na_class, flags);
    else
        return false;
}

/*---------------------------------------------------------------------------*/
void
NA_Set_log_level(const char *level)
{
    hg_log_set_subsys_level(NA_SUBSYS_NAME_STRING, hg_log_name_to_level(level));
}

/*---------------------------------------------------------------------------*/
na_context_t *
NA_Context_create(na_class_t *na_class)
{
    return NA_Context_create_id(na_class, 0);
}

/*---------------------------------------------------------------------------*/
na_context_t *
NA_Context_create_id(na_class_t *na_class, uint8_t id)
{
    struct na_private_context *na_private_context = NULL;
    struct na_completion_queue *backfill_queue = NULL;
    bool lock_init = false;
    na_return_t ret;
    int rc;

    NA_CHECK_SUBSYS_ERROR(
        ctx, na_class == NULL, error, ret, NA_INVALID_ARG, "NULL NA class");

    na_private_context =
        (struct na_private_context *) calloc(1, sizeof(*na_private_context));
    NA_CHECK_SUBSYS_ERROR(ctx, na_private_context == NULL, error, ret, NA_NOMEM,
        "Could not allocate context");
    na_private_context->na_class = na_class;

    /* Initialize backfill queue */
    backfill_queue = &na_private_context->backfill_queue;
    HG_QUEUE_INIT(&backfill_queue->queue);
    hg_atomic_init32(&backfill_queue->count, 0);
    rc = hg_thread_spin_init(&backfill_queue->lock);
    NA_CHECK_SUBSYS_ERROR_NORET(
        ctx, rc != HG_UTIL_SUCCESS, error, "hg_thread_spin_init() failed");
    lock_init = true;

    /* Initialize completion queue */
    na_private_context->completion_queue =
        hg_atomic_queue_alloc(NA_ATOMIC_QUEUE_SIZE);
    NA_CHECK_SUBSYS_ERROR(ctx, na_private_context->completion_queue == NULL,
        error, ret, NA_NOMEM, "Could not allocate queue");

    /* Initialize plugin context */
    if (na_class->ops && na_class->ops->context_create) {
        ret = na_class->ops->context_create(
            na_class, &na_private_context->context.plugin_context, id);
        NA_CHECK_SUBSYS_NA_ERROR(
            ctx, error, ret, "Could not create plugin context");
    }

    return (na_context_t *) na_private_context;

error:
    if (na_private_context) {
        if (lock_init)
            (void) hg_thread_spin_destroy(&backfill_queue->lock);
        hg_atomic_queue_free(na_private_context->completion_queue);
        free(na_private_context);
    }
    return NULL;
}

/*---------------------------------------------------------------------------*/
na_return_t
NA_Context_destroy(na_class_t *na_class, na_context_t *context)
{
    struct na_private_context *na_private_context =
        (struct na_private_context *) context;
    struct na_completion_queue *backfill_queue = NULL;
    bool empty;
    na_return_t ret;

    NA_CHECK_SUBSYS_ERROR(
        ctx, na_class == NULL, error, ret, NA_INVALID_ARG, "NULL NA class");

    if (na_private_context == NULL)
        return NA_SUCCESS;

    /* Check that backfill completion queue is empty now */
    backfill_queue = &na_private_context->backfill_queue;
    hg_thread_spin_lock(&backfill_queue->lock);
    empty = HG_QUEUE_IS_EMPTY(&backfill_queue->queue);
    hg_thread_spin_unlock(&backfill_queue->lock);
    NA_CHECK_SUBSYS_ERROR(ctx, empty == false, error, ret, NA_BUSY,
        "Completion queue should be empty");

    /* Check that completion queue is empty now */
    empty = hg_atomic_queue_is_empty(na_private_context->completion_queue);
    NA_CHECK_SUBSYS_ERROR(ctx, empty == false, error, ret, NA_BUSY,
        "Completion queue should be empty (%u entries remaining)",
        hg_atomic_queue_count(na_private_context->completion_queue));

    /* Destroy NA plugin context */
    if (na_class->ops && na_class->ops->context_destroy) {
        ret = na_class->ops->context_destroy(
            na_class, na_private_context->context.plugin_context);
        NA_CHECK_SUBSYS_NA_ERROR(
            ctx, error, ret, "Could not destroy plugin context");
    }

    hg_atomic_queue_free(na_private_context->completion_queue);
    (void) hg_thread_spin_destroy(&backfill_queue->lock);
    free(na_private_context);

    return NA_SUCCESS;

error:
    return ret;
}

/*---------------------------------------------------------------------------*/
na_op_id_t *
NA_Op_create(na_class_t *na_class, unsigned long flags)
{
    na_op_id_t *ret;

    NA_CHECK_SUBSYS_ERROR_NORET(op, na_class == NULL, error, "NULL NA class");
    NA_CHECK_SUBSYS_ERROR_NORET(op,
        na_class->ops == NULL || na_class->ops->op_create == NULL, error,
        "op_create plugin callback is not defined");

    ret = na_class->ops->op_create(na_class, flags);
    NA_CHECK_SUBSYS_ERROR_NORET(
        op, ret == NULL, error, "Could not create OP ID");

    NA_LOG_SUBSYS_DEBUG(op, "Created new OP ID (%p)", (void *) ret);

    return ret;

error:
    return NULL;
}

/*---------------------------------------------------------------------------*/
void
NA_Op_destroy(na_class_t *na_class, na_op_id_t *op_id)
{
    NA_CHECK_SUBSYS_ERROR_NORET(op, na_class == NULL, error, "NULL NA class");

    if (op_id == NULL)
        return;

    NA_CHECK_SUBSYS_ERROR_NORET(op,
        na_class->ops == NULL || na_class->ops->op_destroy == NULL, error,
        "op_destroy plugin callback is not defined");

    NA_LOG_SUBSYS_DEBUG(op, "Destroying OP ID (%p)", (void *) op_id);

    na_class->ops->op_destroy(na_class, op_id);

error:
    return;
}

/*---------------------------------------------------------------------------*/
na_return_t
NA_Addr_lookup(na_class_t *na_class, const char *name, na_addr_t *addr_p)
{
    const char *short_name = NULL;
    na_return_t ret;

    NA_CHECK_SUBSYS_ERROR(
        addr, na_class == NULL, error, ret, NA_INVALID_ARG, "NULL NA class");
    NA_CHECK_SUBSYS_ERROR(
        addr, name == NULL, error, ret, NA_INVALID_ARG, "Lookup name is NULL");
    NA_CHECK_SUBSYS_ERROR(addr, addr_p == NULL, error, ret, NA_INVALID_ARG,
        "NULL pointer to na_addr_t");

    NA_CHECK_SUBSYS_ERROR(addr,
        na_class->ops == NULL || na_class->ops->addr_lookup == NULL, error, ret,
        NA_PROTOCOL_ERROR, "addr_lookup2 plugin callback is not defined");

    /* If NA class name was specified, we can remove the name here:
     * ie. bmi+tcp://hostname:port -> tcp://hostname:port */
    short_name = strstr(name, NA_CLASS_DELIMITER);
    short_name =
        (short_name == NULL) ? name : short_name + NA_CLASS_DELIMITER_LEN;

    NA_LOG_SUBSYS_DEBUG(addr, "Looking up addr %s", short_name);

    ret = na_class->ops->addr_lookup(na_class, short_name, addr_p);
    NA_CHECK_SUBSYS_NA_ERROR(
        addr, error, ret, "Could not lookup address for %s", short_name);

    NA_LOG_SUBSYS_DEBUG(addr, "Created new address (%p)", (void *) *addr_p);

    return NA_SUCCESS;

error:
    return ret;
}

/*---------------------------------------------------------------------------*/
void
NA_Addr_free(na_class_t *na_class, na_addr_t addr)
{
    NA_CHECK_SUBSYS_ERROR_NORET(addr, na_class == NULL, error, "NULL NA class");

    if (addr == NA_ADDR_NULL)
        return;

    NA_CHECK_SUBSYS_ERROR_NORET(addr,
        na_class->ops == NULL || na_class->ops->addr_free == NULL, error,
        "addr_free plugin callback is not defined");

    NA_LOG_SUBSYS_DEBUG(addr, "Freeing address (%p)", (void *) addr);

    na_class->ops->addr_free(na_class, addr);

error:
    return;
}

/*---------------------------------------------------------------------------*/
na_return_t
NA_Addr_set_remove(na_class_t *na_class, na_addr_t addr)
{
    na_return_t ret;

    NA_CHECK_SUBSYS_ERROR(
        addr, na_class == NULL, error, ret, NA_INVALID_ARG, "NULL NA class");
    NA_CHECK_SUBSYS_ERROR(addr, addr == NULL, error, ret, NA_INVALID_ARG,
        "NULL pointer to na_addr_t");

    if (na_class->ops && na_class->ops->addr_set_remove) {
        ret = na_class->ops->addr_set_remove(na_class, addr);
        NA_CHECK_SUBSYS_NA_ERROR(addr, error, ret,
            "Could not set remove for address (%p)", (void *) addr);
    }

    return NA_SUCCESS;

error:
    return ret;
}

/*---------------------------------------------------------------------------*/
na_return_t
NA_Addr_self(na_class_t *na_class, na_addr_t *addr_p)
{
    na_return_t ret;

    NA_CHECK_SUBSYS_ERROR(
        addr, na_class == NULL, error, ret, NA_INVALID_ARG, "NULL NA class");
    NA_CHECK_SUBSYS_ERROR(addr, addr_p == NULL, error, ret, NA_INVALID_ARG,
        "NULL pointer to na_addr_t");

    NA_CHECK_SUBSYS_ERROR(addr,
        na_class->ops == NULL || na_class->ops->addr_self == NULL, error, ret,
        NA_OPNOTSUPPORTED, "addr_self plugin callback is not defined");

    ret = na_class->ops->addr_self(na_class, addr_p);
    NA_CHECK_SUBSYS_NA_ERROR(addr, error, ret, "Could not get self address");

    NA_LOG_SUBSYS_DEBUG(
        addr, "Created new self address (%p)", (void *) *addr_p);

    return NA_SUCCESS;

error:
    return ret;
}

/*---------------------------------------------------------------------------*/
na_return_t
NA_Addr_dup(na_class_t *na_class, na_addr_t addr, na_addr_t *new_addr_p)
{
    na_return_t ret;

    NA_CHECK_SUBSYS_ERROR(
        addr, na_class == NULL, error, ret, NA_INVALID_ARG, "NULL NA class");
    NA_CHECK_SUBSYS_ERROR(
        addr, addr == NA_ADDR_NULL, error, ret, NA_INVALID_ARG, "NULL addr");
    NA_CHECK_SUBSYS_ERROR(addr, new_addr_p == NULL, error, ret, NA_INVALID_ARG,
        "NULL pointer to NA addr");

    NA_CHECK_SUBSYS_ERROR(addr,
        na_class->ops == NULL || na_class->ops->addr_dup == NULL, error, ret,
        NA_OPNOTSUPPORTED, "addr_dup plugin callback is not defined");

    ret = na_class->ops->addr_dup(na_class, addr, new_addr_p);
    NA_CHECK_SUBSYS_NA_ERROR(
        addr, error, ret, "Could not dup address (%p)", (void *) addr);

    NA_LOG_SUBSYS_DEBUG(addr, "Dup'ed address (%p) to (%p)", (void *) addr,
        (void *) *new_addr_p);

    return NA_SUCCESS;

error:
    return ret;
}

/*---------------------------------------------------------------------------*/
bool
NA_Addr_cmp(na_class_t *na_class, na_addr_t addr1, na_addr_t addr2)
{
    bool ret = false;

    NA_CHECK_SUBSYS_ERROR_NORET(addr, na_class == NULL, done, "NULL NA class");

    if (addr1 == NA_ADDR_NULL && addr2 == NA_ADDR_NULL)
        NA_GOTO_DONE(done, ret, true);

    if (addr1 == NA_ADDR_NULL || addr2 == NA_ADDR_NULL)
        NA_GOTO_DONE(done, ret, false);

    NA_CHECK_SUBSYS_ERROR_NORET(addr,
        na_class->ops == NULL || na_class->ops->addr_cmp == NULL, done,
        "addr_cmp plugin callback is not defined");

    ret = na_class->ops->addr_cmp(na_class, addr1, addr2);

    NA_LOG_SUBSYS_DEBUG(addr, "Compared addresses (%p) and (%p), result: %d",
        (void *) addr1, (void *) addr2, ret);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
na_return_t
NA_Addr_to_string(
    na_class_t *na_class, char *buf, size_t *buf_size, na_addr_t addr)
{
    char *buf_ptr = buf;
    size_t buf_size_used = 0, plugin_buf_size = 0;
    na_return_t ret;

    NA_CHECK_SUBSYS_ERROR(
        addr, na_class == NULL, error, ret, NA_INVALID_ARG, "NULL NA class");
    /* buf can be NULL */
    NA_CHECK_SUBSYS_ERROR(
        addr, buf_size == 0, error, ret, NA_INVALID_ARG, "NULL buffer size");
    NA_CHECK_SUBSYS_ERROR(
        addr, addr == NA_ADDR_NULL, error, ret, NA_INVALID_ARG, "NULL addr");

    NA_CHECK_SUBSYS_ERROR(addr,
        na_class->ops == NULL || na_class->ops->addr_to_string == NULL, error,
        ret, NA_OPNOTSUPPORTED,
        "addr_to_string plugin callback is not defined");

    /* Automatically prepend string by plugin name with class delimiter,
     * except for MPI plugin (special case, because of generated string) */
    if (strcmp(na_class->ops->class_name, "mpi") == 0) {
        buf_size_used = 0;
        plugin_buf_size = *buf_size;
    } else {
        buf_size_used =
            strlen(na_class->ops->class_name) + NA_CLASS_DELIMITER_LEN;
        if (buf_ptr) {
            NA_CHECK_SUBSYS_ERROR(addr, buf_size_used >= *buf_size, error, ret,
                NA_OVERFLOW, "Buffer size too small to copy addr");
            strcpy(buf_ptr, na_class->ops->class_name);
            strcat(buf_ptr, NA_CLASS_DELIMITER);
            buf_ptr += buf_size_used;
            plugin_buf_size = *buf_size - buf_size_used;
        } else
            plugin_buf_size = 0;
    }

    ret = na_class->ops->addr_to_string(
        na_class, buf_ptr, &plugin_buf_size, addr);
    NA_CHECK_SUBSYS_NA_ERROR(addr, error, ret,
        "Could not generate string from addr (%p)", (void *) addr);

    *buf_size = buf_size_used + plugin_buf_size;

    NA_LOG_SUBSYS_DEBUG(addr,
        "Generated string (%s) from address (%p), buf_size=%zu", buf_ptr,
        (void *) addr, *buf_size);

    return NA_SUCCESS;

error:
    return ret;
}

/*---------------------------------------------------------------------------*/
na_return_t
NA_Addr_serialize(
    na_class_t *na_class, void *buf, size_t buf_size, na_addr_t addr)
{
    na_return_t ret;

    NA_CHECK_SUBSYS_ERROR(
        addr, na_class == NULL, error, ret, NA_INVALID_ARG, "NULL NA class");
    NA_CHECK_SUBSYS_ERROR(
        addr, buf == NULL, error, ret, NA_INVALID_ARG, "NULL buffer");
    NA_CHECK_SUBSYS_ERROR(
        addr, buf_size == 0, error, ret, NA_INVALID_ARG, "NULL buffer size");
    NA_CHECK_SUBSYS_ERROR(
        addr, addr == NA_ADDR_NULL, error, ret, NA_INVALID_ARG, "NULL addr");

    NA_CHECK_SUBSYS_ERROR(addr,
        na_class->ops == NULL || na_class->ops->addr_serialize == NULL, error,
        ret, NA_OPNOTSUPPORTED,
        "addr_serialize plugin callback is not defined");

    NA_LOG_SUBSYS_DEBUG(addr, "Serializing address (%p)", (void *) addr);

    ret = na_class->ops->addr_serialize(na_class, buf, buf_size, addr);
    NA_CHECK_SUBSYS_NA_ERROR(
        addr, error, ret, "Could not serialize addr (%p)", (void *) addr);

    return NA_SUCCESS;

error:
    return ret;
}

/*---------------------------------------------------------------------------*/
na_return_t
NA_Addr_deserialize(
    na_class_t *na_class, na_addr_t *addr_p, const void *buf, size_t buf_size)
{
    na_return_t ret;

    NA_CHECK_SUBSYS_ERROR(
        addr, na_class == NULL, error, ret, NA_INVALID_ARG, "NULL NA class");
    NA_CHECK_SUBSYS_ERROR(addr, addr_p == NULL, error, ret, NA_INVALID_ARG,
        "NULL pointer to addr");
    NA_CHECK_SUBSYS_ERROR(
        addr, buf == NULL, error, ret, NA_INVALID_ARG, "NULL buffer");
    NA_CHECK_SUBSYS_ERROR(
        addr, buf_size == 0, error, ret, NA_INVALID_ARG, "NULL buffer size");

    NA_CHECK_SUBSYS_ERROR(addr,
        na_class->ops == NULL || na_class->ops->addr_deserialize == NULL, error,
        ret, NA_OPNOTSUPPORTED,
        "addr_deserialize plugin callback is not defined");

    ret = na_class->ops->addr_deserialize(na_class, addr_p, buf, buf_size);
    NA_CHECK_SUBSYS_NA_ERROR(addr, error, ret,
        "Could not deserialize addr from buffer (%p, %zu)", buf, buf_size);

    NA_LOG_SUBSYS_DEBUG(
        addr, "Deserialized into new address (%p)", (void *) *addr_p);

    return NA_SUCCESS;

error:
    return ret;
}

/*---------------------------------------------------------------------------*/
void *
NA_Msg_buf_alloc(na_class_t *na_class, size_t buf_size, unsigned long flags,
    void **plugin_data_p)
{
    void *ret = NULL;

    NA_CHECK_SUBSYS_ERROR_NORET(msg, na_class == NULL, error, "NULL NA class");
    NA_CHECK_SUBSYS_ERROR_NORET(msg, buf_size == 0, error, "NULL buffer size");
    NA_CHECK_SUBSYS_ERROR_NORET(
        msg, plugin_data_p == NULL, error, "NULL pointer to plugin data");

    if (na_class->ops && na_class->ops->msg_buf_alloc) {
        ret = na_class->ops->msg_buf_alloc(
            na_class, buf_size, flags, plugin_data_p);
        NA_CHECK_SUBSYS_ERROR_NORET(msg, ret == NULL, error,
            "Could not allocate buffer of size %zu", buf_size);
    } else {
        size_t page_size = (size_t) hg_mem_get_page_size();

        ret = hg_mem_aligned_alloc(page_size, buf_size);
        NA_CHECK_SUBSYS_ERROR_NORET(msg, ret == NULL, error,
            "Could not allocate buffer of size %zu", buf_size);
        memset(ret, 0, buf_size);
        *plugin_data_p = (void *) 1; /* Sanity check on free */
    }

    NA_LOG_SUBSYS_DEBUG(msg,
        "Allocated msg buffer (%p), size (%zu bytes), plugin data (%p)", ret,
        buf_size, *plugin_data_p);

    return ret;

error:
    return NULL;
}

/*---------------------------------------------------------------------------*/
void
NA_Msg_buf_free(na_class_t *na_class, void *buf, void *plugin_data)
{
    NA_CHECK_SUBSYS_ERROR_NORET(msg, na_class == NULL, error, "NULL NA class");

    if (buf == NULL)
        return;

    NA_LOG_SUBSYS_DEBUG(
        msg, "Freeing msg buffer (%p), plugin data (%p)", buf, plugin_data);

    if (na_class->ops && na_class->ops->msg_buf_free) {
        na_class->ops->msg_buf_free(na_class, buf, plugin_data);
    } else {
        NA_CHECK_SUBSYS_WARNING(
            msg, plugin_data != (void *) 1, "Invalid plugin data value");
        hg_mem_aligned_free(buf);
    }

error:
    return;
}

/*---------------------------------------------------------------------------*/
na_return_t
NA_Msg_init_unexpected(na_class_t *na_class, void *buf, size_t buf_size)
{
    na_return_t ret;

    NA_CHECK_SUBSYS_ERROR(
        msg, na_class == NULL, error, ret, NA_INVALID_ARG, "NULL NA class");
    NA_CHECK_SUBSYS_ERROR(
        msg, buf == NULL, error, ret, NA_INVALID_ARG, "NULL buffer");
    NA_CHECK_SUBSYS_ERROR(
        msg, buf_size == 0, error, ret, NA_INVALID_ARG, "NULL buffer size");

    /* Optional, silently returns */
    if (na_class->ops && na_class->ops->msg_init_unexpected) {
        ret = na_class->ops->msg_init_unexpected(na_class, buf, buf_size);
        NA_CHECK_SUBSYS_NA_ERROR(
            msg, error, ret, "Could not init unexpected buffer (%p)", buf);

        NA_LOG_SUBSYS_DEBUG(
            msg, "Init unexpected buf (%p), size (%zu)", buf, buf_size);
    }

    return NA_SUCCESS;

error:
    return ret;
}

/*---------------------------------------------------------------------------*/
na_return_t
NA_Msg_init_expected(na_class_t *na_class, void *buf, size_t buf_size)
{
    na_return_t ret;

    NA_CHECK_SUBSYS_ERROR(
        msg, na_class == NULL, error, ret, NA_INVALID_ARG, "NULL NA class");
    NA_CHECK_SUBSYS_ERROR(
        msg, buf == NULL, error, ret, NA_INVALID_ARG, "NULL buffer");
    NA_CHECK_SUBSYS_ERROR(
        msg, buf_size == 0, error, ret, NA_INVALID_ARG, "NULL buffer size");

    /* Optional, silently returns */
    if (na_class->ops && na_class->ops->msg_init_expected) {
        ret = na_class->ops->msg_init_expected(na_class, buf, buf_size);
        NA_CHECK_SUBSYS_NA_ERROR(
            msg, error, ret, "Could not init expected buffer (%p)", buf);

        NA_LOG_SUBSYS_DEBUG(
            msg, "Init expected buf (%p), size (%zu)", buf, buf_size);
    }

    return NA_SUCCESS;

error:
    return ret;
}

/*---------------------------------------------------------------------------*/
na_return_t
NA_Mem_handle_create(na_class_t *na_class, void *buf, size_t buf_size,
    unsigned long flags, na_mem_handle_t *mem_handle_p)
{
    na_return_t ret;

    NA_CHECK_SUBSYS_ERROR(
        mem, na_class == NULL, error, ret, NA_INVALID_ARG, "NULL NA class");
    NA_CHECK_SUBSYS_ERROR(
        mem, buf == NULL, error, ret, NA_INVALID_ARG, "NULL buffer");
    NA_CHECK_SUBSYS_ERROR(
        mem, buf_size == 0, error, ret, NA_INVALID_ARG, "NULL buffer size");

    NA_CHECK_SUBSYS_ERROR(mem,
        na_class->ops == NULL || na_class->ops->mem_handle_create == NULL,
        error, ret, NA_OPNOTSUPPORTED,
        "mem_handle_create plugin callback is not defined");

    ret = na_class->ops->mem_handle_create(
        na_class, buf, buf_size, flags, mem_handle_p);
    NA_CHECK_SUBSYS_NA_ERROR(mem, error, ret, "Could not create memory handle");

    NA_LOG_SUBSYS_DEBUG(mem,
        "Created new mem handle (%p), buf (%p), buf_size (%zu), flags (%lu)",
        (void *) *mem_handle_p, buf, buf_size, flags);

    return NA_SUCCESS;

error:
    return ret;
}

/*---------------------------------------------------------------------------*/
na_return_t
NA_Mem_handle_create_segments(na_class_t *na_class, struct na_segment *segments,
    size_t segment_count, unsigned long flags, na_mem_handle_t *mem_handle_p)
{
    na_return_t ret;

    NA_CHECK_SUBSYS_ERROR(
        mem, na_class == NULL, error, ret, NA_INVALID_ARG, "NULL NA class");
    NA_CHECK_SUBSYS_ERROR(mem, segments == NULL, error, ret, NA_INVALID_ARG,
        "NULL pointer to segments");
    NA_CHECK_SUBSYS_ERROR(mem, segment_count == 0, error, ret, NA_INVALID_ARG,
        "NULL segment count");

    NA_CHECK_SUBSYS_ERROR(mem,
        na_class->ops == NULL ||
            na_class->ops->mem_handle_create_segments == NULL,
        error, ret, NA_OPNOTSUPPORTED,
        "mem_handle_create_segments plugin callback is not defined");

    ret = na_class->ops->mem_handle_create_segments(
        na_class, segments, segment_count, flags, mem_handle_p);
    NA_CHECK_SUBSYS_NA_ERROR(mem, error, ret, "Could not create memory handle");

    NA_LOG_SUBSYS_DEBUG(mem,
        "Created new mem handle (%p) with %zu segments, flags (%lu)",
        (void *) *mem_handle_p, segment_count, flags);

    return NA_SUCCESS;

error:
    return ret;
}

/*---------------------------------------------------------------------------*/
void
NA_Mem_handle_free(na_class_t *na_class, na_mem_handle_t mem_handle)
{
    NA_CHECK_SUBSYS_ERROR_NORET(mem, na_class == NULL, error, "NULL NA class");

    if (mem_handle == NA_MEM_HANDLE_NULL)
        return;

    NA_CHECK_SUBSYS_ERROR_NORET(mem,
        na_class->ops == NULL || na_class->ops->mem_handle_free == NULL, error,
        "mem_handle_free plugin callback is not defined");

    NA_LOG_SUBSYS_DEBUG(mem, "Freeing mem handle (%p)", (void *) mem_handle);

    na_class->ops->mem_handle_free(na_class, mem_handle);

error:
    return;
}

/*---------------------------------------------------------------------------*/
na_return_t
NA_Mem_register(na_class_t *na_class, na_mem_handle_t mem_handle,
    enum na_mem_type mem_type, uint64_t device)
{
    na_return_t ret;

    NA_CHECK_SUBSYS_ERROR(
        mem, na_class == NULL, error, ret, NA_INVALID_ARG, "NULL NA class");
    NA_CHECK_SUBSYS_ERROR(mem, mem_handle == NA_MEM_HANDLE_NULL, error, ret,
        NA_INVALID_ARG, "NULL memory handle");

    /* Optional, silently returns */
    if (na_class->ops && na_class->ops->mem_register) {
        ret =
            na_class->ops->mem_register(na_class, mem_handle, mem_type, device);
        NA_CHECK_SUBSYS_NA_ERROR(mem, error, ret,
            "Could not register mem handle (%p)", (void *) mem_handle);

        NA_LOG_SUBSYS_DEBUG(
            mem, "Registered mem handle (%p)", (void *) mem_handle);
    }

    return NA_SUCCESS;

error:
    return ret;
}

/*---------------------------------------------------------------------------*/
na_return_t
NA_Mem_deregister(na_class_t *na_class, na_mem_handle_t mem_handle)
{
    na_return_t ret;

    NA_CHECK_SUBSYS_ERROR(
        mem, na_class == NULL, error, ret, NA_INVALID_ARG, "NULL NA class");
    NA_CHECK_SUBSYS_ERROR(mem, mem_handle == NA_MEM_HANDLE_NULL, error, ret,
        NA_INVALID_ARG, "NULL memory handle");

    /* Optional, silently returns */
    if (na_class->ops && na_class->ops->mem_deregister) {
        NA_LOG_SUBSYS_DEBUG(
            mem, "Deregistering mem handle (%p)", (void *) mem_handle);

        ret = na_class->ops->mem_deregister(na_class, mem_handle);
        NA_CHECK_SUBSYS_NA_ERROR(mem, error, ret,
            "Could not deregister mem handle (%p)", (void *) mem_handle);
    }

    return NA_SUCCESS;

error:
    return ret;
}

/*---------------------------------------------------------------------------*/
na_return_t
NA_Mem_handle_serialize(na_class_t *na_class, void *buf, size_t buf_size,
    na_mem_handle_t mem_handle)
{
    na_return_t ret;

    NA_CHECK_SUBSYS_ERROR(
        mem, na_class == NULL, error, ret, NA_INVALID_ARG, "NULL NA class");
    NA_CHECK_SUBSYS_ERROR(
        mem, buf == NULL, error, ret, NA_INVALID_ARG, "NULL buffer");
    NA_CHECK_SUBSYS_ERROR(
        mem, buf_size == 0, error, ret, NA_INVALID_ARG, "NULL buffer size");
    NA_CHECK_SUBSYS_ERROR(mem, mem_handle == NA_MEM_HANDLE_NULL, error, ret,
        NA_INVALID_ARG, "NULL memory handle");

    NA_CHECK_SUBSYS_ERROR(mem,
        na_class->ops == NULL || na_class->ops->mem_handle_serialize == NULL,
        error, ret, NA_OPNOTSUPPORTED,
        "mem_handle_serialize plugin callback is not defined");

    NA_LOG_SUBSYS_DEBUG(
        mem, "Serializing mem handle (%p)", (void *) mem_handle);

    ret = na_class->ops->mem_handle_serialize(
        na_class, buf, buf_size, mem_handle);
    NA_CHECK_SUBSYS_NA_ERROR(mem, error, ret,
        "Could not serialize mem handle (%p)", (void *) mem_handle);

    return NA_SUCCESS;

error:
    return ret;
}

/*---------------------------------------------------------------------------*/
na_return_t
NA_Mem_handle_deserialize(na_class_t *na_class, na_mem_handle_t *mem_handle,
    const void *buf, size_t buf_size)
{
    na_return_t ret;

    NA_CHECK_SUBSYS_ERROR(
        mem, na_class == NULL, error, ret, NA_INVALID_ARG, "NULL NA class");
    NA_CHECK_SUBSYS_ERROR(mem, mem_handle == NULL, error, ret, NA_INVALID_ARG,
        "NULL pointer to memory handle");
    NA_CHECK_SUBSYS_ERROR(
        mem, buf == NULL, error, ret, NA_INVALID_ARG, "NULL buffer");
    NA_CHECK_SUBSYS_ERROR(
        mem, buf_size == 0, error, ret, NA_INVALID_ARG, "NULL buffer size");

    NA_CHECK_SUBSYS_ERROR(mem,
        na_class->ops == NULL || na_class->ops->mem_handle_deserialize == NULL,
        error, ret, NA_OPNOTSUPPORTED,
        "mem_handle_deserialize plugin callback is not defined");

    ret = na_class->ops->mem_handle_deserialize(
        na_class, mem_handle, buf, buf_size);
    NA_CHECK_SUBSYS_NA_ERROR(mem, error, ret,
        "Could not deserialize mem handle from buffer (%p, %zu)", buf,
        buf_size);

    NA_LOG_SUBSYS_DEBUG(
        mem, "Deserialized into mem handle (%p)", (void *) *mem_handle);

error:
    return ret;
}

/*---------------------------------------------------------------------------*/
bool
NA_Poll_try_wait(na_class_t *na_class, na_context_t *context)
{
    struct na_private_context *na_private_context =
        (struct na_private_context *) context;

    NA_CHECK_SUBSYS_ERROR_NORET(poll, na_class == NULL, error, "NULL NA class");
    NA_CHECK_SUBSYS_ERROR_NORET(poll, context == NULL, error, "NULL context");

    /* Do not try to wait if NA_NO_BLOCK is set */
    if (na_class->progress_mode & NA_NO_BLOCK)
        return false;

    /* Something is in one of the completion queues */
    if (!hg_atomic_queue_is_empty(na_private_context->completion_queue) ||
        hg_atomic_get32(&na_private_context->backfill_queue.count) > 0)
        return false;

    /* Check plugin try wait */
    if (na_class->ops && na_class->ops->na_poll_try_wait)
        return na_class->ops->na_poll_try_wait(na_class, context);

    NA_LOG_SUBSYS_DEBUG(
        poll_loop, "Safe to wait on context (%p)", (void *) context);

    return true;

error:
    return false;
}

/*---------------------------------------------------------------------------*/
na_return_t
NA_Progress(
    na_class_t *na_class, na_context_t *context, unsigned int timeout_ms)
{
    struct na_private_context *na_private_context =
        (struct na_private_context *) context;

    NA_LOG_SUBSYS_DEBUG(poll_loop,
        "Entering progress on context (%p) for %u ms", (void *) context,
        timeout_ms);

    /* Something is in one of the completion queues */
    if (!hg_atomic_queue_is_empty(na_private_context->completion_queue) ||
        hg_atomic_get32(&na_private_context->backfill_queue.count) > 0) {
        return NA_SUCCESS; /* Progressed */
    }

    /* Try to make progress for remaining time */
    return na_class->ops->progress(na_class, context, timeout_ms);
}

/*---------------------------------------------------------------------------*/
na_return_t
NA_Trigger(
    na_context_t *context, unsigned int max_count, unsigned int *actual_count)
{
    struct na_private_context *na_private_context =
        (struct na_private_context *) context;
    unsigned int count = 0;
    na_return_t ret;

    NA_CHECK_SUBSYS_ERROR(
        op, context == NULL, error, ret, NA_INVALID_ARG, "NULL context");

    while (count < max_count) {
        struct na_cb_completion_data *completion_data_p = NULL;
        struct na_cb_completion_data completion_data;

        completion_data_p =
            hg_atomic_queue_pop_mc(na_private_context->completion_queue);
        if (completion_data_p == NULL) { /* Check backfill queue */
            struct na_completion_queue *backfill_queue =
                &na_private_context->backfill_queue;

            if (hg_atomic_get32(&backfill_queue->count)) {
                hg_thread_spin_lock(&backfill_queue->lock);
                completion_data_p = HG_QUEUE_FIRST(&backfill_queue->queue);
                HG_QUEUE_POP_HEAD(&backfill_queue->queue, entry);
                hg_atomic_decr32(&backfill_queue->count);
                hg_thread_spin_unlock(&backfill_queue->lock);
                if (completion_data_p == NULL)
                    continue; /* Give another chance to grab it */
            } else
                break; /* Completion queues are empty */
        }

        /* Completion data should be valid */
        NA_CHECK_SUBSYS_ERROR(op, completion_data_p == NULL, error, ret,
            NA_INVALID_ARG, "NULL completion data");
        completion_data = *completion_data_p;

        /* Execute plugin callback (free resources etc) first since actual
         * callback will notify user that operation has completed.
         * NB. If the NA operation ID is reused by the plugin for another
         * operation we must be careful that resources are released BEFORE that
         * operation ID gets re-used.
         */
        if (completion_data.plugin_callback)
            completion_data.plugin_callback(
                completion_data.plugin_callback_args);

        /* Execute callback */
        if (completion_data.callback)
            completion_data.callback(&completion_data.callback_info);

        count++;
    }

    if (actual_count)
        *actual_count = count;

    return NA_SUCCESS;

error:
    return ret;
}

/*---------------------------------------------------------------------------*/
na_return_t
NA_Cancel(na_class_t *na_class, na_context_t *context, na_op_id_t *op_id)
{
    na_return_t ret;

    NA_CHECK_SUBSYS_ERROR(
        op, na_class == NULL, error, ret, NA_INVALID_ARG, "NULL NA class");
    NA_CHECK_SUBSYS_ERROR(
        op, context == NULL, error, ret, NA_INVALID_ARG, "NULL context");
    NA_CHECK_SUBSYS_ERROR(
        op, op_id == NULL, error, ret, NA_INVALID_ARG, "NULL operation ID");

    NA_CHECK_SUBSYS_ERROR(op,
        na_class->ops == NULL || na_class->ops->cancel == NULL, error, ret,
        NA_OPNOTSUPPORTED, "cancel plugin callback is not defined");

    NA_LOG_SUBSYS_DEBUG(op, "Canceling op ID (%p)", (void *) op_id);

    ret = na_class->ops->cancel(na_class, context, op_id);
    NA_CHECK_SUBSYS_NA_ERROR(
        op, error, ret, "Could not cancel op ID (%p)", (void *) op_id);

    return NA_SUCCESS;

error:
    return ret;
}

/*---------------------------------------------------------------------------*/
const char *
NA_Error_to_string(na_return_t errnum)
{
    return na_return_name_g[errnum];
}

/*---------------------------------------------------------------------------*/
const char *
na_cb_type_to_string(na_cb_type_t cb_type)
{
    return na_cb_type_name_g[cb_type];
}

/*---------------------------------------------------------------------------*/
void
na_cb_completion_add(
    na_context_t *context, struct na_cb_completion_data *na_cb_completion_data)
{
    struct na_private_context *na_private_context =
        (struct na_private_context *) context;
    struct na_completion_queue *backfill_queue =
        &na_private_context->backfill_queue;

    if (hg_atomic_queue_push(na_private_context->completion_queue,
            na_cb_completion_data) != HG_UTIL_SUCCESS) {
        NA_LOG_SUBSYS_WARNING(perf, "Atomic completion queue is full, pushing "
                                    "completion data to backfill queue");

        /* Queue is full */
        hg_thread_spin_lock(&backfill_queue->lock);
        HG_QUEUE_PUSH_TAIL(
            &backfill_queue->queue, na_cb_completion_data, entry);
        hg_atomic_incr32(&backfill_queue->count);
        hg_thread_spin_unlock(&backfill_queue->lock);
    }
}
