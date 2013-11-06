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

#include <assert.h>
#include <stdlib.h>
#include <string.h>

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

/* Convert value to string */
#define NA_ERROR_STRING_MACRO(def, value, string) \
  if (value == def) string = #def

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
        ret = NA_FAIL;
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
            ret = NA_FAIL;
            goto done;
        }

        strcpy(na_buffer->na_class, _locator);
    } else {
        na_buffer->na_class = NULL;
    }

    na_buffer->na_protocol = (char*) malloc(strlen(token) + 1);
    if (!na_buffer->na_protocol) {
        NA_LOG_ERROR("Could not allocate na_protocol");
        ret = NA_FAIL;
        goto done;
    }

    strcpy(na_buffer->na_protocol, token);

    token = locator + 2;
    token = strtok_r(token, ":", &locator);

    na_buffer->na_host = (char*) malloc(strlen(token) + 1);
    if (!na_buffer->na_host) {
        NA_LOG_ERROR("Could not allocate na_host");
        ret = NA_FAIL;
        goto done;
    }

    strcpy(na_buffer->na_host, token);

    na_buffer->na_port = atoi(locator);

    na_host_string_len = strlen(na_buffer->na_protocol) +
            strlen("://") +
            strlen(na_buffer->na_host) +
            strlen(":") +
            strlen(locator) +
            1;

    na_buffer->na_host_string = (char*) malloc(na_host_string_len);
    if (!na_buffer->na_host_string) {
        NA_LOG_ERROR("Could not allocate na_host_string");
        ret = NA_FAIL;
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
    na_class_t *network_class = NULL;
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

    network_class = na_class_methods[class_index]->initialize(na_buffer, listen);

    NA_free_host_buffer(na_buffer);

    return network_class;
}

/*---------------------------------------------------------------------------*/
na_return_t
NA_Finalize(na_class_t *network_class)
{
    assert(network_class);
    return network_class->finalize();
}

/*---------------------------------------------------------------------------*/
na_return_t
NA_Addr_lookup(na_class_t *network_class,
        na_cb_t callback, void *arg,
        const char *name, na_op_id_t *op_id)
{
    assert(network_class);
    return network_class->addr_lookup(callback, arg, name, op_id);
}

/*---------------------------------------------------------------------------*/
na_return_t
NA_Addr_free(na_class_t *network_class, na_addr_t addr)
{
    assert(network_class);
    return network_class->addr_free(addr);
}

/*---------------------------------------------------------------------------*/
na_return_t
NA_Addr_to_string(na_class_t *network_class, char *buf, na_size_t buf_size,
        na_addr_t addr)
{
    na_return_t ret = NA_SUCCESS;

    assert(network_class);

    if (addr == NA_ADDR_NULL) {
        NA_LOG_ERROR("NULL addr");
        ret = NA_FAIL;
        return ret;
    }

    ret = network_class->addr_to_string(buf, buf_size, addr);

    return ret;
}

/*---------------------------------------------------------------------------*/
na_size_t
NA_Msg_get_max_expected_size(na_class_t *network_class)
{
    assert(network_class);
    return network_class->msg_get_max_expected_size();
}

/*---------------------------------------------------------------------------*/
na_size_t
NA_Msg_get_max_unexpected_size(na_class_t *network_class)
{
    assert(network_class);
    return network_class->msg_get_max_unexpected_size();
}

/*---------------------------------------------------------------------------*/
na_tag_t
NA_Msg_get_max_tag(na_class_t *network_class)
{
    assert(network_class);
    return network_class->msg_get_max_tag();
}

/*---------------------------------------------------------------------------*/
na_return_t
NA_Msg_send_unexpected(na_class_t *network_class,
        na_cb_t callback, void *arg,
        const void *buf, na_size_t buf_size, na_addr_t dest, na_tag_t tag,
        na_op_id_t *op_id)
{
    assert(network_class);
    return network_class->msg_send_unexpected(callback, arg,
            buf, buf_size, dest, tag, op_id);
}

/*---------------------------------------------------------------------------*/
na_return_t
NA_Msg_recv_unexpected(na_class_t *network_class,
        na_cb_t callback, void *arg,
        void *buf, na_size_t buf_size, na_op_id_t *op_id)
{
    assert(network_class);
    return network_class->msg_recv_unexpected(callback, arg,
            buf, buf_size, op_id);
}

/*---------------------------------------------------------------------------*/
na_return_t
NA_Msg_send_expected(na_class_t *network_class,
        na_cb_t callback, void *arg,
        const void *buf, na_size_t buf_size, na_addr_t dest, na_tag_t tag,
        na_op_id_t *op_id)
{
    assert(network_class);
    return network_class->msg_send_expected(callback, arg,
            buf, buf_size, dest, tag, op_id);
}

/*---------------------------------------------------------------------------*/
na_return_t
NA_Msg_recv_expected(na_class_t *network_class,
        na_cb_t callback, void *arg,
        void *buf, na_size_t buf_size, na_addr_t source, na_tag_t tag,
        na_op_id_t *op_id)
{
    assert(network_class);
    return network_class->msg_recv_expected(callback, arg,
            buf, buf_size, source, tag, op_id);
}

/*---------------------------------------------------------------------------*/
na_return_t
NA_Mem_handle_create(na_class_t *network_class, void *buf, na_size_t buf_size,
        unsigned long flags, na_mem_handle_t *mem_handle)
{
    assert(network_class);
    return network_class->mem_handle_create(buf, buf_size, flags, mem_handle);
}

/*---------------------------------------------------------------------------*/
na_return_t
NA_Mem_handle_create_segments(na_class_t *network_class,
        struct na_segment *segments, na_size_t segment_count,
        unsigned long flags, na_mem_handle_t *mem_handle)
{
    assert(network_class);
    return network_class->mem_handle_create_segments(segments, segment_count,
            flags, mem_handle);
}

/*---------------------------------------------------------------------------*/
na_return_t
NA_Mem_handle_free(na_class_t *network_class, na_mem_handle_t mem_handle)
{
    assert(network_class);
    return network_class->mem_handle_free(mem_handle);
}

/*---------------------------------------------------------------------------*/
na_return_t
NA_Mem_register(na_class_t *network_class, na_mem_handle_t mem_handle)
{
    assert(network_class);
    return network_class->mem_register(mem_handle);
}

/*---------------------------------------------------------------------------*/
int
NA_Mem_deregister(na_class_t *network_class, na_mem_handle_t mem_handle)
{
    assert(network_class);
    return network_class->mem_deregister(mem_handle);
}

/*---------------------------------------------------------------------------*/
na_size_t
NA_Mem_handle_get_serialize_size(na_class_t *network_class,
        na_mem_handle_t mem_handle)
{
    assert(network_class);
    return network_class->mem_handle_get_serialize_size(mem_handle);
}

/*---------------------------------------------------------------------------*/
na_return_t
NA_Mem_handle_serialize(na_class_t *network_class,
        void *buf, na_size_t buf_size, na_mem_handle_t mem_handle)
{
    assert(network_class);
    return network_class->mem_handle_serialize(buf, buf_size, mem_handle);
}

/*---------------------------------------------------------------------------*/
na_return_t
NA_Mem_handle_deserialize(na_class_t *network_class,
        na_mem_handle_t *mem_handle, const void *buf, na_size_t buf_size)
{
    assert(network_class);
    return network_class->mem_handle_deserialize(mem_handle, buf, buf_size);
}

/*---------------------------------------------------------------------------*/
na_return_t
NA_Put(na_class_t *network_class,
        na_cb_t callback, void *arg,
        na_mem_handle_t local_mem_handle, na_offset_t local_offset,
        na_mem_handle_t remote_mem_handle, na_offset_t remote_offset,
        na_size_t data_size, na_addr_t remote_addr,
        na_op_id_t *op_id)
{
    assert(network_class);
    return network_class->put(callback, arg,
            local_mem_handle, local_offset, remote_mem_handle, remote_offset,
            data_size, remote_addr, op_id);
}

/*---------------------------------------------------------------------------*/
na_return_t
NA_Get(na_class_t *network_class,
        na_cb_t callback, void *arg,
        na_mem_handle_t local_mem_handle, na_offset_t local_offset,
        na_mem_handle_t remote_mem_handle, na_offset_t remote_offset,
        na_size_t data_size, na_addr_t remote_addr,
        na_op_id_t *op_id)
{
    assert(network_class);
    return network_class->get(callback, arg,
            local_mem_handle, local_offset, remote_mem_handle, remote_offset,
            data_size, remote_addr, op_id);
}

/*---------------------------------------------------------------------------*/
na_return_t
NA_Progress(na_class_t *network_class, unsigned int timeout)
{
    /* TODO per plugin --> push callback to the queue when something completes
     * wake up everyone waiting in the trigger in main na and not in pluggin
     * to avoid duplicating code */
    assert(network_class);
    return network_class->progress(timeout);
}

/*---------------------------------------------------------------------------*/
na_return_t
NA_Trigger(unsigned int NA_UNUSED timeout, unsigned int NA_UNUSED max_count, int NA_UNUSED *actual_count)
{
    na_return_t ret = NA_SUCCESS;

    /* TODO locking with condition variable */
    return ret;
}

/*---------------------------------------------------------------------------*/
na_return_t
NA_Cancel(na_op_id_t NA_UNUSED op_id)
{
    na_return_t ret = NA_SUCCESS;

    return ret;
}

/*---------------------------------------------------------------------------*/
const char *
NA_Error_to_string(na_return_t errnum)
{
    const char *na_error_string = "UNDEFINED/UNRECOGNIZED NA ERROR";

    NA_ERROR_STRING_MACRO(NA_FAIL, errnum, na_error_string);
    NA_ERROR_STRING_MACRO(NA_SUCCESS, errnum, na_error_string);
    NA_ERROR_STRING_MACRO(NA_MEMORY_ERROR, errnum, na_error_string);

    return na_error_string;
}
