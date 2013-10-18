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
#ifdef NA_HAS_SSM
#include "na_ssm.h"
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
static int
NA_parse_host_string(const char *host_string,
        struct na_host_buffer **in_na_buffer)
{
    char *input_string               = NULL;
    char *token                      = NULL;
    char *locator                    = NULL;
    struct na_host_buffer *na_buffer = *in_na_buffer;
    size_t na_host_string_len;
    int ret = NA_SUCCESS;

    input_string = (char*) malloc(strlen(host_string) + 1);
    if (!input_string) {
        NA_ERROR_DEFAULT("Could not allocate string");
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
            NA_ERROR_DEFAULT("Could not allocate na_class");
            ret = NA_FAIL;
            goto done;
        }

        strcpy(na_buffer->na_class, _locator);
    } else {
        na_buffer->na_class = NULL;
    }

    na_buffer->na_protocol = (char*) malloc(strlen(token) + 1);
    if (!na_buffer->na_protocol) {
        NA_ERROR_DEFAULT("Could not allocate na_protocol");
        ret = NA_FAIL;
        goto done;
    }

    strcpy(na_buffer->na_protocol, token);

    token = locator + 2;
    token = strtok_r(token, ":", &locator);

    na_buffer->na_host = (char*) malloc(strlen(token) + 1);
    if (!na_buffer->na_host) {
        NA_ERROR_DEFAULT("Could not allocate na_host");
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
        NA_ERROR_DEFAULT("Could not allocate na_host_string");
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
        NA_ERROR_DEFAULT("Could not allocate na_buffer");
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
int
NA_Finalize(na_class_t *network_class)
{
    assert(network_class);
    return network_class->finalize();
}

/*---------------------------------------------------------------------------*/
int
NA_Addr_lookup(na_class_t *network_class, const char *name, na_addr_t *addr)
{
    assert(network_class);
    return network_class->addr_lookup(name, addr);
}

/*---------------------------------------------------------------------------*/
int
NA_Addr_self(na_class_t *network_class, na_addr_t *addr)
{
    assert(network_class);
    return network_class->addr_self(addr);
}

/*---------------------------------------------------------------------------*/
int
NA_Addr_free(na_class_t *network_class, na_addr_t addr)
{
    assert(network_class);
    return network_class->addr_free(addr);
}

/*---------------------------------------------------------------------------*/
const char *
NA_Addr_to_string(na_class_t *network_class, na_addr_t addr)
{
    assert(network_class);
    return network_class->addr_to_string(addr);
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
int
NA_Msg_send_unexpected(na_class_t *network_class,
        const void *buf, na_size_t buf_size, na_addr_t dest,
        na_tag_t tag, na_request_t *request, void *op_arg)
{
    assert(network_class);
    return network_class->msg_send_unexpected(
            buf, buf_size, dest, tag, request,op_arg);
}

/*---------------------------------------------------------------------------*/
int
NA_Msg_recv_unexpected(na_class_t *network_class,
        void *buf, na_size_t buf_size, na_size_t *actual_buf_size,
        na_addr_t *source, na_tag_t *tag, na_request_t *request, void *op_arg)
{
    assert(network_class);
    return network_class->msg_recv_unexpected(
            buf, buf_size, actual_buf_size, source, tag, request, op_arg);
}

/*---------------------------------------------------------------------------*/
int
NA_Msg_send(na_class_t *network_class,
        const void *buf, na_size_t buf_size, na_addr_t dest,
        na_tag_t tag, na_request_t *request, void *op_arg)
{
    assert(network_class);
    return network_class->msg_send(buf, buf_size, dest, tag, request, op_arg);
}

/*---------------------------------------------------------------------------*/
int
NA_Msg_recv(na_class_t *network_class,
        void *buf, na_size_t buf_size, na_addr_t source,
        na_tag_t tag, na_request_t *request, void *op_arg)
{
    assert(network_class);
    return network_class->msg_recv(buf, buf_size, source, tag, request, op_arg);
}

/*---------------------------------------------------------------------------*/
int
NA_Mem_register(na_class_t *network_class,
        void *buf, na_size_t buf_size, unsigned long flags,
        na_mem_handle_t *mem_handle)
{
    assert(network_class);
    return network_class->mem_register(buf, buf_size, flags, mem_handle);
}

/*---------------------------------------------------------------------------*/
int
NA_Mem_register_segments(na_class_t *network_class,
        na_segment_t *segments, na_size_t segment_count, unsigned long flags,
        na_mem_handle_t *mem_handle)
{
    assert(network_class);
    return network_class->mem_register_segments(segments, segment_count, flags,
            mem_handle);
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
int
NA_Mem_handle_serialize(na_class_t *network_class,
        void *buf, na_size_t buf_size, na_mem_handle_t mem_handle)
{
    assert(network_class);
    return network_class->mem_handle_serialize(buf, buf_size, mem_handle);
}

/*---------------------------------------------------------------------------*/
int
NA_Mem_handle_deserialize(na_class_t *network_class,
        na_mem_handle_t *mem_handle, const void *buf, na_size_t buf_size)
{
    assert(network_class);
    return network_class->mem_handle_deserialize(mem_handle, buf, buf_size);
}

/*---------------------------------------------------------------------------*/
int
NA_Mem_handle_free(na_class_t *network_class, na_mem_handle_t mem_handle)
{
    assert(network_class);
    return network_class->mem_handle_free(mem_handle);
}

/*---------------------------------------------------------------------------*/
int
NA_Put(na_class_t *network_class,
        na_mem_handle_t local_mem_handle, na_offset_t local_offset,
        na_mem_handle_t remote_mem_handle, na_offset_t remote_offset,
        na_size_t length, na_addr_t remote_addr, na_request_t *request)
{
    assert(network_class);
    return network_class->put(local_mem_handle, local_offset,
            remote_mem_handle, remote_offset,
            length, remote_addr, request);
}

/*---------------------------------------------------------------------------*/
int
NA_Get(na_class_t *network_class,
        na_mem_handle_t local_mem_handle, na_offset_t local_offset,
        na_mem_handle_t remote_mem_handle, na_offset_t remote_offset,
        na_size_t length, na_addr_t remote_addr, na_request_t *request)
{
    assert(network_class);
    return network_class->get(local_mem_handle, local_offset,
            remote_mem_handle, remote_offset,
            length, remote_addr, request);
}

/*---------------------------------------------------------------------------*/
int
NA_Wait(na_class_t *network_class,
        na_request_t request, unsigned int timeout, na_status_t *status)
{
    assert(network_class);
    return network_class->wait(request, timeout, status);
}

/*---------------------------------------------------------------------------*/
int
NA_Progress(na_class_t *network_class,
        unsigned int timeout, na_status_t *status)
{
    assert(network_class);
    return network_class->progress(timeout, status);
}

/*---------------------------------------------------------------------------*/
int
NA_Request_free(na_class_t *network_class, na_request_t request)
{
    assert(network_class);
    return network_class->request_free(request);
}
