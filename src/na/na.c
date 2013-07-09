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

#include <assert.h>

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
NA_Addr_free(na_class_t *network_class, na_addr_t addr)
{
    assert(network_class);
    return network_class->addr_free(addr);
}

/*---------------------------------------------------------------------------*/
na_size_t
NA_Msg_get_maximum_size(na_class_t *network_class)
{
    assert(network_class);
    return network_class->msg_get_maximum_size();
}

/*---------------------------------------------------------------------------*/
na_tag_t
NA_Msg_get_maximum_tag(na_class_t *network_class)
{
    assert(network_class);
    return network_class->msg_get_maximum_tag();
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
