/*
 * network_abstraction.c
 *
 *  Created on: Nov 5, 2012
 *      Author: soumagne
 */

#include "network_abstraction.h"

#include <assert.h>

static network_class_t *na_g = NULL;

void na_register(network_class_t *network_class)
{
    assert(na_g == NULL);
    na_g = network_class;
}

void na_finalize(void)
{
    assert(na_g);
    na_g->finalize();
    na_g = NULL;
}

na_size_t na_get_unexpected_size(void)
{
    assert(na_g);
    return na_g->get_unexpected_size();
}

int na_lookup(const char *name, na_addr_t *target)
{
    assert(na_g);
    return na_g->lookup(name, target);
}

int na_free(na_addr_t target)
{
    assert(na_g);
    return na_g->free(target);
}

int na_send_unexpected(const void *buf, na_size_t buf_len, na_addr_t dest,
        na_tag_t tag, na_request_t *request, void *op_arg)
{
    assert(na_g);
    return na_g->send_unexpected(buf, buf_len, dest, tag, request, op_arg);
}

int na_recv_unexpected(void *buf, na_size_t *buf_len, na_addr_t *source,
        na_tag_t *tag, na_request_t *request, void *op_arg)
{
    assert(na_g);
    return na_g->recv_unexpected(buf, buf_len, source, tag, request, op_arg);
}

int na_send(const void *buf, na_size_t buf_len, na_addr_t dest,
        na_tag_t tag, na_request_t *request, void *op_arg)
{
    assert(na_g);
    return na_g->send(buf, buf_len, dest, tag, request, op_arg);
}

int na_recv(void *buf, na_size_t buf_len, na_addr_t source,
        na_tag_t tag, na_request_t *request, void *op_arg)
{
    assert(na_g);
    return na_g->recv(buf, buf_len, source, tag, request, op_arg);
}

int na_mem_register(void *buf, na_size_t buf_len, unsigned long flags, na_mem_handle_t *mem_handle)
{
    assert(na_g);
    return na_g->mem_register(buf, buf_len, flags, mem_handle);
}

int na_mem_deregister(na_mem_handle_t mem_handle)
{
    assert(na_g);
    return na_g->mem_deregister(mem_handle);
}

int na_mem_handle_serialize(void *buf, na_size_t buf_len, na_mem_handle_t mem_handle)
{
    assert(na_g);
    return na_g->mem_handle_serialize(buf, buf_len, mem_handle);
}

int na_mem_handle_deserialize(na_mem_handle_t *mem_handle, const void *buf, na_size_t buf_len)
{
    assert(na_g);
    return na_g->mem_handle_deserialize(mem_handle, buf, buf_len);
}

int na_put(na_mem_handle_t local_mem_handle, na_offset_t local_offset,
        na_mem_handle_t remote_mem_handle, na_offset_t remote_offset,
        na_size_t length, na_addr_t remote_addr, na_request_t *request)
{
    assert(na_g);
    return na_g->put(local_mem_handle, local_offset,
            remote_mem_handle, remote_offset,
            length, remote_addr, request);
}

int na_get(na_mem_handle_t local_mem_handle, na_offset_t local_offset,
        na_mem_handle_t remote_mem_handle, na_offset_t remote_offset,
        na_size_t length, na_addr_t remote_addr, na_request_t *request)
{
    assert(na_g);
    return na_g->get(local_mem_handle, local_offset,
            remote_mem_handle, remote_offset,
            length, remote_addr, request);
}

int na_wait(na_request_t request, int *flag, int timeout, na_status_t *status)
{
    assert(na_g);
    return na_g->wait(request, flag, timeout, status);
}
