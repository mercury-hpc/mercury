/*
 * network_abstraction.c
 */

#include "network_abstraction.h"

#include <assert.h>

static na_network_class_t *na_g = NULL;

/*---------------------------------------------------------------------------
 * Function:    na_register
 *
 * Purpose:     Register a driver to the network abstraction layer
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
void na_register(na_network_class_t *network_class)
{
    assert(na_g == NULL);
    na_g = network_class;
}

/*---------------------------------------------------------------------------
 * Function:    na_finalize
 *
 * Purpose:     Finalize the network abstraction layer
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
void na_finalize(void)
{
    assert(na_g);
    na_g->finalize();
    na_g = NULL;
}

/*---------------------------------------------------------------------------
 * Function:    na_get_unexpected_size
 *
 * Purpose:     Get the maximum size of an unexpected message
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
na_size_t na_get_unexpected_size(void)
{
    assert(na_g);
    return na_g->get_unexpected_size();
}

/*---------------------------------------------------------------------------
 * Function:    na_addr_lookup
 *
 * Purpose:     Lookup an addr from a peer address/name
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int na_addr_lookup(const char *name, na_addr_t *addr)
{
    assert(na_g);
    return na_g->addr_lookup(name, addr);
}

/*---------------------------------------------------------------------------
 * Function:    na_addr_free
 *
 * Purpose:     Free the addr from the list of peers
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int na_addr_free(na_addr_t addr)
{
    assert(na_g);
    return na_g->addr_free(addr);
}

/*---------------------------------------------------------------------------
 * Function:    na_send_unexpected
 *
 * Purpose:     Send a message to dest (unexpected asynchronous)
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int na_send_unexpected(const void *buf, na_size_t buf_len, na_addr_t dest,
        na_tag_t tag, na_request_t *request, void *op_arg)
{
    assert(na_g);
    return na_g->send_unexpected(buf, buf_len, dest, tag, request, op_arg);
}

/*---------------------------------------------------------------------------
 * Function:    na_recv_unexpected
 *
 * Purpose:     Receive a message from source (unexpected asynchronous)
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int na_recv_unexpected(void *buf, na_size_t *buf_len, na_addr_t *source,
        na_tag_t *tag, na_request_t *request, void *op_arg)
{
    assert(na_g);
    return na_g->recv_unexpected(buf, buf_len, source, tag, request, op_arg);
}

/*---------------------------------------------------------------------------
 * Function:    na_send
 *
 * Purpose:     Send a message to dest (asynchronous)
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int na_send(const void *buf, na_size_t buf_len, na_addr_t dest,
        na_tag_t tag, na_request_t *request, void *op_arg)
{
    assert(na_g);
    return na_g->send(buf, buf_len, dest, tag, request, op_arg);
}

/*---------------------------------------------------------------------------
 * Function:    na_recv
 *
 * Purpose:     Receive a message from source (asynchronous)
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int na_recv(void *buf, na_size_t buf_len, na_addr_t source,
        na_tag_t tag, na_request_t *request, void *op_arg)
{
    assert(na_g);
    return na_g->recv(buf, buf_len, source, tag, request, op_arg);
}

/*---------------------------------------------------------------------------
 * Function:    na_mem_register
 *
 * Purpose:     Register memory for RMA operations
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int na_mem_register(void *buf, na_size_t buf_len, unsigned long flags, na_mem_handle_t *mem_handle)
{
    assert(na_g);
    return na_g->mem_register(buf, buf_len, flags, mem_handle);
}

/*---------------------------------------------------------------------------
 * Function:    na_mem_deregister
 *
 * Purpose:     Deregister memory
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int na_mem_deregister(na_mem_handle_t mem_handle)
{
    assert(na_g);
    return na_g->mem_deregister(mem_handle);
}

/*---------------------------------------------------------------------------
 * Function:    na_mem_handle_serialize
 *
 * Purpose:     Serialize memory handle for exchange over the network
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int na_mem_handle_serialize(void *buf, na_size_t buf_len, na_mem_handle_t mem_handle)
{
    assert(na_g);
    return na_g->mem_handle_serialize(buf, buf_len, mem_handle);
}

/*---------------------------------------------------------------------------
 * Function:    na_mem_handle_deserialize
 *
 * Purpose:     Deserialize memory handle
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int na_mem_handle_deserialize(na_mem_handle_t *mem_handle, const void *buf, na_size_t buf_len)
{
    assert(na_g);
    return na_g->mem_handle_deserialize(mem_handle, buf, buf_len);
}

/*---------------------------------------------------------------------------
 * Function:    na_mem_handle_free
 *
 * Purpose:     Free memory handle
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int na_mem_handle_free(na_mem_handle_t mem_handle)
{
    assert(na_g);
    return na_g->mem_handle_free(mem_handle);
}

/*---------------------------------------------------------------------------
 * Function:    na_put
 *
 * Purpose:     Put data to remote target
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int na_put(na_mem_handle_t local_mem_handle, na_offset_t local_offset,
        na_mem_handle_t remote_mem_handle, na_offset_t remote_offset,
        na_size_t length, na_addr_t remote_addr, na_request_t *request)
{
    assert(na_g);
    return na_g->put(local_mem_handle, local_offset,
            remote_mem_handle, remote_offset,
            length, remote_addr, request);
}

/*---------------------------------------------------------------------------
 * Function:    na_get
 *
 * Purpose:     Get data from remote target
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int na_get(na_mem_handle_t local_mem_handle, na_offset_t local_offset,
        na_mem_handle_t remote_mem_handle, na_offset_t remote_offset,
        na_size_t length, na_addr_t remote_addr, na_request_t *request)
{
    assert(na_g);
    return na_g->get(local_mem_handle, local_offset,
            remote_mem_handle, remote_offset,
            length, remote_addr, request);
}

/*---------------------------------------------------------------------------
 * Function:    na_wait
 *
 * Purpose:     Wait for a request to complete or until timeout (ms) is reached
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int na_wait(na_request_t request, unsigned int timeout, na_status_t *status)
{
    assert(na_g);
    return na_g->wait(request, timeout, status);
}
