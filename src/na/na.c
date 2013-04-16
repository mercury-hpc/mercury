/*
 * Copyright (C) 2013 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#include "na.h"

#include <assert.h>

/*---------------------------------------------------------------------------
 * Function:    NA_Finalize
 *
 * Purpose:     Finalize the network abstraction layer
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int NA_Finalize(na_class_t *network_class)
{
    assert(network_class);
    return network_class->finalize();
}

/*---------------------------------------------------------------------------
 * Function:    NA_Get_unexpected_size
 *
 * Purpose:     Get the maximum size of an unexpected message
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
na_size_t NA_Get_unexpected_size(na_class_t *network_class)
{
    assert(network_class);
    return network_class->get_unexpected_size();
}

/*---------------------------------------------------------------------------
 * Function:    NA_Addr_lookup
 *
 * Purpose:     Lookup an addr from a peer address/name
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int NA_Addr_lookup(na_class_t *network_class, const char *name,
        na_addr_t *addr)
{
    assert(network_class);
    return network_class->addr_lookup(name, addr);
}

/*---------------------------------------------------------------------------
 * Function:    NA_Addr_free
 *
 * Purpose:     Free the addr from the list of peers
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int NA_Addr_free(na_class_t *network_class, na_addr_t addr)
{
    assert(network_class);
    return network_class->addr_free(addr);
}

/*---------------------------------------------------------------------------
 * Function:    NA_Send_unexpected
 *
 * Purpose:     Send a message to dest (unexpected asynchronous)
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int NA_Send_unexpected(na_class_t *network_class,
        const void *buf, na_size_t buf_len, na_addr_t dest,
        na_tag_t tag, na_request_t *request, void *op_arg)
{
    assert(network_class);
    return network_class->send_unexpected(buf, buf_len, dest, tag, request, op_arg);
}

/*---------------------------------------------------------------------------
 * Function:    NA_Recv_unexpected
 *
 * Purpose:     Receive a message from source (unexpected asynchronous)
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int NA_Recv_unexpected(na_class_t *network_class,
        void *buf, na_size_t buf_len, na_size_t *actual_buf_len,
        na_addr_t *source, na_tag_t *tag, na_request_t *request, void *op_arg)
{
    assert(network_class);
    return network_class->recv_unexpected(buf, buf_len, actual_buf_len, source, tag, request, op_arg);
}

/*---------------------------------------------------------------------------
 * Function:    NA_Send
 *
 * Purpose:     Send a message to dest (asynchronous)
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int NA_Send(na_class_t *network_class,
        const void *buf, na_size_t buf_len, na_addr_t dest,
        na_tag_t tag, na_request_t *request, void *op_arg)
{
    assert(network_class);
    return network_class->send(buf, buf_len, dest, tag, request, op_arg);
}

/*---------------------------------------------------------------------------
 * Function:    NA_Recv
 *
 * Purpose:     Receive a message from source (asynchronous)
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int NA_Recv(na_class_t *network_class,
        void *buf, na_size_t buf_len, na_addr_t source,
        na_tag_t tag, na_request_t *request, void *op_arg)
{
    assert(network_class);
    return network_class->recv(buf, buf_len, source, tag, request, op_arg);
}

/*---------------------------------------------------------------------------
 * Function:    NA_Mem_register
 *
 * Purpose:     Register memory for RMA operations
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int NA_Mem_register(na_class_t *network_class,
        void *buf, na_size_t buf_len, unsigned long flags,
        na_mem_handle_t *mem_handle)
{
    assert(network_class);
    return network_class->mem_register(buf, buf_len, flags, mem_handle);
}

/*---------------------------------------------------------------------------
 * Function:    NA_Mem_deregister
 *
 * Purpose:     Deregister memory
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int NA_Mem_deregister(na_class_t *network_class,
        na_mem_handle_t mem_handle)
{
    assert(network_class);
    return network_class->mem_deregister(mem_handle);
}

/*---------------------------------------------------------------------------
 * Function:    NA_Mem_handle_serialize
 *
 * Purpose:     Serialize memory handle for exchange over the network
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int NA_Mem_handle_serialize(na_class_t *network_class,
        void *buf, na_size_t buf_len, na_mem_handle_t mem_handle)
{
    assert(network_class);
    return network_class->mem_handle_serialize(buf, buf_len, mem_handle);
}

/*---------------------------------------------------------------------------
 * Function:    NA_Mem_handle_deserialize
 *
 * Purpose:     Deserialize memory handle
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int NA_Mem_handle_deserialize(na_class_t *network_class,
        na_mem_handle_t *mem_handle, const void *buf, na_size_t buf_len)
{
    assert(network_class);
    return network_class->mem_handle_deserialize(mem_handle, buf, buf_len);
}

/*---------------------------------------------------------------------------
 * Function:    NA_Mem_handle_free
 *
 * Purpose:     Free memory handle
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int NA_Mem_handle_free(na_class_t *network_class,
        na_mem_handle_t mem_handle)
{
    assert(network_class);
    return network_class->mem_handle_free(mem_handle);
}

/*---------------------------------------------------------------------------
 * Function:    NA_Put
 *
 * Purpose:     Put data to remote target
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int NA_Put(na_class_t *network_class,
        na_mem_handle_t local_mem_handle, na_offset_t local_offset,
        na_mem_handle_t remote_mem_handle, na_offset_t remote_offset,
        na_size_t length, na_addr_t remote_addr, na_request_t *request)
{
    assert(network_class);
    return network_class->put(local_mem_handle, local_offset,
            remote_mem_handle, remote_offset,
            length, remote_addr, request);
}

/*---------------------------------------------------------------------------
 * Function:    NA_Get
 *
 * Purpose:     Get data from remote target
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int NA_Get(na_class_t *network_class,
        na_mem_handle_t local_mem_handle, na_offset_t local_offset,
        na_mem_handle_t remote_mem_handle, na_offset_t remote_offset,
        na_size_t length, na_addr_t remote_addr, na_request_t *request)
{
    assert(network_class);
    return network_class->get(local_mem_handle, local_offset,
            remote_mem_handle, remote_offset,
            length, remote_addr, request);
}

/*---------------------------------------------------------------------------
 * Function:    NA_Wait
 *
 * Purpose:     Wait for a request to complete or until timeout (ms) is reached
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int NA_Wait(na_class_t *network_class,
        na_request_t request, unsigned int timeout, na_status_t *status)
{
    assert(network_class);
    return network_class->wait(request, timeout, status);
}
