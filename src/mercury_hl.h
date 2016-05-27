/*
 * Copyright (C) 2013-2016 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#ifndef MERCURY_HL_H
#define MERCURY_HL_H

#include "mercury.h"
#include "mercury_bulk.h"
#include "mercury_request.h"

/*****************/
/* Public Macros */
/*****************/

/**
 * Define macros so that default classes/contexts can be easily renamed
 * if we ever need to. Users should use macros and not global variables
 * directly.
 */
#define HG_CLASS_DEFAULT hg_class_default_g
#define HG_CONTEXT_DEFAULT hg_context_default_g
#define HG_REQUEST_CLASS_DEFAULT hg_request_class_default_g
#ifdef __cplusplus
extern "C" {
#endif

/********************/
/* Public Variables */
/********************/

/* HG default */
extern HG_EXPORT hg_class_t *HG_CLASS_DEFAULT;
extern HG_EXPORT hg_context_t *HG_CONTEXT_DEFAULT;
extern HG_EXPORT hg_request_class_t *HG_REQUEST_CLASS_DEFAULT;

/*********************/
/* Public Prototypes */
/*********************/

/**
 * Initialize Mercury high-level layer and create default classes/contexts.
 * If no info_string is passed, the HG HL layer will attempt to initialize
 * NA by using the value contained in the environment variable called
 * MERCURY_PORT_NAME.
 * \remark HG_Hl_finalize() is registered with atexit() so that default
 * classes/contexts are freed at process termination.
 *
 * \param na_info_string [IN]   host address with port number (e.g.,
 *                              "tcp://localhost:3344" or
 *                              "bmi+tcp://localhost:3344")
 * \param na_listen [IN]        listen for incoming connections
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_EXPORT hg_return_t
HG_Hl_init(
        const char *na_info_string,
        hg_bool_t na_listen
        );

/**
 * Initialize Mercury high-level layer and create default class
 * from an existing NA class.
 * \remark HG_Hl_finalize() is registered with atexit() so that default
 * classes/contexts are freed at process termination.
 *
 * \param na_class [IN]         pointer to NA class
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_EXPORT hg_return_t
HG_Hl_init_na(
        na_class_t *na_class
        );


/**
 * Finalize Mercury high-level layer.
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_EXPORT hg_return_t
HG_Hl_finalize(
        void
        );

/**
 * Lookup an address and wait for its completion. Address must be freed
 * using HG_Addr_free().
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_EXPORT hg_return_t
HG_Hl_addr_lookup_wait(
        hg_context_t *context,
        hg_request_class_t *request_class,
        const char *name,
        hg_addr_t *addr,
        unsigned int timeout
        );

/**
 * Forward a call and wait for its completion. A HG handle must have been
 * previously created. Output can be queried using HG_Get_output() and freed
 * using HG_Free_output().
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_EXPORT hg_return_t
HG_Hl_forward_wait(
        hg_request_class_t *request_class,
        hg_handle_t handle,
        void *in_struct,
        unsigned int timeout
        );

/**
 * Initiate a bulk data transfer and wait for its completion.
 *
 * \param context [IN]          pointer to HG context
 * \param op [IN]               transfer operation:
 *                                  - HG_BULK_PUSH
 *                                  - HG_BULK_PULL
 * \param origin_addr [IN]      abstract address of origin
 * \param origin_handle [IN]    abstract bulk handle
 * \param origin_offset [IN]    offset
 * \param local_handle [IN]     abstract bulk handle
 * \param local_offset [IN]     offset
 * \param size [IN]             size of data to be transferred
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_EXPORT hg_return_t
HG_Hl_bulk_transfer_wait(
        hg_context_t *context,
        hg_request_class_t *request_class,
        hg_bulk_op_t op,
        hg_addr_t origin_addr,
        hg_bulk_t origin_handle,
        hg_size_t origin_offset,
        hg_bulk_t local_handle,
        hg_size_t local_offset,
        hg_size_t size,
        unsigned int timeout
        );

/**
 * struct containing data marshalling routines and the callbacks for one member
 * RPC of a protocol
 */
struct rpc_func_t {
	/** pointer to input proc callback */
	hg_return_t (*in_proc_cb)(hg_proc_t, void *);
	/** pointer to output proc callback */
	hg_return_t (*out_proc_cb)(hg_proc_t, void *);
	/** pointer to RPC callback */
	hg_return_t (*rpc_cb)(hg_handle_t);
};

/**
 * Initialization for the HG_Registered_protocol_wait_remote function. Needs to
 * be called on both the origin and target before the origin can call
 * HG_Registered_protocol_wait_remote().
 *
 * \param hg_class [IN]		pointer to HG class
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
hg_return_t HG_Hl_protocol_init(hg_class_t *hg_class);

/**
 * Dynamically register an array of RPCs as well as the RPC callbacks executed
 * when the RPC request ID associated with a member function is received.
 * Associate input and output proc to RPC ID, so that they can be used to
 * serialize and deserialize function parameters. The array of RPCs is
 * considered a protocol. A protocol has a unique name + version combination.
 * This function is to be called on the server side of the transaction. One
 * first calls HG_Register_protocol() on the server side, then on the client
 * side calls HG_Registered_protocol_wait_remote() to obtain the base_id from
 * the server side, then calls HG_Register_protocol_base() on the client side.
 *
 * \param hg_class [IN]		pointer to HG class
 * \param protocol_name [IN]	unique name associated to this protocol
 * \param version [IN]		version number of this protocol
 * \param rpc_func [IN]		array of rpc_func_t structs. Each struct
 *				contains the name of the rpc call, input proc
 *				callback and the output proc callback for this
 *				member function
 * \param count [IN]		number of RPC functions in this protocol
 * \param base_id [OUT]		the base RPC id of the protocol. The i-th RPC
 *				has the RPC ID: bas_id + i
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_EXPORT hg_return_t
HG_Hl_register_protocol(
	hg_class_t *hg_class,
	char *protocol_name,
	int version,
	struct rpc_func_t *rpc_func,
	int count,
	hg_id_t  *base_id
	);

/**
 * Dynamically register an array of RPCs as well as the RPC callbacks executed
 * when the RPC request ID associated with a member function is received.
 * Associate input and output proc to RPC ID, so that they can be used to
 * serialize and deserialize function parameters. The array of RPCs is called a
 * protocol. A protocol has a unique name + version combination. A protocol can
 * be identified by a base ID. Member RPCs of a protocol have continous RPC IDs,
 * the i-th RPC in a protocol has the RPC id: base ID + i.  This function is to
 * be called on the client side of the transaction. One first calls
 * HG_Register_protocol() on the server side, then on the client side calls
 * HG_Registered_protocol_wait_remote() to obtain the base_id from the server
 * side, then calls HG_Register_protocol_base() on the client side.
 *
 * \param hg_class [IN]		pointer to HG class
 * \param protocol_name [IN]	unique name associated to this protocol
 * \param version [IN]		version number of this protocol
 * \param rpc_func [IN]		array of rpc_func_t structs. Each struct
 *				contains the input proc callback and the output
 *				proc callback for one member function
 * \param count [IN]		number of RPC functions in this protocol
 * \param base_id [IN]		the base rpc id of the protocol. The i-th RPC
 *				has the RPC ID: bas_id + i
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_EXPORT hg_return_t
HG_Hl_register_protocol_base(
	hg_class_t *hg_class,
	char *protocol_name,
	int version,
	struct rpc_func_t *rpc_func,
	int count,
	hg_id_t  base_id
	);

/**
 * Query a remote node to find out if an array of protocols has been registered
 * on that node. This is a blocking call.
 *
 * \param context [IN]		pointer to HG context
 * \param request_class [IN]	pointer to request class
 * \param protocol_name [IN]	array of strings which are the name of the
 *				queried protocols
 * \param version [IN]		array of version numbers of the queried
 *				protocols
 * \param count [IN]		number of protocols to query
 * \param addr [IN]		abstract address of the remote node
 * \param results [OUT]		array of ids. results[i] is 0 when the i-th
 *				protocol is not registerd on the remote node,
 *				otherwise contains the base ID of the i-th
 *				protocol on the remote node.
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_EXPORT hg_return_t
HG_Hl_registered_protocol_remote_wait(
	hg_context_t *hg_context,
	hg_request_class_t *request_class,
	const char **protocol_name,
	int *version,
	int count,
	hg_addr_t addr,
	hg_id_t *results,
	unsigned int timeout);

/**
 * Query the local node to find out if a protocol has been registered on this
 * node.
 *
 * \param hg_class [IN]		pointer to HG class
 * \param protocol_name [IN]	strings which is the name of the queried
 *				protocol
 * \param version [IN]		version number of the queried protocol
 * \param result [OUT]		contains the base_id of the protocol if the
 *				protocol is registered on the local node, 0 if
 *				the protocol is not registered on the local
 *				node.
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_EXPORT hg_return_t
HG_Hl_registered_protocol(
	hg_class_t *hg_class,
	const char *protocol_name,
	int version,
	hg_id_t *result
	);

#ifdef __cplusplus
}
#endif

#endif /* MERCURY_HL_H */
