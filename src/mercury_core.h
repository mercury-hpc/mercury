/**
 * Copyright (c) 2013-2022 UChicago Argonne, LLC and The HDF Group.
 * Copyright (c) 2022-2024 Intel Corporation.
 * Copyright (c) 2024-2025 Hewlett Packard Enterprise Development LP.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef MERCURY_CORE_H
#define MERCURY_CORE_H

#include "mercury_core_header.h"
#include "mercury_core_types.h"

#include "na.h"

/*************************************/
/* Public Type and Struct Definition */
/*************************************/

typedef struct hg_core_class hg_core_class_t;     /* Opaque HG core class */
typedef struct hg_core_context hg_core_context_t; /* Opaque HG core context */
typedef struct hg_core_addr *hg_core_addr_t;      /* Abstract HG address */
typedef struct hg_core_handle *hg_core_handle_t;  /* Abstract RPC handle */
typedef struct hg_core_op_id *hg_core_op_id_t;    /* Abstract operation id */

/* HG info struct */
struct hg_core_info {
    hg_core_class_t *core_class; /* HG core class */
    hg_core_context_t *context;  /* HG core context */
    hg_core_addr_t addr;         /* HG address at target/origin */
    hg_id_t id;                  /* RPC ID */
    uint8_t context_id;          /* Context ID at target/origin */
};

/* Callback info structs */
struct hg_core_cb_info_lookup {
    hg_core_addr_t addr; /* HG address */
};

struct hg_core_cb_info_forward {
    hg_core_handle_t handle; /* HG handle */
};

struct hg_core_cb_info_respond {
    hg_core_handle_t handle; /* HG handle */
};

struct hg_core_cb_info {
    union { /* Union of callback info structures */
        struct hg_core_cb_info_lookup lookup;
        struct hg_core_cb_info_forward forward;
        struct hg_core_cb_info_respond respond;
    } info;
    void *arg;         /* User data */
    hg_cb_type_t type; /* Callback type */
    hg_return_t ret;   /* Return value */
};

/* RPC / HG callbacks */
typedef hg_return_t (*hg_core_rpc_cb_t)(hg_core_handle_t handle);
typedef hg_return_t (*hg_core_cb_t)(
    const struct hg_core_cb_info *callback_info);

/*****************/
/* Public Macros */
/*****************/

/* Constant values */
#define HG_CORE_ADDR_NULL    ((hg_core_addr_t) 0)
#define HG_CORE_HANDLE_NULL  ((hg_core_handle_t) 0)
#define HG_CORE_OP_ID_NULL   ((hg_core_op_id_t) 0)
#define HG_CORE_OP_ID_IGNORE ((hg_core_op_id_t *) 1)

/* Flags */
#define HG_CORE_MORE_DATA (1 << 0) /* More data required */

/*********************/
/* Public Prototypes */
/*********************/

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Get information on protocols that are supported by underlying NA plugins. If
 * \info_string is NULL, a list of all supported protocols by all plugins will
 * be returned. The returned list must be freed using
 * HG_Core_free_na_protocol_info().
 *
 * \param info_string [IN]          NULL or "<protocol>" or "<plugin+protocol>"
 * \param na_protocol_info_p [OUT]  linked-list of protocol infos
 *
 * \return HG_SUCCESS or corresponding NA error code
 */
HG_PUBLIC hg_return_t
HG_Core_get_na_protocol_info(
    const char *info_string, struct na_protocol_info **na_protocol_info_p);

/**
 * Free protocol info.
 *
 * \param na_protocol_info [IN/OUT] linked-list of protocol infos
 */
HG_PUBLIC void
HG_Core_free_na_protocol_info(struct na_protocol_info *na_protocol_info);

/**
 * Initialize the core Mercury layer.
 * Must be finalized with HG_Core_finalize().
 *
 * \param na_info_string [IN]   host address with port number (e.g.,
 *                              "tcp://localhost:3344" or
 *                              "bmi+tcp://localhost:3344")
 * \param na_listen [IN]        listen for incoming connections
 *
 * \return Pointer to HG core class or NULL in case of failure
 */
HG_PUBLIC hg_core_class_t *
HG_Core_init(
    const char *na_info_string, uint8_t na_listen) HG_WARN_UNUSED_RESULT;

/**
 * Initialize the Mercury layer with options provided by init_info.
 * Must be finalized with HG_Core_finalize(). Using this routine limits the info
 * struct version to 2.2 version.
 * \remark HG_Core_init_opt() may become HG_Core_init() in the future.
 *
 * \param na_info_string [IN]   host address with port number (e.g.,
 *                              "tcp://localhost:3344" or
 *                              "bmi+tcp://localhost:3344")
 * \param na_listen [IN]        listen for incoming connections
 * \param hg_init_info [IN]     (Optional) HG init info, NULL if no info
 *
 * \return Pointer to HG core class or NULL in case of failure
 */
HG_PUBLIC hg_core_class_t *
HG_Core_init_opt(const char *na_info_string, uint8_t na_listen,
    const struct hg_init_info *hg_init_info) HG_WARN_UNUSED_RESULT;

/**
 * Initialize the Mercury layer with options provided by init_info.
 * Must be finalized with HG_Core_finalize().
 * \remark HG_Core_init_opt() may become HG_Core_init() in the future.
 *
 * \param na_info_string [IN]   host address with port number (e.g.,
 *                              "tcp://localhost:3344" or
 *                              "bmi+tcp://localhost:3344")
 * \param na_listen [IN]        listen for incoming connections
 * \param version [IN]          API version of the init info struct
 * \param hg_init_info [IN]     (Optional) HG init info, NULL if no info
 *
 * \return Pointer to HG core class or NULL in case of failure
 */
HG_PUBLIC hg_core_class_t *
HG_Core_init_opt2(const char *na_info_string, uint8_t na_listen,
    unsigned int version,
    const struct hg_init_info *hg_init_info) HG_WARN_UNUSED_RESULT;

/**
 * Finalize the Mercury layer.
 *
 * \param hg_core_class [IN]    pointer to HG core class
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_PUBLIC hg_return_t
HG_Core_finalize(hg_core_class_t *hg_core_class);

/**
 * Clean up all temporary files that were created in previous HG instances.
 * While temporary resources (e.g., tmp files) are cleaned up on a call
 * to HG_Finalize(), this routine gives a chance to programs that terminate
 * abnormally to easily clean up those resources.
 */
HG_PUBLIC void
HG_Core_cleanup(void);

/**
 * Set callback that will be triggered when additional data needs to be
 * transferred and HG_Core_set_more_data() has been called, usually when the
 * eager message size is exceeded. This allows upper layers to manually transfer
 * data using bulk transfers for example. The done_callback argument allows the
 * upper layer to notify back once the data has been successfully acquired.
 * The release callback allows the upper layer to release resources that were
 * allocated when acquiring the data.
 *
 * \param hg_core_class [IN]                pointer to HG core class
 * \param more_data_acquire_callback [IN]   pointer to acquire function callback
 * \param more_data_release_callback [IN]   pointer to release function callback
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_PUBLIC hg_return_t
HG_Core_set_more_data_callback(struct hg_core_class *hg_core_class,
    hg_return_t (*more_data_acquire_callback)(hg_core_handle_t, hg_op_t,
        void (*done_callback)(hg_core_handle_t, hg_return_t)),
    void (*more_data_release_callback)(hg_core_handle_t));

/**
 * Obtain the name of the given class.
 *
 * \param hg_core_class [IN]    pointer to HG core class
 *
 * \return the name of the class, or NULL if not a valid class
 */
static HG_INLINE const char *
HG_Core_class_get_name(
    const hg_core_class_t *hg_core_class) HG_WARN_UNUSED_RESULT;

/**
 * Obtain the protocol of the given class.
 *
 * \param hg_core_class [IN]    pointer to HG core class
 *
 * \return the protocol of the class, or NULL if not a valid class
 */
static HG_INLINE const char *
HG_Core_class_get_protocol(
    const hg_core_class_t *hg_core_class) HG_WARN_UNUSED_RESULT;

/**
 * Test whether class is listening or not.
 *
 * \param hg_core_class [IN]    pointer to HG core class
 *
 * \return true if listening or false if not, or not a valid class
 */
static HG_INLINE bool
HG_Core_class_is_listening(
    const hg_core_class_t *hg_core_class) HG_WARN_UNUSED_RESULT;

/**
 * Obtain the underlying NA class.
 *
 * \param hg_core_class [IN]    pointer to HG core class
 *
 * \return Pointer to NA class or NULL if not a valid class
 */
static HG_INLINE na_class_t *
HG_Core_class_get_na(
    const hg_core_class_t *hg_core_class) HG_WARN_UNUSED_RESULT;

#ifdef NA_HAS_SM
/**
 * Obtain the underlying NA SM class.
 *
 * \param hg_core_class [IN]    pointer to HG core class
 *
 * \return Pointer to NA SM class or NULL if not a valid class
 */
static HG_INLINE na_class_t *
HG_Core_class_get_na_sm(
    const hg_core_class_t *hg_core_class) HG_WARN_UNUSED_RESULT;
#endif

/**
 * Obtain the maximum eager size for sending RPC inputs.
 *
 * \param hg_core_class [IN]    pointer to HG core class
 *
 * \return the maximum size, or 0 if hg_core_class is not a valid class or
 * XDR is being used
 */
static HG_INLINE hg_size_t
HG_Core_class_get_input_eager_size(
    const hg_core_class_t *hg_core_class) HG_WARN_UNUSED_RESULT;

/**
 * Obtain the maximum eager size for sending RPC outputs.
 *
 * \param hg_core_class [IN]    pointer to HG core class
 *
 * \return the maximum size, or 0 if hg_core_class is not a valid class or XDR
 * is being used
 */
static HG_INLINE hg_size_t
HG_Core_class_get_output_eager_size(
    const hg_core_class_t *hg_core_class) HG_WARN_UNUSED_RESULT;

/**
 * Associate user data to class. When HG_Core_finalize() is called,
 * free_callback (if defined) is called to free the associated data.
 *
 * \param hg_core_class [IN]    pointer to HG core class
 * \param data [IN]             pointer to user data
 * \param free_callback [IN]    pointer to function
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
static HG_INLINE hg_return_t
HG_Core_class_set_data(
    hg_core_class_t *hg_core_class, void *data, void (*free_callback)(void *));

/**
 * Retrieve previously associated data from a given class.
 *
 * \param hg_core_class [IN]    pointer to HG core class
 *
 * \return Pointer to user data or NULL if not set or any error has occurred
 */
static HG_INLINE void *
HG_Core_class_get_data(
    const hg_core_class_t *hg_core_class) HG_WARN_UNUSED_RESULT;

/**
 * Get diagnostic counters associated to HG core class.
 * (Requires debug enabled build)
 *
 * \param hg_core_class [IN]        pointer to HG core class
 * \param diag_counters [IN/OUT]    pointer to counters struct
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_PUBLIC hg_return_t
HG_Core_class_get_counters(const hg_core_class_t *hg_core_class,
    struct hg_diag_counters *diag_counters);

/**
 * Create a new context. Must be destroyed by calling HG_Core_context_destroy().
 *
 * \param hg_core_class [IN]    pointer to HG core class
 *
 * \return Pointer to HG core context or NULL in case of failure
 */
HG_PUBLIC hg_core_context_t *
HG_Core_context_create(hg_core_class_t *hg_core_class) HG_WARN_UNUSED_RESULT;

/**
 * Create a new context with a user-defined context identifier. The context
 * identifier can be used to route RPC requests to specific contexts by using
 * HG_Core_set_target_id().
 * Context must be destroyed by calling HG_Core_context_destroy().
 *
 * \param hg_core_class [IN]    pointer to HG core class
 * \param id [IN]               context ID
 *
 * \return Pointer to HG core context or NULL in case of failure
 */
HG_PUBLIC hg_core_context_t *
HG_Core_context_create_id(
    hg_core_class_t *hg_core_class, uint8_t id) HG_WARN_UNUSED_RESULT;

/**
 * Destroy a context created by HG_Core_context_create().
 *
 * \param context [IN]          pointer to HG core context
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_PUBLIC hg_return_t
HG_Core_context_destroy(hg_core_context_t *context);

/**
 * Retrieve the class used to create the given context.
 *
 * \param context [IN]          pointer to HG core context
 *
 * \return the associated class
 */
static HG_INLINE hg_core_class_t *
HG_Core_context_get_class(
    const hg_core_context_t *context) HG_WARN_UNUSED_RESULT;

/**
 * Retrieve the underlying NA context.
 *
 * \param context [IN]          pointer to HG core context
 *
 * \return the associated context
 */
static HG_INLINE na_context_t *
HG_Core_context_get_na(const hg_core_context_t *context) HG_WARN_UNUSED_RESULT;

#ifdef NA_HAS_SM
/**
 * Retrieve the underlying NA SM context.
 *
 * \param context [IN]          pointer to HG core context
 *
 * \return the associated context
 */
static HG_INLINE na_context_t *
HG_Core_context_get_na_sm(
    const hg_core_context_t *context) HG_WARN_UNUSED_RESULT;
#endif

/**
 * Retrieve context ID from context.
 *
 * \param context [IN]          pointer to HG core context
 *
 * \return Non-negative integer (max value of 255) or 0 if no ID has been set
 */
static HG_INLINE uint8_t
HG_Core_context_get_id(const hg_core_context_t *context) HG_WARN_UNUSED_RESULT;

/**
 * Associate user data to context. When HG_Core_context_destroy() is called,
 * free_callback (if defined) is called to free the associated data.
 *
 * \param context [IN]          pointer to HG core context
 * \param data [IN]             pointer to user data
 * \param free_callback [IN]    pointer to function
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
static HG_INLINE hg_return_t
HG_Core_context_set_data(
    hg_core_context_t *context, void *data, void (*free_callback)(void *));

/**
 * Retrieve previously associated data from a given context.
 *
 * \param context [IN]          pointer to HG core context
 *
 * \return Pointer to user data or NULL if not set or any error has occurred
 */
static HG_INLINE void *
HG_Core_context_get_data(
    const hg_core_context_t *context) HG_WARN_UNUSED_RESULT;

/**
 * Get current number of completion entries in context's completion queue.
 *
 * \param context [IN]          pointer to HG core context
 *
 * \return non-negative integer or zero if no entries
 */
HG_PUBLIC unsigned int
HG_Core_context_get_completion_count(
    const hg_core_context_t *context) HG_WARN_UNUSED_RESULT;

/**
 * Set callback to be called on HG core handle creation. Handles are created
 * both on HG_Core_create() and HG_Core_context_post() calls. This allows
 * upper layers to create and attach data to a handle (using HG_Core_set_data())
 * and later retrieve it using HG_Core_get_data().
 *
 * \param context [IN]          pointer to HG core context
 * \param callback [IN]         pointer to function callback
 * \param arg [IN]              pointer to data passed to callback
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_PUBLIC hg_return_t
HG_Core_context_set_handle_create_callback(hg_core_context_t *context,
    hg_return_t (*callback)(hg_core_handle_t, void *), void *arg);

/**
 * Post requests associated to context in order to receive incoming RPCs.
 * Requests are automatically re-posted after completion until the context is
 * destroyed or HG_Core_context_unpost() is called. Additionally a callback
 * can be triggered on HG handle creation. This allows upper layers to
 * instantiate data that needs to be attached to a handle. Number of requests
 * that are posted can be controlled through HG init info.
 *
 * \param context [IN]          pointer to HG core context
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_PUBLIC hg_return_t
HG_Core_context_post(hg_core_context_t *context);

/**
 * Cancel requests posted and wait for those requests to be successfully
 * canceled. This prevents any further RPCs from being received until
 * HG_Core_context_destroy() is called.
 *
 * \param context [IN]          pointer to HG core context
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_PUBLIC hg_return_t
HG_Core_context_unpost(hg_core_context_t *context);

/**
 * Dynamically register an RPC ID as well as the RPC callback executed
 * when the RPC request ID is received.
 *
 * \param hg_core_class [IN]    pointer to HG core class
 * \param id [IN]               ID to use to register RPC
 * \param rpc_cb [IN]           RPC callback
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_PUBLIC hg_return_t
HG_Core_register(
    hg_core_class_t *hg_core_class, hg_id_t id, hg_core_rpc_cb_t rpc_cb);

/**
 * Deregister RPC ID. Further requests with RPC ID will return an error, it
 * is therefore up to the user to make sure that all requests for that RPC ID
 * have been treated before it is unregistered.
 *
 * \param hg_core_class [IN]    pointer to HG core class
 * \param id [IN]               registered function ID
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_PUBLIC hg_return_t
HG_Core_deregister(hg_core_class_t *hg_core_class, hg_id_t id);

/**
 * Indicate whether HG_Core_register() has been called.
 *
 * \param hg_core_class [IN]    pointer to HG core class
 * \param id [IN]               function ID
 * \param flag_p [OUT]          pointer to boolean
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_PUBLIC hg_return_t
HG_Core_registered(hg_core_class_t *hg_core_class, hg_id_t id, uint8_t *flag_p);

/**
 * Register and associate user data to registered function. When
 * HG_Core_finalize() is called, free_callback (if defined) is called to free
 * the registered data.
 *
 * \param hg_core_class [IN]    pointer to HG core class
 * \param id [IN]               registered function ID
 * \param data [IN]             pointer to data
 * \param free_callback [IN]    pointer to function
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_PUBLIC hg_return_t
HG_Core_register_data(hg_core_class_t *hg_core_class, hg_id_t id, void *data,
    void (*free_callback)(void *));

/**
 * Indicate whether HG_Core_register_data() has been called and return
 * associated data.
 *
 * \param hg_core_class [IN]    pointer to HG core class
 * \param id [IN]               registered function ID
 *
 * \return Pointer to data or NULL
 */
HG_PUBLIC void *
HG_Core_registered_data(
    hg_core_class_t *hg_core_class, hg_id_t id) HG_WARN_UNUSED_RESULT;

/**
 * Disable response for a given RPC ID. This allows an origin process to send an
 * RPC to a target without waiting for a response. The RPC completes locally and
 * the callback on the origin is therefore pushed to the completion queue once
 * the RPC send is completed. By default, all RPCs expect a response to
 * be sent back.
 *
 * \param hg_core_class [IN]    pointer to HG core class
 * \param id [IN]               registered function ID
 * \param disable [IN]          boolean (HG_TRUE to disable
 *                                       HG_FALSE to re-enable)
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_PUBLIC hg_return_t
HG_Core_registered_disable_response(
    hg_core_class_t *hg_core_class, hg_id_t id, uint8_t disable);

/**
 * Check if response is disabled for a given RPC ID
 * (i.e., HG_Registered_disable_response() has been called for this RPC ID).
 *
 * \param hg_core_class [IN]    pointer to HG core class
 * \param id [IN]               registered function ID
 * \param disabled_p [OUT]      boolean (HG_TRUE if disabled
 *                                       HG_FALSE if enabled)
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_PUBLIC hg_return_t
HG_Core_registered_disabled_response(
    hg_core_class_t *hg_core_class, hg_id_t id, uint8_t *disabled_p);

/**
 * Lookup an addr from a peer address/name. Addresses need to be
 * freed by calling HG_Core_addr_free(). After completion, user callback is
 * placed into a completion queue and can be triggered using HG_Core_trigger().
 *
 * \param context [IN]          pointer to context of execution
 * \param callback [IN]         pointer to function callback
 * \param arg [IN]              pointer to data passed to callback
 * \param name [IN]             lookup name
 * \param op_id [OUT]           pointer to returned operation ID (unused)
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_PUBLIC hg_return_t
HG_Core_addr_lookup1(hg_core_context_t *context, hg_core_cb_t callback,
    void *arg, const char *name, hg_core_op_id_t *op_id);

/**
 * Lookup an addr from a peer address/name. Addresses need to be
 * freed by calling HG_Core_addr_free().
 *
 * \param hg_core_class [IN]    pointer to HG core class
 * \param name [IN]             lookup name
 * \param addr_p [OUT]          pointer to abstract address
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_PUBLIC hg_return_t
HG_Core_addr_lookup2(
    hg_core_class_t *hg_core_class, const char *name, hg_core_addr_t *addr_p);

/**
 * Free the addr from the list of peers.
 *
 * \param addr [IN]             abstract address
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_PUBLIC hg_return_t
HG_Core_addr_free(hg_core_addr_t addr);

/**
 * Hint that the address is no longer valid. This may happen if the peer is
 * no longer responding. This can be used to force removal of the
 * peer address from the list of the peers, before freeing it and reclaim
 * resources.
 *
 * \param addr [IN]             abstract address
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_PUBLIC hg_return_t
HG_Core_addr_set_remove(hg_core_addr_t addr);

/**
 * Obtain the underlying NA address from an HG address.
 *
 * \param addr [IN]             abstract address
 *
 * \return abstract NA addr or NULL if not a valid HG address
 */
static HG_INLINE na_addr_t *
HG_Core_addr_get_na(hg_core_addr_t addr) HG_WARN_UNUSED_RESULT;

#ifdef NA_HAS_SM
/**
 * Obtain the underlying NA SM address from an HG address.
 *
 * \param addr [IN]             abstract address
 *
 * \return abstract NA addr or NULL if not a valid HG address
 */
static HG_INLINE na_addr_t *
HG_Core_addr_get_na_sm(hg_core_addr_t addr) HG_WARN_UNUSED_RESULT;
#endif

/**
 * Access self address. Address must be freed with HG_Core_addr_free().
 *
 * \param hg_core_class [IN]    pointer to HG core class
 * \param addr_p [OUT]          pointer to abstract address
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_PUBLIC hg_return_t
HG_Core_addr_self(hg_core_class_t *hg_core_class, hg_core_addr_t *addr_p);

/**
 * Duplicate an existing HG abstract address. The duplicated address can be
 * stored for later use and the origin address be freed safely. The duplicated
 * address must be freed with HG_Core_addr_free().
 *
 * \param addr [IN]             abstract address
 * \param new_addr_p [OUT]      pointer to abstract address
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_PUBLIC hg_return_t
HG_Core_addr_dup(hg_core_addr_t addr, hg_core_addr_t *new_addr_p);

/**
 * Compare two addresses.
 *
 * \param addr1 [IN]            abstract address
 * \param addr2 [IN]            abstract address
 *
 * \return HG_TRUE if addresses are determined to be equal, HG_FALSE otherwise
 */
HG_PUBLIC uint8_t
HG_Core_addr_cmp(
    hg_core_addr_t addr1, hg_core_addr_t addr2) HG_WARN_UNUSED_RESULT;

/**
 * Test whether address is self or not.
 *
 * \param addr [IN]            pointer to abstract address
 *
 * \return true if address is self address, false otherwise
 */
static HG_INLINE bool
HG_Core_addr_is_self(hg_core_addr_t addr) HG_WARN_UNUSED_RESULT;

/**
 * Convert an addr to a string (returned string includes the terminating
 * null byte '\0'). If buf is NULL, the address is not converted and only
 * the required size of the buffer is returned. If the input value passed
 * through buf_size is too small, HG_SIZE_ERROR is returned and the buf_size
 * output is set to the minimum size required.
 *
 * \param buf [IN/OUT]          pointer to destination buffer
 * \param buf_size [IN/OUT]     pointer to buffer size
 * \param addr [IN]             abstract address
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_PUBLIC hg_return_t
HG_Core_addr_to_string(char *buf, hg_size_t *buf_size, hg_core_addr_t addr);

/**
 * Get size required to serialize address.
 *
 * \param addr [IN]             abstract address
 * \param flags [IN]            optional flags
 *
 * \return Non-negative value
 */
HG_PUBLIC hg_size_t
HG_Core_addr_get_serialize_size(
    hg_core_addr_t addr, unsigned long flags) HG_WARN_UNUSED_RESULT;

/**
 * Serialize address into a buffer.
 *
 * \param buf [IN/OUT]          pointer to destination buffer
 * \param buf_size [IN]         pointer to buffer size
 * \param flags [IN]            optional flags
 * \param addr [IN]             abstract address
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_PUBLIC hg_return_t
HG_Core_addr_serialize(
    void *buf, hg_size_t buf_size, unsigned long flags, hg_core_addr_t addr);

/**
 * Deserialize address from a buffer. The returned address must be freed with
 * HG_Core_addr_free().
 *
 * \param hg_core_class [IN]    pointer to HG core class
 * \param addr_p [OUT]          pointer to abstract address
 * \param buf [IN]              pointer to buffer used for deserialization
 * \param buf_size [IN]         buffer size
 * \param flags [IN]            extra flags to describe the address
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_PUBLIC hg_return_t
HG_Core_addr_deserialize(hg_core_class_t *hg_core_class, hg_core_addr_t *addr_p,
    const void *buf, hg_size_t buf_size, uint64_t flags);

/**
 * Initiate a new HG RPC using the specified function ID and the
 * local/remote target defined by addr. The HG handle created can be used to
 * query input and output buffers, as well as issuing the RPC by using
 * HG_Core_forward(). After completion the handle must be freed using
 * HG_Core_destroy().
 *
 * \param context [IN]          pointer to HG core context
 * \param addr [IN]             target address
 * \param id [IN]               registered function ID
 * \param handle_p [OUT]        pointer to HG handle
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_PUBLIC hg_return_t
HG_Core_create(hg_core_context_t *context, hg_core_addr_t addr, hg_id_t id,
    hg_core_handle_t *handle_p);

/**
 * Destroy HG handle. Decrement reference count, resources associated to the
 * handle are freed when the reference count is null.
 *
 * \param handle [IN]           HG handle
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_PUBLIC hg_return_t
HG_Core_destroy(hg_core_handle_t handle);

/**
 * Reset an existing HG handle to make it reusable for RPC forwarding.
 * Both target address and RPC ID can be modified at this time.
 * Operations on that handle must be completed in order to reset that handle
 * safely.
 *
 * \param handle [IN]           HG handle
 * \param addr [IN]             abstract network address of destination
 * \param id [IN]               registered function ID
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_PUBLIC hg_return_t
HG_Core_reset(hg_core_handle_t handle, hg_core_addr_t addr, hg_id_t id);

/**
 * Increment ref count on handle.
 *
 * \param handle [IN]           HG handle
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_PUBLIC hg_return_t
HG_Core_ref_incr(hg_core_handle_t handle);

/**
 * Retrieve ref count from handle.
 *
 * \param handle [IN]           HG handle
 *
 * \return Non-negative value or negative if the handle is not valid
 */
HG_PUBLIC int32_t
HG_Core_ref_get(hg_core_handle_t handle) HG_WARN_UNUSED_RESULT;

/**
 * Allows upper layers to attach data to an existing HG handle.
 * The free_callback argument allows allocated resources to be released when
 * the handle gets freed.
 *
 * \param handle [IN]           HG handle
 * \param data [IN]             pointer to user data
 * \param free_callback         pointer to free function callback
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
static HG_INLINE hg_return_t
HG_Core_set_data(
    hg_core_handle_t handle, void *data, void (*free_callback)(void *));

/**
 * Allows upper layers to retrieve data from an existing HG handle.
 * Only valid if HG_Core_set_data() has been previously called.
 *
 * \param handle [IN]           HG handle
 *
 * \return Pointer to user data or NULL if not set or any error has occurred
 */
static HG_INLINE void *
HG_Core_get_data(hg_core_handle_t handle) HG_WARN_UNUSED_RESULT;

/**
 * Get info from handle.
 *
 * \remark Users must call HG_Core_addr_dup() to safely re-use the addr field.
 *
 * \param handle [IN]           HG handle
 *
 * \return Pointer to info or NULL in case of failure
 */
static HG_INLINE const struct hg_core_info *
HG_Core_get_info(hg_core_handle_t handle) HG_WARN_UNUSED_RESULT;

/**
 * Allows upper layers to retrieve cached RPC data from an existing HG handle.
 * Only valid if HG_Core_register_data() has been previously called.
 *
 * \param handle [IN]           HG handle
 *
 * \return Pointer to user data or NULL if not set or any error has occurred
 */
static HG_INLINE const void *
HG_Core_get_rpc_data(hg_core_handle_t handle) HG_WARN_UNUSED_RESULT;

/**
 * Set target context ID that will receive and process the RPC request
 * (ID is defined on target context creation, see HG_Core_context_create_id()).
 *
 * \param handle [IN]           HG handle
 * \param id [IN]               user-defined target context ID
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
static HG_INLINE hg_return_t
HG_Core_set_target_id(hg_core_handle_t handle, uint8_t id);

/**
 * Get input payload size from handle.
 *
 * \param handle [IN]           HG handle
 *
 * \return Non-negative value or zero if no payload
 */
static HG_INLINE size_t
HG_Core_get_input_payload_size(hg_core_handle_t handle);

/**
 * Get input buffer from handle that can be used for serializing/deserializing
 * parameters.
 *
 * \param handle [IN]           HG handle
 * \param in_buf_p [OUT]        pointer to input buffer
 * \param in_buf_size_p [OUT]   pointer to input buffer size
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
static HG_INLINE hg_return_t
HG_Core_get_input(
    hg_core_handle_t handle, void **in_buf_p, hg_size_t *in_buf_size_p);

/**
 * Release input buffer from handle so that it can be re-used early.
 *
 * \remark If HG_Core_release_input() is not called, the input buffer will
 * later be released when calling HG_Core_destroy().
 *
 * \param handle [IN]           HG handle
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_PUBLIC hg_return_t
HG_Core_release_input(hg_core_handle_t handle);

/**
 * Get output payload size from handle.
 *
 * \param handle [IN]           HG handle
 *
 * \return Non-negative value or zero if no payload
 */
static HG_INLINE size_t
HG_Core_get_output_payload_size(hg_core_handle_t handle);

/**
 * Get output buffer from handle that can be used for serializing/deserializing
 * parameters.
 *
 * \param handle [IN]           HG handle
 * \param out_buf_p [OUT]       pointer to output buffer
 * \param out_buf_size_p [OUT]  pointer to output buffer size
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
static HG_INLINE hg_return_t
HG_Core_get_output(
    hg_core_handle_t handle, void **out_buf_p, hg_size_t *out_buf_size_p);

/**
 * Forward a call using an existing HG handle. Input and output buffers can be
 * queried from the handle to serialize/deserialize parameters.
 * Additionally, a bulk handle can be passed if the size of the input is larger
 * than the queried input buffer size.
 * After completion, the handle must be freed using HG_Core_destroy(), the user
 * callback is placed into a completion queue and can be triggered using
 * HG_Core_trigger().
 *
 * \param handle [IN]           HG handle
 * \param callback [IN]         pointer to function callback
 * \param arg [IN]              pointer to data passed to callback
 * \param payload_size [IN]     size of payload to send
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_PUBLIC hg_return_t
HG_Core_forward(hg_core_handle_t handle, hg_core_cb_t callback, void *arg,
    uint8_t flags, hg_size_t payload_size);

/**
 * Respond back to the origin. The output buffer, which can be used to encode
 * the response, must first be queried using HG_Core_get_output().
 * After completion, the user callback is placed into a completion queue and
 * can be triggered using HG_Core_trigger().
 *
 * \param handle [IN]           HG handle
 * \param callback [IN]         pointer to function callback
 * \param arg [IN]              pointer to data passed to callback
 * \param payload_size [IN]     size of payload to send
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_PUBLIC hg_return_t
HG_Core_respond(hg_core_handle_t handle, hg_core_cb_t callback, void *arg,
    uint8_t flags, hg_size_t payload_size);

/**
 * Cancel an ongoing operation.
 *
 * \param handle [IN]           HG handle
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_PUBLIC hg_return_t
HG_Core_cancel(hg_core_handle_t handle);

/**
 * (Deprecated in favor of HG_Core_event_progress())
 * Try to progress RPC execution for at most timeout until timeout is reached or
 * any completion has occurred.
 * Progress should not be considered as wait, in the sense that it cannot be
 * assumed that completion of a specific operation will occur only when
 * progress is called.
 *
 * \param context [IN]          pointer to HG core context
 * \param timeout [IN]          timeout (in milliseconds)
 *
 * \return HG_SUCCESS if any completion has occurred / HG error code otherwise
 */
HG_PUBLIC hg_return_t
HG_Core_progress(hg_core_context_t *context, unsigned int timeout);

/**
 * (Deprecated in favor of HG_Core_event_trigger())
 * Execute at most max_count callbacks. If timeout is non-zero, wait up to
 * timeout before returning. Function can return when at least one or more
 * callbacks are triggered (at most max_count).
 *
 * \param context [IN]          pointer to HG core context
 * \param timeout [IN]          timeout (in milliseconds)
 * \param max_count [IN]        maximum number of callbacks triggered
 * \param actual_count_p [OUT]  actual number of callbacks triggered
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_PUBLIC hg_return_t
HG_Core_trigger(hg_core_context_t *context, unsigned int timeout,
    unsigned int max_count, unsigned int *actual_count_p);

/**
 * Retrieve file descriptor from internal wait object when supported.
 * The descriptor can be used by upper layers for manual polling through the
 * usual OS select/poll/epoll calls.
 *
 * \param context [IN]          pointer to HG core context
 *
 * \return Non-negative integer if supported and negative if not supported
 */
HG_PUBLIC int
HG_Core_event_get_wait_fd(
    const hg_core_context_t *context) HG_WARN_UNUSED_RESULT;

/**
 * Used to signal when it is safe to block on the file descriptor of the
 * context's wait object or if there is already work that can be progressed.
 * Calling HG_Core_event_ready() is mandatory before any call to
 * select/poll/epoll (or equivalent) or the callee may not be signaled during
 * these calls.
 *
 * \param context [IN/OUT]      pointer to HG core context
 *
 * \return true if there is already work to be progressed or false otherwise
 */
HG_PUBLIC bool
HG_Core_event_ready(hg_core_context_t *context) HG_WARN_UNUSED_RESULT;

/**
 * Progress communication by placing any completed RPC events into the
 * context's completion queue. Completed operations's callbacks can be triggered
 * by a call to HG_Core_event_trigger().
 *
 * \param context [IN/OUT]      pointer to HG core context
 * \param count_p [OUT]         number of entries in context completion queue
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_PUBLIC hg_return_t
HG_Core_event_progress(hg_core_context_t *context, unsigned int *count_p);

/**
 * Execute at most max_count callbacks.
 *
 * \param context [IN]          pointer to HG core context
 * \param max_count [IN]        maximum number of callbacks triggered
 * \param actual_count_p [OUT]  actual number of callbacks triggered
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_PUBLIC hg_return_t
HG_Core_event_trigger(hg_core_context_t *context, unsigned int max_count,
    unsigned int *actual_count_p);

/************************************/
/* Local Type and Struct Definition */
/************************************/

/* HG core class */
struct hg_core_class {
    na_class_t *na_class; /* NA class */
#ifdef NA_HAS_SM
    na_class_t *na_sm_class; /* NA SM class */
#endif
    void *data;                         /* User data */
    void (*data_free_callback)(void *); /* User data free callback */
};

/* HG core context */
struct hg_core_context {
    struct hg_core_class *core_class; /* HG core class */
    na_context_t *na_context;         /* NA context */
#ifdef NA_HAS_SM
    na_context_t *na_sm_context; /* NA SM context */
#endif
    void *data;                         /* User data */
    void (*data_free_callback)(void *); /* User data free callback */
    uint8_t id;                         /* Context ID */
};

/* HG core addr */
struct hg_core_addr {
    struct hg_core_class *core_class; /* HG core class */
    na_addr_t *na_addr;               /* NA address */
#ifdef NA_HAS_SM
    na_addr_t *na_sm_addr; /* NA SM address */
#endif
    uint8_t is_self; /* Self address */
};

/* HG core RPC registration info */
struct hg_core_rpc_info {
    hg_core_rpc_cb_t rpc_cb;       /* RPC callback */
    void *data;                    /* User data */
    void (*free_callback)(void *); /* User data free callback */
    hg_id_t id;                    /* RPC ID */
    uint8_t no_response;           /* RPC response not expected */
};

/* HG core handle */
struct hg_core_handle {
    struct hg_core_info info;           /* HG info */
    struct hg_core_rpc_info *rpc_info;  /* Associated RPC registration info */
    void *data;                         /* User data */
    void (*data_free_callback)(void *); /* User data free callback */
    void *in_buf;                       /* Input buffer */
    void *out_buf;                      /* Output buffer */
    size_t in_buf_size;                 /* Input buffer size */
    size_t out_buf_size;                /* Output buffer size */
    size_t na_in_header_offset;         /* Input NA header offset */
    size_t na_out_header_offset;        /* Output NA header offset */
    size_t in_buf_used;                 /* Amount of input buffer used */
    size_t out_buf_used;                /* Amount of output buffer used */
};

/*---------------------------------------------------------------------------*/
static HG_INLINE const char *
HG_Core_class_get_name(const hg_core_class_t *hg_core_class)
{
    return NA_Get_class_name(hg_core_class->na_class);
}

/*---------------------------------------------------------------------------*/
static HG_INLINE const char *
HG_Core_class_get_protocol(const hg_core_class_t *hg_core_class)
{
    return NA_Get_class_protocol(hg_core_class->na_class);
}

/*---------------------------------------------------------------------------*/
static HG_INLINE bool
HG_Core_class_is_listening(const hg_core_class_t *hg_core_class)
{
    return NA_Is_listening(hg_core_class->na_class);
}

/*---------------------------------------------------------------------------*/
static HG_INLINE na_class_t *
HG_Core_class_get_na(const hg_core_class_t *hg_core_class)
{
    return hg_core_class->na_class;
}

/*---------------------------------------------------------------------------*/
#ifdef NA_HAS_SM
static HG_INLINE na_class_t *
HG_Core_class_get_na_sm(const hg_core_class_t *hg_core_class)
{
    return hg_core_class->na_sm_class;
}
#endif

/*---------------------------------------------------------------------------*/
static HG_INLINE hg_size_t
HG_Core_class_get_input_eager_size(const hg_core_class_t *hg_core_class)
{
    hg_size_t unexp = NA_Msg_get_max_unexpected_size(hg_core_class->na_class),
              header =
                  hg_core_header_request_get_size() +
                  NA_Msg_get_unexpected_header_size(hg_core_class->na_class);

    return (unexp > header) ? unexp - header : 0;
}

/*---------------------------------------------------------------------------*/
static HG_INLINE hg_size_t
HG_Core_class_get_output_eager_size(const hg_core_class_t *hg_core_class)
{
    hg_size_t exp = NA_Msg_get_max_expected_size(hg_core_class->na_class),
              header = hg_core_header_response_get_size() +
                       NA_Msg_get_expected_header_size(hg_core_class->na_class);

    return (exp > header) ? exp - header : 0;
}

/*---------------------------------------------------------------------------*/
static HG_INLINE hg_return_t
HG_Core_class_set_data(
    hg_core_class_t *hg_core_class, void *data, void (*free_callback)(void *))
{
    hg_core_class->data = data;
    hg_core_class->data_free_callback = free_callback;

    return HG_SUCCESS;
}

/*---------------------------------------------------------------------------*/
static HG_INLINE void *
HG_Core_class_get_data(const hg_core_class_t *hg_core_class)
{
    return hg_core_class->data;
}

/*---------------------------------------------------------------------------*/
static HG_INLINE hg_core_class_t *
HG_Core_context_get_class(const hg_core_context_t *context)
{
    return context->core_class;
}

/*---------------------------------------------------------------------------*/
static HG_INLINE na_context_t *
HG_Core_context_get_na(const hg_core_context_t *context)
{
    return context->na_context;
}

/*---------------------------------------------------------------------------*/
#ifdef NA_HAS_SM
static HG_INLINE na_context_t *
HG_Core_context_get_na_sm(const hg_core_context_t *context)
{
    return context->na_sm_context;
}
#endif

/*---------------------------------------------------------------------------*/
static HG_INLINE uint8_t
HG_Core_context_get_id(const hg_core_context_t *context)
{
    return context->id;
}

/*---------------------------------------------------------------------------*/
static HG_INLINE hg_return_t
HG_Core_context_set_data(
    hg_core_context_t *context, void *data, void (*free_callback)(void *))
{
    context->data = data;
    context->data_free_callback = free_callback;

    return HG_SUCCESS;
}

/*---------------------------------------------------------------------------*/
static HG_INLINE void *
HG_Core_context_get_data(const hg_core_context_t *context)
{
    return context->data;
}

/*---------------------------------------------------------------------------*/
static HG_INLINE na_addr_t *
HG_Core_addr_get_na(hg_core_addr_t addr)
{
    return addr->na_addr;
}

/*---------------------------------------------------------------------------*/
#ifdef NA_HAS_SM
static HG_INLINE na_addr_t *
HG_Core_addr_get_na_sm(hg_core_addr_t addr)
{
    return addr->na_sm_addr;
}
#endif

/*---------------------------------------------------------------------------*/
static HG_INLINE bool
HG_Core_addr_is_self(hg_core_addr_t addr)
{
    return (bool) addr->is_self;
}

/*---------------------------------------------------------------------------*/
static HG_INLINE hg_return_t
HG_Core_set_data(
    hg_core_handle_t handle, void *data, void (*free_callback)(void *))
{
    handle->data = data;
    handle->data_free_callback = free_callback;

    return HG_SUCCESS;
}

/*---------------------------------------------------------------------------*/
static HG_INLINE void *
HG_Core_get_data(hg_core_handle_t handle)
{
    return handle->data;
}

/*---------------------------------------------------------------------------*/
static HG_INLINE const struct hg_core_info *
HG_Core_get_info(hg_core_handle_t handle)
{
    return &handle->info;
}

/*---------------------------------------------------------------------------*/
static HG_INLINE const void *
HG_Core_get_rpc_data(hg_core_handle_t handle)
{
    return (handle->rpc_info) ? handle->rpc_info->data : NULL;
}

/*---------------------------------------------------------------------------*/
static HG_INLINE hg_return_t
HG_Core_set_target_id(hg_core_handle_t handle, uint8_t id)
{
    handle->info.context_id = id;

    return HG_SUCCESS;
}

/*---------------------------------------------------------------------------*/
static HG_INLINE size_t
HG_Core_get_input_payload_size(hg_core_handle_t handle)
{
    size_t header_size =
        hg_core_header_request_get_size() + handle->na_in_header_offset;

    if (handle->in_buf_used > header_size)
        return handle->in_buf_used - header_size;
    else
        return 0;
}

/*---------------------------------------------------------------------------*/
static HG_INLINE hg_return_t
HG_Core_get_input(
    hg_core_handle_t handle, void **in_buf_p, hg_size_t *in_buf_size_p)
{
    hg_size_t header_offset =
        hg_core_header_request_get_size() + handle->na_in_header_offset;

    if (handle->in_buf == NULL)
        return HG_FAULT;

    /* Space must be left for request header */
    *in_buf_p = (char *) handle->in_buf + header_offset;
    *in_buf_size_p = handle->in_buf_size - header_offset;

    return HG_SUCCESS;
}

/*---------------------------------------------------------------------------*/
static HG_INLINE size_t
HG_Core_get_output_payload_size(hg_core_handle_t handle)
{
    size_t header_size =
        hg_core_header_response_get_size() + handle->na_out_header_offset;

    if (handle->out_buf_used > header_size)
        return handle->out_buf_used - header_size;
    else
        return 0;
}

/*---------------------------------------------------------------------------*/
static HG_INLINE hg_return_t
HG_Core_get_output(
    hg_core_handle_t handle, void **out_buf_p, hg_size_t *out_buf_size_p)
{
    hg_size_t header_offset =
        hg_core_header_response_get_size() + handle->na_out_header_offset;

    /* Space must be left for response header */
    *out_buf_p = (char *) handle->out_buf + header_offset;
    *out_buf_size_p = handle->out_buf_size - header_offset;

    return HG_SUCCESS;
}

#ifdef __cplusplus
}
#endif

#endif /* MERCURY_CORE_H */
