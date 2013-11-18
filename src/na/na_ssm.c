/*
 * Copyright (C) 2013 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

/**
 * Assumptions: - When na_ssm_cancel() is called, the caller will
 * guarantee that the op id pointer is valid throughout the operation,
 * and not removed from under the cancel request.
 */

/*
 * API Order in the file:
 *  - Send Unexpected
 *  - Recv Unexpected
 *  - Send Expected
 *  - Recv Expected
 *  - Put
 *  - Register
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <unistd.h>
#include <assert.h>

/* Mercury */
#include "mercury_hash_table.h"
#include "mercury_list.h"
#include "mercury_thread.h"
#include "mercury_thread_mutex.h"
#include "mercury_thread_condition.h"
#include "mercury_time.h"

/* NA */
#include "na.h"
#include "na_error.h"
#include "na_private.h"
#include "na_ssm.h"

/* SSM */
#include <ssm/dumb.h>
#include <ssm.h>
#include <ssmptcp.h>

/* Static functions local to SSM */
static na_class_t*
na_ssm_initialize(const struct na_host_buffer *in_host_buffer,
                  na_bool_t                    in_listen);

static na_bool_t
na_ssm_verify(const char *protocol);

static na_return_t
na_ssm_finalize(na_class_t *in_na_class);

static na_return_t
na_ssm_addr_lookup(na_class_t   *in_na_class,
                   na_cb_t       in_callback,
                   void         *in_arg,
                   const char   *in_name,
                   na_op_id_t   *out_opid);

static na_return_t
na_ssm_addr_free(na_class_t   *in_na_class,
                 na_addr_t     in_addr);

static na_return_t
na_ssm_addr_to_string(na_class_t   *in_na_class,
                      char         *inout_buf,
                      na_size_t     in_buf_size,
                      na_addr_t     in_addr);

static na_size_t
na_ssm_msg_get_max_expected_size(na_class_t *in_na_class);

static na_size_t
na_ssm_msg_get_max_unexpected_size(na_class_t *in_na_class);

static na_tag_t
na_ssm_msg_get_maximum_tag(na_class_t  *in_na_class);

static na_return_t
na_ssm_msg_send_unexpected(na_class_t     *in_na_class,
                           na_cb_t         in_callback,
                           void           *in_arg,
                           const void     *in_buf,
                           na_size_t       in_buf_size,
                           na_addr_t       in_destination,
                           na_tag_t        in_tag,
                           na_op_id_t     *out_opid);

static na_return_t
na_ssm_msg_recv_unexpected(na_class_t     *in_na_class,
                           na_cb_t         in_callback,
                           void           *in_user_context,
                           void           *in_buf,
                           na_size_t       in_buf_size,
                           na_op_id_t     *out_opid);

static na_return_t
na_ssm_msg_send_expected(na_class_t  *in_na_class,
                         na_cb_t      in_callback,
                         void        *in_user_context,
                         const void  *in_buf,
                         na_size_t    in_buf_size,
                         na_addr_t    in_dest,
                         na_tag_t     in_tag,
                         na_op_id_t  *out_id);

static na_return_t
na_ssm_msg_recv_expected(na_class_t     *in_na_class,
                         na_cb_t         in_callback,
                         void           *in_context,
                         void           *in_buf,
                         na_size_t       in_buf_size,
                         na_addr_t       in_source,
                         na_tag_t        in_tag,
                         na_op_id_t     *out_id);

static na_return_t
na_ssm_mem_handle_create(na_class_t       *in_na_class,
                         void             *in_buf,
                         na_size_t         in_buf_size,
                         unsigned long     in_flags,
                         na_mem_handle_t  *out_mem_handle);

static na_return_t
na_ssm_mem_handle_free(na_class_t       *in_na_class,
                       na_mem_handle_t   in_mem_handle);

static na_return_t
na_ssm_mem_register(na_class_t        *in_na_class,
                    na_mem_handle_t    in_mem_handle);

static na_return_t
na_ssm_mem_deregister(na_class_t      *in_na_class,
                      na_mem_handle_t  in_mem_handle);

static na_size_t
na_ssm_mem_handle_get_serialize_size(na_class_t     *in_na_class,
                                     na_mem_handle_t in_mem_handle);

static na_return_t
na_ssm_mem_handle_serialize(na_class_t        *in_na_class,
                            void              *in_buf,
                            na_size_t          in_buf_size,
                            na_mem_handle_t    in_mem_handle);

static na_return_t
na_ssm_mem_handle_deserialize(na_class_t      *in_na_class,
                              na_mem_handle_t *in_mem_handle,
                              const void      *in_buf,
                              na_size_t        in_buf_size);

static na_return_t
na_ssm_put(na_class_t         *in_na_class,
           na_cb_t             in_callback,
           void               *in_context,
           na_mem_handle_t     in_local_mem_handle,
           na_offset_t         in_local_offset,
           na_mem_handle_t     in_remote_mem_handle,
           na_offset_t         in_remote_offset,
           na_size_t           in_data_size,
           na_addr_t           in_remote_addr,
           na_op_id_t         *out_opid);

static na_return_t
na_ssm_get(na_class_t         *in_na_class,
           na_cb_t             in_callback,
           void               *in_context,
           na_mem_handle_t     in_local_mem_handle,
           na_offset_t         in_local_offset,
           na_mem_handle_t     in_remote_mem_handle,
           na_offset_t         in_remote_offset,
           na_size_t           in_data_size,
           na_addr_t           in_remote_addr,
           na_op_id_t         *out_opid);

static na_return_t
na_ssm_progress(na_class_t     *in_na_class,
                unsigned int    in_timeout);

static na_return_t
na_ssm_cancel(na_class_t    *in_na_class,
              na_op_id_t     in_opid);

static const char na_ssm_name_g[] = "ssm";

const struct na_class_describe na_ssm_describe_g = {
    na_ssm_name_g,
    na_ssm_verify,
    na_ssm_initialize
};

/* Callbacks */
static void
na_ssm_addr_lookup_release(struct na_cb_info *in_info,
                           void              *in_opid);

static void
na_ssm_msg_recv_release(struct na_cb_info *in_info,
                        void              *in_na_ssm_opid);

static void
na_ssm_msg_send_expected_release(struct na_cb_info *in_info,
                                 void              *in_na_ssm_opid);

static void
na_ssm_unexpected_msg_send_release(struct na_cb_info *in_info,
                                   void              *in_na_ssm_opid);

static void
na_ssm_unexpected_msg_send_callback(void *in_context,
                                    void *in_ssm_event_data);

static void
na_ssm_msg_recv_expected_callback(void *in_context,
                                  void *in_ssm_event_data);

static void
na_ssm_msg_recv_unexpected_callback(void *in_context,
                                    void *in_ssm_event_data);

static void
na_ssm_get_callback(void *cbdat, void *evdat);

static void
na_ssm_msg_send_expected_callback(void *in_context,
                                  void *in_ssm_event_data) ;

static void
na_ssm_put_callback(void *cbdat, void *evdat);

static void
na_ssm_post_callback(void NA_UNUSED(*cbdat), void *evdat);

#ifdef NA_HAS_CLIENT_THREAD
static hg_thread_mutex_t finalizing_mutex;
static bool              finalizing;
static hg_thread_t       progress_service;
#endif

/**
 * Generate unique matchbits
 *
 * @param  in_na_class
 * @return ssm_bits
 */
static inline ssm_bits
generate_unique_matchbits(na_class_t *in_na_class)
{
    struct na_ssm_private_data *v_data = NA_SSM_GET_PRIVATE_DATA(in_na_class);
    
    hg_thread_mutex_lock(&v_data->gen_matchbits);
    v_data->cur_bits++;
    hg_thread_mutex_unlock(&v_data->gen_matchbits);
    
    return v_data->cur_bits;
}

#ifdef NA_HAS_CLIENT_THREAD
/**
 * Function to ensure progress on one-sided operations.
 *
 * @param  in_args
 * @return (void *)
 */
static void*
na_ssm_progress_service(void NA_UNUSED(*in_args))
{
    na_bool_t service_done = 0;

    while (!service_done) {
        na_return_t na_ret;

        hg_thread_mutex_lock(&finalizing_mutex);
        service_done = (finalizing) ? 1 : 0;
        hg_thread_mutex_unlock(&finalizing_mutex);

        na_ret = na_ssm_progress(NULL, 0);
        if (na_ret != NA_SUCCESS) {
            NA_LOG_ERROR("Could not make progress");
            break;
        }

        sleep(0);

        if (service_done)
          break;
    }

    return NULL;
}
#endif

/**
 * Verify if the plugin can accept the input protocol string.
 *
 * @param  in_protocol  Protocol buffer in string.
 * @return na_bool_t    NA_TRUE or NA_FALSE
 */
static na_bool_t
na_ssm_verify(const char *in_protocol)
{
    na_bool_t accept = NA_FALSE;
    
    if (strcmp(in_protocol, "tcp") == 0) {
        accept = NA_TRUE;
    }

    return accept;
}

/**
 * Initialize SSM's transport protocol for the given plugin.
 *
 */
static na_return_t
na_ssm_initialize_ssm_tp(struct na_class      *in_na_ssm_class,
                         const char           *in_protocol,
                         unsigned int          in_port)
{
    struct na_ssm_private_data *v_data = (struct na_ssm_private_data *) in_na_ssm_class->private_data;
    
    if (strcmp(in_protocol, "tcp") == 0)
    {
        v_data->itp = ssmptcp_new_tp(in_port, SSM_NOF);

        if (v_data->itp == NULL)
        {
            NA_LOG_ERROR("Unable to create transport protocol.\n");
            return NA_FAIL; 
        }
    }
    else
    {
        NA_LOG_ERROR("Unable to handle this protocol.\n");
        return NA_INVALID_PARAM;
    }

    return NA_SUCCESS;
}

/**
 * Initialize the SSM buffers.
 *
 * @param  in_na_buffer  Input buffer containing the connection
 *                       information
 * @param  in_listen     Listen flag indicating if this is a server
 *                       or a client.  This is currently being ignored here.
 * @return na_class_t*   Returns a pointer to a location that maps to
 *                       na_ssm_class.
 */
static na_class_t*
na_ssm_initialize(const struct na_host_buffer  *in_na_buffer,
                  na_bool_t                     in_listen)
{
    struct na_class             *v_class     = NULL;
    struct na_ssm_private_data  *v_ssm_data  = NULL;
    na_return_t                  v_return    = NA_SUCCESS;
    int                          i           = 0;

    NA_LOG_DEBUG("Initializing NA-SSM using %s on port %d in "
                 "%d mode.\n", in_na_buffer->na_protocol,
                 in_na_buffer->na_port, in_listen);

    v_class = (struct na_class *) malloc(sizeof(struct na_class));

    if (__unlikely(v_class == NULL))
    {
        NA_LOG_ERROR("Out of memory error.\n");
        return NULL;
    }

    v_ssm_data = (struct na_ssm_private_data *) malloc(sizeof(struct na_ssm_private_data));

    if (__unlikely(v_ssm_data == NULL))
    {
        NA_LOG_ERROR("Out of memory error.\n");
        free(v_class);
        return NULL;
    }

    v_class->private_data      = (void *) v_ssm_data;
    
    v_class->finalize          = na_ssm_finalize;
    v_class->addr_lookup       = na_ssm_addr_lookup;
    v_class->addr_free         = na_ssm_addr_free;
    v_class->addr_to_string    = na_ssm_addr_to_string;
    v_class->msg_get_max_expected_size = na_ssm_msg_get_max_expected_size;
    v_class->msg_get_max_unexpected_size = na_ssm_msg_get_max_unexpected_size;
    v_class->msg_get_max_tag = na_ssm_msg_get_maximum_tag;
    v_class->msg_send_unexpected = na_ssm_msg_send_unexpected;
    v_class->msg_recv_unexpected = na_ssm_msg_recv_unexpected;
    v_class->msg_send_expected = na_ssm_msg_send_expected;
    v_class->msg_recv_expected = na_ssm_msg_recv_expected;
    v_class->mem_handle_create = na_ssm_mem_handle_create;
    v_class->mem_handle_create_segments = NULL;
    v_class->mem_handle_free = na_ssm_mem_handle_free;
    v_class->mem_register = na_ssm_mem_register;
    v_class->mem_deregister = na_ssm_mem_deregister;
    v_class->mem_handle_get_serialize_size = na_ssm_mem_handle_get_serialize_size;
    v_class->mem_handle_serialize = na_ssm_mem_handle_serialize;
    v_class->mem_handle_deserialize = na_ssm_mem_handle_deserialize;
    v_class->put = na_ssm_put;
    v_class->get = na_ssm_get;
    v_class->progress = na_ssm_progress;
    v_class->cancel = na_ssm_cancel;
    
    v_return = na_ssm_initialize_ssm_tp(v_class,
                                        in_na_buffer->na_protocol,
                                        in_na_buffer->na_port);

    if (v_return != NA_SUCCESS)
    {
        NA_LOG_ERROR("Unable to initialize SSM transport protocol.\n");
        return NULL;
    }

    v_ssm_data->ssm = ssm_start(v_ssm_data->itp,
                                NULL,
                                SSM_NOF);

    if (v_ssm_data->ssm == NULL)
    {
        NA_LOG_ERROR("Unable to start ssm transport.\n");
        v_return = NA_PROTOCOL_ERROR;
        goto cleanup;
    }

    /* Prepare unexpected receive buffers */
    v_ssm_data->unexpbuf_cpos      = 0;
    v_ssm_data->unexpbuf_rpos      = 0;
    v_ssm_data->unexpbuf_availpos  = -1;
    v_ssm_data->cur_bits           = 0;

    v_ssm_data->unexpected_callback.pcb    = na_ssm_msg_recv_unexpected_callback;
    v_ssm_data->unexpected_callback.cbdata = v_class;

    v_ssm_data->unexpected_me = ssm_link(v_ssm_data->ssm,
                                         0,
                                         ((ssm_bits) 0xffffffffffffffff >> 2),
                                         SSM_POS_HEAD,
                                         NULL,
                                         &(v_ssm_data->unexpected_callback),
                                         SSM_NOF);

    if (v_ssm_data->unexpected_me == NULL)
    {
        NA_LOG_ERROR("Unable to create SSM link.\n");
        v_return = NA_PROTOCOL_ERROR;
        goto cleanup;
    }

    for (i = 0; i < NA_SSM_UNEXPECTED_BUFFERCOUNT; i++)
    {
        v_ssm_data->unexpbuf[i].buf = (char *) malloc(NA_SSM_UNEXPECTED_SIZE);

        if (v_ssm_data->unexpbuf[i].buf == NULL)
        {
            goto cleanup;
        }
        
        v_ssm_data->unexpbuf[i].mr  = ssm_mr_create(NULL,
                                                    v_ssm_data->unexpbuf[i].buf,
                                                    NA_SSM_UNEXPECTED_SIZE);
        
        if (v_ssm_data->unexpbuf[i].mr == NULL)
        {
            goto cleanup;
        }
        
        v_ssm_data->unexpbuf[i].valid = 0;

        v_return = ssm_post(v_ssm_data->ssm,
                            v_ssm_data->unexpected_me,
                            v_ssm_data->unexpbuf[i].mr,
                            SSM_NOF);

        if (v_return < 0)
        {
            NA_LOG_ERROR("Post failed (init)");
        }
        
        v_ssm_data->unexpbuf_availpos = NA_SSM_NEXT_UNEXPBUF_POS(v_ssm_data->unexpbuf_availpos);
    }

    hg_thread_mutex_init(&v_ssm_data->request_mutex);
    hg_thread_cond_init(&v_ssm_data->comp_req_cond);
    hg_thread_mutex_init(&v_ssm_data->unexp_buf_mutex);
    hg_thread_cond_init(&v_ssm_data->unexp_buf_cond);
    hg_thread_mutex_init(&v_ssm_data->gen_matchbits);

#ifdef NA_HAS_CLIENT_THREAD
    hg_thread_mutex_init(&finalizing_mutex);
    hg_thread_create(&progress_service, &na_ssm_progress_service, NULL);
#endif

    return (na_class_t *) v_class;
    
 cleanup:
    return NULL;
}

/**
 * Finalize the SSM abstraction.
 *
 * @param  in_na_class
 * @return na_return_t
 */
static na_return_t
na_ssm_finalize(na_class_t *in_na_class)
{
    int                  v_return    = 0;
    struct na_ssm_private_data *v_data = (struct na_ssm_private_data *) in_na_class->private_data;

    v_return = ssm_stop(v_data->ssm);

    if (v_return < 0)
      return NA_FAIL;
    else
      return NA_SUCCESS;
}

/**
 * Look up an address from the input address buffer.
 *
 * @param   in_na_class
 * @param   in_callback   User provided callback function
 * @param   in_arg
 * @param   in_name
 * @param   out_opid      Operation ID returned to the caller
 * @return  na_return_t   NA_SUCCESS on success, failure code otherwise
 */
static na_return_t
na_ssm_addr_lookup(na_class_t  *in_na_class,
                   na_cb_t      in_callback,
                   void        *in_arg,
                   const char  *in_name,
                   na_op_id_t  *out_opid)
{
    struct na_ssm_private_data     *v_data    = (struct na_ssm_private_data *) in_na_class->private_data;
    ssmptcp_addrargs_t   v_addrargs;
    struct na_ssm_addr  *v_ssm_addr     = NULL;
    struct na_cb_info   *v_cbinfo       = NULL;
    char                 v_protocol[16];
    na_return_t          v_return       = NA_SUCCESS;
    struct na_ssm_opid  *v_ssm_opid     = NULL;

    v_ssm_addr = (struct na_ssm_addr *) malloc(sizeof(struct na_ssm_addr));

    if (__unlikely(v_ssm_addr == NULL))
    {
        return NA_NOMEM_ERROR;
    }

    sscanf(in_name, "%15[^:]://%63[^:]:%d", v_protocol,
           v_addrargs.host, &(v_addrargs.port));
    
    v_ssm_addr->addr = ssm_addr_create(v_data->ssm,
                                       &v_addrargs);

    if(v_ssm_addr->addr == NULL)
    {
        free(v_ssm_addr);
        return NA_FAIL;
    }
    
    v_cbinfo = (struct na_cb_info *) malloc(sizeof(struct na_cb_info));

    if (__unlikely(v_cbinfo == NULL))
    {
        free(v_ssm_addr);
        return NA_NOMEM_ERROR;
    }

    /* Fill the callback info structure */
    v_cbinfo->arg          = in_arg; 
    v_cbinfo->ret          = NA_SUCCESS; 
    v_cbinfo->type         = NA_CB_LOOKUP; 
    v_cbinfo->info.lookup.addr  = v_ssm_addr; 

    v_ssm_opid = (struct na_ssm_opid *) malloc(sizeof(struct na_ssm_opid));

    if (__unlikely(v_ssm_opid == NULL))
    {
        free(v_ssm_addr);
        return NA_NOMEM_ERROR;
    }

    memset(v_ssm_opid, 0, sizeof(struct na_ssm_opid));
    
    v_ssm_opid->requesttype = SSM_ADDR_LOOKUP_OP;
    
    /* Ignoring the return value here; because this operation *should/can*
     * never fail.
     */
    v_return = na_cb_completion_add(in_callback,
                                    v_cbinfo,
                                    na_ssm_addr_lookup_release,
                                    v_ssm_opid);

    (*out_opid) = (na_op_id_t *) v_ssm_opid;
    
    return v_return;
}

/**
 * Function called to release any resources allocated during the lookup
 * operation.
 *
 * @see na_ssm_addr_lookup
 *
 * @param in_info    NA callback info structure.
 * @param in_opid    Op ID structure allocated by the lookup operation.
 *
 */
static void
na_ssm_addr_lookup_release(struct na_cb_info *in_info,
                           void              *in_opid)
{
    free(in_info);
    free(in_opid);
}

/**
 * Free the address.
 *
 * @param  in_na_class
 * @param  in_addr
 * @return NA_SUCCESS always.
 */
static na_return_t
na_ssm_addr_free(na_class_t    NA_UNUSED *in_na_class,
                 na_addr_t                in_addr)
{
    struct na_ssm_addr *v_addr = (struct na_ssm_addr *) in_addr;

    free(v_addr);
    
    return NA_SUCCESS;
}

/**
 * Convert the given input address to string.
 */
static na_return_t
na_ssm_addr_to_string(na_class_t     NA_UNUSED *in_na_class,
                      char           NA_UNUSED *inout_buf,
                      na_size_t      NA_UNUSED  in_buf_size,
                      na_addr_t      NA_UNUSED  in_addr)
{
    return NA_FAIL;
}

/**
 * Returns maximum expected message size.
 *
 * @param  in_na_class
 * @return na_size_t    Maximum expected message size.
 */
static na_size_t
na_ssm_msg_get_max_expected_size(na_class_t NA_UNUSED *in_na_class)
{
    return NA_SSM_EXPECTED_SIZE;
}

/**
 * Returns maximum unexpected message size.
 *
 * @param  in_na_class
 * @return na_size_t     Maximum unexpected message size.
 */
static na_size_t
na_ssm_msg_get_max_unexpected_size(na_class_t NA_UNUSED *in_na_class)
{
    return NA_SSM_UNEXPECTED_SIZE;
}

/**
 * Returns the maximum tag on a message.
 *
 * @param  in_na_class
 * @return na_tag_t     Maximum tag on a message.
 */
static na_tag_t
na_ssm_msg_get_maximum_tag(na_class_t NA_UNUSED *in_na_class)
{
    return (na_tag_t) (UINT32_MAX);
}

/*======================================================
 * SEND UNEXPECTED
 *======================================================*/

/**
 * Send an unexpected message to the destination.
 *
 * @param   in_callback      User callback
 * @param   in_context       User context
 * @param   in_buf           Input buffer
 * @param   in_buf_size      Input buffer size
 * @param   in_destination   Destination address
 * @param   in_tag           Match entry tag
 * @param   out_opid         NA Op ID
 * @return  na_return_t      NA_SUCCESS/NA_FAIL/NA_NOMEM_ERROR
 *
 * @see na_ssm_unexpected_msg_send_callback()
 * @see na_ssm_unexpected_msg_send_release_callback()
 */
static na_return_t
na_ssm_msg_send_unexpected(na_class_t    *in_na_class,
                           na_cb_t        in_callback,
                           void          *in_context,
                           const void    *in_buf,
                           na_size_t      in_buf_size,
                           na_addr_t      in_destination,
                           na_tag_t       in_tag,
                           na_op_id_t    *out_opid)
{
    na_return_t           v_return          = NA_SUCCESS;
    ssm_size_t            v_ssm_buf_size    = (ssm_size_t) in_buf_size;
    struct na_ssm_addr   *v_ssm_peer_addr   = (struct na_ssm_addr *) in_destination;
    ssm_msg_tag_t         v_ssm_tag         = (ssm_msg_tag_t) in_tag;
    struct na_ssm_opid   *v_ssm_opid        = NULL;
    ssm_mr                v_ssm_mr          = NULL;
    ssm_tx                v_ssm_tx          = NULL;
    struct na_ssm_private_data  *v_data       = (struct na_ssm_private_data *) in_na_class->private_data;
    ssm_cb_t              v_ssm_callback;

    if (__unlikely(in_buf == NULL))
    {
        return NA_INVALID_PARAM;
    }
    
    v_ssm_opid = (struct na_ssm_opid *) malloc(sizeof(struct na_ssm_opid));

    if (__unlikely(v_ssm_opid == NULL))
    {
        return NA_NOMEM_ERROR;
    }

    memset(v_ssm_opid, 0, sizeof(struct na_ssm_opid));
    
    v_ssm_opid->requesttype = SSM_UNEXP_SEND_OP;
    v_ssm_opid->user_context = in_context;
    
    v_ssm_opid->opid_info.send_unexpected.matchbits = (ssm_bits) in_tag +
      NA_SSM_TAG_UNEXPECTED_OFFSET;

    v_ssm_mr = ssm_mr_create(NULL,
                             (void *) in_buf,
                             v_ssm_buf_size);

    if (v_ssm_mr == NULL)
    {
        v_return = NA_FAIL;
        goto out;
    }

    v_ssm_opid->user_callback   = in_callback;
    v_ssm_opid->user_context    = in_context;
    
    v_ssm_callback.pcb    = na_ssm_unexpected_msg_send_callback;
    v_ssm_callback.cbdata = v_ssm_opid;

    v_ssm_tx = ssm_put(v_data->ssm,
                       v_ssm_peer_addr->addr,
                       v_ssm_mr,
                       NULL,
                       v_ssm_tag,
                       &v_ssm_callback,
                       SSM_NOF);

    if (v_ssm_tx == NULL)
    {
        v_return = NA_FAIL;
        goto out;
    }
    
    v_ssm_opid->transaction = v_ssm_tx;
    v_ssm_opid->opid_info.send_unexpected.memregion = v_ssm_mr;

    (*out_opid) = (na_op_id_t *) v_ssm_opid;
    
 out:

    if (v_return != NA_SUCCESS)
    {
        /* release all allocated resources */
        if (v_ssm_mr != NULL)
        {
            ssm_mr_destroy(v_ssm_mr);
        }

        if (v_ssm_opid != NULL)
        {
            free(v_ssm_opid);
        }
    }
    
    return v_return;
}

/**
 * Callback routine for unexpected send message.  This routine is
 * called once the unexpected message completes.
 *
  * @see na_ssm_msg_send_unexpected()
 *
 * @param in_context
 * @param in_ssm_event_data
 *
 */
static void
na_ssm_unexpected_msg_send_callback(void *in_context,
                                    void *in_ssm_event_data) 
{
    ssm_result          v_result         = in_ssm_event_data;
    struct na_ssm_opid *v_ssm_opid       = in_context;
    struct na_cb_info  *v_cbinfo         = NULL;
    na_return_t         v_return         = NA_SUCCESS;
    struct na_ssm_private_data *v_ssm_data = v_ssm_opid->ssm_data;
    
    /* Allocate this memory before we proceed */
    v_cbinfo = (struct na_cb_info *) malloc(sizeof(struct na_cb_info));

    if (__unlikely(v_cbinfo == NULL))
    {
        free(v_ssm_opid);
        v_return = NA_NOMEM_ERROR;
        return;
    }
    
    memset(v_cbinfo, 0, sizeof(struct na_cb_info));
    
    if (v_result->status == SSM_ST_COMPLETE)
    {
        NA_SSM_MARK_OPID_COMPLETE(v_ssm_opid);
        v_return = NA_SUCCESS;
    }
    else if (v_result->status == SSM_ST_CANCEL)
    {
        NA_SSM_MARK_OPID_CANCELED(v_ssm_opid);
        v_return = NA_CANCELED;
    }
    else
    {
        NA_LOG_ERROR("unexp_msg_send_cb(): cb error");
    }

    v_cbinfo->arg = v_ssm_opid->user_context;
    v_cbinfo->ret = v_return;
    
    hg_thread_mutex_lock(&v_ssm_data->request_mutex);
    
    //wake up others
    hg_thread_cond_signal(&v_ssm_data->comp_req_cond);

    hg_thread_mutex_unlock(&v_ssm_data->request_mutex);

    /* Ignoring the return status code because there isn't much we
     * can do if we get an error queueing the callback request.  There
     * must be something majorly wrong in the NA layer.
     */
    na_cb_completion_add(v_ssm_opid->user_callback,
                         v_cbinfo,
                         na_ssm_unexpected_msg_send_release,
                         v_ssm_opid);
}

/**
 * Callback called after NA has called the user's callback.  This
 * callback function only does cleanup/release of resources that were
 * allocated at the beginning of the send unexpected operation.
 *
 * @see na_ssm_msg_send_unexpected()
 * @see na_ssm_unexpected_msg_send_callback()
 *
 * @param in_na_ssm_opid
 * @param in_release_context
 *
 */
static void
na_ssm_unexpected_msg_send_release(struct na_cb_info NA_UNUSED *in_info,
                                   void              *in_na_ssm_opid)
{
    struct na_ssm_opid      *v_ssm_opid       = in_na_ssm_opid;

    if (__unlikely(v_ssm_opid == NULL))
      return;

    ssm_mr_destroy(v_ssm_opid->memregion);
    free(v_ssm_opid);
}

/*======================================================
 * RECV UNEXPECTED
 *======================================================*/

/**
 * Receive an unexpected message.
 *
 * @param in_callback
 * @param in_context
 * @param in_buf
 * @param in_buf_size
 * @param out_opid
 *
 * @return na_return_t
 *
 * @see 
 */
static na_return_t
na_ssm_msg_recv_unexpected(na_class_t      *in_na_class,
                           na_cb_t         NA_UNUSED  in_callback,
                           void            NA_UNUSED *in_context,
                           void            *in_buf,
                           na_size_t        in_buf_size,
                           na_op_id_t      *out_opid)
{
    na_return_t                 v_return   = NA_SUCCESS;
    struct na_ssm_opid         *v_ssm_opid = NULL;
    struct na_ssm_unexpbuf     *v_buf      = NULL;
    struct na_ssm_private_data *v_data     = NA_SSM_GET_PRIVATE_DATA(in_na_class);

    if (__unlikely(in_buf == NULL))
    {
        NA_LOG_ERROR("Invalid input argument, in_buf is NULL.");
        return NA_INVALID_PARAM;
    }

    v_ssm_opid = (struct na_ssm_opid *) malloc(sizeof(struct na_ssm_opid));

    if (__unlikely(v_ssm_opid == NULL))
    {
        hg_thread_mutex_unlock(&v_data->unexp_buf_mutex);
        NA_LOG_ERROR("Out of memory error.");
        return NA_NOMEM_ERROR;
    }
    
    hg_thread_mutex_lock(&v_data->unexp_buf_mutex);

    /* Check if we have anything to read */
    if(v_data->unexpbuf[v_data->unexpbuf_rpos].valid == 0)
    {
        /* We have no new message received, returning success. */
        hg_thread_mutex_unlock(&v_data->unexp_buf_mutex);
        v_return = NA_SUCCESS;
        goto done;
    }
    
    /* Check if the position that we are reading, status is complete. */
    if (v_data->unexpbuf[v_data->unexpbuf_rpos].status != SSM_ST_COMPLETE)
    {
        NA_LOG_ERROR("Unexpected receive failed.");
        v_return = NA_FAIL;
        goto done;
    }
    
    v_buf = &v_data->unexpbuf[v_data->unexpbuf_rpos];
    
    memcpy(in_buf, v_buf->buf, in_buf_size);

    v_ssm_opid->status = SSM_STATUS_INPROGRESS;

    v_buf->valid = 0;

    v_data->unexpbuf_availpos = NA_SSM_NEXT_UNEXPBUF_POS(v_data->unexpbuf_availpos);
    v_data->unexpbuf_rpos     = NA_SSM_NEXT_UNEXPBUF_POS(v_data->unexpbuf_rpos);
    
    (*out_opid) = (na_op_id_t *) v_ssm_opid;

    hg_thread_mutex_unlock(&v_data->unexp_buf_mutex);

 done:
    if (v_return == NA_SUCCESS)
    {
        v_ssm_opid->requesttype = SSM_UNEXP_RECV_OP;        
    }
    else
    {
        free(v_ssm_opid);
    }
    
    return v_return;
}

/**
 * Callback routine when an unexpected message is received.
 *
 * @param in_context
 * @param in_ssm_event_data
 * @return (void)
 *
 * @see
 */
void na_ssm_msg_recv_unexpected_callback(void *in_context,
                                         void *in_ssm_event_data)
{
    ssm_result              v_result     = in_ssm_event_data;
    struct na_ssm_private_data    *v_data  = (struct na_ssm_private_data *) in_context;
    struct na_ssm_unexpbuf *v_buffer     = NULL;
    int                     v_index      = 1;
    
    if (v_result->status != SSM_ST_COMPLETE)
    {
        NA_LOG_ERROR("Unexpected message receive error. Status: %d\n",
                     v_result->status);
        hg_thread_cond_signal(&v_data->unexp_buf_cond);
        return;
    }

    hg_thread_mutex_lock(&v_data->unexp_buf_mutex);

    v_index                             = v_data->unexpbuf_cpos;
    v_data->unexpbuf_cpos = NA_SSM_NEXT_UNEXPBUF_POS(v_data->unexpbuf_cpos);

    hg_thread_mutex_unlock(&v_data->unexp_buf_mutex);
    
    v_buffer = &v_data->unexpbuf[v_index];

    /* cbd->valid    = 1; */
    /* cbd->bits     = r->bits; */
    /* cbd->status   = r->status; */
    /* cbd->addr     = r->addr; */
    /* cbd->bytes    = r->bytes; */
    
    hg_thread_cond_signal(&v_data->unexp_buf_cond);
    
    return;
}

/*======================================================
 * SEND EXPECTED
 *======================================================*/

/**
 * Send an expected message to the given destination address.
 *
 * @param in_callback
 * @param in_arg
 * @param in_buf
 * @param in_buf_size
 * @param in_dest
 * @param in_tag
 * @param out_id
 * @return
 *
 * @see na_ssm_msg_send_expected_callback()
 * @see na_ssm_msg_send_expected_release()
 *
 */
static na_return_t
na_ssm_msg_send_expected(na_class_t   *in_na_class,
                         na_cb_t       in_callback,
                         void         *in_arg,
                         const void   *in_buf,
                         na_size_t     in_buf_size,
                         na_addr_t     NA_UNUSED in_dest,
                         na_tag_t      in_tag,
                         na_op_id_t   *out_id)
{
    na_return_t          v_return        = NA_SUCCESS;
    ssm_size_t           v_ssm_buf_size  = (ssm_size_t) in_buf_size;
    struct na_ssm_addr  *v_ssm_peer_addr = (struct na_ssm_addr *) in_dest;
    ssm_tx               v_transaction   = NULL;
    struct na_ssm_opid  *v_ssm_opid      = NULL;
    struct na_ssm_private_data *v_data     = (struct na_ssm_private_data *) in_na_class->private_data;
    ssm_cb_t             v_callback;

    v_ssm_opid = (struct na_ssm_opid *) malloc(sizeof(struct na_ssm_opid));

    if (__unlikely(v_ssm_opid == NULL))
    {
        NA_LOG_ERROR("Out of memory error.\n");
        return NA_NOMEM_ERROR;
    }

    //    v_send_expected = &(v_ssm_opid->opid_info.send_expected);
    
    v_ssm_opid->user_context = in_arg;
    
    v_ssm_opid->memregion = ssm_mr_create(NULL,
                                          (void *) in_buf,
                                          v_ssm_buf_size);

    if (v_ssm_opid->memregion == NULL)
    {
        NA_LOG_ERROR("Unable to create memory region.\n");
        v_return = NA_FAIL;
        goto cleanup;
    }

    v_callback.pcb = na_ssm_msg_send_expected_callback;
    v_callback.cbdata = NULL;
    
    v_transaction = ssm_put(v_data->ssm,
                            v_ssm_peer_addr->addr,
                            v_ssm_opid->memregion,
                            NULL,
                            (ssm_bits)in_tag + NA_SSM_TAG_EXPECTED_OFFSET,
                            &v_callback,
                            SSM_NOF);

    if (v_transaction == NULL)
    {
        NA_LOG_ERROR("Unable to initiate put operation.\n");
        goto cleanup;
    }
    
    v_ssm_opid->requesttype    = SSM_SEND_OP;
    v_ssm_opid->user_context   = in_arg;
    v_ssm_opid->transaction    = v_transaction;
    v_ssm_opid->user_callback  = in_callback;
    v_ssm_opid->status         = SSM_STATUS_INPROGRESS;

    (*out_id) = (na_op_id_t *) v_ssm_opid;
    
 cleanup:
    if (v_ssm_opid != NULL)
    {        
        free(v_ssm_opid);
    }
    
    return v_return;
}

/**
 * Callback function for an expected send.
 *
 * @param  in_context
 * @param  in_ssm_event_data
 * @return (void)
 *
 * @see na_ssm_msg_send_expected()
 * @see na_ssm_msg_send_expected_release()
 *
 */
void na_ssm_msg_send_expected_callback(void *in_context,
                                       void *in_ssm_event_data) 
{
    ssm_result           v_result = in_ssm_event_data;
    struct na_ssm_opid  *v_ssm_opid = in_context;
    struct na_ssm_private_data *v_data = (struct na_ssm_private_data *) v_ssm_opid->ssm_data;
    
    if (v_result->status == SSM_ST_COMPLETE)
    {
        NA_SSM_MARK_OPID_COMPLETE(v_ssm_opid);
    }
    else if (v_result->status == SSM_ST_CANCEL)
    {
        NA_SSM_MARK_OPID_CANCELED(v_ssm_opid);
    }
    else
    {
        NA_LOG_ERROR("SSM returned error %d", v_result->status);
    }
    
    hg_thread_mutex_lock(&v_data->request_mutex);

    hg_thread_cond_signal(&v_data->comp_req_cond);

    hg_thread_mutex_unlock(&v_data->request_mutex);

    na_cb_completion_add(v_ssm_opid->user_callback,
                         v_ssm_opid->user_context,
                         na_ssm_msg_send_expected_release,
                         v_ssm_opid);
}

/**
 * Release callback routine called after calling the user's callback.
 * This routine only releases any resources allocated during the
 * expected message send operation.
 *
 * @param  in_na_ssm_opid
 * @return
 *
 * @see 
 */
static void
na_ssm_msg_send_expected_release(struct na_cb_info  NA_UNUSED *in_info,
                                 void               *in_na_ssm_opid)
{
    struct na_ssm_opid   *v_ssm_opid = in_na_ssm_opid;

    if (__unlikely(v_ssm_opid == NULL))
      return;

    ssm_mr_destroy(v_ssm_opid->memregion);
    free(v_ssm_opid);
}

/*======================================================
 * RECV EXPECTED
 *======================================================*/

/**
 * Receive an expected message from the source.
 *
 * @param  in_na_class
 * @param  in_callback
 * @param  in_context
 * @param  in_buf
 * @param  in_buf_size
 * @param  in_source
 * @param  in_tag
 * @param  out_opid
 * @return na_return_t
 */
static na_return_t
na_ssm_msg_recv_expected(na_class_t     *in_na_class,
                         na_cb_t         in_callback,
                         void           *in_context,
                         void           *in_buf,
                         na_size_t       in_buf_size,
                         na_addr_t       NA_UNUSED in_source,
                         na_tag_t        in_tag,
                         na_op_id_t     *out_opid)
{
    int                  v_ssm_return     = 0;
    na_return_t          v_return         = NA_SUCCESS;
    ssm_size_t           v_ssm_buf_size   = (ssm_size_t) in_buf_size;
    struct na_ssm_opid  *v_ssm_opid       = NULL;
    ssm_cb_t             v_callback;    
    struct na_ssm_private_data *v_data   = NA_SSM_GET_PRIVATE_DATA(in_na_class);

    v_ssm_opid = (struct na_ssm_opid *) malloc(sizeof(struct na_ssm_opid));

    if (__unlikely(v_ssm_opid == NULL))
    {
        v_return = NA_NOMEM_ERROR;
        goto done;
    }
    
    memset(v_ssm_opid, 0, sizeof(struct na_ssm_opid));
    
    v_ssm_opid->requesttype   = SSM_RECV_OP;
    v_ssm_opid->user_callback = in_callback;
    v_ssm_opid->user_context  = in_context;

    /* Register Memory */
    v_ssm_opid->memregion = ssm_mr_create(NULL,
                                          (void *) in_buf,
                                          v_ssm_buf_size);
    
    if (v_ssm_opid->memregion == NULL)
    {
        NA_LOG_ERROR("ssm_mr_create failed.\n");
        v_return = NA_FAIL;
        goto done;
    }
    
    /* Prepare callback function */
    v_callback.pcb    = na_ssm_msg_recv_expected_callback;
    v_callback.cbdata = v_ssm_opid;

    /* Post the SSM recv request */
    v_ssm_opid->matchentry = ssm_link(v_data->ssm,
                                      in_tag + NA_SSM_TAG_EXPECTED_OFFSET,
                                      0x0 /* mask */,
                                      SSM_POS_HEAD,
                                      NULL,
                                      &v_callback,
                                      SSM_NOF);

    if (v_ssm_opid->matchentry == NULL)
    {
        v_return = NA_FAIL;
        goto done;
    }
    
    v_ssm_return = ssm_post(v_data->ssm,
                            v_ssm_opid->matchentry,
                            v_ssm_opid->memregion,
                            SSM_NOF);
    
    if (v_ssm_return < 0)
    {
        NA_LOG_ERROR("ssm_post() failed");
        v_return = NA_FAIL;
        goto done;
    }

    (*out_opid) = (struct na_op_id_t *) v_ssm_opid;

 done:
    if (v_return != NA_SUCCESS)
    {
        if (v_ssm_opid != NULL)
        {
            free(v_ssm_opid);
        }
    }

    return v_return;
}

/**
 * Callback function for expected receive messages.
 *
 * @param  in_context
 * @param  in_ssm_event_data
 * @return (void)
 *
 * @see na_ssm_msg_recv_expected()
 */
static void
na_ssm_msg_recv_expected_callback(void *in_context,
                                  void *in_ssm_event_data)
{
    ssm_result           v_result     = in_ssm_event_data;
    struct na_ssm_opid  *v_ssm_opid   = in_context;
    struct na_ssm_private_data *v_data = (struct na_ssm_private_data *) v_ssm_opid->ssm_data;
    
    if (v_result->status == SSM_ST_COMPLETE)
    {
        NA_SSM_MARK_OPID_COMPLETE(v_ssm_opid);
    }
    else if (v_result->status == SSM_ST_CANCEL)
    {
        NA_SSM_MARK_OPID_CANCELED(v_ssm_opid);
    }
    else
    {
        NA_LOG_ERROR("msg_recv_cb(): cb error");
    }
    
    hg_thread_mutex_lock(&v_data->request_mutex);

    //wake up others
    hg_thread_cond_signal(&v_data->comp_req_cond);

    hg_thread_mutex_unlock(&v_data->request_mutex);

    /* Ignoring the status returned from na_cb_completion_add() API
     * because there is nothing much we can do if this fails.  This
     * function is not supposed to fail.
     */
    na_cb_completion_add(v_ssm_opid->user_callback,
                         v_ssm_opid->user_context,
                         na_ssm_msg_recv_release,
                         v_ssm_opid);
}

/**
 * Release resources allocated for receiving message.
 *
 * @param  in_info
 * @peram  in_na_ssm_opid
 * @return (void)
 *
 * @see na_ssm_msg_recv_expected()
 * @see na_ssm_msg_recv_expected_callback()
 */
static void
na_ssm_msg_recv_release(struct na_cb_info  NA_UNUSED *in_info,
                        void               *in_na_ssm_opid)
{
    struct na_ssm_opid    *v_ssm_opid      = in_na_ssm_opid;

    if (__unlikely(v_ssm_opid == NULL))
      return;

    free(v_ssm_opid);
}

/**
 * Register memory for RMA operations
 *
 * @param  in_na_class
 * @param  in_mem_handle
 * @return na_return_t
 */
static na_return_t
na_ssm_mem_register(na_class_t        *in_na_class,
                    na_mem_handle_t    in_mem_handle)
{
    na_return_t                 v_return = NA_SUCCESS;
    struct na_ssm_mem_handle   *v_handle = NULL;
    struct na_ssm_private_data *v_data   = NA_SSM_GET_PRIVATE_DATA(in_na_class);

    v_handle = (struct na_ssm_mem_handle *) in_mem_handle;

    if (__unlikely(v_handle == NULL))
    {
        NA_LOG_ERROR("Invalid input parameter; memory handle is NULL.\n");
        return NA_INVALID_PARAM;
    }

    v_handle->mr = ssm_mr_create(NULL,
                                 v_handle->buf,
                                 v_handle->buf_size);

    if (v_handle->mr == NULL)
    {
        NA_LOG_ERROR("SSM failed to create memory region.\n");
        return NA_PROTOCOL_ERROR;
    }

    v_handle->matchbits = generate_unique_matchbits(in_na_class) +
                                           NA_SSM_TAG_RMA_OFFSET;
    v_handle->buf       = v_handle->buf;
    v_handle->cb.pcb    = na_ssm_post_callback;
    v_handle->cb.cbdata = NULL;

    v_handle->me = ssm_link(v_data->ssm,
                            v_handle->matchbits,
                            NA_SSM_TAG_RMA_OFFSET,
                            SSM_POS_HEAD,
                            NULL,
                            &(v_handle->cb),
                            SSM_NOF);

    if (v_handle->me == NULL)
    {
        NA_LOG_ERROR("SSM failed to link memory region.\n");
        ssm_mr_destroy(v_handle->mr);
        return NA_PROTOCOL_ERROR;
    }
    
    v_return = ssm_post(v_data->ssm,
                        v_handle->me,
                        v_handle->mr,
                        SSM_POST_STATIC);

    if (v_return < 0)
    {
        NA_LOG_ERROR("SSM failed to post memory region.\n");
        ssm_unlink(v_data->ssm, v_handle->me);
        ssm_mr_destroy(v_handle->mr);
        return NA_FAIL;
    }
    
    return NA_SUCCESS;
}

static void
na_ssm_post_callback(void NA_UNUSED(*cbdat), void *evdat)
{
    ssm_result v_ssm_result = evdat;
    
    if (v_ssm_result->status != SSM_ST_COMPLETE)
    {
        NA_LOG_ERROR("postedbuf_cb(): cb error");
        return;
    }

    return;
}

/*---------------------------------------------------------------------------
 * Function:    na_ssm_mem_deregister
 *
 * Purpose:     Deregister memory
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
static na_return_t
na_ssm_mem_deregister(na_class_t      NA_UNUSED *in_na_class,
                      na_mem_handle_t  in_mem_handle)
{
    int rc;
    na_return_t               v_return = NA_SUCCESS;
    struct na_ssm_mem_handle *v_handle = NULL;

    v_handle = (struct na_ssm_mem_handle *) in_mem_handle;
    
    rc = ssm_mr_destroy(v_handle->mr);
    
    if (rc == 0)
    {
        v_return = NA_SUCCESS;
    }
    else
    {
        v_return = NA_FAIL;
    }
    
    return v_return;
}

/*---------------------------------------------------------------------------
 * Function:    na_ssm_mem_handle_get_serialize_size
 *
 * Purpose:     Get size required to serialize handle
 *
 *---------------------------------------------------------------------------
 */
na_size_t
na_ssm_mem_handle_get_serialize_size(na_class_t       NA_UNUSED *in_na_class,
                                     na_mem_handle_t   NA_UNUSED in_mem_handle)
{
    return sizeof(struct na_ssm_mem_handle);
}

/*---------------------------------------------------------------------------
 * Function:    na_ssm_mem_handle_serialize
 *
 * Purpose:     Serialize memory handle into a buffer
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
/**
 * Serialize memory handle into a buffer.
 *
 * @param  in_na_class
 * @param  in_buf
 * @param  in_buf_size
 * @param  in_mem_handle
 * @return 
 */
static na_return_t
na_ssm_mem_handle_serialize(na_class_t       NA_UNUSED *in_na_class,
                            void             *in_buf,
                            na_size_t         in_buf_size,
                            na_mem_handle_t   NA_UNUSED in_mem_handle)
{
    na_return_t                v_return = NA_SUCCESS;
    struct na_ssm_mem_handle  *v_handle = NULL;

    v_handle = (struct na_ssm_mem_handle *) in_mem_handle;

    if (__unlikely(v_handle == NULL))
    {
        NA_LOG_ERROR("Invalid input parameter.\n");
        return NA_INVALID_PARAM;
    }

    if (in_buf_size < sizeof(struct na_ssm_mem_handle))
    {
        v_return = NA_FAIL;
    }
    else
    {
        memcpy(in_buf, v_handle, sizeof(struct na_ssm_mem_handle));
    }

    return v_return;
}

/**
 * Deserialize memory handle from the input buffer.
 *
 * @param  in_mem_handle
 * @param  in_buf
 * @param  in_buf_size
 * @return NA_FAIL if buffer is smaller than handle size, NA_SUCCESS
 *         otherwise.
 */
static na_return_t
na_ssm_mem_handle_deserialize(na_class_t       NA_UNUSED *in_na_class,
                              na_mem_handle_t   *out_mem_handle,
                              const void        *in_buf,
                              na_size_t          in_buf_size)
{
    na_return_t                 v_return = NA_SUCCESS;
    struct na_ssm_mem_handle   *v_handle = NULL;

    if (in_buf_size < sizeof(struct na_ssm_mem_handle))
    {
        v_return = NA_FAIL;
    }
    else
    {
        v_handle = (struct na_ssm_mem_handle *)
                            malloc(sizeof(struct na_ssm_mem_handle));

        if (v_handle == NULL)
        {
            return NA_NOMEM_ERROR;
        }
        
        memcpy(v_handle, in_buf, sizeof(struct na_ssm_mem_handle));
        
        (*out_mem_handle) = (na_mem_handle_t) v_handle;
    }

    return v_return;
}

static na_return_t
na_ssm_mem_handle_create(na_class_t      NA_UNUSED *in_na_class,
                         void            NA_UNUSED *in_buf,
                         na_size_t       NA_UNUSED  in_buf_size,
                         unsigned long   NA_UNUSED  in_flags,
                         na_mem_handle_t NA_UNUSED *out_mem_handle)
{
    return NA_SUCCESS;
}

/**
 * Free memory handle
 *
 * @param  in_na_class
 * @param  in_mem_handle
 * @return Always returns success.
 */
static na_return_t
na_ssm_mem_handle_free(na_class_t     NA_UNUSED *in_na_class,
                       na_mem_handle_t in_mem_handle)
{
    struct na_ssm_mem_handle *v_handle = NULL;

    v_handle = (struct na_ssm_mem_handle *) in_mem_handle;

    if (v_handle)
    {
        free(v_handle);
        v_handle = NULL;
    }

    return NA_SUCCESS;
}

/*======================================================
 * PUT
 *======================================================*/

/**
 * Put data to remote target.
 *
 * @param in_local_mem_handle
 */
static na_return_t
na_ssm_put(na_class_t        *in_na_class,
           na_cb_t           NA_UNUSED  in_callback,
           void              NA_UNUSED  *in_context,
           na_mem_handle_t     in_local_mem_handle,
           na_offset_t       NA_UNUSED  in_local_offset,
           na_mem_handle_t   NA_UNUSED  in_remote_mem_handle,
           na_offset_t    NA_UNUSED     in_remote_offset,
           na_size_t     NA_UNUSED      in_data_size,
           na_addr_t           in_remote_addr,
           na_op_id_t    NA_UNUSED     *out_opid)
{
    na_return_t               v_return       = NA_SUCCESS;
    struct na_ssm_mem_handle *v_handle       = NULL;
    struct na_ssm_addr       *v_peer_addr    = NULL; 
    struct na_ssm_opid       *v_opid         = NULL;
    ssm_tx                    v_transaction  = NULL;
    struct na_ssm_private_data      *v_data    = (struct na_ssm_private_data *) in_na_class->private_data;
    ssm_cb_t                  v_callback;
    
    v_handle = (struct na_ssm_mem_handle *) in_local_mem_handle;

    if (__unlikely(v_handle == NULL))
    {
        NA_LOG_ERROR("Invalid input param.\n");
        return NA_INVALID_PARAM;
    }

    v_opid = (struct na_ssm_opid *) malloc(sizeof(struct na_ssm_opid));

    if (__unlikely(v_opid == NULL))
    {
        NA_LOG_ERROR("Out of memory error.\n");
        return NA_NOMEM_ERROR;
    }

    v_peer_addr = (struct na_ssm_addr *) in_remote_addr;
    
    if (__unlikely(v_peer_addr == NULL))
    {
        NA_LOG_ERROR("Invalid input param.\n");
        return NA_INVALID_PARAM;
    }
    
    memset(v_opid, 0, sizeof(struct na_ssm_opid));

    v_opid->requesttype    = SSM_PUT_OP;

    v_callback.pcb    = na_ssm_put_callback;
    v_callback.cbdata = v_opid;

    v_transaction = ssm_put(v_data->ssm,
                            v_peer_addr->addr,
                            v_handle->mr,
                            NULL,
                            v_handle->matchbits,
                            &v_callback,
                            SSM_NOF);

    if (v_transaction == NULL)
    {
        NA_LOG_ERROR("Unable to initiate put operation.\n");
        v_return = NA_FAIL;
        goto cleanup;
    }
    
    v_opid->transaction = v_transaction;

 cleanup:
    return v_return;
}

/**
 * Callback function for post operation.
 *
 * @param  in_context
 * @param  in_ssm_event_data
 * @return (void)
 *
 * @see na_ssm_put()
 */
static void
na_ssm_put_callback(void *in_context,
                    void *in_ssm_event_data) 
{
    ssm_result v_result = in_ssm_event_data;
    struct na_ssm_opid *v_ssm_opid = in_context;
    struct na_ssm_private_data *v_data = (struct na_ssm_private_data *) v_ssm_opid->ssm_data;
    
    if (v_result->status == SSM_ST_COMPLETE)
    {
        NA_SSM_MARK_OPID_COMPLETE(v_ssm_opid);
    }
    
    hg_thread_mutex_lock(&v_data->request_mutex);
    
    //wake up others
    hg_thread_cond_signal(&v_data->comp_req_cond);
    
    hg_thread_mutex_unlock(&v_data->request_mutex);
}

/*======================================================
 * GET
 *======================================================*/

/**
 * Get data from the remote target.
 *
 * @param  in_na_class
 */
static na_return_t
na_ssm_get(na_class_t        *in_na_class,
           na_cb_t            in_callback,
           void              *in_context,
           na_mem_handle_t    in_local_mem_handle,
           na_offset_t        in_local_offset,
           na_mem_handle_t    in_remote_mem_handle,
           na_offset_t        in_remote_offset,
           na_size_t          in_length,
           na_addr_t          in_remote_addr,
           na_op_id_t        *out_opid)
{
    struct na_ssm_mem_handle   *v_local_handle  = NULL;
    struct na_ssm_mem_handle   *v_remote_handle = NULL;
    struct na_ssm_addr         *v_ssm_peer_addr = NULL;
    struct na_ssm_opid         *v_ssm_opid      = NULL;
    ssm_md                      v_remote_md     = NULL;
    ssm_mr                      v_local_mr      = NULL;
    ssm_tx                      v_stx           = NULL;
    struct na_ssm_private_data *v_data          = NA_SSM_GET_PRIVATE_DATA(in_na_class);

    v_local_handle   = (struct na_ssm_mem_handle *)in_local_mem_handle;
    v_remote_handle  = (struct na_ssm_mem_handle *)in_remote_mem_handle;

    /* Allocate memory for op id handle */
    v_ssm_opid = (struct na_ssm_opid *) malloc(sizeof(struct na_ssm_opid));
    
    if (__unlikely(v_ssm_opid == NULL))
    {
        NA_LOG_ERROR("Unable to allocate memory for op id handle.\n");
        return NA_NOMEM_ERROR;
    }

    memset(v_ssm_opid, 0, sizeof(struct na_ssm_opid));
    
    v_remote_md = ssm_md_add(NULL, in_remote_offset, in_length);

    if (v_remote_md == NULL)
    {
        return NA_PROTOCOL_ERROR;
    }

    v_local_mr = ssm_mr_create(v_remote_md,
                               v_local_handle->buf + in_local_offset,
                               in_length);

    if (v_local_mr == NULL)
    {
        NA_LOG_ERROR("SSM failed to create memory region.\n");
        return NA_PROTOCOL_ERROR;
    }
    
    v_ssm_peer_addr = (struct na_ssm_addr *) in_remote_addr;

    v_ssm_opid->requesttype     = SSM_GET_OP;
    v_ssm_opid->user_callback   = in_callback;
    v_ssm_opid->user_context    = in_context;
    v_ssm_opid->ssm_data        = v_data;

    v_ssm_opid->opid_info.get.memory_region = v_local_mr;
    v_ssm_opid->opid_info.get.memory_desc   = v_remote_md;
    
    v_ssm_opid->ssm_callback.pcb    = na_ssm_get_callback;
    v_ssm_opid->ssm_callback.cbdata = v_ssm_opid;

    v_stx = ssm_get(v_data->ssm,
                    v_ssm_peer_addr->addr,
                    v_remote_md,
                    v_local_mr,
                    v_remote_handle->matchbits,
                    &v_ssm_opid->ssm_callback,
                    SSM_NOF);

    if (v_stx == NULL)
    {
        free(v_ssm_opid);
        ssm_mr_destroy(v_local_mr);
        ssm_md_release(v_remote_md);
        return NA_FAIL;
    }
    
    v_ssm_opid->transaction = v_stx;
    v_ssm_opid->status = SSM_STATUS_INPROGRESS;

    /* Fill the return handle. */
    (*out_opid) = (struct na_ssm_opid *) v_ssm_opid;
    
    return NA_SUCCESS;
}

static void
na_ssm_get_callback(void *in_context,
                    void *in_ssm_event_data) 
{
    ssm_result v_result = in_ssm_event_data;
    struct na_ssm_opid *v_ssm_opid = in_context;
    struct na_ssm_private_data *v_data = v_ssm_opid->ssm_data;
    
    if (v_result->status != SSM_ST_COMPLETE)
    {
        NA_LOG_ERROR("Error reported by SSM.");
        return;
    }

    hg_thread_mutex_lock(&v_data->request_mutex);
    
    NA_SSM_MARK_OPID_COMPLETE(v_ssm_opid);

    //wake up others
    hg_thread_cond_signal(&v_data->comp_req_cond);

    hg_thread_mutex_unlock(&v_data->request_mutex);
}

/**
 * Track completion of a RMA operation and make progress.
 *
 * @param  in_na_class
 * @param  in_timeout
 * @return na_return_t
 */
static na_return_t
na_ssm_progress(na_class_t    *in_na_class,
                unsigned int NA_UNUSED in_timeout)
{
    struct timeval v_tv;
    int            v_return    = 0;
    na_bool_t      v_condition = NA_TRUE;
    struct na_ssm_private_data *v_data = (struct na_ssm_private_data *) in_na_class->private_data;

    v_tv.tv_sec = 0;
    v_tv.tv_usec = 1000*10;
    
    sleep(0);

    while (v_condition)
    {
        v_return = ssm_wait(v_data->ssm, &v_tv);
        sleep(0);
        v_condition = (v_return > 0);
    }

    if ( v_return < 0 )
    {
        v_return = NA_FAIL;
    }
    else
    {
        v_return = NA_SUCCESS;
    }

    return v_return;
}

/**
 * Attempt to cancel a transaction that has been initiated.  We assume
 * here that SSM will do the right thing, in that after returning
 * success here, it will still issue a callback at some later point.
 * The callback will contain the actual status indicating if the
 * transaction was completed, failed, or it was canceled.  Here, we
 * just record that a request was received to cancel the operation.
 *
 * @param  in_request
 * @param  in_opid
 * @return na_return_t  Returns success if cancel was scheduled.  If the
 *                      task (or transaction) had already completed, then
 *                      we return failure here.
 */
static na_return_t
na_ssm_cancel(na_class_t    *in_na_class,
              na_op_id_t     in_opid)
{
    struct na_ssm_private_data *v_data = (struct na_ssm_private_data *) in_na_class->private_data;
    struct na_ssm_opid  *v_ssm_opid  = (struct na_ssm_opid *) in_opid;
    int                  v_return    = NA_FAIL;

    if (v_ssm_opid != NULL && v_ssm_opid->transaction != NULL)
    {
        v_return = ssm_cancel(v_data->ssm,
                              v_ssm_opid->transaction);
    }
    
    if (v_return == 0)
    {
        v_return = NA_SUCCESS;
    }
    
    return v_return;
}
