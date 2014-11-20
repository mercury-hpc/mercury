/*
 * Copyright (C) 2013-2014 Argonne National Laboratory, Department of Energy,
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

/* Static NA SSM Class functions */
static na_return_t
na_ssm_initialize(na_class_t           *na_class,
                  const struct na_info *in_info,
                  na_bool_t             in_listen);

static na_bool_t
na_ssm_check_protocol(const char *protocol);

static na_return_t
na_ssm_finalize(na_class_t *in_na_class);

static na_return_t
na_ssm_addr_lookup(na_class_t   *in_na_class,
                   na_context_t *in_context,
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
na_ssm_msg_get_max_tag(na_class_t  *in_na_class);

static na_return_t
na_ssm_msg_send_unexpected(na_class_t     *in_na_class,
                           na_context_t *in_context,
                           na_cb_t         in_callback,
                           void           *in_arg,
                           const void     *in_buf,
                           na_size_t       in_buf_size,
                           na_addr_t       in_destination,
                           na_tag_t        in_tag,
                           na_op_id_t     *out_opid);

static na_return_t
na_ssm_msg_recv_unexpected(na_class_t     *in_na_class,
                           na_context_t *in_context,
                           na_cb_t         in_callback,
                           void           *in_user_context,
                           void           *in_buf,
                           na_size_t       in_buf_size,
                           na_op_id_t     *out_opid);

static na_return_t
na_ssm_msg_send_expected(na_class_t  *in_na_class,
                         na_context_t *in_context,
                         na_cb_t      in_callback,
                         void        *in_user_context,
                         const void  *in_buf,
                         na_size_t    in_buf_size,
                         na_addr_t    in_dest,
                         na_tag_t     in_tag,
                         na_op_id_t  *out_id);

static na_return_t
na_ssm_msg_recv_expected(na_class_t     *in_na_class,
                         na_context_t *in_context,
                         na_cb_t         in_callback,
                         void           *in_arg,
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
           na_context_t *in_context,
           na_cb_t             in_callback,
           void               *in_arg,
           na_mem_handle_t     in_local_mem_handle,
           na_offset_t         in_local_offset,
           na_mem_handle_t     in_remote_mem_handle,
           na_offset_t         in_remote_offset,
           na_size_t           in_data_size,
           na_addr_t           in_remote_addr,
           na_op_id_t         *out_opid);

static na_return_t
na_ssm_get(na_class_t         *in_na_class,
           na_context_t *in_context,
           na_cb_t             in_callback,
           void               *in_arg,
           na_mem_handle_t     in_local_mem_handle,
           na_offset_t         in_local_offset,
           na_mem_handle_t     in_remote_mem_handle,
           na_offset_t         in_remote_offset,
           na_size_t           in_data_size,
           na_addr_t           in_remote_addr,
           na_op_id_t         *out_opid);

static na_return_t
na_ssm_progress(na_class_t     *in_na_class,
                na_context_t *in_context,
                unsigned int    in_timeout);

static na_return_t
na_ssm_cancel(na_class_t    *in_na_class,
              na_context_t *in_context,
              na_op_id_t     in_opid);

/* Callbacks */
static void
na_ssm_addr_lookup_release(struct na_cb_info *in_info,
                           void              *in_opid);

static void
na_ssm_msg_recv_expected_release(struct na_cb_info *in_info,
                        void              *in_na_ssm_opid);

static void
na_ssm_msg_send_expected_release(struct na_cb_info *in_info,
                                 void              *in_na_ssm_opid);

static void
na_ssm_msg_send_unexpected_release(struct na_cb_info *in_info,
                                   void              *in_na_ssm_opid);

static void
na_ssm_msg_send_unexpected_callback(void *in_context,
                                    void *in_ssm_event_data);

static void
na_ssm_msg_recv_expected_callback(void *in_context,
                                  void *in_ssm_event_data);

static void
na_ssm_msg_recv_unexpected_callback(void *in_context,
                                    void *in_ssm_event_data);

static void
na_ssm_msg_recv_unexpected_release(struct na_cb_info  *in_info,
                                   void               *in_na_ssm_opid);

static void
na_ssm_get_callback(void *cbdat, void *evdat);

static void
na_ssm_get_release(struct na_cb_info *in_info,
                   void              *in_na_ssm_opid);

static void
na_ssm_msg_send_expected_callback(void *in_context,
                                  void *in_ssm_event_data);

static void
na_ssm_put_callback(void *cbdat, void *evdat);

static void
na_ssm_put_release(struct na_cb_info *in_info,
                   void              *in_na_ssm_opid);

static void
na_ssm_post_callback(void NA_UNUSED(*cbdat), void *evdat);

/* Global variables */

const na_class_t na_ssm_class_g = {
        NULL,                                 /* private_data */
        "ssm",                                /* name */
        na_ssm_check_protocol,                /* check_protocol */
        na_ssm_initialize,                    /* initialize */
        na_ssm_finalize,                      /* finalize */
        NULL,                                 /* context_create */
        NULL,                                 /* context_destroy */
        na_ssm_addr_lookup,                   /* addr_lookup */
        na_ssm_addr_free,                     /* addr_free */
        NULL,                                 /* addr_self */
        NULL,                                 /* addr_dup */
        NULL,                                 /* addr_is_self */
        na_ssm_addr_to_string,                /* addr_to_string */
        na_ssm_msg_get_max_expected_size,     /* msg_get_max_expected_size */
        na_ssm_msg_get_max_unexpected_size,   /* msg_get_max_expected_size */
        na_ssm_msg_get_max_tag,               /* msg_get_max_tag */
        na_ssm_msg_send_unexpected,           /* msg_send_unexpected */
        na_ssm_msg_recv_unexpected,           /* msg_recv_unexpected */
        na_ssm_msg_send_expected,             /* msg_send_expected */
        na_ssm_msg_recv_expected,             /* msg_recv_expected */
        na_ssm_mem_handle_create,             /* mem_handle_create */
        NULL,                                 /* mem_handle_create_segment */
        na_ssm_mem_handle_free,               /* mem_handle_free */
        na_ssm_mem_register,                  /* mem_register */
        na_ssm_mem_deregister,                /* mem_deregister */
        NULL,                                 /* mem_publish */
        NULL,                                 /* mem_unpublish */
        na_ssm_mem_handle_get_serialize_size, /* mem_handle_get_serialize_size */
        na_ssm_mem_handle_serialize,          /* mem_handle_serialize */
        na_ssm_mem_handle_deserialize,        /* mem_handle_deserialize */
        na_ssm_put,                           /* put */
        na_ssm_get,                           /* get */
        na_ssm_progress,                      /* progress */
        na_ssm_cancel                         /* cancel */
};

/**
 * Generate unique matchbits
 *
 * @param  in_na_class
 * @return ssm_bits
 */
static inline ssm_bits
generate_unique_matchbits(na_class_t *in_na_class)
{
    struct na_ssm_private_data *ssm_data = NA_SSM_PRIVATE_DATA(in_na_class);
    
    hg_thread_mutex_lock(&ssm_data->gen_matchbits);
    ssm_data->cur_bits++;
    hg_thread_mutex_unlock(&ssm_data->gen_matchbits);
    
    return ssm_data->cur_bits;
}

/**
 * Verify if the plugin can accept the input protocol string.
 *
 * @param  in_protocol  Protocol buffer in string.
 * @return na_bool_t    NA_TRUE or NA_FALSE
 */
static na_bool_t
na_ssm_check_protocol(const char *in_protocol)
{
    na_bool_t accept = NA_FALSE;
    
    if (strcmp(in_protocol, "tcp") == 0)
    {
        accept = NA_TRUE;
    }

    return accept;
}

/**
 * Initialize SSM's transport protocol for the given plugin.
 *
 * @param  in_na_ssm_class NA SSM Class structure
 * @param  in_protocol     Protocol type (tcp, ib, ..)
 * @param  in_port         Port number
 * @return na_return_t     NA_SUCCESS/NA_FAIL
 */
static na_return_t
na_ssm_initialize_ssm_tp(struct na_class      *in_na_ssm_class,
                         const char           *in_protocol,
                         unsigned int          in_port)
{
    struct na_ssm_private_data *v_data = NA_SSM_PRIVATE_DATA(in_na_ssm_class);
    
    if (strcmp(in_protocol, "tcp") == 0)
    {
        v_data->itp = ssmptcp_new_tp(in_port, SSM_NOF);

        if (v_data->itp == NULL)
        {
            NA_LOG_ERROR("Unable to create transport protocol.\n");
            return NA_PROTOCOL_ERROR;
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
static na_return_t
na_ssm_initialize(na_class_t            *ssm_class,
                  const struct na_info  *in_info,
                  na_bool_t              in_listen)
{
    na_return_t ret = NA_SUCCESS;
    int ssmret;
    struct na_ssm_private_data *ssm_data = NULL;
    int i = 0;
    int cleanup_index = 0;

    NA_LOG_DEBUG("Initializing NA-SSM using %s on port %d in "
                 "%d mode.\n", in_info->protocol_name,
                 in_info->port, in_listen);

    ssm_data = (struct na_ssm_private_data *)
            malloc(sizeof(struct na_ssm_private_data));
    if (__unlikely(ssm_data == NULL))
    {
        NA_LOG_ERROR("Out of memory error.\n");
        ret = NA_NOMEM_ERROR;
        goto cleanup;
    }
    memset(ssm_data, 0, sizeof(struct na_ssm_private_data));

    /* SSM's private data */
    ssm_class->private_data                = (void *) ssm_data;

    /* Initialize SSM transport protocol */
    ret = na_ssm_initialize_ssm_tp(ssm_class,
                                   in_info->protocol_name,
                                   (in_listen) ? in_info->port : 0);

    if (ret != NA_SUCCESS)
    {
        NA_LOG_ERROR("Unable to initialize SSM transport protocol.\n");
        goto cleanup;
    }

    ssm_data->ssm = ssm_start(ssm_data->itp, NULL, SSM_NOF);
    if (ssm_data->ssm == NULL)
    {
        NA_LOG_ERROR("Unable to start ssm transport.\n");
        ret = NA_PROTOCOL_ERROR;
        goto cleanup;
    }

    /* Prepare unexpected receive buffers */
    ssm_data->cur_bits = 0;
    ssm_data->unexpected_callback.pcb = na_ssm_msg_recv_unexpected_callback;
    ssm_data->unexpected_callback.cbdata = ssm_data;

    ssm_data->unexpected_me = ssm_link(ssm_data->ssm,
                                       0,
                                       ((ssm_bits) 0xffffffffffffffff >> 2),
                                       SSM_POS_HEAD,
                                       NULL,
                                       &(ssm_data->unexpected_callback),
                                       SSM_NOF);

    if (ssm_data->unexpected_me == NULL)
    {
        NA_LOG_ERROR("Unable to create SSM link.\n");
        ret = NA_PROTOCOL_ERROR;
        goto cleanup;
    }

    ssm_data->opid_wait_queue = hg_queue_new();
    if (ssm_data->opid_wait_queue == NULL)
    {
        NA_LOG_ERROR("Unable to create a opid wait queue.\n");
        ret = NA_NOMEM_ERROR;
        goto cleanup;
    }
    
    ssm_data->unexpected_msg_queue = hg_queue_new();
    if (ssm_data->unexpected_msg_queue == NULL)
    {
        NA_LOG_ERROR("Unable to create unexpected message queue.\n");
        ret = NA_NOMEM_ERROR;
        goto cleanup;
    }

    ssm_data->unexpected_msg_complete_queue = hg_queue_new();
    if (ssm_data->unexpected_msg_complete_queue == NULL)
    {
        NA_LOG_ERROR("Unable to create a message complete queue.\n");
        ret = NA_NOMEM_ERROR;
        goto cleanup;
    }
    
    for (i = 0; i < NA_SSM_UNEXPECTED_BUFFERCOUNT; i++)
    {
        struct na_ssm_unexpected_buffer *buffer = malloc(sizeof(struct na_ssm_unexpected_buffer));

        if (buffer == NULL)
        {
            NA_LOG_ERROR("Out of memory error.\n");
            ret = NA_NOMEM_ERROR;
            goto cleanup;
        }
        
        buffer->buf = (char *) malloc(NA_SSM_UNEXPECTED_SIZE);
        if (buffer->buf == NULL)
        {
            free(buffer);
            NA_LOG_ERROR("Out of memory error.\n");
            ret = NA_NOMEM_ERROR;
            goto cleanup;
        }
        
        buffer->mr = ssm_mr_create(NULL, buffer->buf, NA_SSM_UNEXPECTED_SIZE);
        if (buffer->mr == NULL)
        {
            free(buffer->buf);
            free(buffer);
            NA_LOG_ERROR("Failed to create memory region.\n");
            ret = NA_PROTOCOL_ERROR;
            goto cleanup;
        }
        
        ssmret = ssm_post(ssm_data->ssm,
			  ssm_data->unexpected_me,
			  buffer->mr,
			  SSM_NOF);
        
        if (ssmret < 0)
        {
            ssm_mr_destroy(buffer->mr);
            free(buffer->buf);
            free(buffer);
            NA_LOG_ERROR("SSM post failed.\n");
            ret = NA_PROTOCOL_ERROR;
            goto cleanup;
        }
        
        if (!hg_queue_push_tail(ssm_data->unexpected_msg_queue,
                                (hg_queue_value_t) buffer))
        {
            int ssm_ret = ssm_drop(ssm_data->ssm,
                                   ssm_data->unexpected_me,
                                   buffer->mr);
            if (ssm_ret != SSM_REMOVE_OK)
            {
                /* Even if we see this error, we cannot do anything; we just
                 * report the error and continue with cleanup.
                 */
                NA_LOG_ERROR("SSM failed to drop an attached buffer as part "
                             "of cleanup process. Error: %d.\n", ssm_ret);
                ret = NA_PROTOCOL_ERROR;
            }
            
            ssm_mr_destroy(buffer->mr);
            free(buffer->buf);
            free(buffer);
            goto cleanup;
        }
        
        cleanup_index = (i + 1);
    }

    hg_thread_mutex_init(&ssm_data->opid_wait_queue_mutex);
    hg_thread_mutex_init(&ssm_data->unexpected_msg_queue_mutex);
    hg_thread_mutex_init(&ssm_data->unexpected_msg_complete_mutex);
    hg_thread_mutex_init(&ssm_data->gen_matchbits);

    NA_LOG_DEBUG("Exit.\n");
    return ret;
    
 cleanup:

    if (ssm_data)
    {
        if (ssm_data->ssm != NULL)
        {
            if (ssm_data->unexpected_me != NULL)
            {
                ssm_unlink(ssm_data->ssm, ssm_data->unexpected_me);
            }
        
            ssm_stop(ssm_data->ssm);
        }

        if (ssm_data->unexpected_msg_queue != NULL)
        {
            struct na_ssm_unexpected_buffer *buffer = NULL;
                
            for (i = 0; i < cleanup_index; ++i)
            {
                buffer = hg_queue_pop_head(ssm_data->unexpected_msg_complete_queue);
                if (buffer != NULL)
                {
                    int ssm_ret = ssm_drop(ssm_data->ssm,
                                           ssm_data->unexpected_me,
                                           buffer->mr);
                    if (ssm_ret != SSM_REMOVE_OK)
                    {
                        /* Even if we see this error, we cannot do
                         * anything; we just report the error and
                         * continue with cleanup.
                         */
                        NA_LOG_ERROR("SSM failed to drop an attached "
                                     "buffer as part of cleanup process. "
                                     "Error: %d.\n", ssm_ret);
                    }
                    
                    ssm_mr_destroy(buffer->mr);
                    free(buffer->buf);
                    free(buffer);
                }
            }
        }
        
        free(ssm_data);
    }
        
    return ret;
}

/**
 * Finalize the SSM abstraction.
 *
 * @param  in_na_class  Release any resources allocated for this NA SSM
 *                      instance.  in_na_class should not be used after
 *                      calling finalize.
 * @return na_return_t
 */
static na_return_t
na_ssm_finalize(na_class_t *in_na_class)
{
    int ret = 0;
    int i = 0;
    struct na_ssm_private_data *ssm_data = NA_SSM_PRIVATE_DATA(in_na_class);
    struct na_ssm_unexpected_buffer *buffer = NULL;
    
    NA_LOG_DEBUG("Enter.\n");

    for (i = 0; i < NA_SSM_UNEXPECTED_BUFFERCOUNT; ++i)
    {
        buffer = hg_queue_pop_head(ssm_data->unexpected_msg_queue);
        if (buffer != NULL)
        {
            int ssm_ret = ssm_drop(ssm_data->ssm,
                                   ssm_data->unexpected_me,
                                   buffer->mr);
            if (ssm_ret != SSM_REMOVE_OK)
            {
                /* Even if we see this error, we cannot do
                 * anything; we just report the error and
                 * continue with cleanup.
                 */
                NA_LOG_ERROR("SSM failed to drop an attached "
                             "buffer as part of cleanup process. "
                             "Error: %d.\n", ssm_ret);
            }

            ssm_mr_destroy(buffer->mr);
            free(buffer->buf);
            free(buffer);
        }
    }

    buffer = hg_queue_pop_head(ssm_data->unexpected_msg_complete_queue);
    while (buffer != NULL) {
        free(buffer->addr);
	free(buffer);
	buffer = hg_queue_pop_head(ssm_data->unexpected_msg_complete_queue);
    }

    ret = ssm_unlink(ssm_data->ssm, ssm_data->unexpected_me);

    if (ret) {
        if (ret == SSM_REMOVE_INVALID)
	    NA_LOG_ERROR("SSM_REMOVE_INVALID\n");
	NA_LOG_ERROR("SSM_REMOVE_BUSY\n");
    }

    /* If we cannot stop ssm instance, we better do not proceed with
     * releasing resources which may be in use by SSM.
     */
    ret = ssm_stop(ssm_data->ssm);
    if (ret < 0)
    {
        NA_LOG_ERROR("Failed to stop SSM instance. Error: %d.\n", ret);
        return ret;
    }

    ret = ssmptcp_tpdel(ssm_data->itp);
    if (ret) {
        NA_LOG_ERROR("ssmptcp_tpdel failed\n");
    }

    hg_queue_free(ssm_data->opid_wait_queue);
    hg_queue_free(ssm_data->unexpected_msg_queue);
    hg_queue_free(ssm_data->unexpected_msg_complete_queue);

    hg_thread_mutex_destroy(&ssm_data->opid_wait_queue_mutex);
    hg_thread_mutex_destroy(&ssm_data->unexpected_msg_queue_mutex);
    hg_thread_mutex_destroy(&ssm_data->unexpected_msg_complete_mutex);
    hg_thread_mutex_destroy(&ssm_data->gen_matchbits);

    free(ssm_data);
    free(in_na_class);

    NA_LOG_DEBUG("Exit.\n");
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
na_ssm_addr_lookup(na_class_t   *in_na_class,
                   na_context_t *in_context,
                   na_cb_t       in_callback,
                   void         *in_arg,
                   const char   *in_name,
                   na_op_id_t   *out_opid)
{
    struct na_ssm_private_data *ssm_data = NA_SSM_PRIVATE_DATA(in_na_class);
    ssmptcp_addrargs_t addrargs;
    struct na_ssm_addr *ssm_addr = NULL;
    struct na_cb_info *cbinfo = NULL;
    char protocol[16];
    char *address = NULL;
    na_return_t ret = NA_SUCCESS;
    struct na_ssm_opid *ssm_opid = NULL;

    NA_LOG_DEBUG("Enter (in_name: %s).\n", in_name);

    assert(ssm_data);
    
    ssm_addr = (struct na_ssm_addr *) malloc(sizeof(struct na_ssm_addr));
    if (__unlikely(ssm_addr == NULL))
    {
        NA_LOG_ERROR("Out of memory error.\n");
        ret = NA_NOMEM_ERROR;
        goto cleanup;
    }

    address = malloc(NA_SSM_MAX_ADDRESS_LENGTH);
    if (__unlikely(address == NULL))
    {
        NA_LOG_ERROR("Out of memory error.\n");
        ret = NA_NOMEM_ERROR;
        goto cleanup;
    }
    
    sscanf(in_name, "%15[^:]://%63[^:]:%d", protocol, address, &addrargs.port);
    addrargs.host = address;
    
    ssm_addr->addr = ssm_addr_create(ssm_data->ssm, &addrargs);
    if(ssm_addr->addr == NULL)
    {
        NA_LOG_ERROR("Unable to create ssm address\n");
        ret = NA_PROTOCOL_ERROR;
        goto cleanup;
    }
    free(address);
    
    cbinfo = (struct na_cb_info *) malloc(sizeof(struct na_cb_info));
    if (__unlikely(cbinfo == NULL))
    {
        NA_LOG_ERROR("Out of memory error.\n");
        ret = NA_NOMEM_ERROR;
        goto cleanup;
    }

    ssm_opid = (struct na_ssm_opid *) malloc(sizeof(struct na_ssm_opid));
    if (__unlikely(ssm_opid == NULL))
    {
        NA_LOG_ERROR("Out of memory error.\n");
        ret = NA_NOMEM_ERROR;
        goto cleanup;
    }

    memset(ssm_opid, 0, sizeof(struct na_ssm_opid));
    
    ssm_opid->requesttype = NA_CB_LOOKUP;
    ssm_opid->user_callback = in_callback;
    ssm_opid->user_context = in_context;
    ssm_opid->user_arg = in_arg;
    ssm_opid->ssm_data = ssm_data;
    ssm_opid->cbinfo = cbinfo;
    ssm_opid->status = SSM_STATUS_INPROGRESS;
    ssm_opid->result = NA_SUCCESS;

    /* Fill the callback info structure */
    cbinfo->arg               = in_arg; 
    cbinfo->ret               = NA_SUCCESS; 
    cbinfo->type              = NA_CB_LOOKUP; 
    cbinfo->info.lookup.addr  = ssm_addr; 

    ret = na_cb_completion_add(in_context,
                               in_callback,
                               cbinfo,
                               na_ssm_addr_lookup_release,
                               (void *) ssm_opid);

    if (ret != NA_SUCCESS)
    {
        /* Inability to add the callback to the completion queue implies
         * something went horribly wrong.  We cannot recover from here.
         */
        NA_LOG_ERROR("Unable to add to the completion queue.\n");
        goto cleanup;
    }
    
    (*out_opid) = (na_op_id_t *) ssm_opid;
    
 cleanup:
    if (ret != NA_SUCCESS)
    {
        free(address);
        free(ssm_opid);

        if (ssm_addr != NULL && ssm_addr->addr != NULL)
        {
            ssm_addr_destroy(ssm_data->ssm, ssm_addr->addr);
        }
        
        free(ssm_addr);
        free(cbinfo);
        (*out_opid) = NULL;
    }
    
    NA_LOG_DEBUG("Exit (Addr: %p, Status: %d).\n", ssm_addr->addr, ret);
    return ret;
}

/**
 * Release function called to release any resources allocated during
 * the lookup operation.
 *
 * @param  in_info    NA callback info structure.
 * @param  in_opid    Op ID structure allocated by the lookup operation.
 * @return (void)
 *
 * @see na_ssm_addr_lookup
 */
static void
na_ssm_addr_lookup_release(struct na_cb_info *in_info,
                           void              *in_opid)
{
    struct na_ssm_opid *ssm_opid = in_opid;
    
    free(in_info);
    free(ssm_opid);
    
    return;
}

/**
 * Free the address.
 *
 * @param  in_na_class   NA class
 * @param  in_addr       NA address container
 * @return na_return_t   Always returns NA_SUCCESS.
 */
static na_return_t
na_ssm_addr_free(na_class_t    NA_UNUSED *in_na_class,
                 na_addr_t                in_addr)
{
    struct na_ssm_addr *addr = (struct na_ssm_addr *) in_addr;
    free(addr);
    return NA_SUCCESS;
}

/**
 * TODO: Convert the given input address to string.
 *
 * @param  in_na_class
 * @param  inout_buf
 * @param  in_buf_size
 * @param  in_addr
 * @return na_return_t
 */
static na_return_t
na_ssm_addr_to_string(na_class_t     NA_UNUSED *in_na_class,
                      char           NA_UNUSED *inout_buf,
                      na_size_t      NA_UNUSED  in_buf_size,
                      na_addr_t      NA_UNUSED  in_addr)
{
    return NA_SUCCESS;
}

/**
 * Returns maximum expected message size.
 *
 * @param  in_na_class  NA class
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
 * @param  in_na_class   NA Class
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
 * @param  in_na_class  NA Class
 * @return na_tag_t     Maximum tag on a message.
 */
static na_tag_t
na_ssm_msg_get_max_tag(na_class_t NA_UNUSED *in_na_class)
{
    return (na_tag_t) (UINT32_MAX);
}

/**
 * Send an unexpected message to the destination.
 *
 * @param   in_na_class      NA Class
 * @param   in_context       NA Context
 * @param   in_callback      User callback
 * @param   in_arg           User argument
 * @param   in_buf           Input buffer
 * @param   in_buf_size      Input buffer size
 * @param   in_destination   Destination address
 * @param   in_tag           Match entry tag
 * @param   out_opid         NA Op ID
 * @return  na_return_t      NA_SUCCESS/NA_FAIL/NA_NOMEM_ERROR
 *
 * @see na_ssm_msg_send_unexpected_callback()
 * @see na_ssm_msg_send_unexpected_release()
 */
static na_return_t
na_ssm_msg_send_unexpected(na_class_t    *in_na_class,
                           na_context_t  *in_context,
                           na_cb_t        in_callback,
                           void          *in_arg,
                           const void    *in_buf,
                           na_size_t      in_buf_size,
                           na_addr_t      in_destination,
                           na_tag_t       in_tag,
                           na_op_id_t    *out_opid)
{
    na_return_t ret = NA_SUCCESS;
    ssm_size_t ssm_buf_size = (ssm_size_t) in_buf_size;
    struct na_ssm_addr *peer_addr = (struct na_ssm_addr *) in_destination;
    struct na_ssm_opid *ssm_opid = NULL;
    ssm_mr v_ssm_mr = NULL;
    ssm_tx v_ssm_tx = NULL;
    struct na_ssm_private_data *ssm_data = NA_SSM_PRIVATE_DATA(in_na_class);

    NA_LOG_DEBUG("Enter.\n");
    
    assert(ssm_data);
    assert(in_buf);

    ssm_opid = (struct na_ssm_opid *) malloc(sizeof(struct na_ssm_opid));
    if (__unlikely(ssm_opid == NULL))
    {
        NA_LOG_ERROR("Out of memory error.\n");
        return NA_NOMEM_ERROR;
    }
    memset(ssm_opid, 0, sizeof(struct na_ssm_opid));

    ssm_opid->cbinfo = malloc(sizeof(struct na_cb_info));
    if (__unlikely(ssm_opid->cbinfo == NULL))
    {
        free(ssm_opid);
        NA_LOG_ERROR("Out of memory error.\n");
        return NA_NOMEM_ERROR;
    }
    memset(ssm_opid->cbinfo, 0, sizeof(struct na_cb_info));
    
    ssm_opid->requesttype = NA_CB_SEND_UNEXPECTED;
    ssm_opid->user_callback = in_callback;
    ssm_opid->user_arg = in_arg;
    ssm_opid->user_context = in_context;
    ssm_opid->ssm_data = ssm_data;
    ssm_opid->ssm_callback.pcb = na_ssm_msg_send_unexpected_callback;
    ssm_opid->ssm_callback.cbdata = ssm_opid;
    ssm_opid->info.send_unexpected.matchbits = (ssm_bits) in_tag + NA_SSM_TAG_UNEXPECTED_OFFSET;
    
    v_ssm_mr = ssm_mr_create(NULL, (void *) in_buf, ssm_buf_size);
    if (v_ssm_mr == NULL)
    {
        NA_LOG_ERROR("Unable to create memory region.\n");
        ret = NA_PROTOCOL_ERROR;
        goto cleanup;
    }

    v_ssm_tx = ssm_put(ssm_data->ssm,
                       peer_addr->addr,
                       v_ssm_mr,
                       NULL,
                       ssm_opid->info.send_unexpected.matchbits,
                       &ssm_opid->ssm_callback,
                       SSM_NOF);

    if (v_ssm_tx == NULL)
    {
        NA_LOG_ERROR("SSM failed to put the buffer.\n");
        ret = NA_PROTOCOL_ERROR;
        goto cleanup;
    }
    
    ssm_opid->transaction = v_ssm_tx;
    ssm_opid->info.send_unexpected.memregion = v_ssm_mr;

    (*out_opid) = (na_op_id_t *) ssm_opid;
    
 cleanup:

    if (ret != NA_SUCCESS)
    {
        if (v_ssm_mr != NULL)
        {
            ssm_mr_destroy(v_ssm_mr);
        }

        free(ssm_opid);
        (*out_opid) = NULL;
    }

    NA_LOG_DEBUG("Exit (Status: %d).\n", ret);
    return ret;
}

/**
 * Callback routine for unexpected send message.  This routine is
 * called once the unexpected message completes.
 *
 * @param in_context
 * @param in_ssm_event_data
 *
 * @see na_ssm_msg_send_unexpected()
 */
static void
na_ssm_msg_send_unexpected_callback(void *in_context,
                                    void *in_ssm_event_data) 
{
    ssm_result result = in_ssm_event_data;
    struct na_ssm_opid *ssm_opid = in_context;
    struct na_cb_info *cbinfo = ssm_opid->cbinfo;
    na_return_t ret = NA_SUCCESS;

    NA_LOG_DEBUG("Enter.\n");
    
    if (result->status == SSM_ST_COMPLETE)
    {
        NA_SSM_MARK_OPID_COMPLETE(ssm_opid);
        ssm_opid->result = NA_SUCCESS;
    }
    else if (result->status == SSM_ST_CANCEL)
    {
        NA_SSM_MARK_OPID_CANCELED(ssm_opid);
        ssm_opid->result = NA_CANCELED;
    }
    else
    {
        NA_LOG_ERROR("Protocol Error: %d.\n", result->status);
        ssm_opid->result = NA_PROTOCOL_ERROR;
    }

    ssm_opid->status = SSM_STATUS_COMPLETED;
    
    cbinfo->arg = ssm_opid->user_arg;
    cbinfo->ret = ssm_opid->result;
    cbinfo->type = NA_CB_SEND_UNEXPECTED;
    
    ret = na_cb_completion_add(ssm_opid->user_context,
                               ssm_opid->user_callback,
                               cbinfo,
                               na_ssm_msg_send_unexpected_release,
                               (void *) ssm_opid);

    if (ret != NA_SUCCESS)
    {
        NA_LOG_ERROR("Unable to queue the callback.\n");
    }
    
    NA_LOG_DEBUG("Exit (ret: %d)\n", ret);
}

/**
 * Callback called after NA has called the user's callback.  This
 * callback function only does cleanup/release of resources that were
 * allocated at the beginning of the send unexpected operation.
 *
 * @param in_na_ssm_opid
 * @param in_release_context
 *
 * @see na_ssm_msg_send_unexpected()
 * @see na_ssm_msg_send_unexpected_callback()
 */
static void
na_ssm_msg_send_unexpected_release(struct na_cb_info *in_info,
                                   void              *in_na_ssm_opid)
{
    struct na_ssm_opid *v_ssm_opid = in_na_ssm_opid;

    /* FIX: Confirm if this destroy is necessary.  Does SSM destroy the
     * memory region automatically once the buffer is sent?
     */
    ssm_mr_destroy(v_ssm_opid->info.send_unexpected.memregion);
    
    free(in_info);
    free(v_ssm_opid);
    return;
}

/**
 * Receive an unexpected message.
 *
 * @param in_na_class    NA Class
 * @param in_context     NA Context
 * @param in_callback    NA Callback
 * @param in_arg         NA arguments
 * @param in_buf         Input buffer
 * @param in_buf_size    Input buffer length
 * @param out_opid       Out Op Id
 * @return na_return_t   NA_SUCCESS if successfully accepted the request and
 *                       a callback will be called.
 *
 * @see na_ssm_msg_recv_unexpected_callback()
 * @see na_ssm_msg_recv_unexpected_release()
 */
static na_return_t
na_ssm_msg_recv_unexpected(na_class_t      *in_na_class,
                           na_context_t    *in_context,
                           na_cb_t          in_callback,
                           void            *in_arg,
                           void            *in_buf,
                           na_size_t        in_buf_size,
                           na_op_id_t      *out_opid)
{
    na_return_t ret = NA_SUCCESS;
    struct na_ssm_opid *ssm_opid = NULL;
    struct na_ssm_private_data *ssm_data = NA_SSM_PRIVATE_DATA(in_na_class);
    struct na_ssm_unexpected_buffer *buffer = NULL;
    struct na_cb_info *cbinfo = NULL;

    NA_LOG_DEBUG("Enter.\n");

    assert(ssm_data);

    ssm_opid = (struct na_ssm_opid *) malloc(sizeof(struct na_ssm_opid));
    if (__unlikely(ssm_opid == NULL))
    {
        hg_thread_mutex_unlock(&ssm_data->unexpected_msg_queue_mutex);
        NA_LOG_ERROR("Out of memory error.");
        return NA_NOMEM_ERROR;
    }
    memset(ssm_opid, 0, sizeof(struct na_ssm_opid));
    
    ssm_opid->requesttype = NA_CB_RECV_UNEXPECTED;
    ssm_opid->user_callback = in_callback;
    ssm_opid->user_context = in_context;
    ssm_opid->user_arg = in_arg;
    ssm_opid->ssm_data = ssm_data;
    ssm_opid->transaction = NULL;
    ssm_opid->status = SSM_STATUS_INPROGRESS;
    ssm_opid->result = NA_SUCCESS;
    ssm_opid->info.recv_unexpected.input_buffer = in_buf;
    ssm_opid->info.recv_unexpected.input_buffer_size = in_buf_size;

    /* If there is nothing to receive, just accept the request and
     * wait for the receive callback to happen first.
     */
    hg_thread_mutex_lock(&ssm_data->unexpected_msg_complete_mutex);
    buffer = hg_queue_pop_head(ssm_data->unexpected_msg_complete_queue);
    hg_thread_mutex_unlock(&ssm_data->unexpected_msg_complete_mutex);
    
    if (buffer == NULL)
    {
        /* We haven't received anything yet, so push the request into
         * the opid queue and wait for the buffer to arrive.
         */
        hg_thread_mutex_lock(&ssm_data->opid_wait_queue_mutex);
        if (!hg_queue_push_tail(ssm_data->opid_wait_queue,
                                (hg_queue_value_t) ssm_opid))
        {
            NA_LOG_ERROR("Not sure what happend!\n");
        }
        
        hg_thread_mutex_unlock(&ssm_data->opid_wait_queue_mutex);
    }
    else
    {
        if (buffer->status == SSM_ST_COMPLETE)
        {
            ssm_opid->result = NA_SUCCESS;
        }
        else
        {
            ssm_opid->result = NA_PROTOCOL_ERROR;
        }

        ssm_opid->status = SSM_STATUS_COMPLETED;
        
        /* copy the received buffer into the user's buffer */
        memcpy(in_buf, buffer->buf, in_buf_size);
        
        /* recreate the memory region and push the buffer back into
         * the queue */
	ssm_drop(ssm_data->ssm,
		 ssm_data->unexpected_me,
		 buffer->mr);

	ssm_mr_destroy(buffer->mr);

        buffer->mr = ssm_mr_create(NULL,
                                   buffer->buf,
                                   NA_SSM_UNEXPECTED_SIZE);
        ret = ssm_post(ssm_data->ssm,
                       ssm_data->unexpected_me,
                       buffer->mr,
                       SSM_NOF);
        /* push the buffer back into the queue */
        hg_thread_mutex_lock(&ssm_data->unexpected_msg_queue_mutex);
        hg_queue_push_tail(ssm_data->unexpected_msg_queue,
                           (hg_queue_value_t) buffer);
        hg_thread_mutex_unlock(&ssm_data->unexpected_msg_queue_mutex);
        
        cbinfo = malloc(sizeof(struct na_cb_info));
        if (__unlikely(cbinfo == NULL))
        {
            NA_LOG_ERROR("Out of memory error.\n");
            goto done;
        }
        
        cbinfo->arg = in_arg;
        cbinfo->ret = ssm_opid->result;
        cbinfo->type = ssm_opid->requesttype;
        cbinfo->info.recv_unexpected.actual_buf_size = buffer->bytes;
        cbinfo->info.recv_unexpected.source = buffer->addr;
        cbinfo->info.recv_unexpected.tag = buffer->bits;
        
        ret = na_cb_completion_add(in_context,
                                   in_callback,
                                   cbinfo,
                                   na_ssm_msg_recv_unexpected_release,
                                   ssm_opid);
        
        if (ret != NA_SUCCESS)
        {
            NA_LOG_ERROR("Unable to add callback to completion queue.");
        }
    }

    (*out_opid) = (na_op_id_t *) ssm_opid;
    
 done:
    if (ret != NA_SUCCESS)
    {
        free(ssm_opid);
        (*out_opid) = NULL;
    }
    
    NA_LOG_DEBUG("Exit (ret: %d).\n", ret);    
    return ret;
}

/**
 * Callback routine when an unexpected message is received.
 *
 * @param  in_context
 * @param  in_ssm_event_data
 * @return (void)
 *
 * @see na_ssm_msg_recv_unexpected()
 * @see na_ssm_msg_recv_unexpected_release()
 */
static void
na_ssm_msg_recv_unexpected_callback(void *in_context,
                                    void *in_ssm_event_data)
{
    ssm_result result = in_ssm_event_data;
    struct na_ssm_private_data *ssm_data = in_context;
    struct na_ssm_unexpected_buffer *buffer = NULL;
    struct na_ssm_opid *ssm_opid = NULL;
    struct na_cb_info *cbinfo = NULL;
    struct na_ssm_addr *addr = NULL;
    na_return_t ret = NA_SUCCESS;
    
    NA_LOG_DEBUG("Enter (Status: %d).\n", result->status);

    if (result->status == SSM_ST_COMPLETE)
    {
        /* Pop the head */
        hg_thread_mutex_lock(&ssm_data->unexpected_msg_queue_mutex);
        buffer = hg_queue_pop_head(ssm_data->unexpected_msg_queue);        
        hg_thread_mutex_unlock(&ssm_data->unexpected_msg_queue_mutex);

        if (buffer == NULL)
        {
            /* something messed up; we cannot get this callback, but have
             * nothing in the queue.
             */
            NA_LOG_ERROR("Empty buffer.\n");
            return;
        }

        buffer->status = result->status;
        buffer->bytes = result->bytes;

        addr = malloc(sizeof(struct na_ssm_addr));
        if (addr != NULL)
        {
            addr->addr = ssm_addr_cp(ssm_data->ssm, result->addr);
        }

        buffer->addr = addr;
        buffer->bits = result->bits;
        
        /* We got a completed buffer, push it on to the completed queue. */
        hg_thread_mutex_lock(&ssm_data->unexpected_msg_complete_mutex);
        hg_queue_push_tail(ssm_data->unexpected_msg_complete_queue,
                           (hg_queue_value_t) buffer);
        hg_thread_mutex_unlock(&ssm_data->unexpected_msg_complete_mutex);
    }
    else
    {
        NA_LOG_ERROR("Unexpected message receive error. Status: %d\n",
                     result->status);
    }

    hg_thread_mutex_lock(&ssm_data->opid_wait_queue_mutex);
    ssm_opid = hg_queue_pop_head(ssm_data->opid_wait_queue);
    hg_thread_mutex_unlock(&ssm_data->opid_wait_queue_mutex);
    
    if (ssm_opid != NULL)
    {
        ssm_opid->status = SSM_STATUS_COMPLETED;
        if (result->status == SSM_ST_COMPLETE)
        {
            ssm_opid->result = NA_SUCCESS;
        }
        else
        {
            ssm_opid->result = NA_PROTOCOL_ERROR;
        }
        
        /* copy the received buffer into the user's buffer */
        NA_LOG_DEBUG("Copying %lu into buffer %p.\n",
                     buffer->bytes,
                     //ssm_opid->info.recv_unexpected.input_buffer_size,
                     ssm_opid->info.recv_unexpected.input_buffer);
        
        memcpy(ssm_opid->info.recv_unexpected.input_buffer,
               buffer->buf,
               ssm_opid->info.recv_unexpected.input_buffer_size);
        
        /* recreate the memory region and push the buffer back into
         * the queue */
        hg_thread_mutex_lock(&ssm_data->unexpected_msg_queue_mutex);

	ssm_drop(ssm_data->ssm,
		 ssm_data->unexpected_me,
		 buffer->mr);

	ssm_mr_destroy(buffer->mr);

        buffer->mr = ssm_mr_create(NULL,
                                   buffer->buf,
                                   NA_SSM_UNEXPECTED_SIZE);
        
        ret = ssm_post(ssm_data->ssm,
                       ssm_data->unexpected_me,
                       buffer->mr,
                       SSM_NOF);

        hg_queue_push_tail(ssm_data->unexpected_msg_queue,
                           (hg_queue_value_t) buffer);
        hg_thread_mutex_unlock(&ssm_data->unexpected_msg_queue_mutex);

        addr = malloc(sizeof(struct na_ssm_addr));
        if (addr != NULL)
        {
            addr->addr = ssm_addr_cp(ssm_data->ssm, result->addr);
        }

        cbinfo = malloc(sizeof(struct na_cb_info));
        if (__unlikely(cbinfo == NULL))
        {
            goto done;
        }

        cbinfo->arg = ssm_opid->user_arg;
        cbinfo->ret = ssm_opid->result;
        cbinfo->type = ssm_opid->requesttype;

        cbinfo->info.recv_unexpected.actual_buf_size = result->bytes;
        cbinfo->info.recv_unexpected.source = addr;
        cbinfo->info.recv_unexpected.tag = result->bits;

        ret = na_cb_completion_add(ssm_opid->user_context,
                                   ssm_opid->user_callback,
                                   cbinfo,
                                   na_ssm_msg_recv_unexpected_release,
                                   ssm_opid);
        
        if (ret != NA_SUCCESS)
        {
            NA_LOG_ERROR("Unable to add callback to completion queue.");
        }

        /* Pull the buffer out of complete queue and put it back into
         * unexpected message queue.
         */
        hg_thread_mutex_lock(&ssm_data->unexpected_msg_complete_mutex);
        buffer = hg_queue_pop_head(ssm_data->unexpected_msg_complete_queue);
        hg_thread_mutex_unlock(&ssm_data->unexpected_msg_complete_mutex);
    }
    else
    {
        NA_LOG_DEBUG("No ssm_opid! Huh?\n");
    }
    
 done:
    NA_LOG_DEBUG("Exit.\n");
    return;
}

/**
 * Release function for unexpected callbacks.
 *
 * @param  in_info
 * @param  in_na_ssm_opid
 * @return (void)
 */
static void
na_ssm_msg_recv_unexpected_release(struct na_cb_info  *in_info,
                                   void               *in_na_ssm_opid)
{
    struct na_ssm_opid *v_opid = in_na_ssm_opid;
    free(in_info);
    free(v_opid);
    return;
}

/**
 * Send an expected message to the given destination address.
 *
 * @param  in_na_class   NA Class
 * @param  in_context    NA context
 * @param  in_callback   NA user callback
 * @param  in_arg        NA argument
 * @param  in_buf        Input buffer
 * @param  in_buf_size   Input buffer size
 * @param  in_dest       Destination address
 * @param  in_tag        Tag for the buffer
 * @param  out_id        Op Id
 * @return na_return_t   NA_SUCCESS if callback will be called.
 *
 * @see na_ssm_msg_send_expected_callback()
 * @see na_ssm_msg_send_expected_release()
 */
static na_return_t
na_ssm_msg_send_expected(na_class_t   *in_na_class,
                         na_context_t *in_context,
                         na_cb_t       in_callback,
                         void         *in_arg,
                         const void   *in_buf,
                         na_size_t     in_buf_size,
                         na_addr_t     in_dest,
                         na_tag_t      in_tag,
                         na_op_id_t   *out_id)
{
    na_return_t ret = NA_SUCCESS;
    ssm_size_t v_ssm_buf_size = (ssm_size_t) in_buf_size;
    struct na_ssm_addr *peer_addr = (struct na_ssm_addr *) in_dest;
    ssm_tx v_transaction = NULL;
    struct na_ssm_opid *ssm_opid = NULL;
    struct na_ssm_private_data *ssm_data = NA_SSM_PRIVATE_DATA(in_na_class);

    NA_LOG_DEBUG("Enter (Tag: %d).\n", in_tag);
    
    if (in_tag == 4 && in_buf != NULL && in_buf_size > sizeof(int)*1024*1024) {
        int *_buffer = (int *) malloc(sizeof(int) * 1024 * 1024);
        memset(_buffer, 0, sizeof(int)*1024*1024);
        memcpy(_buffer,
               in_buf,
               sizeof(int)*1024*1024);
        NA_LOG_DEBUG("Value: %d\n", _buffer[1]);
        free(_buffer);
    }

    assert(peer_addr->addr);
    
    ssm_opid = (struct na_ssm_opid *) malloc(sizeof(struct na_ssm_opid));
    if (__unlikely(ssm_opid == NULL))
    {
        NA_LOG_ERROR("Out of memory error.\n");
        return NA_NOMEM_ERROR;
    }
    memset(ssm_opid, 0, sizeof(struct na_ssm_opid));

    ssm_opid->cbinfo = malloc(sizeof(struct na_cb_info));
    if (__unlikely(ssm_opid->cbinfo == NULL))
    {
        free(ssm_opid);
        NA_LOG_ERROR("Out of memory error.\n");
        return NA_NOMEM_ERROR;
    }
    memset(ssm_opid->cbinfo, 0, sizeof(struct na_cb_info));
    
    ssm_opid->requesttype = NA_CB_SEND_EXPECTED;
    ssm_opid->user_callback = in_callback;
    ssm_opid->user_context = in_context;
    ssm_opid->user_arg = in_arg;
    ssm_opid->ssm_data = ssm_data;
    ssm_opid->ssm_callback.pcb = na_ssm_msg_send_expected_callback;
    ssm_opid->ssm_callback.cbdata = ssm_opid;
    
    ssm_opid->info.send_expected.memregion = ssm_mr_create(NULL,
                                                           (void *) in_buf,
                                                           v_ssm_buf_size);

    if (ssm_opid->info.send_expected.memregion == NULL)
    {
        NA_LOG_ERROR("Unable to create memory region.\n");
        ret = NA_PROTOCOL_ERROR;
        goto cleanup;
    }

    ssm_opid->info.send_expected.matchbits = (ssm_bits) in_tag +
                                                  NA_SSM_TAG_EXPECTED_OFFSET;
    
    v_transaction = ssm_put(ssm_data->ssm,
                            peer_addr->addr,
                            ssm_opid->info.send_expected.memregion,
                            NULL,
                            (ssm_bits)in_tag + NA_SSM_TAG_EXPECTED_OFFSET,
                            &(ssm_opid->ssm_callback),
                            SSM_NOF);

    if (v_transaction == NULL)
    {
        NA_LOG_ERROR("Unable to initiate put operation.\n");
        ret = NA_PROTOCOL_ERROR;
        goto cleanup;
    }

    NA_LOG_DEBUG("Sending expected message of size %lu with tag %x.\n",
                 in_buf_size,
                 (unsigned int) ssm_opid->info.send_expected.matchbits);

    ssm_opid->transaction    = v_transaction;
    ssm_opid->status         = SSM_STATUS_INPROGRESS;

    (*out_id) = (na_op_id_t *) ssm_opid;
    
 cleanup:
    if (ret != NA_SUCCESS)
    {        
        free(ssm_opid);
        (*out_id) = NULL;
    }

    NA_LOG_DEBUG("Exit (ret: %d).\n", ret);
    return ret;
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
static void
na_ssm_msg_send_expected_callback(void *in_context,
                                  void *in_ssm_event_data) 
{
    ssm_result v_result = in_ssm_event_data;
    struct na_ssm_opid *v_ssm_opid = in_context;
    struct na_cb_info *cbinfo = v_ssm_opid->cbinfo;
    na_return_t ret = NA_SUCCESS;

    NA_LOG_DEBUG("Enter.\n");
    
    if (v_result->status == SSM_ST_COMPLETE)
    {
        NA_SSM_MARK_OPID_COMPLETE(v_ssm_opid);
        v_ssm_opid->result = NA_SUCCESS;
    }
    else if (v_result->status == SSM_ST_CANCEL)
    {
        NA_SSM_MARK_OPID_CANCELED(v_ssm_opid);
        v_ssm_opid->result = NA_CANCELED;
    }
    else
    {
        NA_LOG_ERROR("SSM returned error %d\n", v_result->status);
        v_ssm_opid->result = NA_PROTOCOL_ERROR;
    }

    cbinfo->arg = v_ssm_opid->user_arg;
    cbinfo->ret = v_ssm_opid->result;
    cbinfo->type = v_ssm_opid->requesttype;
    
    ret = na_cb_completion_add(v_ssm_opid->user_context,
                               v_ssm_opid->user_callback,
                               cbinfo,
                               na_ssm_msg_send_expected_release,
                               v_ssm_opid);
    if (ret != NA_SUCCESS)
    {
        NA_LOG_ERROR("Unable to queue completion callback. Error: %d.\n", ret);
    }
    
    NA_LOG_DEBUG("Exit.\n");
    return;
}

/**
 * Release callback routine called after calling the user's callback.
 * This routine only releases any resources allocated during the
 * expected message send operation.
 *
 * @param  in_info          callback info
 * @param  in_na_ssm_opid   ssm opid
 * @return (void)
 *
 * @see na_ssm_msg_send_expected()
 * @see na_ssm_msg_send_expected_callback()
 */
static void
na_ssm_msg_send_expected_release(struct na_cb_info  *in_info,
                                 void               *in_na_ssm_opid)
{
    struct na_ssm_opid   *v_ssm_opid = in_na_ssm_opid;

    /* FIX: Confirm if this destroy is necessary.  Does SSM destroy the
     * memory region automatically once the buffer is sent?
     */
    ssm_mr_destroy(v_ssm_opid->info.send_expected.memregion);
    
    free(in_info);
    free(v_ssm_opid);
    return;
}

/**
 * Receive an expected message from the source.
 *
 * @param  in_na_class    NA class
 * @param  in_context     NA context
 * @param  in_callback    NA user's callback
 * @param  in_arg         NA user's argument
 * @param  in_buf         Input buffer
 * @param  in_buf_size    Input buffer length
 * @param  in_source      Source address
 * @param  in_tag         Buffer tag
 * @param  out_opid       Returned Op Id
 * @return na_return_t    NA_SUCCESS if callback will be called.
 *
 * @see na_ssm_msg_recv_expected_callback()
 * @see na_ssm_msg_recv_expected_release()
 */
static na_return_t
na_ssm_msg_recv_expected(na_class_t     *in_na_class,
                         na_context_t   *in_context,
                         na_cb_t         in_callback,
                         void           *in_arg,
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
    struct na_ssm_private_data *v_data   = NA_SSM_PRIVATE_DATA(in_na_class);

    NA_LOG_DEBUG("Enter.\n");
    
    v_ssm_opid = (struct na_ssm_opid *) malloc(sizeof(struct na_ssm_opid));
    if (__unlikely(v_ssm_opid == NULL))
    {
        v_return = NA_NOMEM_ERROR;
        goto done;
    }
    memset(v_ssm_opid, 0, sizeof(struct na_ssm_opid));
    
    v_ssm_opid->requesttype   = NA_CB_RECV_EXPECTED;
    v_ssm_opid->user_callback = in_callback;
    v_ssm_opid->user_context  = in_context;
    v_ssm_opid->user_arg = in_arg;
    v_ssm_opid->ssm_data = v_data;
    
    /* Register Memory */
    v_ssm_opid->info.recv_expected.memregion = ssm_mr_create(NULL,
                                                             (void *) in_buf,
                                                             v_ssm_buf_size);
    
    if (v_ssm_opid->info.recv_expected.memregion == NULL)
    {
        NA_LOG_ERROR("ssm_mr_create failed.\n");
        v_return = NA_PROTOCOL_ERROR;
        goto done;
    }
    
    /* Prepare callback function */
    v_ssm_opid->ssm_callback.pcb    = na_ssm_msg_recv_expected_callback;
    v_ssm_opid->ssm_callback.cbdata = v_ssm_opid;
    v_ssm_opid->info.recv_expected.input_buffer = in_buf;
    v_ssm_opid->info.recv_expected.input_buffer_size = in_buf_size;
    v_ssm_opid->info.recv_expected.matchbits = (ssm_bits) in_tag + NA_SSM_TAG_EXPECTED_OFFSET;
    
    /* Post the SSM recv request */
    v_ssm_opid->info.recv_expected.matchentry = ssm_link(v_data->ssm,
                                                         (ssm_bits) in_tag + NA_SSM_TAG_EXPECTED_OFFSET,
                                      0x0 /* mask */,
                                      SSM_POS_HEAD,
                                      NULL,
                                      &v_ssm_opid->ssm_callback,
                                      SSM_NOF);

    if (v_ssm_opid->info.recv_expected.matchentry == NULL)
    {
        v_return = NA_PROTOCOL_ERROR;
        goto done;
    }

    NA_LOG_DEBUG("Expecting recv of size %lu with tag: %x.\n", in_buf_size,
                 (unsigned int) v_ssm_opid->info.recv_expected.matchbits);
    
    v_ssm_return = ssm_post(v_data->ssm,
                            v_ssm_opid->info.recv_expected.matchentry,
                            v_ssm_opid->info.recv_expected.memregion,
                            SSM_NOF);
    
    if (v_ssm_return < 0)
    {
        NA_LOG_ERROR("ssm_post() failed");
        v_return = NA_PROTOCOL_ERROR;
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

    NA_LOG_DEBUG("Exit.\n");
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
    na_return_t ret = NA_SUCCESS;
    ssm_result v_result = in_ssm_event_data;
    struct na_ssm_opid *v_ssm_opid = in_context;
    struct na_cb_info *cbinfo = NULL;
                 
    NA_LOG_DEBUG("Enter.\n");
    
    if (v_result->status == SSM_ST_COMPLETE)
    {
        NA_SSM_MARK_OPID_COMPLETE(v_ssm_opid);
        v_ssm_opid->result = NA_SUCCESS;
    }
    else if (v_result->status == SSM_ST_CANCEL)
    {
        NA_SSM_MARK_OPID_CANCELED(v_ssm_opid);
        v_ssm_opid->result = NA_CANCELED;
    }
    else
    {
        NA_LOG_ERROR("SSM message receive failed. Error: %d\n",
                     v_result->status);
        v_ssm_opid->result = NA_PROTOCOL_ERROR;
    }

    cbinfo = malloc(sizeof(struct na_cb_info));
    if (__unlikely(cbinfo == NULL))
    {
        goto done;
    }

    cbinfo->arg = v_ssm_opid->user_arg;
    cbinfo->ret = v_ssm_opid->result;
    cbinfo->type = v_ssm_opid->requesttype;
    
    ret = na_cb_completion_add(v_ssm_opid->user_context,
                               v_ssm_opid->user_callback,
                               cbinfo,
                               na_ssm_msg_recv_expected_release,
                               v_ssm_opid);
    if (ret != NA_SUCCESS)
    {
        NA_LOG_ERROR("Unable to queue the completion callback. Error: %d.\n",
                     ret);
    }
    
 done:
    NA_LOG_DEBUG("Exit.\n");
    return;
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
na_ssm_msg_recv_expected_release(struct na_cb_info  *in_info,
                                 void               *in_na_ssm_opid)
{
    struct na_ssm_opid *v_ssm_opid = in_na_ssm_opid;
    free(in_info);
    free(v_ssm_opid);
    return;
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
    struct na_ssm_private_data *v_data   = NA_SSM_PRIVATE_DATA(in_na_class);

    NA_LOG_DEBUG("Enter.\n");
    
    v_handle = (struct na_ssm_mem_handle *) in_mem_handle;

    assert(v_handle);

    /* v_handle->mr = ssm_mr_create(NULL, */
    /*                              v_handle->buf, */
    /*                              v_handle->buf_size); */

    /* if (v_handle->mr == NULL) */
    /* { */
    /*     NA_LOG_ERROR("SSM failed to create memory region.\n"); */
    /*     return NA_PROTOCOL_ERROR; */
    /* } */

    /* v_handle->matchbits = generate_unique_matchbits(in_na_class) + */
    /*                                        NA_SSM_TAG_RMA_OFFSET; */
    
    v_handle->cb.pcb    = na_ssm_post_callback;
    v_handle->cb.cbdata = v_handle;

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
        return NA_PROTOCOL_ERROR;
    }

    NA_LOG_DEBUG("Exit.\n");
    return NA_SUCCESS;
}

/**
 * Callback function for registered memory region.
 *
 * @param  cbdat
 * @param  evdat
 */
static void
na_ssm_post_callback(void NA_UNUSED(*cbdat), void *evdat)
{
    ssm_result v_ssm_result = evdat;

    NA_LOG_DEBUG("Enter.\n");
    
    if (v_ssm_result->status != SSM_ST_COMPLETE)
    {
        NA_LOG_ERROR("SSM reported error.");
        return;
    }

    NA_LOG_DEBUG("Exit.\n");
    return;
}

/**
 * Deregister memory region.
 *
 * @param  in_na_class
 * @param  in_mem_handle
 * @return na_return_t
 */
static na_return_t
na_ssm_mem_deregister(na_class_t      NA_UNUSED *in_na_class,
                      na_mem_handle_t  in_mem_handle)
{
    int rc;
    na_return_t               v_return = NA_SUCCESS;
    struct na_ssm_mem_handle *v_handle = NULL;

    NA_LOG_DEBUG("Enter.\n");
    
    v_handle = (struct na_ssm_mem_handle *) in_mem_handle;
    
    rc = ssm_mr_destroy(v_handle->mr);
    
    if (rc == 0)
    {
        v_return = NA_SUCCESS;
    }
    else
    {
        v_return = NA_PROTOCOL_ERROR;
    }

    NA_LOG_DEBUG("Exit.\n");
    return v_return;
}

/**
 * Get size required to serialize ssm handle.
 *
 * @param  in_na_class
 * @param  in_mem_handle
 * @return na_size_t
 */
na_size_t
na_ssm_mem_handle_get_serialize_size(na_class_t       NA_UNUSED *in_na_class,
                                     na_mem_handle_t   NA_UNUSED in_mem_handle)
{
    return sizeof(struct na_ssm_mem_handle);
}

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
                            na_mem_handle_t   in_mem_handle)
{
    na_return_t                v_return = NA_SUCCESS;
    struct na_ssm_mem_handle  *v_handle = NULL;

    NA_LOG_DEBUG("Enter.\n");
    
    v_handle = (struct na_ssm_mem_handle *) in_mem_handle;

    if (__unlikely(v_handle == NULL))
    {
        NA_LOG_ERROR("Invalid input parameter.\n");
        return NA_INVALID_PARAM;
    }

    if (in_buf_size < sizeof(struct na_ssm_mem_handle))
    {
        v_return = NA_SIZE_ERROR;
    }
    else
    {
        memcpy(in_buf, v_handle, sizeof(struct na_ssm_mem_handle));
    }

    NA_LOG_DEBUG("Exit. (%d)\n", v_return);
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

    NA_LOG_DEBUG("Enter.\n");
    
    if (in_buf_size < sizeof(struct na_ssm_mem_handle))
    {
        v_return = NA_SIZE_ERROR;
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

    NA_LOG_DEBUG("Exit. (%d)\n", v_return);
    return v_return;
}

/**
 * Create SSM memory handle.
 *
 * @param  in_na_class
 * @param  in_buf
 * @param  in_buf_size
 * @param  in_flags
 * @param  out_mem_handle
 * @return na_return_t
 */
static na_return_t
na_ssm_mem_handle_create(na_class_t      *in_na_class,
                         void            *in_buf,
                         na_size_t        in_buf_size,
                         unsigned long    in_flags,
                         na_mem_handle_t *out_mem_handle)
{
    na_return_t ret = NA_SUCCESS;
    struct na_ssm_mem_handle *handle = NULL;
    
    NA_LOG_DEBUG("Enter (flag: %ld).\n", in_flags);
    
    handle = malloc(sizeof(struct na_ssm_mem_handle));
    if (__unlikely(handle == NULL))
    {
        ret = NA_NOMEM_ERROR;
        goto done;
    }

    handle->buf = in_buf;
    handle->buf_size = in_buf_size;
    handle->flag = in_flags;
    handle->matchbits = generate_unique_matchbits(in_na_class) +
                                               NA_SSM_TAG_RMA_OFFSET;

    handle->mr = ssm_mr_create(NULL, handle->buf, in_buf_size);
    if (handle->mr == NULL)
    {
        NA_LOG_ERROR("Unable to create memory region.\n");
        ret = NA_PROTOCOL_ERROR;
    }

    (*out_mem_handle) = handle;

 done:
    if (ret != NA_SUCCESS)
    {
        free(handle);
        (*out_mem_handle) = NULL;
    }
    
    NA_LOG_DEBUG("Exit.\n");
    return ret;
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
    
    NA_LOG_DEBUG("Enter.\n");
    
    v_handle = (struct na_ssm_mem_handle *) in_mem_handle;

    if (v_handle)
    {
        //        ssm_mr_destroy(v_handle->mr);
        free(v_handle);
        v_handle = NULL;
    }

    NA_LOG_DEBUG("Exit.\n");
    return NA_SUCCESS;
}

/**
 * Put data to remote target.
 *
 * @param in_local_mem_handle
 */
static na_return_t
na_ssm_put(na_class_t        *in_na_class,
           na_context_t *in_context,
           na_cb_t            in_callback,
           void              *in_arg,
           na_mem_handle_t    in_local_mem_handle,
           na_offset_t       NA_UNUSED  in_local_offset,
           na_mem_handle_t    in_remote_mem_handle,
           na_offset_t    NA_UNUSED     in_remote_offset,
           na_size_t     NA_UNUSED      in_data_size,
           na_addr_t           in_remote_addr,
           na_op_id_t         *out_opid)
{
    na_return_t v_return = NA_SUCCESS;
    struct na_ssm_addr *v_peer_addr = (struct na_ssm_addr *) in_remote_addr;
    struct na_ssm_opid *v_opid = NULL;
    ssm_tx v_transaction = NULL;
    struct na_ssm_private_data *v_data = NA_SSM_PRIVATE_DATA(in_na_class);
    struct na_ssm_mem_handle *v_handle = (struct na_ssm_mem_handle *) in_local_mem_handle;
    struct na_ssm_mem_handle *v_rhandle = (struct na_ssm_mem_handle *) in_remote_mem_handle;

    NA_LOG_DEBUG("Enter.\n");
    
    assert(v_peer_addr);
    assert(v_handle);
    
    v_opid = (struct na_ssm_opid *) malloc(sizeof(struct na_ssm_opid));
    if (__unlikely(v_opid == NULL))
    {
        NA_LOG_ERROR("Out of memory error.\n");
        return NA_NOMEM_ERROR;
    }
    memset(v_opid, 0, sizeof(struct na_ssm_opid));

    v_opid->requesttype = NA_CB_PUT;
    v_opid->user_callback = in_callback;
    v_opid->user_arg = in_arg;
    v_opid->user_context = in_context;
    v_opid->ssm_data = v_data;
    v_opid->ssm_callback.pcb = na_ssm_put_callback;
    v_opid->ssm_callback.cbdata = v_opid;

    v_opid->cbinfo = malloc(sizeof(struct na_cb_info));
    if (__unlikely(v_opid->cbinfo == NULL))
    {
        free(v_opid);
        return NA_NOMEM_ERROR;
    }
    
    v_transaction = ssm_put(v_data->ssm,
                            v_peer_addr->addr,
                            v_handle->mr,
                            NULL,
                            v_rhandle->matchbits,
                            &v_opid->ssm_callback,
                            SSM_NOF);

    if (v_transaction == NULL)
    {
        NA_LOG_ERROR("Unable to initiate put operation.\n");
        
        free(v_opid->cbinfo);
        free(v_opid);

        v_return = NA_PROTOCOL_ERROR;
        goto done;
    }
    
    v_opid->transaction = v_transaction;
    (*out_opid) = v_opid;
    
 done:
    NA_LOG_DEBUG("Exit. Status: %d.\n", v_return);
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
    struct na_cb_info *cbinfo = v_ssm_opid->cbinfo;
    na_return_t ret = NA_SUCCESS;

    NA_LOG_DEBUG("Enter.\n");
    
    if (v_result->status == SSM_ST_COMPLETE)
    {
        NA_SSM_MARK_OPID_COMPLETE(v_ssm_opid);
    }

    cbinfo->arg = v_ssm_opid->user_arg;
    cbinfo->ret = NA_SUCCESS;
    cbinfo->type = v_ssm_opid->requesttype;
    
    ret = na_cb_completion_add(v_ssm_opid->user_context,
                               v_ssm_opid->user_callback,
                               cbinfo,
                               na_ssm_put_release,
                               v_ssm_opid);
    if (ret != NA_SUCCESS)
    {
        NA_LOG_ERROR("Unable to queue completion callback. Error: %d.\n", ret);
    }

    NA_LOG_DEBUG("Exit.\n");
    return;
}

/**
 * Release function for ssm_put() call.
 *
 * @param  in_info
 * @param  in_na_ssm_opid
 * @return (void)
 */
static void
na_ssm_put_release(struct na_cb_info *in_info,
                   void              *in_na_ssm_opid)
{
    struct na_ssm_opid *ssm_opid = in_na_ssm_opid;
    free(in_info);
    free(ssm_opid);
    return;
}

/**
 * Get data from the remote target.
 *
 * @param  in_na_class
 */
static na_return_t
na_ssm_get(na_class_t        *in_na_class,
           na_context_t *in_context,
           na_cb_t            in_callback,
           void              *in_arg,
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
    struct na_ssm_private_data *v_data          = NA_SSM_PRIVATE_DATA(in_na_class);

    NA_LOG_DEBUG("Enter (length: %ld).\n", in_length);
    
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

    v_ssm_opid->requesttype     = NA_CB_GET;
    v_ssm_opid->user_callback   = in_callback;
    v_ssm_opid->user_arg    = in_arg;
    v_ssm_opid->user_context = in_context;
    v_ssm_opid->ssm_data        = v_data;

    v_ssm_opid->info.get.memregion = v_local_mr;
    v_ssm_opid->info.get.memdesc   = v_remote_md;
    
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
        return NA_PROTOCOL_ERROR;
    }
    
    v_ssm_opid->transaction = v_stx;
    v_ssm_opid->status = SSM_STATUS_INPROGRESS;

    /* Fill the return handle. */
    (*out_opid) = (struct na_ssm_opid *) v_ssm_opid;

    NA_LOG_DEBUG("Exit.\n");
    return NA_SUCCESS;
}

/**
 * Callback function for the get operation.
 *
 * @param  in_context
 * @param  in_ssm_event_data
 * @return (void)
 *
 * @see na_ssm_get()
 */
static void
na_ssm_get_callback(void *in_context,
                    void *in_ssm_event_data) 
{
    ssm_result v_result   = in_ssm_event_data;
    struct na_ssm_opid *v_ssm_opid = in_context;
    struct na_cb_info *cbinfo = NULL;
    na_return_t ret = NA_SUCCESS;

    NA_LOG_DEBUG("Enter.\n");
    
    if (v_result->status == SSM_ST_COMPLETE)
    {
        NA_SSM_MARK_OPID_COMPLETE(v_ssm_opid);
        v_ssm_opid->result = NA_SUCCESS;
    }
    else if (v_result->status == SSM_ST_CANCEL)
    {
        NA_SSM_MARK_OPID_CANCELED(v_ssm_opid);
        v_ssm_opid->result = NA_CANCELED;
    }
    else
    {
        NA_LOG_ERROR("Error reported by SSM. Error: %d\n",
                     v_result->status);
        v_ssm_opid->result = NA_PROTOCOL_ERROR;
    }

    cbinfo = malloc(sizeof(struct na_cb_info));
    if (__unlikely(cbinfo == NULL))
    {
        goto done;
    }

    cbinfo->arg = v_ssm_opid->user_arg;
    cbinfo->ret = v_ssm_opid->result;
    cbinfo->type = v_ssm_opid->requesttype;
    
    /* Add the request to the callback queue. This API should never fail.
     */
    ret = na_cb_completion_add(v_ssm_opid->user_context,
                               v_ssm_opid->user_callback,
                               cbinfo,
                               na_ssm_get_release,
                               v_ssm_opid);
    if (ret != NA_SUCCESS)
    {
        NA_LOG_ERROR("Unable to queue completion callback. Error: %d.\n", ret);
    }
    
 done:
    NA_LOG_DEBUG("Exit.\n");
    return;
}

/**
 * Release function for resources allocated in na_ssm_get().
 *
 * @param  in_info
 * @param  in_na_ssm_opid
 * @return (void)
 *
 * @see na_ssm_get()
 * @see na_ssm_get_callback()
 */
static void
na_ssm_get_release(struct na_cb_info *in_info,
                   void              *in_na_ssm_opid)
{
    struct na_ssm_opid *v_ssm_opid = in_na_ssm_opid;
    free(in_info);
    free(v_ssm_opid);
    return;
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
                na_context_t  NA_UNUSED *in_context,
                unsigned int   NA_UNUSED in_timeout)
{
    struct timeval              v_tv;
    na_return_t                 v_return    = NA_SUCCESS;
    struct na_ssm_private_data *v_data = NA_SSM_PRIVATE_DATA(in_na_class);

    v_tv.tv_sec  = 0; // in_timeout / 1000;
    v_tv.tv_usec = 10000;
    
    do
    {
        v_return = ssm_wait(v_data->ssm, &v_tv);
        sleep(0);
    } while (v_return > 0);

    if ( v_return < 0 )
    {
        v_return = NA_PROTOCOL_ERROR;
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
 * @param  in_na_class  NA class object for reference.
 * @param  in_opid      Operation ID / Request handle
 * @return na_return_t  Returns success if cancel was scheduled.  If the
 *                      task (or transaction) had already completed, then
 *                      we return failure here.
 */
static na_return_t
na_ssm_cancel(na_class_t    *in_na_class,
              na_context_t NA_UNUSED *in_context,
              na_op_id_t     in_opid)
{
    struct na_ssm_private_data *v_data = NA_SSM_PRIVATE_DATA(in_na_class);
    struct na_ssm_opid  *v_ssm_opid  = (struct na_ssm_opid *) in_opid;
    na_return_t          v_return;

    /* See if we have a ssm transaction id available to cancel the
     * operation.
     */
    if (v_ssm_opid != NULL &&
        v_ssm_opid->transaction != NULL)
    {
        v_return = ssm_cancel(v_data->ssm, v_ssm_opid->transaction);
    }

    /* If SSM returns 0, it will attempt to cancel the operation.  This is
     * not guaranteed, and SSM may still end up completing the operation,
     * instead of canceling it.
     *
     * If SSM returns negative number, then the operation could not be
     * canceled.
     */
    if (v_return == 0)
    {
        v_return = NA_SUCCESS;
    }
    else
    {
        v_return = NA_PROTOCOL_ERROR;
    }
    
    return v_return;
}
