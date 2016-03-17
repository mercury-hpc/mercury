/*
 * Copyright (C) 2013-2016 Argonne National Laboratory, Department of Energy,
 *                         UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */
#include <stdlib.h>
#include <stdio.h>

#include "na_test.h"

#define COMPLETION_MAGIC 123456789

int global_test_error = 0;

/*
 * Prototypes
 */
void cancel_unexpected_send (
    na_class_t   *class,
    na_context_t *context,
    na_addr_t    *server_addr,
    na_size_t     len,
    void         *buf);

void cancel_expected_send (
    na_class_t   *class,
    na_context_t *context,
    na_addr_t    *server_addr,
    na_size_t     len,
    void         *buf);

void cancel_unexpected_recv (
    na_class_t   *class,
    na_context_t *context,
    na_size_t     len,
    void         *buf);

void cancel_expected_recv (
    na_class_t   *class,
    na_context_t *context,
    na_addr_t    *server_addr,
    na_size_t     len,
    void         *buf);

void cancel_put (
    na_class_t   *class,
    na_context_t *context,
    na_addr_t    *server_addr,
    na_size_t     len,
    void         *buf);

void cancel_get (
    na_class_t   *class,
    na_context_t *context,
    na_addr_t    *server_addr,
    na_size_t     len,
    void         *buf);

/*
 * Callbacks
 */
static na_return_t lookup_cb (const struct na_cb_info *callback_info)
{
    na_addr_t *addr = (na_addr_t *) callback_info->arg;

    *addr = callback_info->info.lookup.addr;

    return NA_SUCCESS;
}

static na_return_t callback (const struct na_cb_info *callback_info)
{
    unsigned int *flag = (unsigned int *) callback_info->arg;

    if ((callback_info->ret != NA_CANCELED) ||
        (callback_info->type != *flag))
    {
        fprintf(stderr,
                "unexpected callback values: ret:%d type:%d\n",
                callback_info->ret,
                callback_info->type);
        global_test_error = 1;
    }

    if ((callback_info->type == NA_CB_RECV_UNEXPECTED) &&
        (callback_info->info.recv_unexpected.source))
    {
        free(callback_info->info.recv_unexpected.source);
    }

    *flag = COMPLETION_MAGIC; 

    /* debug      */
    printf("callback: type: %d ret: %d\n",
           callback_info->type, callback_info->ret);

 
    return NA_SUCCESS;
}

int main (int argc, char **argv)
{
    na_class_t   *class = NULL;
    na_context_t *context = NULL;
    na_addr_t     server_addr;
    na_size_t     len;
    void         *buf = NULL;
    char          server_name[NA_TEST_MAX_ADDR_NAME];
    na_return_t   naret;
    unsigned int  count;
    int           found = 0;

    class = NA_Test_client_init(argc,
                                argv,
                                server_name,
                                NA_TEST_MAX_ADDR_NAME,
                                NULL);
    if (!class)
    {
        fprintf(stderr, "NA_Test_client_init failed\n");
        global_test_error = 1;
        goto done;
    }

    context = NA_Context_create(class);
    if (!context)
    {
        fprintf(stderr, "NA_Context_create failed\n");
        global_test_error = 1;
        goto done;
    }

    /*
     * BMI specific debug
     */
    gossip_set_debug_mask(1, 0xffffffffffffffff);
    gossip_enable_stderr();
    

    len = NA_Msg_get_max_unexpected_size(class);
    buf = calloc(len, sizeof(char));
    if (!buf)
    {
        perror("memory allocation failure");
        global_test_error = 1;
        goto done;
    }
    
    naret = NA_Addr_lookup(class,
                           context,
                           lookup_cb,
                           &server_addr,
                           server_name,
                           NA_OP_ID_IGNORE);
    if (naret != NA_SUCCESS)
    {
        fprintf(stderr, "NA_Addr_lookup failed: %d\n", naret);
        global_test_error = 1;
        goto done;
    }
    found = 1;

    /* process lookup */
    NA_Progress(class, context, 1);
    naret = NA_Trigger(context, 0, 1, &count);
    if ((naret != NA_SUCCESS) ||
        (count != 1))
    {
        fprintf(stderr, "NA_Trigger failed: ret=%d count=%d\n",
                naret, count);
    }
    cancel_unexpected_send (class,
                            context,
                            &server_addr,
                            len,
                            buf);



    cancel_expected_send (class,
                          context,
                          &server_addr,
                          len,
                          buf);

    cancel_unexpected_recv (class,
                            context,
                            len,
                            buf);

    cancel_expected_recv (class,
                          context,
                          &server_addr,
                          len,
                          buf);

    cancel_put (class,
                context,
                &server_addr,
                len,
                buf);

    cancel_get (class,
                context,
                &server_addr,
                len,
                buf);

done:
    if (found) NA_Addr_free(class, server_addr);

    if (context) NA_Context_destroy(class, context);

    if (buf) free(buf);

    if (class) NA_Test_finalize(class);

    return global_test_error;
}

void cancel_unexpected_send (
    na_class_t   *class,
    na_context_t *context,
    na_addr_t    *server_addr,
    na_size_t     len,
    void         *buf)
{
    na_return_t   naret;
    na_op_id_t    op_id;
    unsigned int  flag;
    unsigned int  count;

    flag = NA_CB_SEND_UNEXPECTED;
    naret = NA_Msg_send_unexpected(class,
                                   context,
                                   callback,
                                   &flag,
                                   buf,
                                   len,
                                   *server_addr, 
                                   1,
                                   &op_id);
    if (naret != NA_SUCCESS)
    {
        fprintf(stderr, "NA_Msg_send_unexpected failed: %d\n", naret);
        global_test_error = 1;
        return;
    }

    naret = NA_Cancel(class, context, op_id);
    if (naret != NA_SUCCESS)
    {
        fprintf(stderr, "NA_Cancel failed: %d\n", naret);
        global_test_error = 1;
        return;
    }

    NA_Progress(class, context, 1);

    count = 0;
    naret = NA_Trigger(context, 0, 1, &count);
    if ((naret != NA_SUCCESS) ||
        (count != 1))
    {
        fprintf(stderr, "NA_Trigger failed: ret=%d count=%d\n", naret, count);
        global_test_error = 1;
    }

    if (flag != COMPLETION_MAGIC)
    {
        fprintf(stderr, "unexpected send callback failed\n");
        global_test_error = 1;
    }

    return;
}

void cancel_expected_send (
    na_class_t   *class,
    na_context_t *context,
    na_addr_t    *server_addr,
    na_size_t     len,
    void         *buf)
{
    na_return_t   naret;
    na_op_id_t    op_id;
    unsigned int  flag;
    unsigned int  count;
   
    flag = NA_CB_SEND_EXPECTED;
    naret = NA_Msg_send_expected(class,
                                 context,
                                 callback,
                                 &flag,
                                 buf,
                                 len,
                                 *server_addr,
                                 2,
                                 &op_id);
    if (naret != NA_SUCCESS)
    {
        fprintf(stderr, "NA_Msg_send_expected failed: %d\n", naret);
        global_test_error = 1;
        return;
    }

    naret = NA_Cancel(class, context, op_id);
    if (naret != NA_SUCCESS)
    {
        fprintf(stderr, "NA_Cancel failed: %d\n", naret);
        global_test_error = 1;
        return;
    }

    NA_Progress(class, context, 1);

    count = 0;
    naret = NA_Trigger(context, 0, 1, &count);
    if ((naret != NA_SUCCESS) ||
        (count != 1))
    {
        fprintf(stderr, "NA_Trigger failed: ret=%d count=%d\n", naret, count);
        global_test_error = 1;
    }

    if (flag != COMPLETION_MAGIC)
    {
        fprintf(stderr, "expected send callback failed\n");
        global_test_error = 1;
    }

    return;
}

void cancel_unexpected_recv (
    na_class_t   *class,
    na_context_t *context,
    na_size_t     len,
    void         *buf)
{
    na_return_t   naret;
    na_op_id_t    op_id;
    unsigned int  flag;
    unsigned int  count;

    flag = NA_CB_RECV_UNEXPECTED;
    naret = NA_Msg_recv_unexpected(class,
                                   context,
                                   callback,
                                   &flag,
                                   buf,
                                   len,
                                   &op_id);
    if (naret != NA_SUCCESS)
    {
        fprintf(stderr, "NA_Msg_recv_unexpected failed: %d\n", naret);
        global_test_error = 1;
        return;
    }

    naret = NA_Cancel(class, context, op_id);
    if (naret != NA_SUCCESS)
    {
        fprintf(stderr, "NA_Cancel failed: %d\n", naret);
        global_test_error = 1;
        return;
    }

    NA_Progress(class, context, 1);

    count = 0;
    naret = NA_Trigger(context, 0, 1, &count);
    if ((naret != NA_SUCCESS) ||
        (count != 1))
    {
        fprintf(stderr, "NA_Trigger failed: ret=%d count=%d\n", naret, count);
        global_test_error = 1;
    }

    if (flag != COMPLETION_MAGIC)
    {
        fprintf(stderr, "unexpected recv callback failed\n");
        global_test_error = 1;
    }

    return;
}

void cancel_expected_recv (
    na_class_t   *class,
    na_context_t *context,
    na_addr_t    *server_addr,
    na_size_t     len,
    void         *buf)
{
    na_return_t   naret;
    na_op_id_t    op_id;
    unsigned int  flag;
    unsigned int  count;

    flag = NA_CB_RECV_EXPECTED;
    naret = NA_Msg_recv_expected(class,
                                 context,
                                 callback,
                                 &flag,
                                 buf,
                                 len,
                                 *server_addr,
                                 3,
                                 &op_id);
    if (naret != NA_SUCCESS)
    {
        fprintf(stderr, "NA_Msg_recv_expected failed: %d\n", naret);
        global_test_error = 1;
        return;
    }

    naret = NA_Cancel(class, context, op_id);
    if (naret != NA_SUCCESS)
    {
        fprintf(stderr, "NA_Cancel failed: %d\n", naret);
        global_test_error = 1;
        return;
    }

    NA_Progress(class, context, 1);

    count = 0;
    naret = NA_Trigger(context, 0, 1, &count);
    if ((naret != NA_SUCCESS) ||
        (count != 1))
    {
        fprintf(stderr, "NA_Trigger failed: ret=%d count=%d\n", naret, count);
        global_test_error = 1;
    }

    if (flag != COMPLETION_MAGIC)
    {
        fprintf(stderr, "expected recv callback failed\n");
        global_test_error = 1;
    }

    return;
}

void cancel_put (
    na_class_t   *class,
    na_context_t *context,
    na_addr_t    *server_addr,
    na_size_t     len,
    void         *buf)
{
    na_return_t   naret;
    na_op_id_t    op_id;
    unsigned int  flag;
    unsigned int  count;
    na_mem_handle_t mem_handle_local;

    naret = NA_Mem_handle_create(class,
                                 buf,
                                 len,
                                 NA_MEM_READWRITE,
                                 &mem_handle_local);
    if (naret != NA_SUCCESS)
    {
        fprintf(stderr, "NA_Mem_handle_create failed: %d\n", naret);
        global_test_error = 1;
        return;
    }

    naret = NA_Mem_register(class, mem_handle_local);
    if (naret != NA_SUCCESS)
    {
        fprintf(stderr, "NA_Mem_register failed: %d\n", naret);
        global_test_error = 1;
        return;
    }

    naret = NA_Mem_publish(class, &mem_handle_local);
    if (naret != NA_SUCCESS)
    {
        fprintf(stderr, "NA_Mem_publish failed: %d\n", naret);
        global_test_error = 1;
        return;
    }

    flag = NA_CB_PUT;
    naret = NA_Put(class,
                   context,
                   callback,
                   &flag,
                   mem_handle_local,
                   0,
                   mem_handle_local, // fake the remote handle
                   0,
                   len,
                   *server_addr,
                   &op_id);
    if (naret != NA_SUCCESS)
    {
        fprintf(stderr, "NA_Put failed: %d\n", naret);
        global_test_error = 1;
        return;
    }

    naret = NA_Cancel(class, context, op_id);
    if (naret != NA_SUCCESS)
    {
        fprintf(stderr, "NA_Cancel failed: %d\n", naret);
        global_test_error = 1;
        return;
    }

    NA_Progress(class, context, 1);
    NA_Progress(class, context, 1);
    NA_Progress(class, context, 1);

    count = 0;
    naret = NA_Trigger(context, 0, 1, &count);
    if ((naret != NA_SUCCESS) ||
        (count != 1))
    {
        fprintf(stderr, "NA_Trigger failed: ret=%d count=%d\n", naret, count);
        global_test_error = 1;
    }

    if (flag != COMPLETION_MAGIC)
    {
        fprintf(stderr, "put callback failed\n");
        global_test_error = 1;
    }

    NA_Mem_unpublish(class, mem_handle_local);
    NA_Mem_deregister(class, mem_handle_local);
    NA_Mem_handle_free(class, mem_handle_local);

    return; 
}

void cancel_get (
    na_class_t   *class,
    na_context_t *context,
    na_addr_t    *server_addr,
    na_size_t     len,
    void         *buf)
{
    na_return_t   naret;
    na_op_id_t    op_id;
    unsigned int  flag;
    unsigned int  count;
    na_mem_handle_t mem_handle_local;

    naret = NA_Mem_handle_create(class,
                                 buf,
                                 len,
                                 NA_MEM_READ_ONLY,
                                 &mem_handle_local);
    if (naret != NA_SUCCESS)
    {
        fprintf(stderr, "NA_Mem_handle_create failed: %d\n", naret);
        global_test_error = 1;
        return;
    }

    naret = NA_Mem_register(class, mem_handle_local);
    if (naret != NA_SUCCESS)
    {
        fprintf(stderr, "NA_Mem_register failed: %d\n", naret);
        global_test_error = 1;
        return;
    }

    naret = NA_Mem_publish(class, &mem_handle_local);
    if (naret != NA_SUCCESS)
    {
        fprintf(stderr, "NA_Mem_publish failed: %d\n", naret);
        global_test_error = 1;
        return;
    }

    flag = NA_CB_GET;
    naret = NA_Get(class,
                   context,
                   callback,
                   &flag,
                   mem_handle_local,
                   0,
                   mem_handle_local, // fake the remote handle
                   0,
                   len,
                   *server_addr,
                   &op_id);
    if (naret != NA_SUCCESS)
    {
        fprintf(stderr, "NA_Get failed: %d\n", naret);
        global_test_error = 1;
        return;
    }

    naret = NA_Cancel(class, context, op_id);
    if (naret != NA_SUCCESS)
    {
        fprintf(stderr, "NA_Cancel failed: %d\n", naret);
        global_test_error = 1;
        return;
    }

    NA_Progress(class, context, 1);
    NA_Progress(class, context, 1);
    NA_Progress(class, context, 1);

    count = 0;
    naret = NA_Trigger(context, 0, 1, &count);
    if ((naret != NA_SUCCESS) ||
        (count != 1))
    {
        fprintf(stderr, "NA_Trigger failed: ret=%d count=%d\n", naret, count);
        global_test_error = 1;
    }

    if (flag != COMPLETION_MAGIC)
    {
        fprintf(stderr, "get callback failed\n");
        global_test_error = 1;
    }

    NA_Mem_unpublish(class, mem_handle_local);
    NA_Mem_deregister(class, mem_handle_local);
    NA_Mem_handle_free(class, mem_handle_local);

    return; 
}
