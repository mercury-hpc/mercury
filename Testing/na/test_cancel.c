#include <stdlib.h>
#include <stdio.h>

#include "na_test.h"

int global_test_error = 0;

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
    na_op_id_t    op_id;
    unsigned int  flag;
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
    gossip_set_debug_mask(1, 0xffffffffffffffff);
    gossip_enable_stderr();
     */

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

    /*
     * cancel unexpected send
     */
    flag = NA_CB_SEND_UNEXPECTED;
    naret = NA_Msg_send_unexpected(class,
                                   context,
                                   callback,
                                   &flag,
                                   buf,
                                   len,
                                   server_addr, 
                                   1,
                                   &op_id);
    if (naret != NA_SUCCESS)
    {
        fprintf(stderr, "NA_Msg_send_unexpected failed: %d\n", naret);
        global_test_error = 1;
        goto done;
    }

    naret = NA_Cancel(class, context, op_id);
    if (naret != NA_SUCCESS)
    {
        fprintf(stderr, "NA_Cancel failed: %d\n", naret);
        global_test_error = 1;
        goto done;
    }

    NA_Progress(class, context, 1);

    count = 0;
    naret = NA_Trigger(context, 0, 1, &count);
    if ((naret != NA_SUCCESS) ||
        (count != 1))
    {
        fprintf(stderr, "NA_Trigger failed: ret=%d count=%d\n", naret, count);
    }

done:
    if (found) NA_Addr_free(class, server_addr);

    if (context) NA_Context_destroy(class, context);

    if (buf) free(buf);

    if (class) NA_Test_finalize(class);

    return global_test_error;
}
