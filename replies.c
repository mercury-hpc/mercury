#include <assert.h>
#include <err.h>
#include <inttypes.h>   /* for PRIx8, etc. */
#include <libgen.h>     /* basename */
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <sys/param.h>  /* for MIN, MAX */

#include <ucp/api/ucp.h>

#include "util.h"

typedef enum {
      OP_REQUEST    = 0
    , OP_ACK        = 1
    , OP_NACK       = 2
} wireup_op_t;

typedef struct _wireup_msg {
    uint32_t sender_ep_idx;
    uint16_t op;        // wireup_op_t
    uint16_t addrlen;
    uint8_t addr[1];
} wireup_msg_t;

typedef struct _recv_desc {
    /* fields set at setup: */
    ucp_worker_h worker;
    void *request;
    wireup_msg_t *msg;
    size_t msglen;
    /* fields set by callback: */
    size_t length;
    ucp_tag_t sender_tag;
    ucs_status_t status;
    /* fields shared by setup and callback: */
    bool completed;
} recv_desc_t;

static const ucp_tag_t wireup_tag = 17;

static void recv_desc_setup(ucp_worker_h, wireup_msg_t *, size_t,
    recv_desc_t *);

static void
usage(const char *_progname)
{
    char *progname = strdup(_progname);
    assert(progname != NULL);
    fprintf(stderr, "usage: %s [remote address]\n", basename(progname));
    free(progname);
    exit(EXIT_FAILURE);
}

static void
send_callback(void *request, ucs_status_t status, void *user_data)
{
    recv_desc_t *recv_desc = user_data;

    recv_desc->status = status;

    recv_desc->completed = true;
    ucp_request_release(request);
}

static void
recv_desc_callback(void *request, ucs_status_t status,
    const ucp_tag_recv_info_t *tag_info, void *user_data)
{
    const size_t hdrlen = offsetof(wireup_msg_t, addr[0]);
    recv_desc_t *desc = user_data;

    /* Do nothing if the request was cancelled. */
    if (desc->request == NULL)
        return;

    desc->status = status;
    desc->length = tag_info->length;
    desc->sender_tag = tag_info->sender_tag;
    desc->completed = true;

    if (status == UCS_ERR_MESSAGE_TRUNCATED) {
        size_t msglen = desc->msglen;
        wireup_msg_t * const msg = desc->msg, *nmsg;
        /* Twice the message length is twice the header length plus
         * twice the payload length, so subtract one header length.
         */
        size_t nmsglen =
            MAX(tag_info->length, twice_or_max(msglen) - hdrlen);

        printf("%zu-byte message truncated, "
               "increasing buffer length %zu -> %zu bytes.\n",
            tag_info->length, msglen, nmsglen);

        free(msg);

        if ((nmsg = malloc(nmsglen)) == NULL)
            err(EXIT_FAILURE, "%s: malloc", __func__);

        desc->msglen = nmsglen;
        desc->msg = nmsg;
    }
    assert(request == desc->request);
    desc->request = NULL;
    ucp_request_release(request);
}

static void
run_client(ucp_worker_h worker, ucp_address_t *server_addr)
{
    ucs_status_t status;
    void *request;
    ucp_ep_h server_ep;
    recv_desc_t recv_desc = {.completed = false};
    wireup_msg_t *msg;
    size_t msglen;
    const ucp_request_param_t send_params = {
      .op_attr_mask = UCP_OP_ATTR_FIELD_CALLBACK |
                      UCP_OP_ATTR_FIELD_USER_DATA 
    , .cb = {.send = send_callback}
    , .user_data = &recv_desc
    };
    const ucp_ep_params_t ep_params = {
      .field_mask = UCP_EP_PARAM_FIELD_REMOTE_ADDRESS |
                    UCP_EP_PARAM_FIELD_ERR_HANDLER
    , .err_mode = UCP_ERR_HANDLING_MODE_NONE
    , .address = server_addr
    };

    msglen = sizeof(*msg) + 15;
    if ((msg = calloc(1, msglen)) == NULL)
        err(EXIT_FAILURE, "%s: malloc", __func__);

    if ((status = ucp_ep_create(worker, &ep_params, &server_ep)) != UCS_OK)
        errx(EXIT_FAILURE, "client %s: ucp_ep_create", __func__);

    request = ucp_tag_send_nbx(server_ep, msg, msglen,
        wireup_tag, &send_params);

    if (UCS_PTR_IS_ERR(request)) {
        warnx("%s: ucp_tag_send_nbx: %s", __func__,
            ucs_status_string(UCS_PTR_STATUS(request)));
    } else if (UCS_PTR_IS_PTR(request)) {
        while (!recv_desc.completed)
            ucp_worker_progress(worker);
        if (recv_desc.status != UCS_OK) {
            printf("send error, %s, exiting.\n",
                ucs_status_string(recv_desc.status));
        }
        printf("send succeeded, exiting.\n");
    } else if (request == UCS_OK)
        printf("send succeeded immediately, exiting.\n");
    ucp_ep_destroy(server_ep);
}

static void
recv_desc_setup(ucp_worker_h worker, wireup_msg_t *msg, size_t msglen,
    recv_desc_t *desc)
{
    const ucp_request_param_t /* reply_params = {
      .op_attr_mask = UCP_OP_ATTR_FIELD_CALLBACK |
                      UCP_OP_ATTR_FIELD_USER_DATA 
    , .cb = {.recv = reply_callback}
    , .user_data = &recv_desc
    }, */ recv_params = {
      .op_attr_mask = UCP_OP_ATTR_FIELD_CALLBACK |
                      UCP_OP_ATTR_FIELD_USER_DATA 
    , .cb = {.recv = recv_desc_callback}
    , .user_data = desc
    };
    void *request;

    desc->worker = worker;
    desc->msg = msg;
    desc->msglen = msglen;
    desc->completed = false;

    request = ucp_tag_recv_nbx(worker, msg, msglen, wireup_tag,
        UINT64_MAX, &recv_params);
    if (UCS_PTR_IS_ERR(request)) {
        errx(EXIT_FAILURE, "%s: ucp_tag_recv_nbx: %s", __func__,
            ucs_status_string(UCS_PTR_STATUS(request)));
    }
    desc->request = request;
}

static void
run_server(ucp_worker_h worker)
{
    recv_desc_t recv_desc[3];
    int i;

    for (i = 0; i < NELTS(recv_desc); i++) {
        wireup_msg_t *msg;
        const size_t msglen = sizeof(*msg);

        if ((msg = malloc(msglen)) == NULL)
            err(EXIT_FAILURE, "%s: malloc", __func__);

        recv_desc_setup(worker, msg, msglen, &recv_desc[i]);
    }

    for (i = 0; ; i = (i + 1) % NELTS(recv_desc)) {
        while (!recv_desc[i].completed)
            ucp_worker_progress(worker);
        printf("sender tag %" PRIu64 "\n", recv_desc[i].sender_tag);
        assert(recv_desc[i].request == NULL);
        if (recv_desc[i].status == UCS_OK) {
            printf("received %zu-byte message, exiting.\n",
                recv_desc[i].length);
            break;
        } else if (recv_desc[i].status != UCS_ERR_MESSAGE_TRUNCATED) {
            printf("receive error, %s, exiting.\n",
                ucs_status_string(recv_desc[i].status));
            break;
        }
        recv_desc_setup(worker, recv_desc[i].msg, recv_desc[i].msglen,
            &recv_desc[i]);
    }
    for (i = 0; i < NELTS(recv_desc); i++) {
        void *request;
        recv_desc_t *desc = &recv_desc[i];

        if ((request = desc->request) == NULL)
            continue;
        desc->request = NULL;
        ucp_request_cancel(worker, request);
        ucp_request_release(request);
    }
}

int
main(int argc, char **argv)
{
    ucs_status_t status;
    ucp_config_t *config;
    ucp_context_h context;
    ucp_worker_h worker;
    ucp_address_t *local_addr;
    ucp_address_t *remote_addr;
    size_t i, local_addr_len, remote_addr_len;
    const char *delim = "";
    ucp_params_t global_params = {
      .field_mask = UCP_PARAM_FIELD_FEATURES
    , .features = UCP_FEATURE_TAG | UCP_FEATURE_RMA
    };
    ucp_worker_params_t worker_params = {
      .field_mask = UCP_WORKER_PARAM_FIELD_THREAD_MODE
    , .thread_mode = UCS_THREAD_MODE_MULTI
    };

    if (argc > 2)
        usage(argv[0]);
    if (argc == 2) {
        uint8_t *buf;

        if (colon_separated_octets_to_bytes(argv[1], &buf,
                                            &remote_addr_len) == -1)
            errx(EXIT_FAILURE, "could not parse remote address `%s`", argv[1]);
        printf("parsed %zu-byte remote address\n", remote_addr_len);
        remote_addr = (void *)buf;
    } else {
        remote_addr = NULL;
    }

    if ((status = ucp_config_read(NULL, NULL, &config)) != UCS_OK)
        errx(EXIT_FAILURE, "%s: ucp_config_read", __func__);

    if ((status = ucp_init(&global_params, config, &context)) != UCS_OK)
        errx(EXIT_FAILURE, "%s: ucp_init", __func__);

    ucp_config_release(config);

    status = ucp_worker_create(context, &worker_params, &worker);
    if (status != UCS_OK) {
        errx(EXIT_FAILURE, "%s: ucp_worker_create", __func__);
        goto cleanup_context;
    }

    status = ucp_worker_get_address(worker, &local_addr, &local_addr_len);
    if (status != UCS_OK) {
        errx(EXIT_FAILURE, "%s: ucp_worker_get_address", __func__);
        goto cleanup_worker;
    }

    printf("%zu-byte local address ", local_addr_len);
    for (i = 0; i < local_addr_len; i++) {
        printf("%s%02" PRIx8, delim, ((uint8_t *)local_addr)[i]);
        delim = ":";
    }
    printf("\n");

    if (remote_addr != NULL) {      /* * * client mode * * */
        run_client(worker, remote_addr);
    } else {                        /* * * server mode * * */
        run_server(worker);
    }

    ucp_worker_release_address(worker, local_addr);
cleanup_worker:
    ucp_worker_destroy(worker);
cleanup_context:
    ucp_cleanup(context);
    return EXIT_SUCCESS;
}
