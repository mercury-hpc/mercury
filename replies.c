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
      OP_REQ   = 0
    , OP_ACK   = 1
    , OP_NACK  = 2
} wireup_op_t;

typedef struct _wireup_msg {
    uint32_t sender_ep_idx;
    uint16_t op;        // wireup_op_t
    uint16_t addrlen;
    uint8_t addr[];
} wireup_msg_t;

typedef struct _txdesc {
    void *request;
    ucs_status_t status;
    bool completed;
} txdesc_t;

typedef struct _rxdesc {
    /* fields set at setup: */
    void *request;
    void *buf;
    size_t buflen;
    /* fields set by callback: */
    size_t rxlen;
    ucp_tag_t sender_tag;
    ucs_status_t status;
    /* fields shared by setup and callback: */
    bool completed;
} rxdesc_t;

static const ucp_tag_t wireup_tag = 17;

static void rxdesc_setup(ucp_worker_h, void *, size_t, rxdesc_t *);

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
    txdesc_t *desc = user_data;

    desc->status = status;

    desc->completed = true;
    ucp_request_release(request);
}

static void
rxdesc_callback(void *request, ucs_status_t status,
    const ucp_tag_recv_info_t *tag_info, void *user_data)
{
    const size_t hdrlen = offsetof(wireup_msg_t, addr[0]);
    rxdesc_t *desc = user_data;

    /* Do nothing if the request was cancelled. */
    if (desc->request == NULL)
        return;

    desc->status = status;
    desc->rxlen = tag_info->length;
    desc->sender_tag = tag_info->sender_tag;
    desc->completed = true;

    if (status == UCS_ERR_MESSAGE_TRUNCATED) {
        size_t buflen = desc->buflen;
        void * const buf = desc->buf, *nbuf;
        /* Twice the message length is twice the header length plus
         * twice the payload length, so subtract one header length.
         */
        size_t nbuflen =
            MAX(tag_info->length, twice_or_max(buflen) - hdrlen);

        printf("%zu-byte message truncated, "
               "increasing buffer length %zu -> %zu bytes.\n",
            tag_info->length, buflen, nbuflen);

        free(buf);

        if ((nbuf = malloc(nbuflen)) == NULL)
            err(EXIT_FAILURE, "%s: malloc", __func__);

        desc->buflen = nbuflen;
        desc->buf = nbuf;
    }
    assert(request == desc->request);
    desc->request = NULL;
    ucp_request_release(request);
}

static void
run_client(ucp_worker_h worker, ucp_address_t *local_addr,
    size_t local_addr_len, ucp_address_t *remote_addr,
    size_t remote_addr_len)
{
    rxdesc_t rdesc;
    ucs_status_t status;
    void *request;
    ucp_ep_h remote_ep;
    txdesc_t desc = {.completed = false};
    wireup_msg_t reply;
    wireup_msg_t *req;
    size_t reqlen;
    const ucp_request_param_t send_params = {
      .op_attr_mask = UCP_OP_ATTR_FIELD_CALLBACK |
                      UCP_OP_ATTR_FIELD_USER_DATA 
    , .cb = {.send = send_callback}
    , .user_data = &desc
    };
    const ucp_ep_params_t ep_params = {
      .field_mask = UCP_EP_PARAM_FIELD_REMOTE_ADDRESS |
                    UCP_EP_PARAM_FIELD_ERR_HANDLER
    , .address = remote_addr
    , .err_mode = UCP_ERR_HANDLING_MODE_NONE
    };

    reqlen = sizeof(*req) + remote_addr_len;
    if ((req = calloc(1, reqlen)) == NULL)
        err(EXIT_FAILURE, "%s: malloc", __func__);

    if ((status = ucp_ep_create(worker, &ep_params, &remote_ep)) != UCS_OK)
        errx(EXIT_FAILURE, "client %s: ucp_ep_create", __func__);

    rxdesc_setup(worker, &reply, sizeof(reply), &rdesc);

    req->op = OP_REQ;
    req->sender_ep_idx = 0;
    req->addrlen = local_addr_len;
    memcpy(&req->addr[0], local_addr, local_addr_len);

    request = ucp_tag_send_nbx(remote_ep, req, reqlen,
        wireup_tag, &send_params);

    if (UCS_PTR_IS_ERR(request)) {
        warnx("%s: ucp_tag_send_nbx: %s", __func__,
            ucs_status_string(UCS_PTR_STATUS(request)));
    } else if (UCS_PTR_IS_PTR(request)) {
        while (!desc.completed)
            ucp_worker_progress(worker);
        if (desc.status != UCS_OK) {
            printf("send error, %s, exiting.\n",
                ucs_status_string(desc.status));
        }
        printf("send succeeded, exiting.\n");
    } else if (request == UCS_OK)
        printf("send succeeded immediately, exiting.\n");

    while (!rdesc.completed)
        ucp_worker_progress(worker);

    assert(reply.op == OP_ACK);

    ucp_ep_destroy(remote_ep);
}

static void
rxdesc_setup(ucp_worker_h worker, void *buf, size_t buflen,
    rxdesc_t *desc)
{
    const ucp_request_param_t /* reply_params = {
      .op_attr_mask = UCP_OP_ATTR_FIELD_CALLBACK |
                      UCP_OP_ATTR_FIELD_USER_DATA 
    , .cb = {.recv = reply_callback}
    , .user_data = &rxdesc
    }, */ recv_params = {
      .op_attr_mask = UCP_OP_ATTR_FIELD_CALLBACK |
                      UCP_OP_ATTR_FIELD_USER_DATA 
    , .cb = {.recv = rxdesc_callback}
    , .user_data = desc
    };
    void *request;

    desc->buf = buf;
    desc->buflen = buflen;
    desc->completed = false;

    request = ucp_tag_recv_nbx(worker, buf, buflen, wireup_tag,
        UINT64_MAX, &recv_params);
    if (UCS_PTR_IS_ERR(request)) {
        errx(EXIT_FAILURE, "%s: ucp_tag_recv_nbx: %s", __func__,
            ucs_status_string(UCS_PTR_STATUS(request)));
    }
    desc->request = request;
}

static const char *
wireup_op_string(wireup_op_t op)
{
    switch (op) {
    case OP_REQ:
        return "req";
    case OP_ACK:
        return "ack";
    case OP_NACK:
        return "nack";
    default:
        return "<unknown>";
    }
}

static void
process_rx_msg(ucp_worker_h worker, ucp_tag_t tag, void *buf, size_t buflen)
{
    ucp_ep_params_t ep_params = {
      .field_mask = UCP_EP_PARAM_FIELD_REMOTE_ADDRESS |
                    UCP_EP_PARAM_FIELD_ERR_HANDLER
    , .address = NULL
    , .err_mode = UCP_ERR_HANDLING_MODE_NONE
    };
    wireup_msg_t *msg;
    ucp_ep_h reply_ep;
    const size_t hdrlen = offsetof(wireup_msg_t, addr[0]);
    ucs_status_t status;

    if (buflen < hdrlen) {
        warnx("%s: dropping %zu-byte message, shorter than header\n", __func__,
            buflen);
        return;
    }

    msg = buf;

    if (msg->op != OP_REQ) {
        warnx("%s: received unexpected %s-type op\n", __func__,
            wireup_op_string(msg->op));
        return;
    }

    if (buflen < offsetof(wireup_msg_t, addr[0]) + msg->addrlen) {
        warnx("%s: dropping %zu-byte message, address truncated\n",
            __func__, buflen);
    }
    ep_params.address = (void *)msg->addr;
    status = ucp_ep_create(worker, &ep_params, &reply_ep);
    /* TBD send nack on error */
    if (status != UCS_OK)
        warnx("%s: ucp_ep_create failed", __func__);

    wireup_msg_t reply = (wireup_msg_t){ .sender_ep_idx = 0, .op = OP_ACK, .addrlen = 0};
    txdesc_t desc = {.completed = false};
    const ucp_request_param_t send_params = {
      .op_attr_mask = UCP_OP_ATTR_FIELD_CALLBACK |
                      UCP_OP_ATTR_FIELD_USER_DATA 
    , .cb = {.send = send_callback}
    , .user_data = &desc
    };
    void *request;

    request = ucp_tag_send_nbx(reply_ep, &reply, sizeof(reply),
        tag, &send_params);

    if (UCS_PTR_IS_ERR(request)) {
        warnx("%s: ucp_tag_send_nbx: %s", __func__,
            ucs_status_string(UCS_PTR_STATUS(request)));
    } else if (UCS_PTR_IS_PTR(request)) {
        while (!desc.completed)
            ucp_worker_progress(worker);
        if (desc.status != UCS_OK) {
            printf("send error, %s, exiting.\n",
                ucs_status_string(desc.status));
        }
        printf("send succeeded, exiting.\n");
    } else if (request == UCS_OK)
        printf("send succeeded immediately, exiting.\n");

    ucp_ep_destroy(reply_ep);
}

static void
run_server(ucp_worker_h worker)
{
    rxdesc_t rxdesc[3];
    int i;

    /* Allocate a buffer for each receive descriptor and queue with
     * UCP.
     */
    for (i = 0; i < NELTS(rxdesc); i++) {
        wireup_msg_t *msg;
        const size_t msglen = sizeof(*msg);

        if ((msg = malloc(msglen)) == NULL)
            err(EXIT_FAILURE, "%s: malloc", __func__);

        rxdesc_setup(worker, msg, msglen, &rxdesc[i]);
    }

    for (i = 0; ; i = (i + 1) % NELTS(rxdesc)) {
        rxdesc_t *rdesc = &rxdesc[i];

        while (!rdesc->completed)
            ucp_worker_progress(worker);

        assert(rdesc->request == NULL);

        if (rdesc->status == UCS_OK) {
            printf("received %zu-byte message tagged %" PRIu64
                   ", processing...\n", rdesc->rxlen, rxdesc[i].sender_tag);
            process_rx_msg(worker, rdesc->sender_tag, rdesc->buf, rdesc->rxlen);
        } else if (rdesc->status != UCS_ERR_MESSAGE_TRUNCATED) {
            printf("receive error, %s, exiting.\n",
                ucs_status_string(rdesc->status));
            break;
        }
        rxdesc_setup(worker, rdesc->buf, rdesc->buflen, rdesc);
    }

    /* Release UCP resources held by each descriptor.  Free buffers. */
    for (i = 0; i < NELTS(rxdesc); i++) {
        void *request;
        rxdesc_t *desc = &rxdesc[i];

        if ((request = desc->request) == NULL)
            continue;
        desc->request = NULL;
        ucp_request_cancel(worker, request);
        ucp_request_release(request);
        free(desc->buf);
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
        run_client(worker, local_addr, local_addr_len,
            remote_addr, remote_addr_len);
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
