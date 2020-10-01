#include <assert.h>
#include <err.h>
#include <inttypes.h>   /* for PRIx8, etc. */
#include <libgen.h>     /* basename */
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <ucp/api/ucp.h>

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

typedef struct _reply_context {
    size_t length;
    ucs_status_t status;
    bool completed;
    ucp_tag_t sender_tag;
} reply_context_t;

static const ucp_tag_t wireup_tag = 17;

/* If `str` is the empty string, then store NULL at `bufp` and 0 at
 * `buflenp`, and return 0.
 *
 * If `str` consists of one or more hexadecimal octets,
 * [0-9a-fA-F][0-9a-fA-F], separated by colons, then parse the octets
 * into bytes, storing them in a buffer allocated on the heap.  Store a
 * pointer to the buffer at `bufp` and the number of bytes at `buflenp`,
 * and return 0.
 *
 * If `str` contains any other string, or if memory on the heap cannot
 * be allocated, then store NULL at `bufp` and 0 at `buflenp`, and
 * return -1.
 */
static int
colon_separated_octets_to_bytes(const char *str, uint8_t **bufp,
    size_t *buflenp)
{
    uint8_t *buf;
    size_t buflen, noctets;
    int i = 0, nread, rc;
    *bufp = NULL;
    *buflenp = 0;

    noctets = (strlen(str) + 1) / 3;

    if (noctets < 1)
        return 0;

    if ((buf = malloc(noctets)) == NULL)
        return -1;

    rc = sscanf(&str[i], "%02" SCNx8 "%n", &buf[0], &nread);
    if (rc == EOF) {
        free(buf);
        return 0;
    } else if (rc != 1) {
        free(buf);
        return -1;
    }

    for (buflen = 1, i = nread;
         (rc = sscanf(&str[i], ":%02" SCNx8 "%n", &buf[buflen], &nread)) == 1;
         i += nread)
        buflen++;

    if (rc != EOF || str[i] != '\0') {
        free(buf);
        return -1;
    }

    assert(buflen == noctets);
    *bufp = buf;
    *buflenp = buflen;
    return 0;
}

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
    reply_context_t *reply_ctx = user_data;

    /* TBD check error status */

    reply_ctx->completed = true;
}

static void
recv_callback(void *request, ucs_status_t status,
    const ucp_tag_recv_info_t *tag_info, void *user_data)
{
    reply_context_t *reply_ctx = user_data;

    reply_ctx->status = status;

    reply_ctx->length = tag_info->length;
    reply_ctx->sender_tag = tag_info->sender_tag;

    reply_ctx->completed = true;
}

static void
run_client(ucp_worker_h worker, ucp_address_t *server_addr)
{
    ucs_status_t status;
    void *request;
    ucp_ep_h server_ep;
    reply_context_t reply_ctx = {.completed = false};
    wireup_msg_t *msg;
    size_t msglen;
    const ucp_request_param_t send_params = {
      .op_attr_mask = UCP_OP_ATTR_FIELD_CALLBACK |
                      UCP_OP_ATTR_FIELD_USER_DATA 
    , .cb = {.send = send_callback}
    , .user_data = &reply_ctx
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
        while (!reply_ctx.completed)
            ucp_worker_progress(worker);
        ucp_request_release(request);
        printf("send succeeded, exiting.\n");
    } else if (request == UCS_OK)
        printf("send succeeded, exiting.\n");
    ucp_ep_destroy(server_ep);
}

static void
wireup_recv(ucp_worker_h worker, void *buf, size_t buflen, reply_context_t *ctx)
{
    const ucp_request_param_t /* reply_params = {
      .op_attr_mask = UCP_OP_ATTR_FIELD_CALLBACK |
                      UCP_OP_ATTR_FIELD_USER_DATA 
    , .cb = {.recv = reply_callback}
    , .user_data = &reply_ctx
    }, */ recv_params = {
      .op_attr_mask = UCP_OP_ATTR_FIELD_CALLBACK |
                      UCP_OP_ATTR_FIELD_USER_DATA 
    , .cb = {.recv = recv_callback}
    , .user_data = ctx
    };
    void *request;
    request = ucp_tag_recv_nbx(worker, buf, buflen, wireup_tag,
        UINT64_MAX, &recv_params);
    if (UCS_PTR_IS_ERR(request)) {
        warnx("%s: ucp_tag_recv_nbx: %s", __func__,
            ucs_status_string(UCS_PTR_STATUS(request)));
    } else if (UCS_PTR_IS_PTR(request)) {
        while (!ctx->completed)
            ucp_worker_progress(worker);
        ucp_request_release(request);
    }
}

static void
run_server(ucp_worker_h worker)
{
    reply_context_t reply_ctx = {.completed = false, .length = 0};
    wireup_msg_t *msg;
    size_t msglen;

    msglen = sizeof(*msg);
    if ((msg = malloc(msglen)) == NULL)
        err(EXIT_FAILURE, "%s: malloc", __func__);

    for (;; reply_ctx.completed = false) {
        wireup_recv(worker, msg, msglen, &reply_ctx);
        printf("sender tag %" PRIu64 "\n", reply_ctx.sender_tag);
        if (reply_ctx.status == UCS_OK) {
            printf("received %zu-byte message, exiting.\n", reply_ctx.length);
            break;
        }
        if (reply_ctx.status == UCS_ERR_MESSAGE_TRUNCATED) {
            size_t nmsglen = offsetof(wireup_msg_t, addr[0]) +
                             (msglen - offsetof(wireup_msg_t, addr[0])) * 2;

            printf("message truncated, increasing buffer length %zu -> %zu.\n",
                msglen, nmsglen);

            free(msg);

            msglen = nmsglen;
            if ((msg = malloc(msglen)) == NULL)
                err(EXIT_FAILURE, "%s: malloc", __func__);
        } else if (reply_ctx.status != UCS_OK) {
            printf("receive error, %s, exiting.\n",
                ucs_status_string(reply_ctx.status));
            break;
        }
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
