#include <err.h>
#include <inttypes.h> /* PRIu32 */
#include <stdlib.h> /* calloc, malloc */
#include <string.h> /* memcpy */
#include <time.h> /* clock_gettime(2) */
#include <unistd.h> /* size_t, SIZE_MAX */

#include "ring.h"
#include "tag.h"
#include "util.h"
#include "wireup.h"
#include "wiring.h"

struct _wire_state {
    wire_state_t *(*timeout)(wiring_t *, wire_t *);
    wire_state_t *(*receive)(wiring_t *, wire_t *, const wireup_msg_t *);
    uint64_t expiration;
};

enum {
  WIRE_S_INITIAL
, WIRE_S_EARLY_LIFE
, WIRE_S_LATE_LIFE
, WIRE_S_DEAD
};

static const ucp_tag_t wireup_start_tag = TAG_CHNL_WIREUP | TAG_ID_MASK;

static const uint64_t keepalive_interval = 1000000000;  // 1 second
static const uint64_t timeout_interval = 2 * keepalive_interval;

static uint64_t getnanos(void);

static wiring_t *wireup_rx_req(wiring_t *, const wireup_msg_t *);

static void wireup_send_callback(void *, ucs_status_t, void *);

static wire_state_t *destroy(wiring_t *, wire_t *);
static wire_state_t *reject_timeout(wiring_t *, wire_t *);
static wire_state_t *reject_msg(wiring_t *, wire_t *, const wireup_msg_t *);
static wire_state_t *continue_early_life(wiring_t *, wire_t *,
    const wireup_msg_t *);
static wire_state_t *start_early_life(wiring_t *, wire_t *,
    const wireup_msg_t *);
static wire_state_t *start_late_life(wiring_t *, wire_t *);

wire_state_t state[] = {
  [WIRE_S_INITIAL] = {.timeout = destroy,
                      .receive = start_early_life}
, [WIRE_S_EARLY_LIFE] = {.timeout = start_late_life,
                         .receive = continue_early_life}
, [WIRE_S_LATE_LIFE] = {.timeout = destroy,
                        .receive = continue_early_life}
, [WIRE_S_DEAD] = {.timeout = reject_timeout,
                   .receive = reject_msg}
};

static void *
zalloc(size_t sz)
{
    return calloc(1, sz);
}

static void
wiring_release_wire(wiring_t *wiring, wire_t *w)
{
    sender_id_t id = w - &wiring->wire[0];

    assert(id < wiring->nwires);

    wiring_timeout_remove(wiring, w);
    wiring_free_put(wiring, id);
}

static void
wireup_msg_transition(wiring_t *wiring, const ucp_tag_t sender_tag,
    const wireup_msg_t *msg)
{
    wire_t *w;
    const uint64_t proto_id = TAG_GET_ID(sender_tag);
    sender_id_t id;

    if (proto_id > SENDER_ID_MAX) {
        warnx("%s: illegal sender ID %016" PRIx64 " id mask %016" PRIx64 " chnl mask %016" PRIx64, __func__, proto_id, TAG_ID_MASK, TAG_CHNL_MASK);
        return;
    }
    if (proto_id >= wiring->nwires) {
        warnx("%s: out of bounds sender ID %" PRIu64, __func__, proto_id);
        return;
    }

    id = (sender_id_t)proto_id;
    w = &wiring->wire[id];

    w->state = (*w->state->receive)(wiring, w, msg);
}

#if 0
static void
wireup_timeout_transition(wiring_t *wiring, uint64_t now)
{
    wire_t *w;

    while ((w = wiring_timeout_peek(wiring)) != NULL && w->expiration <= now) {
        wiring_timeout_remove(wiring, w);
        w->state = (*w->state->timeout)(wiring, w);
    }
}
#endif

static wire_state_t *
start_early_life(wiring_t *wiring, wire_t *w, const wireup_msg_t *msg)
{
    sender_id_t id = w - &wiring->wire[0];

    if (msg->sender_id > INT32_MAX) {
        warnx("%s: bad foreign sender ID %" PRId32 " for wire %" PRIdSENDER,
            __func__, msg->sender_id, id);
        return w->state;
    }

    if (msg->op != OP_ACK) {
        warnx("%s: unexpected opcode %" PRIu16 " for wire %" PRIdSENDER,
            __func__, msg->op, id);
        return w->state;
    }

    if (msg->addrlen != 0) {
        warnx("%s: unexpected addr. len. %" PRIu16 " for wire %" PRIdSENDER,
            __func__, msg->addrlen, id);
        return w->state;
    }

    w->id = id;
    wiring_timeout_remove(wiring, w);
    wiring_timeout_put(wiring, w, getnanos() + timeout_interval);

    return &state[WIRE_S_EARLY_LIFE];
}

static wire_state_t *
continue_early_life(wiring_t *wiring, wire_t *w, const wireup_msg_t *msg)
{
    sender_id_t id = w - &wiring->wire[0];

    if (msg->sender_id > INT32_MAX) {
        warnx("%s: bad foreign sender ID %" PRId32 " for wire %" PRIdSENDER,
            __func__, msg->sender_id, id);
        return w->state;
    }

    if (msg->op != OP_KEEPALIVE) {
        warnx("%s: unexpected opcode %" PRIu16 " for wire %" PRIdSENDER,
            __func__, msg->op, id);
        return w->state;
    }

    if (msg->addrlen != 0) {
        warnx("%s: unexpected addr. len. %" PRIu16 " for wire %" PRIdSENDER,
            __func__, msg->addrlen, id);
        return w->state;
    }

    if (msg->sender_id != w->id) {
        warnx("%s: sender ID %" PRIu32 " mismatches assignment %" PRIdSENDER
            " for wire %" PRIdSENDER, __func__, msg->sender_id, w->id, id);
        wiring_release_wire(wiring, w);
        return &state[WIRE_S_DEAD];
    }

    return &state[WIRE_S_EARLY_LIFE];
}

static wire_state_t *
start_late_life(wiring_t *wiring, wire_t *w)
{
    ucp_request_param_t tx_params;
    wireup_msg_t *msg;
    ucs_status_ptr_t request;
    const ucp_tag_t tag = TAG_CHNL_WIREUP | SHIFTIN(w->id, TAG_ID_MASK);
    const sender_id_t id = w - &wiring->wire[0];

    if ((msg = zalloc(sizeof(*msg))) == NULL)
        return &state[WIRE_S_LATE_LIFE];

    *msg = (wireup_msg_t){.op = OP_KEEPALIVE, .sender_id = id, .addrlen = 0};

    tx_params = (ucp_request_param_t){
      .op_attr_mask = UCP_OP_ATTR_FIELD_CALLBACK | UCP_OP_ATTR_FIELD_USER_DATA
    , .cb = {.send = wireup_send_callback}
    , .user_data = msg
    };

    request = ucp_tag_send_nbx(w->ep, msg, sizeof(*msg), tag, &tx_params);

    if (UCS_PTR_IS_ERR(request)) {
        warnx("%s: ucp_tag_send_nbx: %s", __func__,
            ucs_status_string(UCS_PTR_STATUS(request)));
        free(msg); 
    } else if (request == UCS_OK)
        free(msg);

    wiring_timeout_put(wiring, w, getnanos() + timeout_interval);

    return &state[WIRE_S_LATE_LIFE];
}

static wire_state_t *
reject_timeout(wiring_t *wiring, wire_t *w)
{
    sender_id_t id = w - &wiring->wire[0];

    warnx("%s: rejecting timeout for wire %" PRIdSENDER, __func__, id);

    return &state[WIRE_S_DEAD];
}

static wire_state_t *
reject_msg(wiring_t *wiring, wire_t *w, const wireup_msg_t *msg)
{
    sender_id_t id = w - &wiring->wire[0];

    warnx("%s: rejecting message from %" PRIdSENDER " for wire %" PRIdSENDER,
        __func__, msg->sender_id, id);

    return &state[WIRE_S_DEAD];
}

static wire_state_t *
destroy(wiring_t *wiring, wire_t *w)
{
    wiring_release_wire(wiring, w);
    return &state[WIRE_S_DEAD];
}

static void
wireup_send_callback(void *request, ucs_status_t status, void *user_data)
{
    wireup_msg_t *msg = user_data;

    printf("%s: sent id %" PRIu32 " addr. len. %" PRIu16 " status %s\n",
        __func__, msg->sender_id, msg->addrlen, ucs_status_string(status));

    free(msg);
}

void
wiring_destroy(wiring_t *wiring)
{
    rxring_destroy(&wiring->ring);
    /* TBD tear down wires; send a bad keepalive or a "bye" to destroy wires
     * on peers?
     */
    assert(false);
    free(wiring);
}

wiring_t *
wiring_create(ucp_worker_h worker, size_t request_size)
{
    wiring_t *wiring;
    const size_t nwires = 1;
    size_t i;

    wiring = zalloc(sizeof(*wiring) + sizeof(wire_t) * nwires);
    if (wiring == NULL)
        return NULL;

    wiring->nwires = nwires;

    for (i = 0; i < nwires; i++) {
        wiring->wire[i] = (wire_t){
              .next_free = i + 1
            , .state = &state[WIRE_S_DEAD]
            , .next_to_expire = SENDER_ID_NIL
            , .ep = NULL
            , .id = SENDER_ID_NIL
            , .expiration = 0};
    }

    wiring->wire[nwires - 1].next_free = SENDER_ID_NIL;
    wiring->first_free = 0;

    wiring->first_to_expire = wiring->last_to_expire = SENDER_ID_NIL;

    rxring_init(worker, &wiring->ring, request_size,
        TAG_CHNL_WIREUP, TAG_CHNL_MASK, sizeof(wireup_msg_t) + 93, 3);

    return wiring;
}

wiring_t *
wiring_enlarge(wiring_t *wiring)
{
    const size_t hdrsize = sizeof(wiring_t),
                 osize = hdrsize + wiring->nwires * sizeof(wire_t);
    const size_t proto_nsize = twice_or_max(osize) - hdrsize;
    const size_t nwires = (proto_nsize - hdrsize) / sizeof(wire_t);
    const size_t nsize = hdrsize + nwires * sizeof(wire_t);
    size_t i;

    if (nsize <= osize)
        return NULL;

    wiring = realloc(wiring, nsize);

    if (wiring == NULL)
        return NULL;

    for (i = wiring->nwires; i < nwires; i++) {
        wiring->wire[i] = (wire_t){
              .next_free = i + 1
            , .state = &state[WIRE_S_DEAD]
            , .next_to_expire = SENDER_ID_NIL
            , .ep = NULL
            , .id = SENDER_ID_NIL
            , .expiration = 0};
    }
    wiring->wire[nwires - 1].next_free = wiring->first_free;
    wiring->first_free = wiring->nwires;
    wiring->nwires = nwires;

    return wiring;
}

static uint64_t
getnanos(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) == -1)
        err(EXIT_FAILURE, "%s: clock_gettime", __func__);

    return ts.tv_sec * (uint64_t)1000000000 + ts.tv_nsec;
}

const char *
wireup_op_string(wireup_op_t op)
{
    switch (op) {
    case OP_REQ:
        return "req";
    case OP_ACK:
        return "ack";
    case OP_KEEPALIVE:
        return "keepalive";
    default:
        return "<unknown>";
    }
}

/* Answer a request. */
wire_t *
wireup_respond(wiring_t **wiringp, sender_id_t rid,
    ucp_address_t *raddr, size_t raddrlen)
{
    ucp_ep_params_t ep_params = {
      .field_mask = UCP_EP_PARAM_FIELD_REMOTE_ADDRESS |
                    UCP_EP_PARAM_FIELD_ERR_HANDLER
    , .address = raddr
    , .err_mode = UCP_ERR_HANDLING_MODE_NONE
    };
    ucp_request_param_t tx_params;
    wiring_t *wiring = *wiringp;
    wireup_msg_t *msg;
    wire_t *w;
    ucp_ep_h ep;
    ucs_status_ptr_t request;
    sender_id_t id;
    const size_t msglen = sizeof(*msg);
    ucs_status_t status;

    if ((msg = zalloc(msglen)) == NULL)
        return NULL;

    if ((id = wiring_free_get(wiring)) == SENDER_ID_NIL) {
        if ((wiring = wiring_enlarge(wiring)) == NULL)
            goto free_msg;
        *wiringp = wiring;
        if ((id = wiring_free_get(wiring)) == SENDER_ID_NIL)
            goto free_msg;
    }

    w = &wiring->wire[id];

    *msg = (wireup_msg_t){.op = OP_ACK, .sender_id = id, .addrlen = 0};

    status = ucp_ep_create(wiring->ring.worker, &ep_params, &ep);
    if (status != UCS_OK) {
        warnx("%s: ucp_ep_create: %s", __func__, ucs_status_string(status));
        goto free_wire;
    }
    *w = (wire_t){.ep = ep, .id = rid, .state = &state[WIRE_S_EARLY_LIFE]};

    wiring_timeout_put(wiring, w, getnanos() + timeout_interval);

    tx_params = (ucp_request_param_t){
      .op_attr_mask = UCP_OP_ATTR_FIELD_CALLBACK | UCP_OP_ATTR_FIELD_USER_DATA
    , .cb = {.send = wireup_send_callback}
    , .user_data = msg
    };
    request = ucp_tag_send_nbx(ep, msg, msglen, wireup_start_tag, &tx_params);

    if (UCS_PTR_IS_ERR(request)) {
        warnx("%s: ucp_tag_send_nbx: %s", __func__,
            ucs_status_string(UCS_PTR_STATUS(request)));
        goto free_wire; 
    } else if (request == UCS_OK)
        free(msg);

    return w;
free_wire:
    wiring_free_put(wiring, id);
free_msg:
    free(msg);
    return NULL;
}

/* Initiate wireup: create a wire, configure an endpoint for `raddr`, send
 * a message to the endpoint telling our wire's Sender ID.
 */
wire_t *
wireup_start(wiring_t **wiringp, ucp_address_t *laddr, size_t laddrlen,
    ucp_address_t *raddr, size_t raddrlen)
{
    ucp_ep_params_t ep_params = {
      .field_mask = UCP_EP_PARAM_FIELD_REMOTE_ADDRESS |
                    UCP_EP_PARAM_FIELD_ERR_HANDLER
    , .address = raddr
    , .err_mode = UCP_ERR_HANDLING_MODE_NONE
    };
    ucp_request_param_t tx_params;
    wiring_t *wiring = *wiringp;
    wireup_msg_t *msg;
    wire_t *w;
    ucp_ep_h ep;
    ucs_status_ptr_t request;
    sender_id_t id;
    const size_t msglen = sizeof(*msg) + laddrlen;
    ucs_status_t status;

    if ((msg = zalloc(msglen)) == NULL)
        return NULL;

    if ((id = wiring_free_get(wiring)) == SENDER_ID_NIL) {
        if ((wiring = wiring_enlarge(wiring)) == NULL)
            goto free_msg;
        *wiringp = wiring;
        if ((id = wiring_free_get(wiring)) == SENDER_ID_NIL)
            goto free_msg;
    }

    w = &wiring->wire[id];

    *msg = (wireup_msg_t){.op = OP_REQ, .sender_id = id, .addrlen = laddrlen};
    memcpy(&msg->addr[0], laddr, laddrlen);

    status = ucp_ep_create(wiring->ring.worker, &ep_params, &ep);
    if (status != UCS_OK) {
        warnx("%s: ucp_ep_create: %s", __func__, ucs_status_string(status));
        goto free_wire;
    }
    *w = (wire_t){.ep = ep, .id = SENDER_ID_NIL,
        .state = &state[WIRE_S_INITIAL]};

    wiring_timeout_put(wiring, w, getnanos() + timeout_interval);

    tx_params = (ucp_request_param_t){
      .op_attr_mask = UCP_OP_ATTR_FIELD_CALLBACK | UCP_OP_ATTR_FIELD_USER_DATA
    , .cb = {.send = wireup_send_callback}
    , .user_data = msg
    };
    request = ucp_tag_send_nbx(ep, msg, msglen, wireup_start_tag, &tx_params);

    if (UCS_PTR_IS_ERR(request)) {
        warnx("%s: ucp_tag_send_nbx: %s", __func__,
            ucs_status_string(UCS_PTR_STATUS(request)));
        goto free_wire; 
    } else if (request == UCS_OK)
        free(msg);

    return w;
free_wire:
    wiring_free_put(wiring, id);
free_msg:
    free(msg);
    return NULL;
}

static wiring_t *
wireup_rx_msg(wiring_t *wiring, const ucp_tag_t sender_tag,
    const void *buf, size_t buflen)
{
    const wireup_msg_t *msg;
    const size_t hdrlen = offsetof(wireup_msg_t, addr[0]);
    wireup_op_t op;

    assert((sender_tag & TAG_CHNL_MASK) == TAG_CHNL_WIREUP);

    if (buflen < hdrlen) {
        warnx("%s: dropping %zu-byte message, shorter than header\n", __func__,
            buflen);
        return wiring;
    }

    msg = buf;

    switch (msg->op) {
    case OP_REQ:
    case OP_ACK:
    case OP_KEEPALIVE:
        op = msg->op;
        break;
    default:
        warnx("%s: unexpected opcode %" PRIu16 ", dropping\n", __func__,
            msg->op);
        return wiring;
    }

    if (buflen < offsetof(wireup_msg_t, addr[0]) + msg->addrlen) {
        warnx("%s: %zu-byte message, address truncated, dropping\n",
            __func__, buflen);
        return wiring;
    }

    switch (op) {
    case OP_ACK:
        wireup_msg_transition(wiring, sender_tag, msg);
        break;
    case OP_REQ:
        wiring = wireup_rx_req(wiring, msg);
        break;
    case OP_KEEPALIVE:
        wireup_msg_transition(wiring, sender_tag, msg);
        break;
    }
    return wiring;
}

static wiring_t *
wireup_rx_req(wiring_t *wiring, const wireup_msg_t *msg)
{
    wire_t *w;

    /* XXX In principle, can't the empty string be a valid address? */
    if (msg->addrlen == 0) {
        warnx("%s: empty address, dropping", __func__);
        return wiring;
    }

    w = wireup_respond(&wiring, msg->sender_id,
       (void *)&msg->addr[0], msg->addrlen);

    if (w == NULL) {
        warnx("%s: failed to prepare & send wireup response", __func__);
        return wiring;
    }

    printf("%s: my sender id %td, remote sender id %" PRIdSENDER "\n", __func__,
        w - &wiring->wire[0], w->id);

    return wiring;
}

bool
wireup_once(wiring_t *wiring)
{
    rxring_t *ring = &wiring->ring;
    rxdesc_t *rdesc;

    /* TBD timeouts */

    if ((rdesc = rxring_next(ring)) == NULL)
        return true;

    if (rdesc->status == UCS_OK) {
        printf("received %zu-byte message tagged %" PRIu64
               ", processing...\n", rdesc->rxlen, rdesc->sender_tag);
        wireup_rx_msg(wiring, rdesc->sender_tag, rdesc->buf,
            rdesc->rxlen);
    } else if (rdesc->status == UCS_ERR_MESSAGE_TRUNCATED) {
        const size_t hdrlen = offsetof(wireup_msg_t, addr[0]);
        printf("%s: truncated desc %p buf %p buflen %zu\n", __func__,
           (void *)rdesc, rdesc->buf, rdesc->buflen);
        size_t buflen = rdesc->buflen;
        void * const buf = rdesc->buf, *nbuf;
        /* Twice the message length is twice the header length plus
         * twice the payload length, so subtract one header length to
         * double only the payload length.
         */
        size_t nbuflen = twice_or_max(buflen) - hdrlen;

        /* TBD enlarge all Rx buffers */

        printf("increasing buffer length %zu -> %zu bytes.\n", buflen, nbuflen);

        if ((nbuf = malloc(nbuflen)) == NULL)
            err(EXIT_FAILURE, "%s: malloc", __func__);

        rdesc->buflen = nbuflen;
        rdesc->buf = nbuf;
        free(buf);
    } else {
        printf("receive error, %s, exiting.\n",
            ucs_status_string(rdesc->status));
        return false;
    }
    rxdesc_setup(ring, rdesc->buf, rdesc->buflen, rdesc);
    return true;
}
