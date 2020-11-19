#include <err.h>
#include <inttypes.h> /* PRIu32 */
#include <stdlib.h> /* calloc, malloc */
#include <string.h> /* memcpy */
#include <time.h> /* clock_gettime(2) */
#include <unistd.h> /* size_t, SIZE_MAX */

#include "rxpool.h"
#include "tag.h"
#include "util.h"
#include "wireup.h"
#include "wiring_impl.h"

struct _wire_state {
    const wire_state_t *(*expire)(wiring_t *, wire_t *);
    const wire_state_t *(*wakeup)(wiring_t *, wire_t *);
    const wire_state_t *(*receive)(wiring_t *, wire_t *, const wireup_msg_t *);
    const char *descr;
};

enum {
  WIRE_S_INITIAL
, WIRE_S_LIVE
, WIRE_S_DEAD
};

static const ucp_tag_t wireup_start_tag = TAG_CHNL_WIREUP | TAG_ID_MASK;

static const uint64_t keepalive_interval = 1000000000;  // 1 second
static const uint64_t timeout_interval = 2 * keepalive_interval;

static uint64_t getnanos(void);

static void wireup_rx_req(wiring_t *, const wireup_msg_t *);

static void wireup_stop_internal(wiring_t *, wire_t *, bool);
static void wireup_send_callback(void *, ucs_status_t, void *);
static void wireup_last_send_callback(void *, ucs_status_t, void *);

static wstorage_t *wiring_enlarge(wstorage_t *);
static bool wireup_send(wire_t *);
static const wire_state_t *continue_life(wiring_t *, wire_t *,
    const wireup_msg_t *);
static const wire_state_t *destroy(wiring_t *, wire_t *);
static const wire_state_t *reject_msg(wiring_t *, wire_t *,
    const wireup_msg_t *);
static const wire_state_t *reject_expire(wiring_t *, wire_t *);
static const wire_state_t *ignore_wakeup(wiring_t *, wire_t *);
static const wire_state_t *send_keepalive(wiring_t *, wire_t *);
static const wire_state_t *retry(wiring_t *, wire_t *);
static const wire_state_t *start_life(wiring_t *, wire_t *,
    const wireup_msg_t *);

wire_state_t state[] = {
  [WIRE_S_INITIAL] = {.expire = retry,
                      .wakeup = ignore_wakeup,
                      .receive = start_life,
                      .descr = "initial"}
, [WIRE_S_LIVE] = {.expire = destroy,
                   .wakeup = send_keepalive,
                   .receive = continue_life,
                   .descr = "live"}
, [WIRE_S_DEAD] = {.expire = reject_expire,
                   .wakeup = ignore_wakeup,
                   .receive = reject_msg,
                   .descr = "dead"}
};

static void *
zalloc(size_t sz)
{
    return calloc(1, sz);
}

/* Return the next larger buffer length to try if `buflen` did not fit a
 * received packet.
 *
 * Twice the message length is twice the header length plus twice the
 * payload length, so subtract one header length to double only the
 * payload length.
 */
static size_t
next_buflen(size_t buflen)
{
        const size_t hdrlen = offsetof(wireup_msg_t, addr[0]);
        if (buflen == 0)
            return sizeof(wireup_msg_t) + 93;
        return twice_or_max(buflen) - hdrlen;
}

static void
wiring_release_wire(wiring_t *wiring, wire_t *w)
{
    wstorage_t *st = wiring->storage;
    sender_id_t id = w - &st->wire[0];
    wireup_msg_t *msg;
    ucp_ep_h ep;

    assert(id < st->nwires);

    if ((msg = w->msg) != NULL) {
        w->msg = NULL;
        free(msg);
    }
    if ((ep = w->ep) != NULL) {
        void *request;

        w->ep = NULL;
        request = ucp_ep_close_nb(ep, UCP_EP_CLOSE_MODE_FLUSH);
        if (UCS_PTR_IS_ERR(request)) {
            warnx("%s: ucp_ep_close_nb: %s", __func__,
                ucs_status_string(UCS_PTR_STATUS(request)));
        } else if (request != UCS_OK)
            ucp_request_free(request);
    }
    w->id = SENDER_ID_NIL;
    w->msglen = 0;
    wiring_expiration_remove(st, w);
    wiring_wakeup_remove(st, w);
    wiring_free_put(st, id);
}

static void
wireup_transition(wiring_t *wiring, wire_t *w,
    const wire_state_t *nstate)
{
    wstorage_t *st = wiring->storage;
    const wire_state_t *ostate;
    bool reset_cb;

    ostate = w->state;
    w->state = nstate;

    printf("%s: wire %td state change %s -> %s\n",
        __func__, w - &st->wire[0], ostate->descr, nstate->descr);

    if (w->cb == NULL || ostate == nstate)
        reset_cb = false; // no callback or no state change: do nothing
    else if (nstate == &state[WIRE_S_DEAD])
        reset_cb = !(*w->cb)(wire_ev_died, w->cb_arg);
    else if (nstate == &state[WIRE_S_LIVE])
        reset_cb = !(*w->cb)(wire_ev_estd, w->cb_arg);

    if (reset_cb) {
        w->cb = NULL;
        w->cb_arg = NULL;
    }
}

static void
wireup_msg_transition(wiring_t *wiring, const ucp_tag_t sender_tag,
    const wireup_msg_t *msg)
{
    wstorage_t *st = wiring->storage;
    wire_t *w;
    const uint64_t proto_id = TAG_GET_ID(sender_tag);
    sender_id_t id;

    if (proto_id > SENDER_ID_MAX) {
        warnx("%s: illegal sender ID %" PRIu64, __func__, proto_id);
        return;
    }
    if (proto_id >= st->nwires) {
        warnx("%s: out of bounds sender ID %" PRIu64, __func__, proto_id);
        return;
    }

    id = (sender_id_t)proto_id;
    w = &st->wire[id];

    printf("%s: wire %" PRIdSENDER " %s message\n",
        __func__, id, wireup_op_string(msg->op));

    wireup_transition(wiring, w, (*w->state->receive)(wiring, w, msg));
}

static void
wireup_wakeup_transition(wiring_t *wiring, uint64_t now)
{
    wstorage_t *st = wiring->storage;
    wire_t *w;

    while ((w = wiring_wakeup_peek(st)) != NULL) {
        if (w->tlink[timo_wakeup].due > now)
            break;
        wiring_wakeup_remove(st, w);
        printf("%s: wire %td woke\n", __func__, w - &st->wire[0]);
        wireup_transition(wiring, w, (*w->state->wakeup)(wiring, w));
    }
}

static void
wireup_expire_transition(wiring_t *wiring, uint64_t now)
{
    wstorage_t *st = wiring->storage;
    wire_t *w;

    while ((w = wiring_expiration_peek(st)) != NULL) {
        if (w->tlink[timo_expire].due > now)
            break;
        wiring_expiration_remove(st, w);
        printf("%s: wire %td expired\n", __func__, w - &st->wire[0]);
        wireup_transition(wiring, w, (*w->state->expire)(wiring, w));
    }
}

static const wire_state_t *
start_life(wiring_t *wiring, wire_t *w, const wireup_msg_t *msg)
{
    wstorage_t *st = wiring->storage;
    sender_id_t id = w - &st->wire[0];

    if (msg->sender_id > SENDER_ID_MAX) {
        warnx("%s: bad foreign sender ID %" PRId32 " for wire %" PRIdSENDER,
            __func__, msg->sender_id, id);
        return w->state;
    }

    if (msg->op == OP_STOP) {
        wiring_release_wire(wiring, w);
        return &state[WIRE_S_DEAD];
    } else if (msg->op != OP_ACK) {
        warnx("%s: unexpected opcode %" PRIu16 " for wire %" PRIdSENDER,
            __func__, msg->op, id);
        return w->state;
    }

    if (msg->addrlen != 0) {
        warnx("%s: unexpected addr. len. %" PRIu16 " for wire %" PRIdSENDER,
            __func__, msg->addrlen, id);
        return w->state;
    }

    w->id = msg->sender_id;
    free(w->msg);
    w->msg = NULL;
    w->msglen = 0;
    wiring_expiration_remove(st, w);
    wiring_expiration_put(st, w, getnanos() + timeout_interval);
    wiring_wakeup_put(st, w, getnanos() + keepalive_interval);

    return &state[WIRE_S_LIVE];
}

static const wire_state_t *
continue_life(wiring_t *wiring, wire_t *w, const wireup_msg_t *msg)
{
    wstorage_t *st = wiring->storage;
    sender_id_t id = w - &st->wire[0];

    if (msg->sender_id > SENDER_ID_MAX) {
        warnx("%s: bad foreign sender ID %" PRId32 " for wire %" PRIdSENDER,
            __func__, msg->sender_id, id);
        return w->state;
    }

    if (msg->op == OP_STOP) {
        wiring_release_wire(wiring, w);
        return &state[WIRE_S_DEAD];
    } else if (msg->op != OP_KEEPALIVE) {
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

    wiring_expiration_remove(st, w);
    wiring_expiration_put(st, w, getnanos() + timeout_interval);

    return &state[WIRE_S_LIVE];
}

static const wire_state_t *
send_keepalive(wiring_t *wiring, wire_t *w)
{
    wstorage_t *st = wiring->storage;
    ucp_request_param_t tx_params;
    wireup_msg_t *msg;
    ucs_status_ptr_t request;
    const ucp_tag_t tag = TAG_CHNL_WIREUP | SHIFTIN(w->id, TAG_ID_MASK);
    const sender_id_t id = w - &st->wire[0];

    if ((msg = zalloc(sizeof(*msg))) == NULL)
        return w->state;

    *msg = (wireup_msg_t){.op = OP_KEEPALIVE, .sender_id = id, .addrlen = 0};

    tx_params = (ucp_request_param_t){
      .op_attr_mask = UCP_OP_ATTR_FIELD_CALLBACK | UCP_OP_ATTR_FIELD_USER_DATA
    , .cb = {.send = wireup_last_send_callback}
    , .user_data = msg
    };

    request = ucp_tag_send_nbx(w->ep, msg, sizeof(*msg), tag, &tx_params);

    if (UCS_PTR_IS_ERR(request)) {
        warnx("%s: ucp_tag_send_nbx: %s", __func__,
            ucs_status_string(UCS_PTR_STATUS(request)));
        free(msg);
    } else if (request == UCS_OK)
        free(msg);

    wiring_wakeup_put(st, w, getnanos() + keepalive_interval);

    return w->state;
}

static const wire_state_t *
ignore_wakeup(wiring_t *wiring, wire_t *w)
{
    wstorage_t *st = wiring->storage;
    sender_id_t id = w - &st->wire[0];

    warnx("%s: ignoring wakeup for wire %" PRIdSENDER, __func__, id);

    return w->state;
}

static const wire_state_t *
reject_expire(wiring_t *wiring, wire_t *w)
{
    wstorage_t *st = wiring->storage;
    sender_id_t id = w - &st->wire[0];

    warnx("%s: rejecting expiration for wire %" PRIdSENDER, __func__, id);

    return &state[WIRE_S_DEAD];
}

static const wire_state_t *
reject_msg(wiring_t *wiring, wire_t *w, const wireup_msg_t *msg)
{
    wstorage_t *st = wiring->storage;
    sender_id_t id = w - &st->wire[0];

    warnx("%s: rejecting message from %" PRIdSENDER " for wire %" PRIdSENDER,
        __func__, msg->sender_id, id);

    return &state[WIRE_S_DEAD];
}

static const wire_state_t *
retry(wiring_t *wiring, wire_t *w)
{
    wstorage_t *st = wiring->storage;
    sender_id_t id = w - &st->wire[0];

    warnx("%s: retrying establishment of wire %" PRIdSENDER, __func__, id);

    if (!wireup_send(w)) {
        wiring_release_wire(wiring, w);
        return &state[WIRE_S_DEAD];
    }

    wiring_expiration_put(st, w, getnanos() + timeout_interval);

    return &state[WIRE_S_INITIAL];
}

static const wire_state_t *
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
}

static void
wireup_last_send_callback(void *request, ucs_status_t status, void *user_data)
{
    wireup_msg_t *msg = user_data;

    printf("%s: sent id %" PRIu32 " addr. len. %" PRIu16 " status %s\n",
        __func__, msg->sender_id, msg->addrlen, ucs_status_string(status));

    free(msg);
}

/* Release all resources belonging to `wiring`.  If `orderly` is true,
 * then alert our peers that we are discarding all of our wires so that
 * they can clean up their local state.
 */
void
wiring_teardown(wiring_t *wiring, bool orderly)
{
    wstorage_t *st = wiring->storage;
    size_t i;

    if (st->rxpool != NULL)
        rxpool_destroy(st->rxpool);

    for (i = 0; i < st->nwires; i++)
        wireup_stop_internal(wiring, &st->wire[i], orderly);

    free(st);
}

/* Release all resources belonging to `wiring` and free `wiring` itself.
 * If `orderly` is true, then alert our peers that we are discarding all
 * of our wires so that they can clean up their local state.
 */
void
wiring_destroy(wiring_t *wiring, bool orderly)
{
    wiring_teardown(wiring, orderly);
    free(wiring);
}

static inline bool
wire_is_connected(wiring_t *wiring, wire_id_t wid)
{
    wstorage_t *st = wiring->storage;
    wire_t *w;

    if (wid.id < 0 || st->nwires <= wid.id)
        return false;

    w = &st->wire[wid.id];

    return w->state == &state[WIRE_S_LIVE];
}

sender_id_t
wire_get_sender_id(wiring_t *wiring, wire_id_t wid)
{
    if (!wire_is_connected(wiring, wid))
        return SENDER_ID_NIL;

    return wiring->storage->wire[wid.id].id;
}

bool
wireup_stop(wiring_t *wiring, wire_id_t wid, bool orderly)
{
    wstorage_t *st = wiring->storage;

    if (wid.id < 0 || st->nwires <= wid.id)
        return false;

    wireup_stop_internal(wiring, &st->wire[wid.id], orderly);
    return true;
}

/* Move the state machine on wire `w` to DEAD state and release its
 * resources.  If `orderly` is true, then send a STOP message to the peer
 * so that it can release its wire.
 */
static void
wireup_stop_internal(wiring_t *wiring, wire_t *w, bool orderly)
{
    ucp_request_param_t tx_params;
    wireup_msg_t *msg;
    ucs_status_ptr_t request;
    wstorage_t *st = wiring->storage;
    const ucp_tag_t tag = TAG_CHNL_WIREUP | SHIFTIN(w->id, TAG_ID_MASK);
    const sender_id_t id = w - &st->wire[0];

    if (w->state == &state[WIRE_S_DEAD])
        goto out;

    if ((msg = zalloc(sizeof(*msg))) == NULL)
        goto out;

    *msg = (wireup_msg_t){.op = OP_STOP, .sender_id = id, .addrlen = 0};

    tx_params = (ucp_request_param_t){
      .op_attr_mask = UCP_OP_ATTR_FIELD_CALLBACK | UCP_OP_ATTR_FIELD_USER_DATA
    , .cb = {.send = wireup_last_send_callback}
    , .user_data = msg
    };

    request = ucp_tag_send_nbx(w->ep, msg, sizeof(*msg), tag, &tx_params);

    if (UCS_PTR_IS_ERR(request)) {
        warnx("%s: ucp_tag_send_nbx: %s", __func__,
            ucs_status_string(UCS_PTR_STATUS(request)));
        free(msg);
    } else if (request == UCS_OK)
        free(msg);

out:
    wiring_release_wire(wiring, w);
}

bool
wiring_init(wiring_t *wiring, ucp_worker_h worker, size_t request_size)
{
    wstorage_t *st;
    const size_t nwires = 1;
    int which;
    size_t i;

    st = zalloc(sizeof(*st) + sizeof(wire_t) * nwires);
    if (st == NULL)
        return false;

    wiring->storage = st;

    st->nwires = nwires;

    for (i = 0; i < nwires; i++) {
        st->wire[i] = (wire_t){
              .next_free = i + 1
            , .state = &state[WIRE_S_DEAD]
            , .tlink = {{.prev = i, .next = i, .due = 0},
                        {.prev = i, .next = i, .due = 0}}
            , .ep = NULL
            , .id = SENDER_ID_NIL};
    }

    st->wire[nwires - 1].next_free = SENDER_ID_NIL;
    st->first_free = 0;

    for (which = 0; which < timo_nlinks; which++)
        st->thead[which].first = st->thead[which].last = SENDER_ID_NIL;

    st->rxpool = rxpool_create(worker, next_buflen, request_size,
        TAG_CHNL_WIREUP, TAG_CHNL_MASK, 3);

    if (st->rxpool == NULL) {
        wiring_teardown(wiring, true);
        return false;
    }

    return true;
}

wiring_t *
wiring_create(ucp_worker_h worker, size_t request_size)
{
    wiring_t *wiring;

    if ((wiring = malloc(sizeof(*wiring))) == NULL)
        return NULL;

    if (!wiring_init(wiring, worker, request_size)) {
        free(wiring);
        return NULL;
    }

    return wiring;
}

static wstorage_t *
wiring_enlarge(wstorage_t *st)
{
    const size_t hdrsize = sizeof(wstorage_t),
                 osize = hdrsize + st->nwires * sizeof(wire_t);
    const size_t proto_nsize = twice_or_max(osize) - hdrsize;
    const size_t nwires = (proto_nsize - hdrsize) / sizeof(wire_t);
    const size_t nsize = hdrsize + nwires * sizeof(wire_t);
    size_t i;

    if (nsize <= osize)
        return NULL;

    st = realloc(st, nsize);

    if (st == NULL)
        return NULL;

    for (i = st->nwires; i < nwires; i++) {
        st->wire[i] = (wire_t){
              .next_free = i + 1
            , .state = &state[WIRE_S_DEAD]
            , .tlink = {{.prev = i, .next = i, .due = 0},
                        {.prev = i, .next = i, .due = 0}}
            , .ep = NULL
            , .id = SENDER_ID_NIL};
    }
    st->wire[nwires - 1].next_free = st->first_free;
    st->first_free = st->nwires;
    st->nwires = nwires;

    return st;
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
    case OP_ACK:
        return "ack";
    case OP_KEEPALIVE:
        return "keepalive";
    case OP_REQ:
        return "req";
    case OP_STOP:
        return "stop";
    default:
        return "<unknown>";
    }
}

/* Answer a request. */
wire_t *
wireup_respond(wiring_t *wiring, sender_id_t rid,
    ucp_address_t *raddr, size_t raddrlen)
{
    ucp_ep_params_t ep_params = {
      .field_mask = UCP_EP_PARAM_FIELD_REMOTE_ADDRESS |
                    UCP_EP_PARAM_FIELD_ERR_HANDLER
    , .address = raddr
    , .err_mode = UCP_ERR_HANDLING_MODE_NONE
    };
    ucp_request_param_t tx_params;
    wstorage_t *st = wiring->storage;
    wireup_msg_t *msg;
    wire_t *w;
    ucp_ep_h ep;
    const ucp_tag_t tag = TAG_CHNL_WIREUP | SHIFTIN(rid, TAG_ID_MASK);
    ucs_status_ptr_t request;
    sender_id_t id;
    const size_t msglen = sizeof(*msg);
    ucs_status_t status;

    if ((msg = zalloc(msglen)) == NULL)
        return NULL;

    if ((id = wiring_free_get(st)) == SENDER_ID_NIL) {
        if ((st = wiring_enlarge(st)) == NULL)
            goto free_msg;
        wiring->storage = st;
        if ((id = wiring_free_get(st)) == SENDER_ID_NIL)
            goto free_msg;
    }

    w = &st->wire[id];

    *msg = (wireup_msg_t){.op = OP_ACK, .sender_id = id, .addrlen = 0};

    status = ucp_ep_create(st->rxpool->worker, &ep_params, &ep);
    if (status != UCS_OK) {
        warnx("%s: ucp_ep_create: %s", __func__, ucs_status_string(status));
        goto free_wire;
    }
    *w = (wire_t){.ep = ep, .id = rid, .state = &state[WIRE_S_LIVE]};

    wiring_expiration_put(st, w, getnanos() + timeout_interval);
    wiring_wakeup_put(st, w, getnanos() + keepalive_interval);

    tx_params = (ucp_request_param_t){
      .op_attr_mask = UCP_OP_ATTR_FIELD_CALLBACK | UCP_OP_ATTR_FIELD_USER_DATA
    , .cb = {.send = wireup_last_send_callback}
    , .user_data = msg
    };
    request = ucp_tag_send_nbx(ep, msg, msglen, tag, &tx_params);

    if (UCS_PTR_IS_ERR(request)) {
        warnx("%s: ucp_tag_send_nbx: %s", __func__,
            ucs_status_string(UCS_PTR_STATUS(request)));
        goto free_wire;
    } else if (request == UCS_OK)
        free(msg);

    return w;
free_wire:
    wiring_free_put(st, id);
free_msg:
    free(msg);
    return NULL;
}

static bool
wireup_send(wire_t *w)
{
    ucp_ep_h ep = w->ep;
    wireup_msg_t *msg = w->msg;
    ucs_status_ptr_t request;
    size_t msglen = w->msglen;

    ucp_request_param_t tx_params = {
      .op_attr_mask = UCP_OP_ATTR_FIELD_CALLBACK | UCP_OP_ATTR_FIELD_USER_DATA
    , .cb = {.send = wireup_send_callback}
    , .user_data = msg
    };
    request = ucp_tag_send_nbx(ep, msg, msglen, wireup_start_tag, &tx_params);

    if (UCS_PTR_IS_ERR(request)) {
        warnx("%s: ucp_tag_send_nbx: %s", __func__,
            ucs_status_string(UCS_PTR_STATUS(request)));
        return false;
    }
    return true;
}

/* Initiate wireup: create a wire, configure an endpoint for `raddr`, send
 * a message to the endpoint telling our wire's Sender ID and our address.
 */
wire_id_t
wireup_start(wiring_t * const wiring, ucp_address_t *laddr, size_t laddrlen,
    ucp_address_t *raddr, size_t raddrlen, wire_event_cb_t *cb, void *cb_arg)
{
    ucp_ep_params_t ep_params = {
      .field_mask = UCP_EP_PARAM_FIELD_REMOTE_ADDRESS |
                    UCP_EP_PARAM_FIELD_ERR_HANDLER
    , .address = raddr
    , .err_mode = UCP_ERR_HANDLING_MODE_NONE
    };
    wstorage_t *st = wiring->storage;
    wireup_msg_t *msg;
    wire_t *w;
    ucp_ep_h ep;
    sender_id_t id;
    const size_t msglen = sizeof(*msg) + laddrlen;
    ucs_status_t status;

    if ((msg = zalloc(msglen)) == NULL)
        return (wire_id_t){.id = SENDER_ID_NIL};

    if ((id = wiring_free_get(st)) == SENDER_ID_NIL) {
        if ((st = wiring_enlarge(st)) == NULL)
            goto free_msg;
        wiring->storage = st;
        if ((id = wiring_free_get(st)) == SENDER_ID_NIL)
            goto free_msg;
    }

    w = &st->wire[id];

    *msg = (wireup_msg_t){.op = OP_REQ, .sender_id = id, .addrlen = laddrlen};
    memcpy(&msg->addr[0], laddr, laddrlen);

    status = ucp_ep_create(st->rxpool->worker, &ep_params, &ep);
    if (status != UCS_OK) {
        warnx("%s: ucp_ep_create: %s", __func__, ucs_status_string(status));
        goto free_wire;
    }
    *w = (wire_t){.ep = ep, .id = SENDER_ID_NIL,
        .state = &state[WIRE_S_INITIAL], .msg = msg, .msglen = msglen,
        .cb = cb, .cb_arg = cb_arg};

    wiring_expiration_put(st, w, getnanos() + timeout_interval);

    if (!wireup_send(w))
        goto free_wire;

    return (wire_id_t){.id = id};
free_msg:
    free(msg);
    return (wire_id_t){.id = SENDER_ID_NIL};
free_wire:
    wiring_release_wire(wiring, w);
    return (wire_id_t){.id = SENDER_ID_NIL};
}

static void
wireup_rx_msg(wiring_t * const wiring, const ucp_tag_t sender_tag,
    const void *buf, size_t buflen)
{
    const wireup_msg_t *msg;
    const size_t hdrlen = offsetof(wireup_msg_t, addr[0]);
    wireup_op_t op;

    assert((sender_tag & TAG_CHNL_MASK) == TAG_CHNL_WIREUP);

    if (buflen < hdrlen) {
        warnx("%s: dropping %zu-byte message, shorter than header\n", __func__,
            buflen);
        return;
    }

    msg = buf;

    switch (msg->op) {
    case OP_ACK:
    case OP_KEEPALIVE:
    case OP_REQ:
    case OP_STOP:
        op = msg->op;
        break;
    default:
        warnx("%s: unexpected opcode %" PRIu16 ", dropping\n", __func__,
            msg->op);
        return;
    }

    if (buflen < offsetof(wireup_msg_t, addr[0]) + msg->addrlen) {
        warnx("%s: %zu-byte message, address truncated, dropping\n",
            __func__, buflen);
        return;
    }

    switch (op) {
    case OP_REQ:
        wireup_rx_req(wiring, msg);
        break;
    case OP_ACK:
    case OP_KEEPALIVE:
    case OP_STOP:
        wireup_msg_transition(wiring, sender_tag, msg);
        break;
    }
}

static void
wireup_rx_req(wiring_t *wiring, const wireup_msg_t *msg)
{
    wire_t *w;

    /* XXX In principle, can't the empty string be a valid address? */
    if (msg->addrlen == 0) {
        warnx("%s: empty address, dropping", __func__);
        return;
    }

    w = wireup_respond(wiring, msg->sender_id,
       (void *)&msg->addr[0], msg->addrlen);

    if (w == NULL) {
        warnx("%s: failed to prepare & send wireup response", __func__);
        return;
    }

    printf("%s: my sender id %td, remote sender id %" PRIdSENDER "\n", __func__,
        w - &wiring->storage->wire[0], w->id);
}

bool
wireup_once(wiring_t *wiring)
{
    wstorage_t * const st = wiring->storage;
    rxpool_t *rxpool = st->rxpool;
    rxdesc_t *rdesc;
    uint64_t now = getnanos();

    wireup_expire_transition(wiring, now);
    wireup_wakeup_transition(wiring, now);

    if ((rdesc = rxpool_next(rxpool)) == NULL)
        return true;

    if (rdesc->status == UCS_OK) {
        printf("received %zu-byte message tagged %" PRIu64
               ", processing...\n", rdesc->rxlen, rdesc->sender_tag);
        wireup_rx_msg(wiring, rdesc->sender_tag, rdesc->buf, rdesc->rxlen);
    } else {
        printf("receive error, %s, exiting.\n",
            ucs_status_string(rdesc->status));
        return false;
    }
    rxdesc_release(rxpool, rdesc);
    return true;
}

/* Store at `maskp` and `atagp` the mask and tag that wireup reserves
 * for the application program.  For each application message tag,
 * `tag`, `tag & *maskp` must equal `*atagp`.
 *
 * All bits in the mask are consecutive.  They bits include either the
 * most-significant bit or the least-significant bit.
 *
 * If either pointer is NULL, don't try to write through it.
 */
void
wireup_app_tag(wiring_t *wiring, uint64_t *atagp, uint64_t *maskp)
{
    if (atagp != NULL)
        *atagp = TAG_CHNL_APP;
    if (maskp != NULL)
        *maskp = TAG_CHNL_MASK;
}

const char *
wire_event_string(wire_event_t ev)
{
    switch (ev) {
    case wire_ev_estd:
        return "estd";
    case wire_ev_died:
        return "died";
    default:
        return "<unknown>";
    }
}
