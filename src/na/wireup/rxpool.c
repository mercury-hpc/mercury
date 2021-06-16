#include <assert.h>
#include <err.h>
#include <inttypes.h> /* PRI?64 */
#include <limits.h> /* UINT_MAX */
#include <pthread.h>
#include <stdalign.h> /* alignof */
#include <stdint.h> /* SIZE_MAX */
#include <stdlib.h> /* malloc */

#include <ucp/api/ucp.h>

#include "../../hlog/src/hlog.h"
#include "rxpool.h"
#include "util.h"

HLOG_OUTLET_SHORT_DEFN(rxpool, all);

static rxdesc_t *rxpool_next_slow(rxpool_t *, rxdesc_t *);
static void rxdesc_setup(rxpool_t *, void *, size_t, rxdesc_t *);

static void
rxdesc_callback(void *request, ucs_status_t status,
    const ucp_tag_recv_info_t *tag_info, void *user_data)
{
    rxdesc_t *desc = request;
    rxpool_t *rxpool = user_data;

    desc->status = status;
    desc->ucx_owns = false;

    switch (status) {
    case UCS_OK:
        desc->rxlen = tag_info->length;
        desc->sender_tag = tag_info->sender_tag;
        break;
    case UCS_ERR_CANCELED: // Do nothing if the request was cancelled.
    default:
        break;
    }

    hlog_fast(rxpool, "%s: pushing completed desc %p tag %" PRIx64, __func__,
        (void *)desc, desc->sender_tag);

    if (hg_atomic_queue_push(rxpool->complete, desc) == HG_UTIL_FAIL)
        errx(EXIT_FAILURE, "%s: push failed", __func__);
}

/* Allocate and initialize a receive-descriptor pool.  On success,
 * return a new pool.  Otherwise, return NULL on error.
 *
 * This is a thin layer over `rxpool_init`, see that routine's
 * documentation for more detail.
 *
 * The caller should release all of the resources connected with this
 * pool by calling `rxpool_destroy`.
 */
rxpool_t *
rxpool_create(ucp_worker_h worker, rxpool_next_buflen_t next_buflen,
    size_t request_size, ucp_tag_t tag, ucp_tag_t tag_mask, size_t nelts)
{
    rxpool_t *rxpool;

    rxpool = malloc(sizeof(*rxpool));
    if (rxpool == NULL)
        return NULL;

    return rxpool_init(rxpool, worker, next_buflen, request_size, tag, tag_mask,
        nelts);
}

static size_t
roundup_to_power_of_2(size_t x)
{
    size_t y = 1;

    while (y < x && SIZE_MAX - y >= y)
        y += y;

    if (y < x)
        return 0;

    return y;
}

/* Initialize the receive-descriptor pool, `rxpool`.  On success, return
 * `rxpool`.  Otherwise, return NULL.
 *
 * The pool posts receives on `worker`.  The lifetime of `worker` must
 * exceed that of `rxpool`.
 *
 * `next_buflen` points to a function that the pool calls when a received
 * message does not fit into a receive buffer.  `next_buflen` tells
 * the next larger buffer size to use.  When its argument is `0`, it
 * returns the initial size in bytes for the pool's receive buffers.
 * For any other argument, `n`, it returns the next larger buffer size,
 * which must be at least `n + 1`.
 *
 * `request_size` tells how many bytes to reserve for use by UCP at
 * the beginning of a buffer `malloc(3)`d for a receive descriptor
 * (`rxdesc_t`).
 *
 * `tag` and `tag_mask` describe the messages of interest to the pool.
 * The pool will exclusively receive messages whose tags `rxtag` satisfy
 * `rxtag ^ tag_mask == tag & tag_mask`.
 *
 * The pool will buffer `nelts` received messages.  If `nelts`
 * messages are already buffered, then the `nelts + 1`th message and
 * subsequent messages may be dropped.  The owner of the pool
 * replenishes it by performing `rxpool_next` to retrieve a message and
 * `rxpool_release` to release that message's descriptor.
 */
rxpool_t *
rxpool_init(rxpool_t *rxpool, ucp_worker_h worker,
    rxpool_next_buflen_t next_buflen, size_t request_size,
    ucp_tag_t tag, ucp_tag_t tag_mask, size_t nelts)
{
    size_t i;
    const size_t buflen = (*next_buflen)(0);
    /* The queue needs to have capacity for all `nelts` elements,
     * but `hg_atomic_queue_alloc(qlen)` has room for only `qlen - 1`,
     * so round up `nelts + 1` instead of `nelts` to get the smallest
     * `qlen` that's large enough.
     */
    const size_t qlen = roundup_to_power_of_2(nelts + 1);
    assert(buflen > 0);

    hlog_fast(rxpool, "%s: %zu elements, max queue length %zu", __func__,
        nelts, qlen);

    TAILQ_INIT(&rxpool->alldesc);

    if (qlen == 0) {
        // TBD log error
        return NULL;
    }

    rxpool->complete = hg_atomic_queue_alloc((unsigned int)qlen);
    if (rxpool->complete == NULL) {
        // TBD log error
        return NULL;
    }

    rxpool->next_buflen = next_buflen;
    rxpool->initbuflen = buflen;
    rxpool->worker = worker;
    rxpool->tag = tag;
    rxpool->tag_mask = tag_mask;
    rxpool->request_size = request_size;

    /* Allocate a buffer for each receive descriptor and queue with
     * UCP.
     */
    for (i = 0; i < nelts; i++) {
        rxdesc_t *rdesc;
        void *buf;

        if ((buf = malloc(buflen)) == NULL) {
            // err(EXIT_FAILURE, "%s: malloc", __func__);
            return NULL;
        }

        rdesc = header_alloc(request_size,
                              alignof(rxdesc_t), sizeof(rxdesc_t));

        if (rdesc == NULL) {
            // err(EXIT_FAILURE, "%s: header_alloc", __func__);
            return NULL;
        }

        TAILQ_INSERT_HEAD(&rxpool->alldesc, rdesc, linkall);

        rxdesc_setup(rxpool, buf, buflen, rdesc);
    }
    return rxpool;
}

/* (Re)initialize the receive descriptor `desc` belonging to `rxpool`
 * and post a receive for up to `buflen` bytes at `buf`.  After the posted
 * receive finishes (or errors out), `rxpool_next(rxpool)` will return the
 * descriptor.
 */
static void
rxdesc_setup(rxpool_t *rxpool, void *buf, size_t buflen, rxdesc_t *desc)
{
    const ucp_request_param_t recv_params = {
      .op_attr_mask = UCP_OP_ATTR_FIELD_CALLBACK |
                      UCP_OP_ATTR_FIELD_REQUEST |
                      UCP_OP_ATTR_FIELD_USER_DATA
    , .cb = {.recv = rxdesc_callback}
    , .request = desc
    , .user_data = rxpool
    };
    ucp_worker_h worker = rxpool->worker;
    void *request;

    desc->buf = buf;
    desc->buflen = buflen;
    desc->ucx_owns = true;

    hlog_fast(rxpool, "%s: initialized desc %p buf %p buflen %zu", __func__,
       (void *)desc, desc->buf, desc->buflen);
    request = ucp_tag_recv_nbx(worker, buf, buflen, rxpool->tag,
        rxpool->tag_mask, &recv_params);

    /* TBD expect NULL.  Handle it by immediately enqueueing the completion? */
    if (request == NULL)
        errx(EXIT_FAILURE, "%s: ucp_tag_recv_nbx: request == NULL", __func__);

    if (UCS_PTR_IS_ERR(request)) {
        errx(EXIT_FAILURE, "%s: ucp_tag_recv_nbx: %s", __func__,
            ucs_status_string(UCS_PTR_STATUS(request)));
    }

    if (request != desc)
        errx(EXIT_FAILURE, "%s: ucp_tag_recv_nbx: request != desc", __func__);
}

/* Reclaim the resources connected with `rxpool`: cancel the posted
 * receives and wait for them to complete.  Free the receive descriptors
 * and release the completion queue.
 *
 * Note well: the caller is responsible for `free(3)`ing `rxpool`.
 */
void
rxpool_teardown(rxpool_t *rxpool)
{
    rxdesc_t *desc;
    ucp_worker_h worker = rxpool->worker;

    /* Release UCP resources held by each descriptor.  Free buffers. */
    TAILQ_FOREACH(desc, &rxpool->alldesc, linkall) {
        hlog_fast(rxpool, "%s: cancelling desc %p", __func__, (void *)desc);
        if (desc->ucx_owns)
            ucp_request_cancel(worker, desc);
    }

    while ((desc = TAILQ_FIRST(&rxpool->alldesc)) != NULL) {
        void *buf;

        if (desc->ucx_owns) {
            while ((desc = rxpool_next(rxpool)) == NULL)
                ucp_worker_progress(worker);
        }

        hlog_fast(rxpool, "%s: freeing desc %p", __func__, (void *)desc);

        if ((buf = desc->buf) != NULL) {
            desc->buf = NULL;
            free(buf);
        }

        TAILQ_REMOVE(&rxpool->alldesc, desc, linkall);

        header_free(rxpool->request_size, alignof(rxdesc_t), desc);
    }
    hg_atomic_queue_free(rxpool->complete);
    rxpool->complete = NULL;
}

/* Reclaim the resources connected with `rxpool` and `free(3)` `rxpool`.
 * See `rxpool_teardown` for details.
 */
void
rxpool_destroy(rxpool_t *rxpool)
{
    rxpool_teardown(rxpool);
    free(rxpool);
}

static rxdesc_t *
rxpool_pop(rxpool_t *rxpool)
{
    rxdesc_t *rdesc = hg_atomic_queue_pop_sc(rxpool->complete);

    if (rdesc == NULL)
        return NULL;

    hlog_fast(rxpool, "%s: popped completed desc %p tag %" PRIx64, __func__,
        (void *)rdesc, rdesc->sender_tag);

    return rdesc;
}

/* Return the next completed Rx descriptor in `rxpool` or NULL if
 * there are none.  The caller should check the error status
 * before trying to use the Rx buffer.
 *
 * The caller "owns" the descriptor.  The pool cannot reuse the
 * descriptor until the caller releases it with `rxdesc_release`.
 *
 * Callers are responsible for synchronizing calls to rxpool_next().
 */
rxdesc_t *
rxpool_next(rxpool_t *rxpool)
{
    rxdesc_t *rdesc = rxpool_pop(rxpool);

    if (rdesc == NULL)
        return NULL;

    if (rdesc->status != UCS_ERR_MESSAGE_TRUNCATED &&
        rdesc->status != UCS_ERR_CANCELED)
        return rdesc;

    return rxpool_next_slow(rxpool, rdesc);
}

static size_t
rxpool_buflen_step(rxpool_t *rxpool, rxdesc_t *head)
{
    const size_t buflen = head->buflen;
    size_t nbuflen;
    rxdesc_t *desc;

    if (buflen >= rxpool->initbuflen)
        rxpool->initbuflen = (*rxpool->next_buflen)(buflen);

    nbuflen = rxpool->initbuflen;

    /* If we could not increase the buffer length, there is nothing
     * more we can do.
     */
    if (nbuflen == buflen)
        return nbuflen;

    hlog_fast(rxpool, "increasing buffer length %zu -> %zu bytes.",
        buflen, nbuflen);

    /* Cancel the rest so that we enlarge them in the following
     * rxpool_next() calls.
     */
    TAILQ_FOREACH(desc, &rxpool->alldesc, linkall) {
        if (desc == head)
            continue;
        if (!desc->ucx_owns)
            continue;
        if (desc->buflen >= nbuflen)
            continue;
        hlog_fast(rxpool, "%s: cancelling short desc %p",
            __func__, (void *)desc);
        ucp_request_cancel(rxpool->worker, desc);
    }

    return nbuflen;
}

static rxdesc_t *
rxpool_next_slow(rxpool_t *rxpool, rxdesc_t *head)
{
    size_t nbuflen;

    nbuflen = rxpool->initbuflen;

    /* Loop while a truncated or cancelled descriptor is at
     * the head of the FIFO.
     */
    do {
        size_t buflen = head->buflen;
        void * const buf = head->buf, *nbuf;

        hlog_fast(rxpool, "%s: rx desc %p %s, buflen %zu",
            __func__, (void *)head,
           (head->status == UCS_ERR_CANCELED) ? "cancelled" : "truncated",
           head->buflen);

        /* If we cannot allocate a new buffer, then we cannot resolve
         * the cancellation/truncation here, so toss the error up to the
         * caller.
         */
        if (head->status == UCS_ERR_MESSAGE_TRUNCATED && buflen >= nbuflen) {
            nbuflen = rxpool_buflen_step(rxpool, head);

            /* If we could not increase the buffer length, then let the caller
             * handle it.
             */
            if (nbuflen == buflen)
                break;
        }
        if ((nbuf = malloc(nbuflen)) == NULL)
            break;

        rxdesc_setup(rxpool, nbuf, nbuflen, head);
        free(buf);
    } while ((head = rxpool_pop(rxpool)) != NULL &&
             (head->status == UCS_ERR_MESSAGE_TRUNCATED ||
              head->status == UCS_ERR_CANCELED));

    return head;
}

/* Relinquish the caller's ownership of the receive descriptor `rdesc`.
 * Under the control of `rxpool`, the descriptor can receive a new message.
 *
 * `rdesc` must be a descriptor returned by a previous call to
 * `rxpool_next(rxpool)`.
 */
void
rxdesc_release(rxpool_t *rxpool, rxdesc_t *rdesc)
{
    const size_t nbuflen = rxpool->initbuflen;

    if (nbuflen > rdesc->buflen) {
        void *const buf = rdesc->buf, *nbuf;
        if ((nbuf = malloc(nbuflen)) != NULL) {
            rdesc->buf = nbuf;
            rdesc->buflen = nbuflen;
            free(buf);
        }
    }
    rxdesc_setup(rxpool, rdesc->buf, rdesc->buflen, rdesc);
}
