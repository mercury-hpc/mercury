#include <assert.h>
#include <err.h>
#include <stdalign.h> /* alignof */
#include <stdlib.h> /* malloc */

#include <ucp/api/ucp.h>

#include "ring.h"
#include "util.h"

#include <pthread.h>

static void
rxdesc_fifo_init(rxdesc_fifo_t *fifo)
{
    (void)pthread_mutex_init(&fifo->mtx, NULL);
    fifo->head = NULL;
    fifo->tailp = &fifo->head;
}

static void
rxdesc_fifo_put(rxdesc_fifo_t *fifo, rxdesc_t *desc)
{
    (void)pthread_mutex_lock(&fifo->mtx);
    desc->fifonext = NULL;
    *fifo->tailp = desc;
    fifo->tailp = &desc->fifonext;
    (void)pthread_mutex_unlock(&fifo->mtx);
}

static rxdesc_t *
rxdesc_fifo_get_locked(rxdesc_fifo_t *fifo)
{
    rxdesc_t *desc;

    desc = fifo->head;
    if (desc == NULL) {
        assert(fifo->tailp == &fifo->head);
        return NULL;
    }

    if ((fifo->head = desc->fifonext) != NULL)
        return desc;

    assert(fifo->tailp == &desc->fifonext);
    fifo->tailp = &fifo->head;

    return desc;
}

static rxdesc_t *
rxdesc_fifo_get(rxdesc_fifo_t *fifo)
{
    rxdesc_t *desc;

    (void)pthread_mutex_lock(&fifo->mtx);
    desc = rxdesc_fifo_get_locked(fifo);
    (void)pthread_mutex_unlock(&fifo->mtx);
    return desc;
}

static void
rxdesc_callback(void *request, ucs_status_t status,
    const ucp_tag_recv_info_t *tag_info, void *user_data)
{
    rxdesc_t *desc = request;
    rxring_t *ring = user_data;

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

    rxdesc_fifo_put(&ring->complete, desc);
}

/* Allocate a buffer with a `size`-bytes, `alignment`-aligned payload
 * preceded by a `header_size` header, padding the allocation with up
 * to `alignment - 1` bytes to ensure that the payload is properly aligned.
 *
 * If `alignment` is 0, do not try to align the payload.  It's ok if
 * `size` is 0, however, `header_alloc` is undefined if both `header_size`
 * and `size` are 0.
 *
 * Return a pointer to the payload or set errno and return NULL
 * on error.  Possible `errno` values correspond with malloc(3).
 */
static void *
header_alloc(size_t header_size, size_t alignment, size_t size)
{
    const size_t pad = (alignment == 0 || header_size % alignment == 0)
                        ? 0
                        : alignment - header_size % alignment;

    return (char *)malloc(header_size + pad + size) + header_size + pad;
}

/* Free the buffer `buf` that was returned previously by a call
 * to `header_alloc(header_size, alignment, ...)`.
 */
static void
header_free(size_t header_size, size_t alignment, void *buf)
{
    const size_t pad = (alignment == 0 || header_size % alignment == 0)
                        ? 0
                        : alignment - header_size % alignment;

    free((char *)buf - header_size - pad);
}

void
rxring_init(ucp_worker_h worker, rxring_t *ring, size_t request_size,
    ucp_tag_t tag, ucp_tag_t tag_mask, size_t buflen, size_t nelts)
{
    size_t i;

    TAILQ_INIT(&ring->alldesc);
    rxdesc_fifo_init(&ring->complete);

    ring->worker = worker;
    ring->tag = tag;
    ring->tag_mask = tag_mask;
    ring->request_size = request_size;

    /* Allocate a buffer for each receive descriptor and queue with
     * UCP.
     */
    for (i = 0; i < nelts; i++) {
        rxdesc_t *rdesc;
        void *buf;

        if ((buf = malloc(buflen)) == NULL)
            err(EXIT_FAILURE, "%s: malloc", __func__);

        rdesc = header_alloc(request_size,
                              alignof(rxdesc_t), sizeof(rxdesc_t));

        if (rdesc == NULL)
            err(EXIT_FAILURE, "%s: header_alloc", __func__);

        TAILQ_INSERT_HEAD(&ring->alldesc, rdesc, linkall);

        rxdesc_setup(ring, buf, buflen, rdesc);
    }
}

void
rxdesc_setup(rxring_t *ring, void *buf, size_t buflen, rxdesc_t *desc)
{
    const ucp_request_param_t recv_params = {
      .op_attr_mask = UCP_OP_ATTR_FIELD_CALLBACK |
                      UCP_OP_ATTR_FIELD_REQUEST |
                      UCP_OP_ATTR_FIELD_USER_DATA 
    , .cb = {.recv = rxdesc_callback}
    , .request = desc
    , .user_data = ring
    };
    ucp_worker_h worker = ring->worker;
    void *request;

    desc->buf = buf;
    desc->buflen = buflen;
    desc->ucx_owns = true;

    printf("%s: initialized desc %p buf %p buflen %zu\n", __func__,
       (void *)desc, desc->buf, desc->buflen);
    request = ucp_tag_recv_nbx(worker, buf, buflen, ring->tag,
        ring->tag_mask, &recv_params);

    assert(request == desc);

    if (UCS_PTR_IS_ERR(request)) {
        errx(EXIT_FAILURE, "%s: ucp_tag_recv_nbx: %s", __func__,
            ucs_status_string(UCS_PTR_STATUS(request)));
    }
}

void
rxring_destroy(rxring_t *ring)
{
    rxdesc_t *desc;
    ucp_worker_h worker = ring->worker;

    /* Release UCP resources held by each descriptor.  Free buffers. */
    TAILQ_FOREACH(desc, &ring->alldesc, linkall) {
        printf("%s: cancelling desc %p\n", __func__, (void *)desc);
        ucp_request_cancel(worker, desc);
    }

    while ((desc = TAILQ_FIRST(&ring->alldesc)) != NULL) {
        void *buf;

        if (desc->ucx_owns) {
            while ((desc = rxring_next(ring)) == NULL)
                ucp_worker_progress(worker);
        }

        printf("%s: freeing desc %p\n", __func__, (void *)desc);

        if ((buf = desc->buf) != NULL) {
            desc->buf = NULL;
            free(buf);
        }

        TAILQ_REMOVE(&ring->alldesc, desc, linkall);

        header_free(ring->request_size, alignof(rxdesc_t), desc);
    }
}

void
rxdesc_init(void *request)
{
}

rxdesc_t *
rxring_next(rxring_t *ring)
{
    return rxdesc_fifo_get(&ring->complete);
}
