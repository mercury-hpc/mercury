#include <assert.h>
#include <err.h>
#include <stdlib.h> /* malloc */

#include <ucp/api/ucp.h>

#include "ring.h"
#include "util.h"

static void
rxdesc_callback(void *request, ucs_status_t status,
    const ucp_tag_recv_info_t *tag_info, void *user_data)
{
    rxdesc_t *desc = user_data;

    /* Do nothing if the request was cancelled. */
    if (desc->request == NULL)
        return;

    if ((desc->status = status) == UCS_OK) {
        desc->rxlen = tag_info->length;
        desc->sender_tag = tag_info->sender_tag;
    }
    desc->completed = true;

    assert(request == desc->request);
    desc->request = NULL;
    ucp_request_free(request);
}

void
rxring_init(ucp_worker_h worker, rxring_t *ring, ucp_tag_t tag,
    ucp_tag_t tag_mask, size_t buflen)
{
    int i;
    const size_t ndescs = NELTS(ring->desc);

    ring->worker = worker;
    ring->tag = tag;
    ring->tag_mask = tag_mask;

    /* Allocate a buffer for each receive descriptor and queue with
     * UCP.
     */
    for (i = 0; i < ndescs; i++) {
        void *buf;

        if ((buf = malloc(buflen)) == NULL)
            err(EXIT_FAILURE, "%s: malloc", __func__);

        rxdesc_setup(ring, buf, buflen, &ring->desc[i]);
    }
}

void
rxdesc_setup(rxring_t *ring, void *buf, size_t buflen, rxdesc_t *desc)
{
    const ucp_request_param_t recv_params = {
      .op_attr_mask = UCP_OP_ATTR_FIELD_CALLBACK |
                      UCP_OP_ATTR_FIELD_USER_DATA 
    , .cb = {.recv = rxdesc_callback}
    , .user_data = desc
    };
    ucp_worker_h worker = ring->worker;
    void *request;

    desc->buf = buf;
    desc->buflen = buflen;
    desc->completed = false;

    request = ucp_tag_recv_nbx(worker, buf, buflen, ring->tag,
        ring->tag_mask, &recv_params);
    if (UCS_PTR_IS_ERR(request)) {
        errx(EXIT_FAILURE, "%s: ucp_tag_recv_nbx: %s", __func__,
            ucs_status_string(UCS_PTR_STATUS(request)));
    }
    desc->request = request;
}

void
rxring_destroy(rxring_t *ring)
{
    ucp_worker_h worker = ring->worker;
    const size_t ndescs = NELTS(ring->desc);
    int i;

    /* Release UCP resources held by each descriptor.  Free buffers. */
    for (i = 0; i < ndescs; i++) {
        void *request;
        rxdesc_t *desc = &ring->desc[i];
        void *buf;

        if ((buf = desc->buf) != NULL) {
            desc->buf = NULL;
            free(buf);
        }

        if ((request = desc->request) == NULL)
            continue;
        desc->request = NULL;
        ucp_request_cancel(worker, request);
        ucp_request_free(request);
    }
}
