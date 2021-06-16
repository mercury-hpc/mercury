#ifndef WIREUP_RXPOOL_H
#define WIREUP_RXPOOL_H

#include <stdbool.h>

#include <sys/queue.h>

#include <ucp/api/ucp.h>

#include "mercury_atomic_queue.h"

typedef size_t (*rxpool_next_buflen_t)(size_t);

struct rxpool;
typedef struct rxpool rxpool_t;

/* An `rxpool` creates a receive descriptor to describe an empty buffer
 * for a single received message.  When a message is received, an `rxpool`
 * updates the corresponding descriptor with the received message's length
 * and tag or error status.
 *
 * `rxpool` API users are allowed to examine the fields `buf`, `rxlen`,
 * `sender_tag`, and `status`.  All other fields are private to the
 * pool.
 *
 * The `ucp_request_t`s used by a receive pool have a `rxdesc_t` "prefix".
 */
struct rxdesc;
typedef struct rxdesc rxdesc_t;

struct rxdesc {
    /* fields set at setup */
    void *buf;                      /* at `buf` there are `buflen` bytes
                                     * reserved for one received message
                                     */
    size_t buflen;
    /* fields set by callback */
    size_t rxlen;                   /* for a received message, the length of
                                     * the message at `buf`.  Valid only if
                                     * `status` is UCS_OK.
                                     */
    ucp_tag_t sender_tag;           /* for a received message, the tag applied
                                     * by the sender.  Valid only if
                                     * `status` is UCS_OK.
                                     */
    ucs_status_t status;            /* for a received message, the UCX status */
    /* fields shared by setup and callback */
    bool ucx_owns;                  /* `true` if a UCX posted receive is
                                     * outstanding for this descriptor,
                                     * `false` otherwise.
                                     */
    /* linkage for list of all descriptors in the pool */
    TAILQ_ENTRY(rxdesc) linkall;
};

typedef TAILQ_HEAD(_rxdesc_list, rxdesc) rxdesc_list_t;

struct rxpool {
    ucp_tag_t tag, tag_mask;
    ucp_worker_h worker;
    size_t request_size;
    size_t initbuflen;
    rxpool_next_buflen_t next_buflen;
    rxdesc_list_t alldesc;
    struct hg_atomic_queue *complete;
};

rxdesc_t *rxpool_next(rxpool_t *);
rxpool_t *rxpool_create(ucp_worker_h, rxpool_next_buflen_t, size_t, ucp_tag_t,
    ucp_tag_t, size_t);
rxpool_t *rxpool_init(rxpool_t *, ucp_worker_h, rxpool_next_buflen_t, size_t,
    ucp_tag_t, ucp_tag_t, size_t);
void rxpool_teardown(rxpool_t *);
void rxpool_destroy(rxpool_t *);
void rxdesc_release(rxpool_t *, rxdesc_t *);

#endif /* WIREUP_RXPOOL_H */
