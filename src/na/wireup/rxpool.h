#ifndef WIREUP_RXPOOL_H
#define WIREUP_RXPOOL_H

#include <stdbool.h>

#include <sys/queue.h>

#include <ucp/api/ucp.h>

typedef size_t (*rxpool_next_buflen_t)(size_t);

struct rxpool;
typedef struct rxpool rxpool_t;

struct rxdesc;
typedef struct rxdesc rxdesc_t;

struct rxdesc {
    /* fields set at setup */
    void *buf;
    size_t buflen;
    /* fields set by callback */
    size_t rxlen;
    ucp_tag_t sender_tag;
    ucs_status_t status;
    /* fields shared by setup and callback */
    rxdesc_t *fifonext;
    TAILQ_ENTRY(rxdesc) linkall;
    bool ucx_owns;
};

typedef struct rxdesc_fifo {
    pthread_mutex_t mtx;
    rxdesc_t *head, **tailp;
} rxdesc_fifo_t;

typedef TAILQ_HEAD(_rxdesc_list, rxdesc) rxdesc_list_t;

struct rxpool {
    ucp_tag_t tag, tag_mask;
    ucp_worker_h worker;
    size_t request_size;
    size_t initbuflen;
    rxpool_next_buflen_t next_buflen;
    rxdesc_list_t alldesc;
    rxdesc_fifo_t complete;
};

rxdesc_t *rxpool_next(rxpool_t *);
void rxdesc_setup(rxpool_t *, void *, size_t, rxdesc_t *);
rxpool_t *rxpool_create(ucp_worker_h, rxpool_next_buflen_t, size_t, ucp_tag_t,
    ucp_tag_t, size_t);
void rxpool_init(rxpool_t *, ucp_worker_h, rxpool_next_buflen_t, size_t,
    ucp_tag_t, ucp_tag_t, size_t);
void rxpool_teardown(rxpool_t *);
void rxpool_destroy(rxpool_t *);
void rxdesc_release(rxpool_t *, rxdesc_t *);

#endif /* WIREUP_RXPOOL_H */
