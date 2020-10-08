#ifndef _RING_H_
#define _RING_H_

#include <stdbool.h>

#include <sys/queue.h>

typedef struct _txdesc {
    void *request;
    ucs_status_t status;
    bool completed;
} txdesc_t;

struct _rxring;
typedef struct _rxring rxring_t;

struct _rxdesc;
typedef struct _rxdesc rxdesc_t;

struct _rxdesc {
    /* fields set at setup */
    void *buf;
    size_t buflen;
    /* fields set by callback */
    size_t rxlen;
    ucp_tag_t sender_tag;
    ucs_status_t status;
    /* fields shared by setup and callback */
    rxdesc_t *fifonext;
    TAILQ_ENTRY(_rxdesc) linkall;
    bool ucx_owns;
};

typedef struct _rxdesc_fifo {
    pthread_mutex_t mtx;
    rxdesc_t *head, **tailp;
} rxdesc_fifo_t;

typedef TAILQ_HEAD(_rxdesc_list, _rxdesc) rxdesc_list_t;

struct _rxring {
    ucp_tag_t tag, tag_mask;
    ucp_worker_h worker;
    size_t request_size;
    rxdesc_list_t alldesc;
    rxdesc_fifo_t complete;
};

void rxdesc_init(void *);
rxdesc_t *rxring_next(rxring_t *);
void rxdesc_setup(rxring_t *, void *, size_t, rxdesc_t *);
void rxring_init(ucp_worker_h, rxring_t *, size_t, ucp_tag_t, ucp_tag_t,
   size_t, size_t);
void rxring_destroy(rxring_t *);

#endif /* _RING_H_ */
