#ifndef _RING_H_
#define _RING_H_

#include <stdbool.h>

typedef struct _txdesc {
    void *request;
    ucs_status_t status;
    bool completed;
} txdesc_t;

typedef struct _rxdesc {
    /* fields set at setup */
    void *request;
    void *buf;
    size_t buflen;
    /* fields set by callback */
    size_t rxlen;
    ucp_tag_t sender_tag;
    ucs_status_t status;
    /* fields shared by setup and callback */
    bool completed;
} rxdesc_t;

typedef struct _rxring {
    ucp_tag_t tag, tag_mask;
    ucp_worker_h worker;
    rxdesc_t desc[3];
    int rxnext;
} rxring_t;

void rxdesc_setup(rxring_t *, void *, size_t, rxdesc_t *);
void rxring_init(ucp_worker_h, rxring_t *, ucp_tag_t, ucp_tag_t, size_t);
void rxring_destroy(rxring_t *);

#endif /* _RING_H_ */
