#ifndef _WIRING_IMPL_H_
#define _WIRING_IMPL_H_

#include "wiring.h"

struct _wstorage;
typedef struct _wstorage wstorage_t;

struct _wire_state;
typedef struct _wire_state wire_state_t;

typedef struct _timeout_link {
    sender_id_t prev, next;
} timeout_link_t;

typedef struct _timeout_head {
    sender_id_t first, last;
} timeout_head_t;

struct _wire {
    sender_id_t next_free;
    timeout_link_t expire;
    sender_id_t id;     // Sender ID assigned by remote
    uint64_t expiration;
    ucp_ep_h ep;        // Endpoint connected to remote
    const wire_state_t *state;
    size_t msglen;
    wireup_msg_t *msg;  /* In initial state, the request to be
                         * (re)transmitted.  In all other states,
                         * NULL.
                         */
};

struct _wiring {
    wstorage_t *storage;
};

struct _wstorage {
    rxpool_t *rxpool;
    sender_id_t first_free;
    timeout_head_t expire;
    size_t nwires;
    wire_t wire[];
};

static inline void
wiring_timeout_put(wstorage_t *storage, wire_t *w, uint64_t expiration)
{
    sender_id_t id = w - &storage->wire[0];

    w->expiration = expiration;
    w->expire.next = SENDER_ID_NIL;
    w->expire.prev = storage->expire.last;

    if (storage->expire.last == SENDER_ID_NIL) {
        assert(storage->expire.first == SENDER_ID_NIL);
        storage->expire.first = id;
    } else {
        assert(storage->wire[storage->expire.last].expiration <= expiration);
        storage->wire[storage->expire.last].expire.next = id;
    }
    storage->expire.last = id;
}

static inline wire_t *
wiring_timeout_peek(wstorage_t *storage)
{
    sender_id_t id;

    if ((id = storage->expire.first) == SENDER_ID_NIL)
        return NULL;

    assert(0 <= id && id < storage->nwires);

    return &storage->wire[id];
}

static inline wire_t *
wiring_timeout_get(wstorage_t *storage)
{
    sender_id_t id;
    wire_t *w;

    if ((id = storage->expire.first) == SENDER_ID_NIL)
        return NULL;

    w = &storage->wire[id];
    storage->expire.first = w->expire.next;

    assert(w->expire.next != id && w->expire.prev != id);

    assert((storage->expire.first == SENDER_ID_NIL) ==
           (id == storage->expire.last));

    if (storage->expire.first == SENDER_ID_NIL)
        storage->expire.last = SENDER_ID_NIL;
    else
        storage->wire[storage->expire.first].expire.prev = SENDER_ID_NIL;

    w->expire.next = w->expire.prev = id;
    return w;
}

static inline void
wiring_timeout_remove(wstorage_t *storage, wire_t *w)
{
    sender_id_t id = w - &storage->wire[0];

    assert(0 <= id && id < storage->nwires);

    assert((w->expire.next == id) == (w->expire.prev == id));

    if (w->expire.next == id)
        return;

    if (w->expire.next == SENDER_ID_NIL) {
        assert(storage->expire.last == id);
        storage->expire.last = w->expire.prev;
    } else {
        storage->wire[w->expire.next].expire.prev = w->expire.prev;
    }

    if (w->expire.prev == SENDER_ID_NIL) {
        assert(storage->expire.first == id);
        storage->expire.first = w->expire.next;
    } else {
        storage->wire[w->expire.prev].expire.next = w->expire.next;
    }

    w->expire.next = w->expire.prev = id;
}

static inline sender_id_t
wiring_free_get(wstorage_t *storage)
{
    sender_id_t id;
    wire_t *w;

    if ((id = storage->first_free) == SENDER_ID_NIL)
        return SENDER_ID_NIL;
    w = &storage->wire[id];
    assert(w->expire.next == id && w->expire.prev == id);
    storage->first_free = w->next_free;
    w->next_free = SENDER_ID_NIL;

    return id;
}

static inline void
wiring_free_put(wstorage_t *storage, sender_id_t id)
{
    assert(id != SENDER_ID_NIL);

    storage->wire[id].next_free = storage->first_free;
    storage->first_free = id;
}

static inline bool
wire_is_connected(const wire_t *w)
{
    return w->id != SENDER_ID_NIL;
}

#endif /* _WIRING_IMPL_H_ */
