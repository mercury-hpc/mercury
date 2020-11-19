#ifndef _WIRING_IMPL_H_
#define _WIRING_IMPL_H_

#include "wiring.h"

struct _wire;
typedef struct _wire wire_t;

struct _wire_state;
typedef struct _wire_state wire_state_t;

typedef struct _timeout_link {
    sender_id_t prev, next;
    uint64_t due;
} timeout_link_t;

typedef struct _timeout_head {
    sender_id_t first, last;
} timeout_head_t;

enum {
  timo_expire = 0
, timo_wakeup
, timo_nlinks
};

struct _wire {
    sender_id_t next_free;
    timeout_link_t tlink[timo_nlinks];
    sender_id_t id;     // Sender ID assigned by remote
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
    timeout_head_t thead[timo_nlinks];
    size_t nwires;
    wire_t wire[];
};

static inline void
wiring_timeout_put(wstorage_t *storage, wire_t *w, int which,
    uint64_t expiration)
{
    sender_id_t id = w - &storage->wire[0];
    timeout_link_t *link = &w->tlink[which];
    timeout_head_t *head = &storage->thead[which];

    link->due = expiration;
    link->next = SENDER_ID_NIL;
    link->prev = head->last;

    if (head->last == SENDER_ID_NIL) {
        assert(head->first == SENDER_ID_NIL);
        head->first = id;
    } else {
        timeout_link_t *lastlink =
            &storage->wire[head->last].tlink[which];
        assert(lastlink->due <= expiration);
        lastlink->next = id;
    }
    head->last = id;
}

static inline wire_t *
wiring_timeout_peek(wstorage_t *storage, int which)
{
    sender_id_t id;
    timeout_head_t *head = &storage->thead[which];

    if ((id = head->first) == SENDER_ID_NIL)
        return NULL;

    assert(0 <= id && id < storage->nwires);

    return &storage->wire[id];
}

static inline wire_t *
wiring_timeout_get(wstorage_t *storage, int which)
{
    sender_id_t id;
    wire_t *w;
    timeout_head_t *head = &storage->thead[which];
    timeout_link_t *link;

    if ((id = head->first) == SENDER_ID_NIL)
        return NULL;

    w = &storage->wire[id];
    link = &w->tlink[which];
    head->first = link->next;

    assert(link->next != id && link->prev != id);

    assert((head->first == SENDER_ID_NIL) ==
           (id == head->last));

    if (head->first == SENDER_ID_NIL)
        head->last = SENDER_ID_NIL;
    else {
        timeout_link_t *lastlink =
            &storage->wire[head->first].tlink[which];
        lastlink->prev = SENDER_ID_NIL;
    }

    link->next = link->prev = id;
    return w;
}

static inline void
wiring_timeout_remove(wstorage_t *storage, wire_t *w, int which)
{
    sender_id_t id = w - &storage->wire[0];
    timeout_head_t *head = &storage->thead[which];
    timeout_link_t *link = &w->tlink[which];

    assert(0 <= id && id < storage->nwires);

    assert((link->next == id) == (link->prev == id));

    if (link->next == id)
        return;

    if (link->next == SENDER_ID_NIL) {
        assert(head->last == id);
        head->last = link->prev;
    } else {
        storage->wire[link->next].tlink[which].prev = link->prev;
    }

    if (link->prev == SENDER_ID_NIL) {
        assert(head->first == id);
        head->first = link->next;
    } else {
        storage->wire[link->prev].tlink[which].next = link->next;
    }

    link->due = 0;
    link->next = link->prev = id;
}

static inline void
wiring_expiration_put(wstorage_t *storage, wire_t *w, uint64_t expiration)
{
    wiring_timeout_put(storage, w, timo_expire, expiration);
}

static inline wire_t *
wiring_expiration_peek(wstorage_t *storage)
{
    return wiring_timeout_peek(storage, timo_expire);
}

static inline wire_t *
wiring_expiration_get(wstorage_t *storage)
{
    return wiring_timeout_get(storage, timo_expire);
}

static inline void
wiring_expiration_remove(wstorage_t *storage, wire_t *w)
{
    wiring_timeout_remove(storage, w, timo_expire);
}

static inline void
wiring_wakeup_put(wstorage_t *storage, wire_t *w, uint64_t wakeup)
{
    wiring_timeout_put(storage, w, timo_wakeup, wakeup);
}

static inline wire_t *
wiring_wakeup_peek(wstorage_t *storage)
{
    return wiring_timeout_peek(storage, timo_wakeup);
}

static inline wire_t *
wiring_wakeup_get(wstorage_t *storage)
{
    return wiring_timeout_get(storage, timo_wakeup);
}

static inline void
wiring_wakeup_remove(wstorage_t *storage, wire_t *w)
{
    wiring_timeout_remove(storage, w, timo_wakeup);
}

static inline sender_id_t
wiring_free_get(wstorage_t *storage)
{
    wire_t *w;
    sender_id_t id;
    int which;

    if ((id = storage->first_free) == SENDER_ID_NIL)
        return SENDER_ID_NIL;
    w = &storage->wire[id];
    for (which = 0; which < timo_nlinks; which++) {
        timeout_link_t *link = &w->tlink[which];
        assert(link->next == id && link->prev == id);
    }
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
