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
    timeout_link_t tlink[timo_nlinks];
    const wire_state_t *state;
    ucp_ep_h ep;        // Endpoint connected to remote
    wireup_msg_t *msg;  /* In initial state, the request to be
                         * (re)transmitted.  In all other states,
                         * NULL.
                         */
    size_t msglen;
    sender_id_t next_free;
    sender_id_t id;     // Sender ID assigned by remote
    wire_event_cb_t cb;
    void *cb_arg;
};

struct _wstorage {
    sender_id_t first_free;
    timeout_head_t thead[timo_nlinks];
    sender_id_t nwires;
    wire_t wire[];
};

static inline sender_id_t
wire_index(wstorage_t *storage, wire_t *w)
{
    return (sender_id_t)(w - &storage->wire[0]);
}

static inline void
wiring_timeout_put(wstorage_t *storage, wire_t *w, int which,
    uint64_t expiration)
{
    sender_id_t id = wire_index(storage, w);
    timeout_link_t *link = &w->tlink[which];
    timeout_head_t *head = &storage->thead[which];

    link->due = expiration;
    link->next = sender_id_nil;
    link->prev = head->last;

    if (head->last == sender_id_nil) {
        assert(head->first == sender_id_nil);
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

    if ((id = head->first) == sender_id_nil)
        return NULL;

    assert(id < storage->nwires);

    return &storage->wire[id];
}

static inline wire_t *
wiring_timeout_get(wstorage_t *storage, int which)
{
    sender_id_t id;
    wire_t *w;
    timeout_head_t *head = &storage->thead[which];
    timeout_link_t *link;

    if ((id = head->first) == sender_id_nil)
        return NULL;

    w = &storage->wire[id];
    link = &w->tlink[which];
    head->first = link->next;

    assert(link->next != id && link->prev != id);

    assert((head->first == sender_id_nil) == (id == head->last));

    if (head->first == sender_id_nil)
        head->last = sender_id_nil;
    else {
        timeout_link_t *lastlink =
            &storage->wire[head->first].tlink[which];
        lastlink->prev = sender_id_nil;
    }

    link->next = link->prev = id;
    return w;
}

static inline void
wiring_timeout_remove(wstorage_t *storage, wire_t *w, int which)
{
    sender_id_t id = wire_index(storage, w);
    timeout_head_t *head = &storage->thead[which];
    timeout_link_t *link = &w->tlink[which];

    assert(id < storage->nwires);

    assert((link->next == id) == (link->prev == id));

    if (link->next == id)
        return;

    if (link->next == sender_id_nil) {
        assert(head->last == id);
        head->last = link->prev;
    } else {
        storage->wire[link->next].tlink[which].prev = link->prev;
    }

    if (link->prev == sender_id_nil) {
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

    if ((id = storage->first_free) == sender_id_nil)
        return sender_id_nil;
    w = &storage->wire[id];
    for (which = 0; which < timo_nlinks; which++) {
        timeout_link_t * wiring_debug_used link = &w->tlink[which];
        assert(link->next == id && link->prev == id);
    }
    storage->first_free = w->next_free;
    w->next_free = sender_id_nil;

    return id;
}

static inline void
wiring_free_put(wstorage_t *storage, sender_id_t id)
{
    assert(id != sender_id_nil);

    storage->wire[id].next_free = storage->first_free;
    storage->first_free = id;
}

#endif /* _WIRING_IMPL_H_ */
