#ifndef _WIRING_IMPL_H_
#define _WIRING_IMPL_H_

#include "wiring.h"

struct _wstorage {
    rxpool_t *rxpool;
    sender_id_t first_free;
    sender_id_t first_to_expire, last_to_expire;
    size_t nwires;
    wire_t wire[];
};

static inline void
wiring_timeout_put(wstorage_t *storage, wire_t *w, uint64_t expiration)
{
    sender_id_t id = w - &storage->wire[0];

    w->expiration = expiration;
    w->next_to_expire = SENDER_ID_NIL;
    w->prev_to_expire = storage->last_to_expire;

    if (storage->last_to_expire == SENDER_ID_NIL) {
        assert(storage->first_to_expire == SENDER_ID_NIL);
        storage->first_to_expire = id;
    } else {
        assert(storage->wire[storage->last_to_expire].expiration <= expiration);
        storage->wire[storage->last_to_expire].next_to_expire = id;
    }
    storage->last_to_expire = id;
}

static inline wire_t *
wiring_timeout_peek(wstorage_t *storage)
{
    sender_id_t id;

    if ((id = storage->first_to_expire) == SENDER_ID_NIL)
        return NULL;

    assert(0 <= id && id < storage->nwires);

    return &storage->wire[id];
}

static inline wire_t *
wiring_timeout_get(wstorage_t *storage)
{
    sender_id_t id;
    wire_t *w;

    if ((id = storage->first_to_expire) == SENDER_ID_NIL)
        return NULL;

    w = &storage->wire[id];
    storage->first_to_expire = w->next_to_expire;

    assert(w->next_to_expire != id && w->prev_to_expire != id);

    assert((storage->first_to_expire == SENDER_ID_NIL) ==
           (id == storage->last_to_expire));

    if (storage->first_to_expire == SENDER_ID_NIL)
        storage->last_to_expire = SENDER_ID_NIL;
    else
        storage->wire[storage->first_to_expire].prev_to_expire = SENDER_ID_NIL;

    w->next_to_expire = w->prev_to_expire = id;
    return w;
}

static inline void
wiring_timeout_remove(wstorage_t *storage, wire_t *w)
{
    sender_id_t id = w - &storage->wire[0];

    assert(0 <= id && id < storage->nwires);

    assert((w->next_to_expire == id) == (w->prev_to_expire == id));

    if (w->next_to_expire == id)
        return;

    if (w->next_to_expire == SENDER_ID_NIL) {
        assert(storage->last_to_expire == id);
        storage->last_to_expire = w->prev_to_expire;
    } else {
        storage->wire[w->next_to_expire].prev_to_expire = w->prev_to_expire;
    }

    if (w->prev_to_expire == SENDER_ID_NIL) {
        assert(storage->first_to_expire == id);
        storage->first_to_expire = w->next_to_expire;
    } else {
        storage->wire[w->prev_to_expire].next_to_expire = w->next_to_expire;
    }

    w->next_to_expire = w->prev_to_expire = id;
}

static inline sender_id_t
wiring_free_get(wstorage_t *storage)
{
    sender_id_t id;
    wire_t *w;

    if ((id = storage->first_free) == SENDER_ID_NIL)
        return SENDER_ID_NIL;
    w = &storage->wire[id];
    assert(w->next_to_expire == id && w->prev_to_expire == id);
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
