/*
 * See wireup.md for a discussion of the "wireup" protocol
 * whose data structures and message format are defined here.
 */

#ifndef _WIRES_H_
#define _WIRES_H_

#include <assert.h>
#include <inttypes.h>   /* PRId32 */
#include <stdbool.h>
#include <stdint.h>     /* int32_t */
#include <unistd.h>     /* size_t, SIZE_MAX */

#include <sys/queue.h>

#include <ucp/api/ucp.h>

typedef int32_t sender_id_t;

#define SENDER_ID_MAX INT32_MAX

#define PRIdSENDER PRId32

#define SENDER_ID_NIL ((sender_id_t)-1)

struct _wire;
typedef struct _wire wire_t;

struct _wiring;
typedef struct _wiring wiring_t;

struct _wire_state;
typedef struct _wire_state wire_state_t;

struct _wire {
    sender_id_t next_free;
    sender_id_t prev_to_expire, next_to_expire;
    uint64_t expiration;
    ucp_ep_h ep;        // Endpoint connected to remote
    wire_state_t *state;
    sender_id_t id;     // Sender ID assigned by remote
};

struct _wiring {
    rxring_t *ring;
    sender_id_t first_free;
    sender_id_t first_to_expire, last_to_expire;
    size_t nwires;
    wire_t wire[];
};

static inline void
wiring_timeout_put(wiring_t *wiring, wire_t *w, uint64_t expiration)
{
    sender_id_t id = w - &wiring->wire[0];

    w->expiration = expiration;
    w->next_to_expire = SENDER_ID_NIL;
    w->prev_to_expire = wiring->last_to_expire;

    if (wiring->last_to_expire == SENDER_ID_NIL) {
        assert(wiring->first_to_expire == SENDER_ID_NIL);
        wiring->first_to_expire = id;
    } else {
        assert(wiring->wire[wiring->last_to_expire].expiration <= expiration);
        wiring->wire[wiring->last_to_expire].next_to_expire = id;
    }
    wiring->last_to_expire = id;
}

static inline wire_t *
wiring_timeout_peek(wiring_t *wiring)
{
    sender_id_t id;

    if ((id = wiring->first_to_expire) == SENDER_ID_NIL)
        return NULL;

    assert(0 <= id && id < wiring->nwires);

    return &wiring->wire[id];
}

static inline wire_t *
wiring_timeout_get(wiring_t *wiring)
{
    sender_id_t id;
    wire_t *w;

    if ((id = wiring->first_to_expire) == SENDER_ID_NIL)
        return NULL;

    w = &wiring->wire[id];
    wiring->first_to_expire = w->next_to_expire;

    assert(w->next_to_expire != id && w->prev_to_expire != id);

    assert((wiring->first_to_expire == SENDER_ID_NIL) ==
           (id == wiring->last_to_expire));

    if (wiring->first_to_expire == SENDER_ID_NIL)
        wiring->last_to_expire = SENDER_ID_NIL;
    else
        wiring->wire[wiring->first_to_expire].prev_to_expire = SENDER_ID_NIL;

    w->next_to_expire = w->prev_to_expire = id;
    return w;
}

static inline void
wiring_timeout_remove(wiring_t *wiring, wire_t *w)
{
    sender_id_t id = w - &wiring->wire[0];

    assert(0 <= id && id < wiring->nwires);

    assert((w->next_to_expire == id) == (w->prev_to_expire == id));

    if (w->next_to_expire == id)
        return;

    if (w->next_to_expire == SENDER_ID_NIL) {
        assert(wiring->last_to_expire == id);
        wiring->last_to_expire = w->prev_to_expire;
    } else {
        wiring->wire[w->next_to_expire].prev_to_expire = w->prev_to_expire;
    }

    if (w->prev_to_expire == SENDER_ID_NIL) {
        assert(wiring->first_to_expire == id);
        wiring->first_to_expire = w->next_to_expire;
    } else {
        wiring->wire[w->prev_to_expire].next_to_expire = w->next_to_expire;
    }

    w->next_to_expire = w->prev_to_expire = id;
}

static inline sender_id_t
wiring_free_get(wiring_t *wiring)
{
    sender_id_t id;

    if ((id = wiring->first_free) == SENDER_ID_NIL)
        return SENDER_ID_NIL;
    wiring->first_free = wiring->wire[id].next_free;
    wiring->wire[id].next_free = SENDER_ID_NIL;

    return id;
}

static inline void
wiring_free_put(wiring_t *wiring, sender_id_t id)
{
    assert(id != SENDER_ID_NIL);

    wiring->wire[id].next_free = wiring->first_free;
    wiring->first_free = id;
}

static inline bool
wire_is_connected(const wire_t *w)
{
    return w->id != SENDER_ID_NIL;
}

wiring_t *wiring_create(ucp_worker_h, size_t);
bool wireup_once(wiring_t **);
wiring_t *wiring_enlarge(wiring_t *);
void wiring_destroy(wiring_t *);
wire_t *wireup_start(wiring_t **, ucp_address_t *, size_t,
    ucp_address_t *, size_t);

#endif /* _WIRES_H_ */
