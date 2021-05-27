/*
 * See wireup.md for a discussion of the "wireup" protocol
 * whose data structures and message format are defined here.
 */

#ifndef _WIRES_H_
#define _WIRES_H_

#include <assert.h>
#include <inttypes.h>   /* PRIu32 */
#include <stdbool.h>
#include <stdint.h>     /* int32_t */
#include <unistd.h>     /* size_t, SIZE_MAX */

#include <sys/queue.h>

#include <ucp/api/ucp.h>

#include "wiring_compat.h"
#include "wireup.h"

typedef uint32_t sender_id_t;

#define SENDER_ID_MAX UINT32_MAX

#define PRIuSENDER PRIu32

#define sender_id_nil SENDER_ID_MAX

struct _wiring;
typedef struct _wiring wiring_t;

struct _wstorage;
typedef struct _wstorage wstorage_t;

typedef struct _wiring_lock_bundle {
    void (*lock)(wiring_t *, void *);
    void (*unlock)(wiring_t *, void *);
    bool (*assert_locked)(wiring_t *, void *);
    void *arg;
} wiring_lock_bundle_t;

/* TBD A wire ID can embed a generation
 * number to guard against wire
 * reassignment.  OR, add a "reclaimed"
 * state after "dead" to the wire state machine?
 * "Dead" wires will not be reused.
 */
typedef struct _wire_id {
    sender_id_t wiring_atomic id;
} wire_id_t;

typedef enum {
  wire_ev_estd = 0
, wire_ev_closed
, wire_ev_reclaimed
} wire_event_t;

typedef struct _wire_event_info {
    wire_event_t event;
    ucp_ep_h ep;
    sender_id_t sender_id;
} wire_event_info_t;

typedef struct _wire_accept_info {
    const ucp_address_t *addr;
    size_t addrlen;
    wire_id_t wire_id;
    sender_id_t sender_id;
    ucp_ep_h ep;
} wire_accept_info_t;

/* Indication of a wire established or a wire that died. */
typedef bool (*wire_event_cb_t)(wire_event_info_t, void *);

/* Indication of a new wire accepted from a remote peer. */
typedef void *(*wire_accept_cb_t)(wire_accept_info_t, void *,
    wire_event_cb_t *, void **);

struct wiring_request;
typedef struct wiring_request wiring_request_t;

typedef struct wiring_request {
    wiring_request_t *next;
} wiring_request_t;

struct wiring_ref;
typedef struct wiring_ref wiring_ref_t;

struct wiring_ref {
    volatile bool wiring_atomic busy;
    volatile uint64_t wiring_atomic epoch;
    wiring_ref_t *next;
    void (*reclaim)(wiring_ref_t *);
};

typedef struct wiring_garbage_bin {
    sender_id_t first_closed;
    void **assoc;
    wstorage_t *storage;
    wiring_ref_t * volatile wiring_atomic first_ref;
} wiring_garbage_bin_t;

typedef struct wiring_garbage_schedule {
    /* a writer both initiates new epochs and reclaims resources connected
     * with prior epochs.  first <= last, always.  If first < last, then
     * there are resources to reclaim in the circular buffer `last - first`
     * circular-buffer bins starting at bin[first % NELTS(bin)].
     */
    struct {
        volatile uint64_t wiring_atomic first, last;
    } epoch;
    struct {
        volatile uint64_t wiring_atomic prev, next;
    } work_available;
    /* The wire_t storage and the associated-data table cannot
     * be reallocated more than 64 times during a program's
     * lifetime, because the size of each doubles with each reallocation
     * and we do not expect for 2^64 bytes to be available for
     * either.  So 64 bins should be enough to hold all of the
     * garbage related to those reallocations.  64 additional bins
     * are for chains of closed wires whose reclamation is deferred.
     */
    wiring_garbage_bin_t bin[128];
} wiring_garbage_schedule_t;

struct _wiring {
    wiring_lock_bundle_t lkb;
    wire_accept_cb_t accept_cb;
    void *accept_cb_arg;
    rxpool_t *rxpool;
    wstorage_t *storage;
    void **assoc;   /* assoc[i] is a pointer to wire i's optional
                     * "associated data"
                     */
    ucp_worker_h worker;
    size_t request_size;
    /* wiring_request_t queues are protected by the wiring_t lock, lkb. */
    wiring_request_t *req_outst_head;    // ucp_request_t's outstanding
    wiring_request_t **req_outst_tailp;  // ucp_request_ts outstanding
    wiring_request_t *req_free_head;     // ucp_request_t free list
    wiring_garbage_schedule_t garbage_sched;
};

#define wire_id_nil (wire_id_t){.id = sender_id_nil}

wiring_t *wiring_create(ucp_worker_h, size_t, const wiring_lock_bundle_t *,
    wire_accept_cb_t, void *);
bool wiring_init(wiring_t *, ucp_worker_h, size_t,
    const wiring_lock_bundle_t *, wire_accept_cb_t, void *);
int wireup_once(wiring_t *);
void wiring_destroy(wiring_t *, bool);
void wiring_teardown(wiring_t *, bool);
wire_id_t wireup_start(wiring_t *, ucp_address_t *, size_t,
    ucp_address_t *, size_t, wire_event_cb_t, void *, void *);
bool wireup_stop(wiring_t *, wire_id_t, bool);
void wireup_app_tag(wiring_t *, uint64_t *, uint64_t *);
const char *wire_event_string(wire_event_t);
sender_id_t wire_get_sender_id(wiring_t *, wire_id_t);
void *wire_get_data(wiring_t *, wire_id_t);

void wiring_lock(wiring_t *);
void wiring_unlock(wiring_t *);
void wiring_assert_locked_impl(wiring_t *, const char *, int);

void wiring_ref_init(wiring_t *, wiring_ref_t *,
    void (*reclaim)(wiring_ref_t *));

#define wiring_assert_locked(wiring)                            \
do {                                                            \
    wiring_t *wal_wiring = (wiring);                            \
    if (wal_wiring->lkb.assert_locked == NULL)                  \
        break;                                                  \
    wiring_assert_locked_impl(wal_wiring, __FILE__, __LINE__);  \
} while (0)

extern void * const wire_data_nil;

static inline bool
wire_is_valid(wire_id_t wid)
{
    return wid.id != sender_id_nil;
}

/* Callers are responsible for serializing wiring_ref_get() and
 * wiring_ref_put() calls affecting the same `ref`.
 */
static inline void
wiring_ref_get(wiring_t *wiring, wiring_ref_t *ref)
{
    wiring_garbage_schedule_t *sched = &wiring->garbage_sched;
    const uint64_t last = atomic_load_explicit(&sched->epoch.last,
        memory_order_acquire);

    assert(!atomic_load_explicit(&ref->busy, memory_order_relaxed));

    atomic_store_explicit(&ref->busy, true, memory_order_release);

    const uint64_t epoch = atomic_load_explicit(&ref->epoch,
        memory_order_relaxed);

    if (epoch == last)
        return;

    atomic_store_explicit(&ref->epoch, last, memory_order_release);

    atomic_fetch_add_explicit(&sched->work_available, 1,
                              memory_order_relaxed);
}

static inline void
wiring_ref_put(wiring_t wiring_unused *wiring, wiring_ref_t *ref)
{
    wiring_garbage_schedule_t *sched = &wiring->garbage_sched;
    const uint64_t last = atomic_load_explicit(&sched->epoch.last,
        memory_order_acquire);

    assert(atomic_load_explicit(&ref->busy, memory_order_relaxed));

    atomic_store_explicit(&ref->busy, false, memory_order_release);

    const uint64_t epoch = atomic_load_explicit(&ref->epoch,
        memory_order_relaxed);

    if (epoch == last)
        return;

    atomic_store_explicit(&ref->epoch, last, memory_order_release);

    atomic_fetch_add_explicit(&sched->work_available, 1,
                              memory_order_relaxed);
}

static inline void
wiring_ref_free(wiring_t *wiring, wiring_ref_t *ref)
{
    wiring_garbage_schedule_t *sched = &wiring->garbage_sched;

    assert(!atomic_load_explicit(&ref->busy, memory_order_relaxed));

    ref->epoch = UINT64_MAX;

    atomic_fetch_add_explicit(&sched->work_available, 1,
                              memory_order_relaxed);
}

#endif /* _WIRES_H_ */
