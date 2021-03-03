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
, wire_ev_died
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

extern void * const wire_data_nil;

static inline bool
wire_is_valid(wire_id_t wid)
{
    return wid.id != sender_id_nil;
}

#endif /* _WIRES_H_ */
