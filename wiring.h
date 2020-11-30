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

#include "wiring_compat.h"
#include "wireup.h"

typedef int32_t wiring_atomic sender_id_t;

#define SENDER_ID_MAX INT32_MAX

#define PRIdSENDER PRId32

#define sender_id_nil ((sender_id_t)-1)

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

struct _rxpool;
typedef struct _rxpool rxpool_t;

struct _wiring {
    rxpool_t *rxpool;
    wstorage_t *storage;
    wiring_lock_bundle_t lkb;
};

/* TBD A wire ID can embed a generation
 * number to guard against wire
 * reassignment.  OR, add a "reclaimed"
 * state after "dead" to the wire state machine?
 * "Dead" wires will not be reused.
 */
typedef struct _wire_id {
    sender_id_t id;
} wire_id_t;

#define wire_id_nil (wire_id_t){.id = sender_id_nil}

typedef enum {
  wire_ev_estd = 0
, wire_ev_died
} wire_event_t;

typedef struct _wire_event_info {
    wire_event_t event;
    ucp_ep_h ep;
    sender_id_t sender_id;
} wire_event_info_t;

typedef bool (*wire_event_cb_t)(wire_event_info_t, void *);

wiring_t *wiring_create(ucp_worker_h, size_t, const wiring_lock_bundle_t *);
bool wiring_init(wiring_t *, ucp_worker_h, size_t,
    const wiring_lock_bundle_t *);
bool wireup_once(wiring_t *);
void wiring_destroy(wiring_t *, bool);
void wiring_teardown(wiring_t *, bool);
wire_id_t wireup_start(wiring_t *, ucp_address_t *, size_t,
    ucp_address_t *, size_t, wire_event_cb_t, void *);
bool wireup_stop(wiring_t *, wire_id_t, bool);
void wireup_app_tag(wiring_t *, uint64_t *, uint64_t *);
const char *wire_event_string(wire_event_t);
sender_id_t wire_get_sender_id(wiring_t *, wire_id_t);

static inline bool
wire_is_valid(wire_id_t wid)
{
    return wid.id != sender_id_nil;
}

#endif /* _WIRES_H_ */
