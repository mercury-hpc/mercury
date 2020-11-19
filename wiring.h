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

#include "wireup.h"

typedef int32_t sender_id_t;

#define SENDER_ID_MAX INT32_MAX

#define PRIdSENDER PRId32

#define SENDER_ID_NIL ((sender_id_t)-1)

struct _wiring;
typedef struct _wiring wiring_t;

struct _wstorage;
typedef struct _wstorage wstorage_t;

struct _wiring {
    wstorage_t *storage;
};

typedef struct _wire_id {
    sender_id_t id;
} wire_id_t;

wiring_t *wiring_create(ucp_worker_h, size_t);
bool wiring_init(wiring_t *, ucp_worker_h, size_t);
bool wireup_once(wiring_t *);
void wiring_destroy(wiring_t *, bool);
void wiring_teardown(wiring_t *, bool);
wire_id_t wireup_start(wiring_t *, ucp_address_t *, size_t,
    ucp_address_t *, size_t);
bool wireup_stop(wiring_t *, wire_id_t, bool);
void wireup_app_tag(wiring_t *, uint64_t *, uint64_t *);

static inline bool
wire_id_is_valid(wire_id_t wid)
{
    return wid.id != SENDER_ID_NIL;
}

#endif /* _WIRES_H_ */
