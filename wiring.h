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

struct _wire;
typedef struct _wire wire_t;

struct _wstorage;
typedef struct _wstorage wstorage_t;

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
    size_t msglen;
    wireup_msg_t *msg;  /* In initial state, the request to be
                         * (re)transmitted.  In all other states,
                         * NULL.
                         */
};

struct _wiring {
    wstorage_t *storage;
};

wiring_t *wiring_create(ucp_worker_h, size_t);
bool wireup_once(wiring_t *);
wstorage_t *wiring_enlarge(wstorage_t *);
void wiring_destroy(wiring_t *);
wire_t *wireup_start(wiring_t *, ucp_address_t *, size_t,
    ucp_address_t *, size_t);

#endif /* _WIRES_H_ */
