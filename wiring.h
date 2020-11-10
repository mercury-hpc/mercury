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

struct _wiring;
typedef struct _wiring wiring_t;

wiring_t *wiring_create(ucp_worker_h, size_t);
bool wireup_once(wiring_t *);
void wiring_destroy(wiring_t *, bool);
wire_t *wireup_start(wiring_t *, ucp_address_t *, size_t,
    ucp_address_t *, size_t);
void wireup_stop(wiring_t *, wire_t *, bool);

#endif /* _WIRES_H_ */
