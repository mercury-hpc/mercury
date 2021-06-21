/*
 * Copyright (C) 2020 The HDF Group.  All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#include <stdalign.h>
#include <string.h> /* memcmp */

#include "na_plugin.h"

#include "na_ip.h"

#include "mercury_hash_table.h"
#include "mercury_time.h"

#include <ucp/api/ucp.h>

#include "../hlog/src/hlog.h"

#include "wireup/rxpool.h"
#include "wireup/util.h"
#include "wireup/wiring.h"
#include "wireup/bits.h"

/*
 * Local Macros
 */
#define NA_UCX_MSG_SIZE_MAX 4096    /* arbitrary choice; cannot be too high,
                                     * Mercury preallocates many buffers of
                                     * this size
                                     */

HLOG_OUTLET_SHORT_DEFN(ctx, all);
HLOG_OUTLET_SHORT_DEFN(nacl, all);
HLOG_OUTLET_SHORT_DEFN(addr_noisy, all);
HLOG_OUTLET_SHORT_DEFN(addr, addr_noisy);
HLOG_OUTLET_SHORT_DEFN(memh, all);
HLOG_OUTLET_SHORT_DEFN(op_life_noisy, all);
HLOG_OUTLET_SHORT_DEFN(op_life, op_life_noisy);
HLOG_OUTLET_SHORT_DEFN(progress, all);
HLOG_OUTLET_SHORT_DEFN(rdma, all);
HLOG_OUTLET_SHORT_DEFN(rdma_err, rdma);
HLOG_OUTLET_SHORT_DEFN(rx, all);
HLOG_OUTLET_SHORT_DEFN(tx, all);
HLOG_OUTLET_SHORT_DEFN(ucx_rxbuf, all);
HLOG_OUTLET_SHORT_DEFN(ucx_txbuf, all);
HLOG_OUTLET_SHORT_DEFN(wire_life, all);

/*
 * Local Type and Struct Definition
 */

struct _na_ucx_context;
typedef struct _na_ucx_context na_ucx_context_t;

typedef struct na_addr na_ucx_addr_t;

typedef struct _address_wire {
    /* `sender_id`, if not nil, is for use only
     * with context `ctx`.
     *
     * Reads are synchronized by `mutcnt`.
     *
     * Writes are synchronized both by
     * the wiring lock and by `mutcnt`.
     */
    na_ucx_context_t * wiring_atomic ctx;
    /* If `wire_is_valid(wire_id)`, identity of
     * `owner`'s session in the wireup protocol.
     * if `!wire_is_valid(wire_id)`, wireup has not
     * begun.
     *
     * Writes are synchronized by the wiring lock.
     */
    wire_id_t wire_id;
    /* If `sender_id` is equal to `sender_id_nil`,
     * then wireup either has not begun, or has not
     * completed.
     *
     * Otherwise, wireup has completed, and
     * `sender_id` is the "return address"
     * to embed in messages to the `owner` addressee.
     *
     * Reads and writes are synchronized by
     * `mutcnt`.
     */
    sender_id_t wiring_atomic sender_id;
    /* After wireup has completed
     * (`sender_id != sender_id_nil`), `ep` is
     * connected to the `owner` addressee.
     *
     * Reads and writes are synchronized by
     * `mutcnt`.
     */
    ucp_ep_h wiring_atomic ep;
    /* Pointer to the address that owns this
     * wire cache; constant for the cache's lifetime.
     */
    na_ucx_addr_t *owner;
    /* Mutation count: starts at 0.  The wireup
     * event callback is the only writer, and
     * callbacks are serialized by the wireup
     * procedure.
     *
     * The callback increases `mutcnt` by one
     * before it modifies `sender_id` and `ep`.
     * When it has finished its modifications,
     * it increases `mutcnt` by one more.  Thus
     * `mutcnt` is odd while `sender_id` and `ep`
     * are unstable, and even while they are
     * stable.
     *
     * A reader, such as na_ucx_msg_send_unexpected,
     * should start by polling `mutcnt` until it is
     * even, then read `sender_id` and `ep`, then
     * re-read `mutcnt`.  If `mutcnt` has changed
     * between the first read and the second, then
     * the reader should restart at polling
     * `mutcnt`.  When a reader completes the
     * read sequence with `mutcnt` unchanged from
     * beginning to end, it has a consistent pair
     * of `sender_id` and `ep`.
     */
    hg_atomic_int32_t mutcnt;
    // TBD circular list linkage
    HG_QUEUE_HEAD(na_op_id) deferrals;
} address_wire_t;

typedef struct _address_wire_aseq {
    address_wire_t *cache;
    hg_util_int32_t enter_mutcnt;
} address_wire_aseq_t;

struct na_addr {
    address_wire_t wire_cache;
    hg_atomic_int32_t refcount;
    size_t addrlen;         /* Native address len */
    uint8_t addr[];         /* Native address */
};

typedef enum {
  na_ucx_mem_local
, na_ucx_mem_packed_remote
, na_ucx_mem_unpacked_remote
} na_mem_handle_kind_t;

typedef struct {
    uint64_t remote_base_addr;
    ucp_rkey_h rkey;
} unpacked_rkey_t;

typedef struct _na_mem_handle_header {
    uint64_t base_addr;
    uint32_t paylen;
} na_mem_handle_header_t;

typedef struct {
    char *buf;
    size_t buflen;
} packed_rkey_t;

struct na_mem_handle {
    hg_atomic_int32_t kind;   // one of na_mem_handle_kind_t
    hg_thread_mutex_t unpack_lock;
    union {
        struct {
            ucp_mem_h mh;
            char *buf;
        } local;
        unpacked_rkey_t unpacked_remote;
        packed_rkey_t packed_remote;
    } handle;
};

typedef enum _op_status {
  op_s_complete = 0
, op_s_underway
, op_s_canceled
, op_s_deferred
} op_status_t;

typedef struct _op_rxinfo {
    void *buf;
} op_rxinfo_t;

typedef struct _op_txinfo {
    const void *buf;
    uint64_t tag;
    na_size_t buf_size;
    HG_QUEUE_ENTRY(na_op_id) link;
} op_txinfo_t;

struct na_ucx_class;
typedef struct na_ucx_class na_ucx_class_t;

struct na_op_id {
    struct na_cb_completion_data completion_data;
    struct {
        na_context_t *na;
        na_ucx_context_t *nu;
    } ctx;
    hg_atomic_int32_t status;
    union {
        op_rxinfo_t rx;
        op_txinfo_t tx;
    } info;
    wiring_ref_t ref;
    na_ucx_class_t *nucl;
};

struct _na_ucx_context {
    wiring_t wiring;
    ucp_worker_h worker;
    na_class_t *nacl;
    na_ucx_addr_t *self;
    /* (app.tag, app.tagmask) describes the tag space reserved for
     * the application.  The wireup tag space is excluded.
     *
     * XXX make this per-class?
     * That's NA's expectation.
     *
     * (exp.tag, msg.tagmask) describes the tag space reserved for
     * expected messages, and (unexp.tag, msg.tagmask) describes the
     * tag space reserved for unexpected messages.  Those spaces are
     * independent of each other.  Both are subspaces of app.
     */
    struct {
        uint64_t tag, tagmask;
    } app;
    struct {
        uint64_t tag;
    } exp, unexp;
    struct {
        uint64_t tagmask;
        unsigned tagshift;
        uint64_t tagmax;
    } msg;
    na_uint8_t id;
};

struct na_ucx_class {
    wiring_lock_bundle_t lkb;
    hg_thread_mutex_t wiring_api_lock;
    ucp_context_h uctx;
    size_t request_size;        /* Size in bytes of the UCX transaction
                                 * identifier ("request").
                                 */
    hg_thread_mutex_t addr_lock;/* Synchronizes access to `addr_tbl`. */
    hg_hash_table_t *addr_tbl;  /* All addresses, deduplicated. */
    na_ucx_context_t context;   /* The solitary context. */
    hg_atomic_int32_t ncontexts;/* Always 1, for now. */
};

typedef struct _na_ucx_header {
    sender_id_t sender_id;
} na_ucx_header_t;

/*
 * Plugin callbacks
 */

static na_return_t na_ucx_addr_dup(na_class_t *, na_addr_t, na_addr_t *);
static na_addr_t na_ucx_addr_dedup(na_class_t *, na_addr_t);
static na_bool_t na_ucx_check_protocol(const char *);
static na_return_t na_ucx_initialize(na_class_t *, const struct na_info *,
    na_bool_t);
static na_return_t na_ucx_finalize(na_class_t *);
static na_return_t na_ucx_context_create(na_class_t *, void **, na_uint8_t);
static na_return_t na_ucx_context_destroy(na_class_t *, void *);
static na_return_t na_ucx_addr_to_string(na_class_t *, char *, na_size_t *,
    na_addr_t);
static na_return_t na_ucx_addr_lookup(na_class_t *, const char *, na_addr_t *);
static na_bool_t na_ucx_addr_cmp(na_class_t *, na_addr_t, na_addr_t);
static NA_INLINE na_return_t na_ucx_addr_dup(na_class_t *, na_addr_t,
    na_addr_t *);
static NA_INLINE na_return_t na_ucx_addr_free(na_class_t *, na_addr_t);
static NA_INLINE na_return_t na_ucx_addr_set_remove(na_class_t *, na_addr_t);
static NA_INLINE na_return_t na_ucx_addr_self(na_class_t *, na_addr_t *);
static NA_INLINE na_bool_t na_ucx_addr_is_self(na_class_t *, na_addr_t);
static NA_INLINE na_size_t na_ucx_addr_get_serialize_size(na_class_t *,
    na_addr_t);
static na_return_t na_ucx_addr_serialize(na_class_t *, void *, na_size_t,
    na_addr_t);
static na_return_t na_ucx_addr_deserialize(na_class_t *, na_addr_t *,
    const void *, na_size_t);
static na_op_id_t *na_ucx_op_create(na_class_t *);
static na_return_t na_ucx_op_destroy(na_class_t *, na_op_id_t *);
static na_return_t na_ucx_msg_send_unexpected(na_class_t *, na_context_t *,
    na_cb_t, void *, const void *, na_size_t, void *, na_addr_t, na_uint8_t,
    na_tag_t, na_op_id_t *);
static na_return_t na_ucx_msg_recv_unexpected(na_class_t *, na_context_t *,
    na_cb_t, void *, void *, na_size_t, void *, na_op_id_t *);
static na_return_t na_ucx_msg_send_expected(na_class_t *, na_context_t *,
    na_cb_t, void *, const void *, na_size_t,
    void *, na_addr_t, na_uint8_t, na_tag_t, na_op_id_t *);
static na_return_t na_ucx_msg_recv_expected(na_class_t *, na_context_t *,
    na_cb_t, void *, void *, na_size_t,
    void *, na_addr_t, na_uint8_t, na_tag_t, na_op_id_t *);
static na_return_t na_ucx_mem_handle_create(na_class_t NA_UNUSED *, void *,
    na_size_t, unsigned long, na_mem_handle_t *);
static na_return_t na_ucx_mem_handle_free( na_class_t *, na_mem_handle_t);
static NA_INLINE na_size_t na_ucx_mem_handle_get_max_segments(
    const na_class_t *);
static na_return_t na_ucx_mem_register(na_class_t *, na_mem_handle_t);
static na_return_t na_ucx_mem_deregister(na_class_t *, na_mem_handle_t);
static NA_INLINE na_size_t na_ucx_mem_handle_get_serialize_size(
    na_class_t *, na_mem_handle_t);
static na_return_t na_ucx_mem_handle_serialize(na_class_t *, void *,
    na_size_t, na_mem_handle_t);
static na_return_t na_ucx_mem_handle_deserialize(na_class_t *,
    na_mem_handle_t *, const void *, na_size_t);
static na_return_t na_ucx_put(na_class_t *, na_context_t *, na_cb_t, void *,
    na_mem_handle_t, na_offset_t, na_mem_handle_t, na_offset_t,
    na_size_t, na_addr_t, na_uint8_t, na_op_id_t *);
static na_return_t na_ucx_get(na_class_t *, na_context_t *, na_cb_t, void *,
    na_mem_handle_t, na_offset_t, na_mem_handle_t, na_offset_t,
    na_size_t, na_addr_t, na_uint8_t, na_op_id_t *);
#if 0
static NA_INLINE int na_ucx_poll_get_fd(na_class_t *, na_context_t *);
static NA_INLINE na_bool_t na_ucx_poll_try_wait(na_class_t *, na_context_t *);
#endif
static na_return_t na_ucx_progress(na_class_t *, na_context_t *, unsigned int);
static na_return_t na_ucx_cancel(na_class_t *, na_context_t *, na_op_id_t *);

static NA_INLINE na_size_t na_ucx_msg_get_header_size(const na_class_t *);
static NA_INLINE na_size_t na_ucx_msg_get_max_size(const na_class_t *);
static NA_INLINE na_tag_t na_ucx_msg_get_max_tag(const na_class_t *);

static bool wire_event_callback(wire_event_info_t, void *);

/*
 * Local Variables
 */

const struct na_class_ops NA_PLUGIN_OPS(ucx) = {
    "ucx",                                 /* name */
    na_ucx_check_protocol,                 /* check_protocol */
    na_ucx_initialize,                     /* initialize */
    na_ucx_finalize,                       /* finalize */
    NULL,                                  /* cleanup */
    na_ucx_context_create,                 /* context_create */
    na_ucx_context_destroy,                /* context_destroy */
    na_ucx_op_create,                      /* op_create */
    na_ucx_op_destroy,                     /* op_destroy */
    na_ucx_addr_lookup,                    /* addr_lookup */
    na_ucx_addr_free,                      /* addr_free */
    na_ucx_addr_set_remove,                /* addr_set_remove */
    na_ucx_addr_self,                      /* addr_self */
    na_ucx_addr_dup,                       /* addr_dup */
    na_ucx_addr_cmp,                       /* addr_cmp */
    na_ucx_addr_is_self,                   /* addr_is_self */
    na_ucx_addr_to_string,                 /* addr_to_string */
    na_ucx_addr_get_serialize_size,        /* addr_get_serialize_size */
    na_ucx_addr_serialize,                 /* addr_serialize */
    na_ucx_addr_deserialize,               /* addr_deserialize */
    na_ucx_msg_get_max_size,               /* msg_get_max_unexpected_size */
    na_ucx_msg_get_max_size,               /* msg_get_max_expected_size */
    na_ucx_msg_get_header_size,            /* msg_get_unexpected_header_size */
    na_ucx_msg_get_header_size,            /* msg_get_expected_header_size */
    na_ucx_msg_get_max_tag,                /* msg_get_max_tag */
    NULL,                                  /* msg_buf_alloc */
    NULL,                                  /* msg_buf_free */
    NULL,                                  /* msg_init_unexpected */
    na_ucx_msg_send_unexpected,            /* msg_send_unexpected */
    na_ucx_msg_recv_unexpected,            /* msg_recv_unexpected */
    NULL,                                  /* msg_init_expected */
    na_ucx_msg_send_expected,              /* msg_send_expected */
    na_ucx_msg_recv_expected,              /* msg_recv_expected */
    na_ucx_mem_handle_create,              /* mem_handle_create */
    NULL,                                  /* mem_handle_create_segment */
    na_ucx_mem_handle_free,                /* mem_handle_free */
    na_ucx_mem_handle_get_max_segments,    /* mem_handle_get_max_segments */
    na_ucx_mem_register,                   /* mem_register */
    na_ucx_mem_deregister,                 /* mem_deregister */
    na_ucx_mem_handle_get_serialize_size,  /* mem_handle_get_serialize_size */
    na_ucx_mem_handle_serialize,           /* mem_handle_serialize */
    na_ucx_mem_handle_deserialize,         /* mem_handle_deserialize */
    na_ucx_put,                            /* put */
    na_ucx_get,                            /* get */
#if 0
    na_ucx_poll_get_fd,                    /* poll_get_fd */
    na_ucx_poll_try_wait,                  /* poll_try_wait */
#else
    NULL,                                  /* poll_get_fd */
    NULL,                                  /* poll_try_wait */
#endif
    na_ucx_progress,                       /* progress */
    na_ucx_cancel                          /* cancel */
};

#ifndef NA_UCX_HAS_THREAD_MODE_NAMES
#    define NA_UCX_THREAD_MODES                                                \
        X(UCS_THREAD_MODE_SINGLE, "single")                                    \
        X(UCS_THREAD_MODE_SERIALIZED, "serialized")                            \
        X(UCS_THREAD_MODE_MULTI, "multi")
#    define X(a, b) b,
static const char *ucs_thread_mode_names[UCS_THREAD_MODE_LAST] = {
    NA_UCX_THREAD_MODES};
#    undef X
#endif

/*
 * Local Helper Functions
 */

static const char *
op_status_string(op_status_t status)
{
    switch (status) {
    case op_s_canceled:
        return "canceled";
    case op_s_complete:
        return "complete";
    case op_s_deferred:
        return "deferred";
    case op_s_underway:
        return "underway";
    default:
        return "<unknown>";
    }
}

static void *
memdup(const void *buf, size_t buflen)
{
    void *nbuf;

    if ((nbuf = malloc(buflen)) == NULL)
        return NULL;

    return memcpy(nbuf, buf, buflen);
}

static NA_DEBUG_LOG_USED const char *
na_cb_type_string(na_cb_type_t ty)
{
    switch (ty) {
    case NA_CB_SEND_UNEXPECTED:
        return "send-unexpected";
    case NA_CB_RECV_UNEXPECTED:
        return "recv-unexpected";
    case NA_CB_SEND_EXPECTED:
        return "send-expected";
    case NA_CB_RECV_EXPECTED:
        return "recv-expected";
    case NA_CB_PUT:
        return "put";
    case NA_CB_GET:
        return "get";
    default:
        return "unknown";
    }
}

static inline const char *
get_octet(const void *_buf, na_size_t buf_size, unsigned int idx)
{
#define NBUFS 128
    static const char none[] = "--";
    static char s[NBUFS][3];
    static int next = 0;
    const char *result = s[next];
    const char *buf = _buf;

    if (idx >= buf_size)
        return none;
    (void)snprintf(s[next], sizeof(s[0]), "%02" PRIx8, buf[idx]);

    next = (next + 1) % NBUFS;
    return result;
}

static void *
zalloc(size_t size)
{
    return calloc(1, size);
}

static NA_INLINE void
op_id_release(void *arg)
{
    na_op_id_t *op_id = arg;

    if (hg_atomic_get32(&op_id->status) != op_s_complete)
        NA_LOG_ERROR("releasing an incomplete op");
}

static inline const na_ucx_class_t *
na_ucx_class_const(const na_class_t *nacl)
{
    return nacl->plugin_class;
}

static inline na_ucx_class_t *
na_ucx_class(na_class_t *nacl)
{
    return nacl->plugin_class;
}

/* Return `x` rotated by 4 bits plus `x`.  Think of the result of
 * `stir(x)` as `17 * x`, only without shifting the most significant
 * bits into oblivion.
 */
static inline uint64_t
stir(uint64_t x)
{
    return x + (x >> 60) + (x << 60);
}

static void
address_wire_init(address_wire_t *cache, na_ucx_addr_t *addr,
    na_ucx_context_t *ctx)
{
    cache->wire_id = wire_id_nil;
    cache->sender_id = sender_id_nil;
    cache->owner = addr;
    cache->ctx = ctx;
    cache->mutcnt = 0;
    HG_QUEUE_INIT(&cache->deferrals);
}

static inline address_wire_aseq_t
address_wire_write_begin(address_wire_t *cache)
{
    const address_wire_aseq_t aseq =
        {.cache = cache, .enter_mutcnt = hg_atomic_incr32(&cache->mutcnt)};
    /* Only this routine modifies the cache, and calls are synchronized by
     * the `na_context_t`'s wiring, so we should never see an odd generation
     * number, indicating a modification in progress.
     */
    assert(aseq.enter_mutcnt % 2 == 1);
    return aseq;
}

static inline void
address_wire_write_end(address_wire_aseq_t aseq)
{
    const hg_util_int32_t NA_DEBUG_USED exit_mutcnt =
        hg_atomic_incr32(&aseq.cache->mutcnt);
    assert(exit_mutcnt == aseq.enter_mutcnt + 1);
}

static unsigned int
na_ucx_addr_hash(hg_hash_table_key_t key)
{
    na_ucx_addr_t *addr = key;
    const uint64_t shiftout = (uint64_t)UINT_MAX + 1;
    uint64_t mix;
    unsigned int code;
    size_t i;

    /* Mix in all bytes of the address. */
    for (mix = 0, i = 0; i < addr->addrlen; i++, mix = stir(mix))
        mix ^= addr->addr[i];

    /* Shift all bits out of `mix`, XOR into the hash code. */
    for (code = 0; mix != 0; mix /= shiftout)
        code ^= (unsigned int)(mix % shiftout);

    return code;
}

static int
na_ucx_addr_equal(hg_hash_table_key_t key1, hg_hash_table_key_t key2)
{
    na_ucx_addr_t *addr1 = key1, *addr2 = key2;

    if (addr1->addrlen != addr2->addrlen)
        return 0;

    return memcmp(addr1->addr, addr2->addr, addr1->addrlen) == 0;
}

#if 0
static void
na_ucx_wiring_lock(wiring_t NA_UNUSED *wiring, void *arg)
{
    hg_thread_mutex_t *mtx = arg;
    const int NA_DEBUG_USED rc = hg_thread_mutex_lock(mtx);

    assert(rc == HG_UTIL_SUCCESS);
}

static void
na_ucx_wiring_unlock(wiring_t NA_UNUSED *wiring, void *arg)
{
    hg_thread_mutex_t *mtx = arg;
    const int NA_DEBUG_USED rc = hg_thread_mutex_unlock(mtx);

    assert(rc == HG_UTIL_SUCCESS);
}

static bool
na_ucx_wiring_assert_locked(wiring_t NA_UNUSED *wiring, void *arg)
{
    hg_thread_mutex_t *mtx = arg;
    const int rc = hg_thread_mutex_try_lock(mtx);

    if (rc == HG_UTIL_SUCCESS) {
        (void)hg_thread_mutex_unlock(mtx);
        return false;
    }
    return true;
}
#endif

static void *
wire_accept_callback(wire_accept_info_t info, void *arg,
    wire_event_cb_t *cbp, void **argp)
{
    na_ucx_context_t *nuctx = arg;
    na_ucx_addr_t *taddr, *addr;

    hlog_fast(wire_life, "%s: enter arg %p addrlen %zu",
        __func__, arg, info.addrlen);

    if ((taddr = malloc(sizeof(*taddr) + info.addrlen)) == NULL) {
        NA_LOG_ERROR("could not allocate address storage");
        return NULL;
    }

    *taddr = (na_ucx_addr_t){
        .wire_cache = {
            .wire_id = info.wire_id
          , .sender_id = info.sender_id
          , .ctx = nuctx
          , .ep = info.ep
          , .owner = taddr
          , .mutcnt = 0
          , .deferrals = HG_QUEUE_HEAD_INITIALIZER(taddr->wire_cache.deferrals)
        }
      , .refcount = 1   // the wire has a reference
      , .addrlen = info.addrlen
    };
    memcpy(&taddr->addr[0], info.addr, info.addrlen);

    addr = na_ucx_addr_dedup(nuctx->nacl, taddr);

    /* If we found a duplicate, then update its wire ID, sender ID, and
     * endpoint.
     */
    if (addr != taddr) {
        address_wire_aseq_t aseq;
        address_wire_t *cache = &addr->wire_cache;

        wiring_assert_locked(&nuctx->wiring);
        aseq = address_wire_write_begin(cache);

        /* TBD assert prior values are nil? */
        atomic_store_explicit(&cache->wire_id.id, info.wire_id.id,
            memory_order_relaxed);
        atomic_store_explicit(&cache->sender_id, info.sender_id,
            memory_order_relaxed);
        atomic_store_explicit(&cache->ep, info.ep,
            memory_order_relaxed);

        address_wire_write_end(aseq);
    } else {
        *cbp = wire_event_callback;
        *argp = &addr->wire_cache;
    }

    hlog_fast(wire_life, "%s: exit arg %p addr %p",
        __func__, arg, (void *)addr);

    return addr;
}

static void
na_ucx_context_teardown(na_ucx_context_t *nctx, na_class_t *nacl)
{
    na_ucx_addr_t *self;

    if ((self = nctx->self) == NULL)
        return;

    nctx->self = NULL;
    (void)na_ucx_addr_free(nacl, self);

    wiring_lock(&nctx->wiring);
    wiring_teardown(&nctx->wiring, false);
    wiring_unlock(&nctx->wiring);

    assert(nctx->worker != NULL);
    ucp_worker_destroy(nctx->worker);
    nctx->worker = NULL;

    return;
}

static unsigned
mask_to_shift(uint64_t mask)
{
    uint64_t lowest = LOWEST_SET_BIT(mask);
    unsigned i;

    for (i = 0; i < 64; i++) {
        if ((lowest & BIT(i)) != 0)
            break;
    }
    return i;
}

static na_return_t
na_ucx_context_init(
    na_ucx_context_t *nctx, na_ucx_class_t *nucl, ucs_thread_mode_t thread_mode)
{
    ucp_worker_params_t worker_params = {
      .field_mask = UCP_WORKER_PARAM_FIELD_THREAD_MODE
    , .thread_mode = thread_mode
    };
    ucp_worker_attr_t worker_actuals = {
      .field_mask = UCP_WORKER_ATTR_FIELD_THREAD_MODE
    };
    ucp_address_t *uaddr;
    na_ucx_addr_t *self;
    uint64_t expflag;
    size_t uaddrlen;
    ucs_status_t status;
    int ret;

    status = ucp_worker_create(nucl->uctx, &worker_params, &nctx->worker);

    if (status != UCS_OK)
        return NA_PROTOCOL_ERROR;   // arbitrary choice

    /* Print worker info */
    NA_LOG_SUBSYS_DEBUG_FUNC(ctx, ucp_worker_print_info(nctx->worker,
        hg_log_get_stream_debug()), "Worker info");

    status = ucp_worker_query(nctx->worker, &worker_actuals);

    if (status != UCS_OK) {
        NA_LOG_ERROR("ucp_worker_query: %s", ucs_status_string(status));
        goto cleanup_worker;
    }

    if ((worker_actuals.field_mask & UCP_WORKER_ATTR_FIELD_THREAD_MODE) == 0) {
        NA_LOG_ERROR("worker attributes contain no thread mode");
        goto cleanup_worker;
    }

    if (thread_mode != UCS_THREAD_MODE_SINGLE
        && worker_actuals.thread_mode < thread_mode) {
        NA_LOG_ERROR("UCP worker thread mode (%s) is not supported",
            ucs_thread_mode_names[worker_actuals.thread_mode]);
        goto cleanup_worker;
    }

    status = ucp_worker_get_address(nctx->worker, &uaddr, &uaddrlen);
    if (status != UCS_OK) {
        NA_LOG_ERROR("ucp_worker_get_address: %s", ucs_status_string(status));
        goto cleanup_worker;
    }

    if ((self = malloc(sizeof(*self) + uaddrlen)) == NULL)
        goto cleanup_addr;

    address_wire_init(&self->wire_cache, self, nctx);

    self->refcount = 1;
    self->addrlen = uaddrlen;

    memcpy(&self->addr[0], uaddr, uaddrlen);

    nctx->self = self;

    (void)hg_thread_mutex_lock(&nucl->addr_lock);

    ret = hg_hash_table_insert(nucl->addr_tbl, self, self);

    (void)hg_thread_mutex_unlock(&nucl->addr_lock);

    if (!ret)
        goto cleanup_self;

    if (!wiring_init(&nctx->wiring, nctx->worker, nucl->request_size,
            &nucl->lkb, wire_accept_callback, nctx))
        goto cleanup_tbl;

    wireup_app_tag(&nctx->wiring, &nctx->app.tag, &nctx->app.tagmask);

    /* Find the highest bit in the application tag space.  We will set it to
     * indicate an expected message and clear it to indicate an unexpected
     * message.
     */
    expflag = ~nctx->app.tagmask ^ (~nctx->app.tagmask >> 1);
    nctx->msg.tagmask = nctx->app.tagmask | expflag;
    nctx->msg.tagmax = SHIFTOUT_MASK(~nctx->msg.tagmask);
    nctx->msg.tagshift = mask_to_shift(~nctx->msg.tagmask);
    nctx->exp.tag = nctx->app.tag | expflag;
    nctx->unexp.tag = nctx->app.tag;

    ucp_worker_release_address(nctx->worker, uaddr);
    return NA_SUCCESS;
cleanup_tbl:
    (void)hg_thread_mutex_lock(&nucl->addr_lock);
    hg_hash_table_remove(nucl->addr_tbl, self);
    (void)hg_thread_mutex_unlock(&nucl->addr_lock);
cleanup_self:
    free(self);
cleanup_addr:
    ucp_worker_release_address(nctx->worker, uaddr);
cleanup_worker:
    ucp_worker_destroy(nctx->worker);
    return NA_PROTOCOL_ERROR;   // XXX arbitrary choice of error status
}

/* Look for a duplicate of `addr` in our table.  If one is found, then
 * free `addr` and return the duplicate.  Otherwise, return `addr`.
 */
static na_addr_t
na_ucx_addr_dedup(na_class_t *nacl, na_addr_t addr)
{
    na_ucx_class_t *nucl = na_ucx_class(nacl);
    na_ucx_addr_t *dupaddr;

    (void)hg_thread_mutex_lock(&nucl->addr_lock);
    dupaddr = hg_hash_table_lookup(nucl->addr_tbl, addr);
    if (dupaddr != HG_HASH_TABLE_NULL) {
        free(addr);
        (void)na_ucx_addr_dup(nacl, dupaddr, &addr);
    } else {
        hg_hash_table_insert(nucl->addr_tbl, addr, addr);
    }
    (void)hg_thread_mutex_unlock(&nucl->addr_lock);
    return addr;
}

/*
 * NA Class Operations
 */

static na_bool_t
na_ucx_check_protocol(const char *protocol_name)
{
    ucp_config_t *config = NULL;
    ucp_params_t params = {
      .field_mask = UCP_PARAM_FIELD_FEATURES
    , .features = UCP_FEATURE_TAG | UCP_FEATURE_RMA
    };
    ucp_context_h context = NULL;
    ucs_status_t status;
    na_bool_t accept = NA_FALSE;

    status = ucp_config_read(NULL, NULL, &config);
    NA_CHECK_SUBSYS_ERROR_NORET(cls, status != UCS_OK, done,
        "ucp_config_read() failed (%s)", ucs_status_string(status));

    /* Print UCX config */
    NA_LOG_SUBSYS_DEBUG_FUNC(cls, ucp_config_print(config,
            hg_log_get_stream_debug(), "NA UCX class configuration",
            UCS_CONFIG_PRINT_CONFIG | UCS_CONFIG_PRINT_HEADER
            | UCS_CONFIG_PRINT_DOC | UCS_CONFIG_PRINT_HIDDEN)
        , "UCX global configuration");

    status = ucp_config_modify(config, "TLS", protocol_name);
    NA_CHECK_SUBSYS_ERROR_NORET(cls, status != UCS_OK, done,
        "ucp_config_modify() failed (%s)", ucs_status_string(status));

    status = ucp_init(&params, config, &context);
    if (status == UCS_OK) {
        accept = NA_TRUE;
        ucp_cleanup(context);
    }

done:
    if (config)
        ucp_config_release(config);

    return accept;
}

static na_return_t
na_ucx_initialize(na_class_t *nacl, const struct na_info *na_info,
    na_bool_t NA_UNUSED listen)
{
#ifdef NA_UCX_HAS_LIB_QUERY
    ucp_lib_attr_t ucp_lib_attrs;
#endif
    ucp_params_t global_params = {
      .field_mask = UCP_PARAM_FIELD_FEATURES | UCP_PARAM_FIELD_REQUEST_SIZE
    , .features = UCP_FEATURE_TAG | UCP_FEATURE_RMA
    , .request_size = sizeof(rxdesc_t)
    };
    ucp_context_attr_t uctx_attrs = {
        .field_mask = UCP_ATTR_FIELD_REQUEST_SIZE | UCP_ATTR_FIELD_THREAD_MODE
    };
    na_ucx_class_t *nucl;
    ucp_config_t *config;
    ucs_thread_mode_t context_thread_mode = UCS_THREAD_MODE_SINGLE,
        worker_thread_mode = UCS_THREAD_MODE_MULTI;
    na_return_t ret;
    ucs_status_t status;
    int rc;

    if (na_info->na_init_info != NULL) {
        /* Thread mode */
        if ((na_info->na_init_info->max_contexts > 1)
            && !(na_info->na_init_info->thread_mode & NA_THREAD_MODE_SINGLE)) {
            /* If the UCP context can potentially be used by more than one
             * worker / thread, then this context needs thread safety. */
            global_params.field_mask |= UCP_PARAM_FIELD_MT_WORKERS_SHARED;
            global_params.mt_workers_shared = 1;
            context_thread_mode = UCS_THREAD_MODE_MULTI;
        }
        if (na_info->na_init_info->thread_mode & NA_THREAD_MODE_SINGLE_CTX)
            worker_thread_mode = UCS_THREAD_MODE_SINGLE;
    }

#ifdef NA_UCX_HAS_LIB_QUERY
    ucp_lib_attrs.field_mask = UCP_LIB_ATTR_FIELD_MAX_THREAD_LEVEL;
    status = ucp_lib_query(&ucp_lib_attrs);
    NA_CHECK_SUBSYS_ERROR(cls, status != UCS_OK, cleanup, ret,
        NA_PROTOCOL_ERROR, "ucp_context_query: %s", ucs_status_string(status));
    NA_CHECK_SUBSYS_ERROR(cls,
        (ucp_lib_attrs.field_mask & UCP_LIB_ATTR_FIELD_MAX_THREAD_LEVEL) == 0,
        cleanup, ret, NA_PROTOCOL_ERROR,
        "lib attributes contain no max thread level");

    /* Best effort to ensure thread safety
     * (no error to allow for UCS_THREAD_MODE_SERIAL) */
    if (worker_thread_mode != UCS_THREAD_MODE_SINGLE
        && ucp_lib_attrs.max_thread_level < worker_thread_mode) {
        worker_thread_mode = ucp_lib_attrs.max_thread_level;
        NA_LOG_WARNING("Max worker thread level is: %s",
            ucs_thread_mode_names[worker_thread_mode]);
    }
#endif

    hlog_fast(nacl, "%s: enter nacl %p", __func__, (void *)nacl);

    nucl = malloc(sizeof(*nucl));
    NA_CHECK_SUBSYS_ERROR(cls, nucl == NULL, cleanup, ret, NA_NOMEM,
        "Could not allocate NA private data class");

    *nucl = (na_ucx_class_t){.uctx = NULL, .addr_tbl = NULL};

    nacl->plugin_class = nucl;

    rc = hg_thread_mutex_init(&nucl->addr_lock);
    NA_CHECK_SUBSYS_ERROR(cls, rc != HG_UTIL_SUCCESS, cleanup ,ret, NA_NOMEM,
        "Could not initialize address lock");

    nucl->addr_tbl = hg_hash_table_new(na_ucx_addr_hash, na_ucx_addr_equal);
    NA_CHECK_SUBSYS_ERROR(cls, nucl->addr_tbl == NULL, cleanup ,ret, NA_NOMEM,
        "Could not allocate address table");

    /* Read UCP configuration */
    status = ucp_config_read(NULL, NULL, &config);
    NA_CHECK_SUBSYS_ERROR(cls, status != UCS_OK, cleanup, ret, NA_PROTOCOL_ERROR,
        "ucp_config_read() failed (%s)", ucs_status_string(status));

    /* Set user-requested transport */
    status = ucp_config_modify(config, "TLS", na_info->protocol_name);
    NA_CHECK_SUBSYS_ERROR(cls, status != UCS_OK, cleanup, ret, NA_PROTOCOL_ERROR,
        "ucp_config_modify() failed (%s)", ucs_status_string(status));

    /* Use mutex instead of spinlock */
    status = ucp_config_modify(config, "USE_MT_MUTEX", "y");
    NA_CHECK_SUBSYS_ERROR(cls, status != UCS_OK, cleanup, ret, NA_PROTOCOL_ERROR,
        "ucp_config_modify() failed (%s)", ucs_status_string(status));

    /* TODO Currently assume that systems are homogeneous */
    status = ucp_config_modify(config, "UNIFIED_MODE", "y");
    NA_CHECK_SUBSYS_ERROR(cls, status != UCS_OK, cleanup, ret, NA_PROTOCOL_ERROR,
        "ucp_config_modify() failed (%s)", ucs_status_string(status));

    /* Add address debug info if running in debug */
    status = ucp_config_modify(config, "ADDRESS_DEBUG_INFO", "y");
    NA_CHECK_SUBSYS_ERROR(cls, status != UCS_OK, cleanup, ret, NA_PROTOCOL_ERROR,
        "ucp_config_modify() failed (%s)", ucs_status_string(status));

    /* Set hostname (use default interface name if no hostname was passed) */
    if (na_info->host_name) {
        char *host_name = NULL, *ifa_name = NULL;
        unsigned int port;

        host_name = strdup(na_info->host_name);
        NA_CHECK_SUBSYS_ERROR(cls, host_name == NULL, cleanup, ret, NA_NOMEM,
            "strdup() of host_name failed");

        /* Extract hostname */
        if (strstr(host_name, ":")) {
            char *port_str = NULL;
            strtok_r(host_name, ":", &port_str);
            port = (unsigned int) strtoul(port_str, NULL, 10);
        }

        /* Try to get matching IP/device */
        ret = na_ip_check_interface(host_name, port, &ifa_name, NULL);
        free(host_name);
        NA_CHECK_SUBSYS_NA_ERROR(
            cls, cleanup, ret, "Could not check interfaces");

        if (ifa_name) {
            status = ucp_config_modify(config, "NET_DEVICES", ifa_name);
            free(ifa_name);
            NA_CHECK_SUBSYS_ERROR(cls, status != UCS_OK, cleanup, ret,
                NA_PROTOCOL_ERROR, "ucp_config_modify() failed (%s)",
                ucs_status_string(status));
        } else
            NA_LOG_SUBSYS_WARNING(cls,
                "Could not find NET_DEVICE to use, using default");
    }

    /* Print UCX config */
    NA_LOG_SUBSYS_DEBUG_FUNC(cls, ucp_config_print(config,
            hg_log_get_stream_debug(), "NA UCX class configuration used",
            UCS_CONFIG_PRINT_CONFIG | UCS_CONFIG_PRINT_HEADER)
        , "Now using the following UCX global configuration");

    // TBD create a rxpool_ucp_init() that augments global_params with
    // the necessary request_size?
    status = ucp_init(&global_params, config, &nucl->uctx);
    ucp_config_release(config);
    NA_CHECK_SUBSYS_ERROR(cls, status != UCS_OK, cleanup, ret, NA_PROTOCOL_ERROR,
        "ucp_init() failed (%s)", ucs_status_string(status));

    /* Print context info */
    NA_LOG_SUBSYS_DEBUG_FUNC(cls, ucp_context_print_info(nucl->uctx,
        hg_log_get_stream_debug()), "Context info");

    /* Query context to ensure we got what we asked for */
    status = ucp_context_query(nucl->uctx, &uctx_attrs);
    NA_CHECK_SUBSYS_ERROR(cls, status != UCS_OK, cleanup, ret, NA_PROTOCOL_ERROR,
        "ucp_context_query() failed (%s)", ucs_status_string(status));

    /* Check that expected fields are present */
    NA_CHECK_SUBSYS_ERROR(cls,
        (uctx_attrs.field_mask & UCP_ATTR_FIELD_REQUEST_SIZE) == 0, cleanup,
        ret, NA_PROTOCOL_ERROR,
        "context attributes contain no request size");
    NA_CHECK_SUBSYS_ERROR(cls,
        (uctx_attrs.field_mask & UCP_ATTR_FIELD_THREAD_MODE) == 0, cleanup,
        ret, NA_PROTOCOL_ERROR,
        "context attributes contain no thread mode");

    nucl->wiring_api_lock = (hg_thread_mutex_t)HG_THREAD_MUTEX_INITIALIZER;

    nucl->lkb = (wiring_lock_bundle_t){
      .arg = &nucl->wiring_api_lock
    , .lock = NULL
    , .unlock = NULL
    , .assert_locked = NULL
    };

    nucl->request_size = uctx_attrs.request_size;

    /* Do not continue if thread mode is less than expected */
    NA_CHECK_SUBSYS_ERROR(cls, context_thread_mode != UCS_THREAD_MODE_SINGLE
        && uctx_attrs.thread_mode < context_thread_mode, cleanup, ret,
        NA_PROTOCOL_ERROR, "Context thread mode is: %s",
        ucs_thread_mode_names[uctx_attrs.thread_mode]);

    /* Create single worker */
    ret = na_ucx_context_init(&nucl->context, nucl, worker_thread_mode);
    NA_CHECK_SUBSYS_NA_ERROR(
        cls, cleanup, ret, "Could not initialize UCX worker");

    assert(nucl == na_ucx_class(nacl));

    return NA_SUCCESS;

cleanup:
    na_ucx_finalize(nacl);

    return ret;
}

static na_return_t
na_ucx_finalize(na_class_t *nacl)
{
    na_ucx_class_t *nucl = na_ucx_class(nacl);

    hlog_fast(nacl, "%s: enter nacl %p", __func__, (void *)nacl);

    if (nucl == NULL)
        return NA_SUCCESS;

    if (hg_atomic_get32(&nucl->ncontexts) != 0)
        return NA_BUSY;

    na_ucx_context_teardown(&nucl->context, nacl);

    nacl->plugin_class = NULL;
    if (nucl->uctx != NULL) {
        ucp_cleanup(nucl->uctx);
        nucl->uctx = NULL;
    }
    if (nucl->addr_tbl != NULL) {
        hg_hash_table_free(nucl->addr_tbl);
        nucl->addr_tbl = NULL;
    }

    (void)hg_thread_mutex_destroy(&nucl->addr_lock);

    free(nucl);
    return NA_SUCCESS;
}

static na_return_t
na_ucx_context_create(na_class_t *nacl, void **context, na_uint8_t id)
{
    na_ucx_class_t *nucl = na_ucx_class(nacl);
    na_ucx_context_t *ctx = &nucl->context;

    if (!hg_atomic_cas32(&nucl->ncontexts, 0, 1)) {
        hlog_fast(ctx, "%s: no context available", __func__);
        return NA_NOMEM;
    }

    ctx->id = id;
    ctx->nacl = nacl;

    *context = ctx;

    hlog_fast(ctx, "%s: exit context %p", __func__, *context);

    return NA_SUCCESS;
}

static na_return_t
na_ucx_context_destroy(na_class_t *nacl, void *context)
{
    na_ucx_class_t *nucl = na_ucx_class(nacl);

    hlog_fast(ctx, "%s: enter context %p", __func__, (void *)context);

    if (context != &nucl->context || !hg_atomic_cas32(&nucl->ncontexts, 1, 0))
        return NA_NOENTRY;

    return NA_SUCCESS;
}

static na_return_t
na_ucx_addr_to_string(na_class_t NA_UNUSED *nacl,
    char *buf, na_size_t *buflenp, na_addr_t _addr)
{
    na_ucx_addr_t *addr = _addr;
    const char *delim = "";
    char *s = buf;
    size_t i, nempty = *buflenp;

    hlog_fast(addr, "%s: enter buf %p *buflenp %" PRIu64 " addrlen %zu",
        __func__, buf, *buflenp, addr->addrlen);

    if (buf == NULL) {
        *buflenp = MAX(3 * addr->addrlen, 1);
        return NA_SUCCESS;
    }

    for (i = 0; i < addr->addrlen; i++) {
        const int rc = snprintf(s, nempty, "%s%02" PRIx8, delim, addr->addr[i]);

        if (rc < 0)
            return NA_PROTOCOL_ERROR;

        if ((size_t)rc >= nempty) {
            NA_LOG_ERROR("exit w/ error buf %p", buf);
            *buflenp = 3 * addr->addrlen;
            return NA_OVERFLOW;
        }

        nempty -= (size_t)rc;
        s += rc;

        delim = ":";
    }

    hlog_fast(addr, "%s: exit buf %p '%s'", __func__, buf, buf);
    return NA_SUCCESS;
}

static na_return_t
na_ucx_addr_lookup(na_class_t *nacl, const char * const name, na_addr_t *addrp)
{
    na_ucx_addr_t *addr;
    size_t buflen = 0, noctets;
    int i = 0, nread, rc;
    uint8_t *buf;

    hlog_fast(addr, "enter lookup (len %zu) %s", strlen(name), name);

    noctets = (strlen(name) + 1) / 3;

    if (noctets < 1)
        return 0;

    if ((addr = malloc(sizeof(*addr) + noctets)) == NULL)
        return NA_NOMEM;

    address_wire_init(&addr->wire_cache, addr, NULL);

    addr->refcount = 1;
    addr->addrlen = 0;

    buf = &addr->addr[0];

    rc = sscanf(&name[i], "%02" SCNx8 "%n", &buf[buflen], &nread);
    if (rc == EOF) {
        goto out;
    } else if (rc != 1) {
        NA_LOG_ERROR("parse error at '%s'", &name[i]);
        free(addr);
        return NA_INVALID_ARG;
    }

    for (buflen = 1, i = nread;
         (rc = sscanf(&name[i], ":%02" SCNx8 "%n", &buf[buflen], &nread)) == 1;
         i += nread) {
        buflen++;
    }

    if (rc != EOF || name[i] != '\0') {
        NA_LOG_ERROR("residual characters '%s'", &name[i]);
        free(addr);
        return NA_INVALID_ARG;
    }

    assert(buflen == noctets);

out:
    addr->addrlen = buflen;
    *addrp = na_ucx_addr_dedup(nacl, addr);

    hlog_fast(addr, "exit lookup %s, %p, refs %" PRId32, name,
        (void *)*addrp, (*addrp)->refcount);

    return NA_SUCCESS;
}

static na_bool_t
na_ucx_addr_cmp(na_class_t NA_UNUSED *nacl, na_addr_t addr1, na_addr_t addr2)
{
    return addr1 == addr2;
}

static hg_util_int32_t
addr_decref(na_ucx_addr_t *addr, const char *reason)
{
    const hg_util_int32_t count = hg_atomic_decr32(&addr->refcount);

    hlog_fast(addr_noisy, "%s: addr %p new refs %" PRId32 " for %s", __func__,
        (void *)addr, count, reason);

    return count;
}

static hg_util_int32_t
addr_incref(na_ucx_addr_t *addr, const char *reason)
{
    const hg_util_int32_t count = hg_atomic_incr32(&addr->refcount);

    hlog_fast(addr_noisy, "%s: addr %p new refs %" PRId32 " for %s", __func__,
        (void *)addr, count, reason);

    return count;
}

static NA_INLINE na_return_t
na_ucx_addr_dup(na_class_t NA_UNUSED *nacl, na_addr_t _addr,
    na_addr_t *new_addr)
{
    na_ucx_addr_t *addr = _addr;

    hlog_fast(addr, "duplicating addr %p", (void *)_addr);

    addr_incref(addr, __func__);
    *new_addr = _addr;
    return NA_SUCCESS;
}

static NA_INLINE na_return_t
na_ucx_addr_free(na_class_t *nacl, na_addr_t _addr)
{
    na_ucx_class_t *nucl = na_ucx_class(nacl);
    na_ucx_addr_t *addr = _addr;
    wiring_t *wiring = &nucl->context.wiring;
    int NA_DEBUG_USED found;

    hlog_fast(addr, "freeing addr %p", (void *)_addr);

    if (addr_decref(addr, __func__) > 0)
        return NA_SUCCESS; // more references remain, so don't free

    hlog_fast(addr, "destroying addr %p", (void *)_addr);

    assert(addr != nucl->context.self);

    (void)hg_thread_mutex_lock(&nucl->addr_lock);

    found = hg_hash_table_remove(nucl->addr_tbl, addr);

    (void)hg_thread_mutex_unlock(&nucl->addr_lock);

    assert(found);

    if (wire_is_valid(addr->wire_cache.wire_id)) {
        wiring_lock(wiring);
        wireup_stop(wiring, addr->wire_cache.wire_id, true);
        wiring_unlock(wiring);
    }

    free(addr);
    return NA_SUCCESS;
}

static NA_INLINE na_return_t
na_ucx_addr_set_remove(na_class_t NA_UNUSED *nacl, na_addr_t NA_UNUSED addr)
{
    return NA_SUCCESS;
}

static NA_INLINE na_return_t
na_ucx_addr_self(na_class_t *nacl, na_addr_t *addrp)
{
    na_ucx_class_t *nucl = na_ucx_class(nacl);

    return na_ucx_addr_dup(nacl, nucl->context.self, addrp);
}

static NA_INLINE na_bool_t
na_ucx_addr_is_self(na_class_t *nacl, na_addr_t addr)
{
    na_ucx_class_t *nucl = na_ucx_class(nacl);

    return nucl->context.self == addr;
}

static NA_INLINE na_size_t
na_ucx_addr_get_serialize_size(na_class_t NA_UNUSED *nacl, na_addr_t _addr)
{
    na_ucx_addr_t *addr = _addr;

    return sizeof(uint16_t) + addr->addrlen;
}

static na_return_t
na_ucx_addr_serialize(na_class_t NA_UNUSED *nacl, void *buf,
    na_size_t buf_size, na_addr_t _addr)
{
    na_ucx_addr_t *addr = _addr;
    uint16_t addrlen;

    hlog_fast(addr, "enter serialize buf %p len %zu", buf, buf_size);

    if (buf_size < sizeof(addrlen) + addr->addrlen) {
        NA_LOG_ERROR("Buffer size too small for serializing address");
        return NA_OVERFLOW;
    }

    if (UINT16_MAX < addr->addrlen) {
        NA_LOG_ERROR("Length field too narrow for serialized address length");
        return NA_OVERFLOW;
    }

    addrlen = (uint16_t)addr->addrlen;
    memcpy(buf, &addrlen, sizeof(addrlen));
    memcpy((char *)buf + sizeof(addrlen), &addr->addr[0], addrlen);

    return NA_SUCCESS;
}

static na_return_t
na_ucx_addr_deserialize(na_class_t *nacl, na_addr_t *addrp, const void *buf,
    na_size_t buf_size)
{
    uint16_t addrlen;
    na_ucx_addr_t *addr;

    hlog_fast(addr, "enter deserialize buf %p len %zu", buf, buf_size);

    if (buf_size < sizeof(addrlen)) {
        NA_LOG_ERROR("Buffer too short for address length");
        return NA_INVALID_ARG;
    }

    memcpy(&addrlen, buf, sizeof(addrlen));

    if (buf_size < sizeof(addrlen) + addrlen) {
        NA_LOG_ERROR("Buffer truncates address");
        return NA_INVALID_ARG;
    }

    if (addrlen < 1) {
        NA_LOG_ERROR("Address length is zero");
        return NA_INVALID_ARG;
    }

    if ((addr = malloc(sizeof(*addr) + addrlen)) == NULL)
        return NA_NOMEM;

    *addr = (na_ucx_addr_t){
        .wire_cache = {
            .wire_id = wire_id_nil
          , .sender_id = sender_id_nil
          , .ctx = NULL
          , .ep = NULL
          , .owner = addr
          , .mutcnt = 0
          , .deferrals = HG_QUEUE_HEAD_INITIALIZER(addr->wire_cache.deferrals)
        }
      , .refcount = 1
      , .addrlen = addrlen
    };
    memcpy(&addr->addr[0], (const char *)buf + sizeof(addrlen), addrlen);

    *addrp = na_ucx_addr_dedup(nacl, addr);

    hlog_fast(addr, "exit deserialize buf %p addr %p", buf, (void *)*addrp);

    return NA_SUCCESS;
}

static void
op_ref_reclaim(wiring_ref_t *ref)
{
    na_op_id_t *op = (na_op_id_t *)((char *)ref - offsetof(na_op_id_t, ref));

    hlog_fast(op_life, "%s: destroyed op %p", __func__, (void *)op);

    header_free(op->nucl->request_size, alignof(na_op_id_t), op);
}

static na_op_id_t *
na_ucx_op_create(na_class_t NA_UNUSED *nacl)
{
    na_ucx_class_t *nucl = na_ucx_class(nacl);
    wiring_t *wiring = &nucl->context.wiring;
    na_op_id_t *id;

    id = header_alloc(nucl->request_size, alignof(na_op_id_t), sizeof(*id));

    if (id == NULL) {
        NA_LOG_ERROR("Could not allocate NA UCX operation ID");
        return NULL;
    }

    /* Set op ID release callbacks */
    hg_atomic_set32(&id->status, op_s_complete);
    id->completion_data.plugin_callback = op_id_release;
    id->completion_data.plugin_callback_args = id;
    wiring_ref_init(wiring, &id->ref, op_ref_reclaim);
    id->nucl = nucl;

    hlog_fast(op_life, "%s: created op %p", __func__, (void *)id);

    return id;
}

static na_return_t
na_ucx_op_destroy(na_class_t *nacl, na_op_id_t *id)
{
    na_ucx_class_t *nucl = na_ucx_class(nacl);

    wiring_ref_free(&nucl->context.wiring, &id->ref);

    hlog_fast(op_life, "%s: destroyed op %p", __func__, (void *)id);

    return NA_SUCCESS;
}

static void
recv_callback(void *request, ucs_status_t status,
    const ucp_tag_recv_info_t *info, void NA_UNUSED *user_data)
{
    static const struct na_cb_info_recv_unexpected recv_unexpected_errinfo = {
      .actual_buf_size = 0
    , .source = NA_ADDR_NULL
    , .tag = 0
    };
    na_op_id_t *op = request;
    na_ucx_context_t *nuctx = op->ctx.nu;
    struct na_cb_info *cbinfo = &op->completion_data.callback_info;
    struct na_cb_info_recv_unexpected *recv_unexpected =
        &cbinfo->info.recv_unexpected;
    const op_status_t expected_status =
        (status == UCS_ERR_CANCELED) ? op_s_canceled : op_s_underway;

    hlog_fast(op_life, "%s: op %p", __func__, (void *)op);

    if (hg_atomic_get32(&op->status) != (hg_util_int32_t)expected_status) {
        NA_LOG_ERROR("op id %p: expected status %s, found %s",
            (void *)op,
            op_status_string(expected_status),
            op_status_string(op->status));
    } else {
        hlog_fast(op_life_noisy, "%s: op %p ucx status %s", __func__,
            (void *)op, ucs_status_string(status));
    }

    hg_atomic_set32(&op->status, op_s_complete);

    if (status == UCS_OK) {
        wire_id_t wire_id;
        const void *buf = op->info.rx.buf;
        void *data;
        na_addr_t source;

        // XXX use standard endianness
        memcpy(&wire_id.id, buf, sizeof(wire_id.id));

        if (cbinfo->type != NA_CB_RECV_UNEXPECTED) {
            source = NULL;
        } else if ((data = wire_get_data(&nuctx->wiring, wire_id)) ==
                 wire_data_nil) {
            *recv_unexpected = recv_unexpected_errinfo;
            cbinfo->ret = NA_PROTOCOL_ERROR;
            goto out;
        } else {
            source = data;
            addr_incref(source, "sender address");
        }

        assert((info->sender_tag & nuctx->app.tagmask) == nuctx->app.tag);

        *recv_unexpected = (struct na_cb_info_recv_unexpected){
          .actual_buf_size = (na_size_t)info->length
        , .source = source
        , .tag = (na_tag_t)((info->sender_tag & ~nuctx->msg.tagmask) >>
                            nuctx->msg.tagshift)};

        hlog_fast(op_life_noisy,
            "%s: op %p ucx tag %" PRIx64 " na tag %" PRIu32,
            __func__, (void *)op, info->sender_tag, recv_unexpected->tag);

        hlog_fast(ucx_rxbuf, "%s: %zu rx bytes"
                     " %s:%s:%s:%s:%s:%s:%s:%s:%s:%s:%s:%s:%s:%s:%s:%s"
                     ":%s:%s:%s:%s:%s:%s:%s:%s:%s:%s:%s:%s:%s:%s:%s:%s"
                     ":%s:%s:%s:%s:%s:%s:%s:%s:%s:%s:%s:%s:%s:%s:%s:%s"
                     ":%s:%s:%s:%s:%s:%s:%s:%s:%s:%s:%s:%s:%s:%s:%s:%s",
            __func__,
            info->length,
            get_octet(buf, info->length,  0), get_octet(buf, info->length,  1),
            get_octet(buf, info->length,  2), get_octet(buf, info->length,  3),
            get_octet(buf, info->length,  4), get_octet(buf, info->length,  5),
            get_octet(buf, info->length,  6), get_octet(buf, info->length,  7),
            get_octet(buf, info->length,  8), get_octet(buf, info->length,  9),
            get_octet(buf, info->length, 10), get_octet(buf, info->length, 11),
            get_octet(buf, info->length, 12), get_octet(buf, info->length, 13),
            get_octet(buf, info->length, 14), get_octet(buf, info->length, 15),
            get_octet(buf, info->length, 16), get_octet(buf, info->length, 17),
            get_octet(buf, info->length, 18), get_octet(buf, info->length, 19),
            get_octet(buf, info->length, 20), get_octet(buf, info->length, 21),
            get_octet(buf, info->length, 22), get_octet(buf, info->length, 23),
            get_octet(buf, info->length, 24), get_octet(buf, info->length, 25),
            get_octet(buf, info->length, 26), get_octet(buf, info->length, 27),
            get_octet(buf, info->length, 28), get_octet(buf, info->length, 29),
            get_octet(buf, info->length, 30), get_octet(buf, info->length, 31),
            get_octet(buf, info->length, 32), get_octet(buf, info->length, 33),
            get_octet(buf, info->length, 34), get_octet(buf, info->length, 35),
            get_octet(buf, info->length, 36), get_octet(buf, info->length, 37),
            get_octet(buf, info->length, 38), get_octet(buf, info->length, 39),
            get_octet(buf, info->length, 40), get_octet(buf, info->length, 41),
            get_octet(buf, info->length, 42), get_octet(buf, info->length, 43),
            get_octet(buf, info->length, 44), get_octet(buf, info->length, 45),
            get_octet(buf, info->length, 46), get_octet(buf, info->length, 47),
            get_octet(buf, info->length, 48), get_octet(buf, info->length, 49),
            get_octet(buf, info->length, 50), get_octet(buf, info->length, 51),
            get_octet(buf, info->length, 52), get_octet(buf, info->length, 53),
            get_octet(buf, info->length, 54), get_octet(buf, info->length, 55),
            get_octet(buf, info->length, 56), get_octet(buf, info->length, 57),
            get_octet(buf, info->length, 58), get_octet(buf, info->length, 59),
            get_octet(buf, info->length, 60), get_octet(buf, info->length, 61),
            get_octet(buf, info->length, 62), get_octet(buf, info->length, 63));

        cbinfo->ret = NA_SUCCESS;
    } else if (status == UCS_ERR_CANCELED) {
        *recv_unexpected = recv_unexpected_errinfo;
        cbinfo->ret = NA_CANCELED;
    } else {
        *recv_unexpected = recv_unexpected_errinfo;
        cbinfo->ret = NA_PROTOCOL_ERROR;
    }

out:
    // TBD use lighter weight synchronization in _ref_put, _ref_get.
    wiring_ref_put(&nuctx->wiring, &op->ref);

    hlog_fast(op_life_noisy, "%s: enqueueing completion for op %p",
        __func__, (void *)op);
    na_cb_completion_add(op->ctx.na, &op->completion_data);
}

static void
send_callback(void *request, ucs_status_t status, void NA_UNUSED *user_data)
{
    na_op_id_t *op = request;
    na_ucx_context_t *nuctx = op->ctx.nu;
    struct na_cb_info *cbinfo = &op->completion_data.callback_info;
    const op_status_t expected_status =
        (status == UCS_ERR_CANCELED) ? op_s_canceled : op_s_underway;

    hlog_fast(op_life, "%s: op %p", __func__, (void *)op);

    hlog_fast(op_life_noisy, "%s: op %p ucx status %s", __func__,
        (void *)op, ucs_status_string(status));

    if (hg_atomic_get32(&op->status) != (hg_util_int32_t)expected_status) {
        NA_LOG_ERROR("op id %p: %s expected status %s, found %s",
            (void *)op,
	    na_cb_type_string(op->completion_data.callback_info.type),
            op_status_string(expected_status),
            op_status_string(op->status));
    }
    hg_atomic_set32(&op->status, op_s_complete);

    if (status == UCS_OK)
        cbinfo->ret = NA_SUCCESS;
    else if (status == UCS_ERR_CANCELED)
        cbinfo->ret = NA_CANCELED;
    else
        cbinfo->ret = NA_PROTOCOL_ERROR;

    wiring_ref_put(&nuctx->wiring, &op->ref);

    hlog_fast(op_life_noisy,
        "%s: enqueueing completion for op %p", __func__, (void *)op);

    na_cb_completion_add(op->ctx.na, &op->completion_data);
}

static na_return_t
na_ucx_progress(na_class_t NA_UNUSED *nacl,
    na_context_t *context, unsigned int timeout_ms)
{
    na_ucx_context_t *nuctx = context->plugin_context;
    hg_time_t deadline, now = hg_time_from_ms(0);

    hlog_fast(progress, "%s: enter timeout %ums", __func__, timeout_ms);

    if (timeout_ms != 0 && hg_time_get_current_ms(&now) < 0)
        return NA_AGAIN;    // TBD pick a different/better return code?

    deadline = hg_time_add(now, hg_time_from_ms(timeout_ms));

    do {
        int ret;
        bool progress = false;

        if (ucp_worker_progress(nuctx->worker) != 0) {
            hlog_fast(progress, "%s: UCP made progress", __func__);
            progress = true;
        }

        wiring_lock(&nuctx->wiring);
        while ((ret = wireup_once(&nuctx->wiring)) > 0) {
            hlog_fast(progress, "%s: wireup made progress", __func__);
            progress = true;
        }
        wiring_unlock(&nuctx->wiring);

        if (ret < 0) {
            NA_LOG_ERROR("wireup failed");
            return NA_PROTOCOL_ERROR;
        }

        if (progress)
            return NA_SUCCESS;

        if (timeout_ms != 0 && hg_time_get_current_ms(&now) < 0) {
            NA_LOG_ERROR("could not get current time");
            return NA_AGAIN;    // TBD pick a different/better return code?
        }
    } while (hg_time_less(now, deadline));

    hlog_fast(progress, "%s: timed out", __func__);
    return NA_TIMEOUT;
}

static na_return_t
na_ucx_cancel(na_class_t NA_UNUSED *nacl, na_context_t *context,
    na_op_id_t *op)
{
    na_ucx_context_t *ctx = context->plugin_context;

    hlog_fast(op_life, "%s: op %p", __func__, (void *)op);

    switch (op->completion_data.callback_info.type) {
    case NA_CB_PUT:
    case NA_CB_GET:
    case NA_CB_RECV_UNEXPECTED:
    case NA_CB_RECV_EXPECTED:
        if (hg_atomic_cas32(&op->status, op_s_underway, op_s_canceled)) {
            /* UCP will still run the callback */
            ucp_request_cancel(ctx->worker, op);
        } else {
            hg_util_int32_t NA_DEBUG_USED status = hg_atomic_get32(&op->status);
            hlog_assert(status == op_s_canceled || status == op_s_complete);
        }
        return NA_SUCCESS;
    case NA_CB_SEND_UNEXPECTED:
    case NA_CB_SEND_EXPECTED:
        if (hg_atomic_cas32(&op->status, op_s_underway, op_s_canceled)) {
            /* UCP will still run the callback */
            ucp_request_cancel(ctx->worker, op);
        } else if (hg_atomic_cas32(&op->status, op_s_deferred, op_s_canceled)) {
            ;   // do nothing
        } else {
            hg_util_int32_t NA_DEBUG_USED status = hg_atomic_get32(&op->status);
            hlog_assert(status == op_s_canceled || status == op_s_complete);
        }
        return NA_SUCCESS;
    default:
        return (hg_atomic_get32(&op->status) == op_s_complete)
            ? NA_SUCCESS
            : NA_INVALID_ARG;  // error return follows OFI plugin
    }
}

static void
tagged_send(na_ucx_context_t *nuctx, const void *buf, na_size_t buf_size,
    ucp_ep_h ep, sender_id_t sender_id, uint64_t tag, na_op_id_t *op)
{
    const ucp_request_param_t tx_params = {
      .op_attr_mask = UCP_OP_ATTR_FIELD_CALLBACK | UCP_OP_ATTR_FIELD_REQUEST
    , .cb = {.send = send_callback}
    , .request = op
    };
    ucs_status_ptr_t request;

    assert(buf_size >= sizeof(sender_id));

    // XXX use standard endianness
    memcpy((void *)(uintptr_t)buf, &sender_id, sizeof(sender_id));

    hlog_fast(ucx_txbuf,
        "%s: posting %s buf %p len %zu tag %" PRIx64 " op %p"
        " %s:%s:%s:%s:%s:%s:%s:%s:%s:%s:%s:%s:%s:%s:%s:%s"
        ":%s:%s:%s:%s:%s:%s:%s:%s:%s:%s:%s:%s:%s:%s:%s:%s"
        ":%s:%s:%s:%s:%s:%s:%s:%s:%s:%s:%s:%s:%s:%s:%s:%s"
        ":%s:%s:%s:%s:%s:%s:%s:%s:%s:%s:%s:%s:%s:%s:%s:%s", __func__,
        na_cb_type_string(op->completion_data.callback_info.type), buf,
        buf_size, tag, (void *)op,
        get_octet(buf, buf_size,  0), get_octet(buf, buf_size,  1),
        get_octet(buf, buf_size,  2), get_octet(buf, buf_size,  3),
        get_octet(buf, buf_size,  4), get_octet(buf, buf_size,  5),
        get_octet(buf, buf_size,  6), get_octet(buf, buf_size,  7),
        get_octet(buf, buf_size,  8), get_octet(buf, buf_size,  9),
        get_octet(buf, buf_size, 10), get_octet(buf, buf_size, 11),
        get_octet(buf, buf_size, 12), get_octet(buf, buf_size, 13),
        get_octet(buf, buf_size, 14), get_octet(buf, buf_size, 15),
        get_octet(buf, buf_size, 16), get_octet(buf, buf_size, 17),
        get_octet(buf, buf_size, 18), get_octet(buf, buf_size, 19),
        get_octet(buf, buf_size, 20), get_octet(buf, buf_size, 21),
        get_octet(buf, buf_size, 22), get_octet(buf, buf_size, 23),
        get_octet(buf, buf_size, 24), get_octet(buf, buf_size, 25),
        get_octet(buf, buf_size, 26), get_octet(buf, buf_size, 27),
        get_octet(buf, buf_size, 28), get_octet(buf, buf_size, 29),
        get_octet(buf, buf_size, 30), get_octet(buf, buf_size, 31),
        get_octet(buf, buf_size, 32), get_octet(buf, buf_size, 33),
        get_octet(buf, buf_size, 34), get_octet(buf, buf_size, 35),
        get_octet(buf, buf_size, 36), get_octet(buf, buf_size, 37),
        get_octet(buf, buf_size, 38), get_octet(buf, buf_size, 39),
        get_octet(buf, buf_size, 40), get_octet(buf, buf_size, 41),
        get_octet(buf, buf_size, 42), get_octet(buf, buf_size, 43),
        get_octet(buf, buf_size, 44), get_octet(buf, buf_size, 45),
        get_octet(buf, buf_size, 46), get_octet(buf, buf_size, 47),
        get_octet(buf, buf_size, 48), get_octet(buf, buf_size, 49),
        get_octet(buf, buf_size, 50), get_octet(buf, buf_size, 51),
        get_octet(buf, buf_size, 52), get_octet(buf, buf_size, 53),
        get_octet(buf, buf_size, 54), get_octet(buf, buf_size, 55),
        get_octet(buf, buf_size, 56), get_octet(buf, buf_size, 57),
        get_octet(buf, buf_size, 58), get_octet(buf, buf_size, 59),
        get_octet(buf, buf_size, 60), get_octet(buf, buf_size, 61),
        get_octet(buf, buf_size, 62), get_octet(buf, buf_size, 63));

    wiring_ref_get(&nuctx->wiring, &op->ref);
    request = ucp_tag_send_nbx(ep, buf, buf_size, tag, &tx_params);

    if (UCS_PTR_IS_ERR(request)) {
        NA_LOG_ERROR("ucp_tag_send_nbx: %s",
            ucs_status_string(UCS_PTR_STATUS(request)));
        hlog_fast(op_life, "%s: failed op %p", __func__, (void *)op);
        hg_atomic_set32(&op->status, op_s_complete);
        op->completion_data.callback_info.ret = NA_PROTOCOL_ERROR;
        wiring_ref_put(&nuctx->wiring, &op->ref);
        na_cb_completion_add(op->ctx.na, &op->completion_data);
    } else if (request == UCS_OK) {
        // send was immediate: queue completion
        hlog_fast(op_life, "%s: completed op %p", __func__, (void *)op);
        hg_atomic_set32(&op->status, op_s_complete);
        op->completion_data.callback_info.ret = NA_SUCCESS;
        wiring_ref_put(&nuctx->wiring, &op->ref);
        na_cb_completion_add(op->ctx.na, &op->completion_data);
    } else {
        hlog_fast(op_life, "%s: posted op %p", __func__, (void *)op);
    }
}

static bool
wire_event_callback(wire_event_info_t info, void *arg)
{
    address_wire_aseq_t aseq;
    address_wire_t *cache = arg;
    na_op_id_t *op;
    na_ucx_addr_t *owner = cache->owner;

    hlog_fast(wire_life, "%s: enter cache %p", __func__, (void *)cache);

    assert(info.event == wire_ev_estd || info.event == wire_ev_closed ||
           info.event == wire_ev_reclaimed);

    wiring_assert_locked(&cache->ctx->wiring);

    if (info.event == wire_ev_closed) {
        hlog_fast(wire_life, "%s: closed", __func__);

        assert(HG_QUEUE_IS_EMPTY(&cache->deferrals));

        return true;
    }

    if (info.event == wire_ev_reclaimed) {
        hlog_fast(wire_life, "%s: reclaimed", __func__);

        /* No in-flight wireup operations will reference this wire
         * so it has been reclaimed.
         */
        aseq = address_wire_write_begin(cache);
        atomic_store_explicit(&cache->sender_id, sender_id_nil,
            memory_order_relaxed);
        atomic_store_explicit(&cache->wire_id.id, sender_id_nil,
            memory_order_relaxed);
        atomic_store_explicit(&cache->ep, NULL, memory_order_relaxed);
        address_wire_write_end(aseq);

        /* Now the address can be reclaimed
         * safely, too.  Decrease the reference count that we increased when
         * either the local host initiated wireup or the local host
         * accepted the remote's wireup request.
         */
        (void)na_ucx_addr_free(cache->ctx->nacl, owner);

        return true;
    }

    hlog_fast(wire_life, "%s: established", __func__);

    /* Transmit deferred messages before saving the sender ID so that
     * a new transmission cannot slip out before the deferred ones.
     * New transmissions will find that the sender ID is nil and wait
     * for us to release the wiring lock.
     */
    hlog_fast(op_life, "%s: begin deferred xmits", __func__);
    HG_QUEUE_FOREACH(op, &cache->deferrals, info.tx.link) {
        const void *buf = op->info.tx.buf;
        na_size_t buf_size = op->info.tx.buf_size;
        uint64_t tag = op->info.tx.tag;
        if (hg_atomic_cas32(&op->status, op_s_deferred, op_s_underway)) {
            hlog_fast(op_life,
                "%s:     op %p deferred -> underway", __func__, (void *)op);
            tagged_send(cache->ctx, buf, buf_size, info.ep, info.sender_id,
                tag, op);
        } else if (hg_atomic_cas32(&op->status, op_s_canceled, op_s_complete)) {
            hlog_fast(op_life,
                "%s:     op %p canceled -> complete", __func__, (void *)op);
            struct na_cb_info *cbinfo = &op->completion_data.callback_info;
            cbinfo->ret = NA_CANCELED;
            na_cb_completion_add(op->ctx.na, &op->completion_data);
        } else {
            hlog_fast(op_life,
                "%s:     op %p expected deferred/canceled, found %s", __func__,
                (void *)op, op_status_string(op->status));
        }
    }

    HG_QUEUE_INIT(&cache->deferrals);

    hlog_fast(op_life, "%s: end deferred xmits", __func__);

    aseq = address_wire_write_begin(cache);
    atomic_store_explicit(&cache->ep, info.ep, memory_order_relaxed);
    atomic_store_explicit(&cache->sender_id, info.sender_id,
        memory_order_relaxed);
    address_wire_write_end(aseq);

    return true;
}

static address_wire_aseq_t
address_wire_read_begin(address_wire_t *cache)
{
    address_wire_aseq_t aseq = {.cache = cache};

    while ((aseq.enter_mutcnt = hg_atomic_get32(&cache->mutcnt)) % 2 != 0)
            cpu_spinwait(); // give the writer a chance to finish its update

    return aseq;
}

static bool
address_wire_read_end(address_wire_aseq_t aseq)
{
    return hg_atomic_get32(&aseq.cache->mutcnt) == aseq.enter_mutcnt;
}

static na_return_t
na_ucx_msg_send(na_context_t *context,
    na_cb_t callback, void *arg, const void *buf, na_size_t buf_size,
    na_addr_t dest_addr, na_tag_t proto_tag, na_cb_type_t cb_type,
    na_op_id_t *op_id)
{
    na_ucx_context_t *cached_ctx, * const nuctx = context->plugin_context;
    sender_id_t sender_id;
    na_return_t ret;
    address_wire_t *cache = &dest_addr->wire_cache;
    ucp_ep_h ep;
    uint64_t tag;
    const na_tag_t NA_DEBUG_USED maxtag =
        (na_tag_t)MIN(NA_TAG_MAX, nuctx->msg.tagmax);

    assert(proto_tag <= maxtag);

    hlog_fast(tx, "%s: posting %s buf %p len %zu na tag %" PRIx32
        " op %p arg %p",
        __func__, na_cb_type_string(cb_type), buf, buf_size, proto_tag,
        (void *)op_id, arg);

    for (;;) {
        const address_wire_aseq_t aseq = address_wire_read_begin(cache);
        sender_id = atomic_load_explicit(&cache->sender_id,
            memory_order_relaxed);
        cached_ctx = atomic_load_explicit(&cache->ctx, memory_order_relaxed);
        /* XXX The endpoint mustn't be destroyed between the time we
         * load its pointer and the time we transmit on it, but the wireup
         * state machine isn't synchronized with transmission.
         *
         * Wireup probably should not
         * release an endpoint until an explicit wireup_stop() is performed.
         * I can introduce a state between "dead" and "reclaimed".
         *
         * Alternatively, defer releasing the endpoint until an "epoch" has
         * passed.
         */
        ep = atomic_load_explicit(&cache->ep, memory_order_relaxed);
        if (address_wire_read_end(aseq))
            break;
    }

    tag = proto_tag << nuctx->msg.tagshift;
    if (cb_type == NA_CB_SEND_EXPECTED)
        tag |= nuctx->exp.tag;
    else
        tag |= nuctx->unexp.tag;

    /* TBD Assert expected op_id->status */
    op_id->ctx.na = context;
    op_id->ctx.nu = nuctx;
    op_id->completion_data.callback_info.type = cb_type;
    op_id->completion_data.callback = callback;
    op_id->completion_data.callback_info.arg = arg;
    op_id->info.tx.buf = buf;
    op_id->info.tx.buf_size = buf_size;
    op_id->info.tx.tag = tag;

    /* Fast path: if the sender ID is established, and the cached context
     * matches the caller's context, then don't acquire the lock,
     * just send and return.
     */
    if (cached_ctx == context->plugin_context && sender_id != sender_id_nil) {
        op_id->status = op_s_underway;
        tagged_send(cached_ctx, buf, buf_size, ep, sender_id, tag, op_id);
        return NA_SUCCESS;
    }

    wiring_lock(&nuctx->wiring);

    /* Since we last checked, sender_id or ctx may have been set.  Check
     * once more.
     *
     * TBD handle cache->ctx that is equal to neither NULL nor
     * context->plugin_context.
     */
    if ((cached_ctx = cache->ctx) == NULL) {
        /* This thread can write to `cache->ctx` without conflicting
         * with any other thread: because the thread holds the lock,
         * no new wire-event callback will be established on `cache`.
         * Because `cache->ctx == NULL`, no wireup is underway, so no
         * wire-event callback is already established.
         */
        const address_wire_aseq_t aseq = address_wire_write_begin(cache);

        cache->ctx = cached_ctx = nuctx;

        hlog_fast(tx, "%s: starting wireup, cache %p", __func__, (void *)cache);

        addr_incref(cache->owner, "wireup");

        cache->wire_id = wireup_start(&cached_ctx->wiring,
            (ucp_address_t *)&cached_ctx->self->addr[0],
            cached_ctx->self->addrlen,
            (ucp_address_t *)&dest_addr->addr[0], dest_addr->addrlen,
            wire_event_callback, cache, dest_addr);

        address_wire_write_end(aseq);

        if (!wire_is_valid(cache->wire_id)) {
            NA_LOG_ERROR("could not start wireup, cache %p", (void *)cache);
            addr_decref(cache->owner, "wireup failure");
            ret = NA_NOMEM;
            goto release;
        }
    } else if ((sender_id = cache->sender_id) != sender_id_nil) {
        op_id->status = op_s_underway;
        tagged_send(cached_ctx, buf, buf_size, ep, sender_id, tag, op_id);
        ret = NA_SUCCESS;
        goto release;
    } else if (!wire_is_valid(cache->wire_id)) {

        const address_wire_aseq_t aseq = address_wire_write_begin(cache);

        hlog_fast(tx, "%s: starting wireup, cache %p", __func__, (void *)cache);

        addr_incref(cache->owner, "wireup");

        cache->wire_id = wireup_start(&cached_ctx->wiring,
            (ucp_address_t *)&cached_ctx->self->addr[0],
            cached_ctx->self->addrlen,
            (ucp_address_t *)&dest_addr->addr[0], dest_addr->addrlen,
            wire_event_callback, cache, dest_addr);

        address_wire_write_end(aseq);

        if (!wire_is_valid(cache->wire_id)) {
            NA_LOG_ERROR("could not start wireup, cache %p", (void *)cache);
            addr_decref(cache->owner, "wireup failure");
            ret = NA_NOMEM;
            goto release;
        }
    }

    hlog_fast(tx, "%s: deferring op %p", __func__, (void *)op_id);

    hg_atomic_set32(&op_id->status, op_s_deferred);

    HG_QUEUE_PUSH_TAIL(&cache->deferrals, op_id, info.tx.link);

    ret = NA_SUCCESS;
release:
    // TBD put the following comments into the right place or delete them.
    //
    // if dest_addr has no wire ID, increase refcount on dest_addr by 1,
    //     start wireup with dest_addr as callback arg; set wire ID on
    //     dest_addr; enqueue op_id on dest_addr; in wireup callback,
    //     set sender ID on dest_addr, decrease refcount by 1, return false
    //     to stop callbacks.
    // if dest_addr has wire ID but no sender ID, enqueue op_id on dest_addr.
    // if dest_addr has sender ID, put it into the header and send the message.
    wiring_unlock(&nuctx->wiring);
    return ret;
}

static na_return_t
na_ucx_msg_send_unexpected(na_class_t NA_UNUSED *nacl,
    na_context_t *context, na_cb_t callback, void *arg,
    const void *buf, na_size_t buf_size, void NA_UNUSED *plugin_data,
    na_addr_t dest_addr, na_uint8_t NA_UNUSED dest_id, na_tag_t tag,
    na_op_id_t *op_id)
{
    return na_ucx_msg_send(context, callback, arg,
        buf, buf_size, dest_addr, tag, NA_CB_SEND_UNEXPECTED, op_id);
}

static na_return_t
na_ucx_msg_recv(na_context_t *ctx, na_cb_t callback, void *arg,
    void *buf, na_size_t buf_size, uint64_t tag, uint64_t tagmask,
    na_cb_type_t cb_type, na_op_id_t *op)
{
    na_ucx_context_t *nuctx = ctx->plugin_context;
    const ucp_request_param_t recv_params = {
      .op_attr_mask = UCP_OP_ATTR_FIELD_CALLBACK |
                      UCP_OP_ATTR_FIELD_REQUEST
    , .cb = {.recv = recv_callback}
    , .request = op
    };
    ucp_worker_h worker = nuctx->worker;
    void *request;

    hlog_fast(rx,
        "%s: posting %s buf %p len %zu tag %" PRIx64 " mask %" PRIx64
        " op %p arg %p",
        __func__, na_cb_type_string(cb_type), buf, buf_size, tag, tagmask,
        (void *)op, arg);

    /* TBD Assert expected status? */
    hg_atomic_set32(&op->status, op_s_underway);
    op->ctx.na = ctx;
    op->ctx.nu = nuctx;
    op->info.rx.buf = buf;
    op->completion_data.callback_info.type = cb_type;
    op->completion_data.callback = callback;
    op->completion_data.callback_info.arg = arg;

    wiring_ref_get(&nuctx->wiring, &op->ref);

    request =
        ucp_tag_recv_nbx(worker, buf, buf_size, tag, tagmask, &recv_params);

    if (UCS_PTR_IS_ERR(request)) {
        NA_LOG_ERROR("ucp_tag_recv_nbx: %s",
            ucs_status_string(UCS_PTR_STATUS(request)));
        wiring_ref_put(&nuctx->wiring, &op->ref);
        hlog_fast(op_life, "%s: failed op %p", __func__, (void *)op);
        op->status = op_s_complete;
        return NA_PROTOCOL_ERROR;
    } else {
        hlog_fast(op_life, "%s: posted op %p", __func__, (void *)op);
    }

    return NA_SUCCESS;
}

static na_return_t
na_ucx_msg_recv_unexpected(na_class_t NA_UNUSED *nacl, na_context_t *ctx,
    na_cb_t callback, void *arg, void *buf, na_size_t buf_size,
    void NA_UNUSED *plugin_data, na_op_id_t *op_id)
{
    na_ucx_context_t *nuctx = ctx->plugin_context;

    return na_ucx_msg_recv(ctx, callback, arg, buf, buf_size,
        nuctx->unexp.tag, nuctx->msg.tagmask, NA_CB_RECV_UNEXPECTED, op_id);
}

static na_return_t
na_ucx_msg_send_expected(na_class_t NA_UNUSED *nacl, na_context_t *ctx,
    na_cb_t callback, void *arg, const void *buf, na_size_t buf_size,
    void NA_UNUSED *plugin_data, na_addr_t dest_addr,
    na_uint8_t NA_UNUSED dest_id, na_tag_t tag, na_op_id_t *op_id)
{
    return na_ucx_msg_send(ctx, callback, arg,
        buf, buf_size, dest_addr, tag, NA_CB_SEND_EXPECTED, op_id);
}

static na_return_t
na_ucx_msg_recv_expected(na_class_t NA_UNUSED *nacl, na_context_t *ctx,
    na_cb_t callback, void *arg, void *buf, na_size_t buf_size,
    void NA_UNUSED *plugin_data, na_addr_t NA_UNUSED source_addr,
    na_uint8_t NA_UNUSED source_id, na_tag_t proto_tag, na_op_id_t *op_id)
{
    na_ucx_context_t *nuctx = ctx->plugin_context;
    const na_tag_t NA_DEBUG_USED maxtag =
        (na_tag_t)MIN(NA_TAG_MAX, nuctx->msg.tagmax);

    assert(proto_tag <= maxtag);

    return na_ucx_msg_recv(ctx, callback, arg, buf, buf_size,
        nuctx->exp.tag | (proto_tag << nuctx->msg.tagshift), UINT64_MAX,
        NA_CB_RECV_EXPECTED, op_id);
}

static na_return_t
na_ucx_mem_handle_create(na_class_t *nacl, void *buf,
    na_size_t buf_size, unsigned long NA_UNUSED flags, na_mem_handle_t *mhp)
{
    const ucp_mem_map_params_t params = {
      .field_mask = UCP_MEM_MAP_PARAM_FIELD_ADDRESS |
                    UCP_MEM_MAP_PARAM_FIELD_LENGTH
    , .address = buf
    , .length = buf_size
    };
    const na_ucx_class_t *nucl = na_ucx_class_const(nacl);
    ucs_status_t status;
    na_mem_handle_t mh;

    if ((mh = zalloc(sizeof(*mh))) == NULL)
        return NA_NOMEM;

    hlog_fast(memh, "%s: memory handle %p", __func__, (void *)mh);

    hg_atomic_set32(&mh->kind, na_ucx_mem_local);
    mh->handle.local.buf = buf;
    status = ucp_mem_map(nucl->uctx, &params, &mh->handle.local.mh);

    if (status != UCS_OK) {
        free(mh);
        return NA_PROTOCOL_ERROR;
    }

    *mhp = mh;
    return NA_SUCCESS;
}

static na_return_t
na_ucx_mem_handle_free(na_class_t *nacl, na_mem_handle_t mh)
{
    const na_ucx_class_t *nucl = na_ucx_class_const(nacl);
    ucs_status_t status;

    hlog_fast(memh, "%s: memory handle %p", __func__, (void *)mh);

    switch (hg_atomic_get32(&mh->kind)) {
    case na_ucx_mem_local:
        status = ucp_mem_unmap(nucl->uctx, mh->handle.local.mh);
        free(mh);
        return (status == UCS_OK) ? NA_SUCCESS : NA_PROTOCOL_ERROR;
    case na_ucx_mem_unpacked_remote:
        ucp_rkey_destroy(mh->handle.unpacked_remote.rkey);
        free(mh);
        return NA_SUCCESS;
    case na_ucx_mem_packed_remote:
        free(mh->handle.packed_remote.buf);
        free(mh);
        return NA_SUCCESS;
    default:
        return NA_INVALID_ARG;
    }
}

static NA_INLINE na_size_t
na_ucx_mem_handle_get_max_segments(const na_class_t NA_UNUSED *nacl)
{
    return 1;
}

/* This is a no-op for UCP but we do check the arguments. */
static na_return_t
na_ucx_mem_register(na_class_t NA_UNUSED *nacl, na_mem_handle_t mh)
{
    hlog_fast(memh, "%s: memory handle %p", __func__, (void *)mh);

    if (hg_atomic_get32(&mh->kind) != na_ucx_mem_local) {
        NA_LOG_ERROR("%p is not a local handle", (void *)mh);
        return NA_INVALID_ARG;
    }
    return NA_SUCCESS;
}

/* This is a no-op for UCP but we do check the arguments. */
static na_return_t
na_ucx_mem_deregister(na_class_t NA_UNUSED *nacl, na_mem_handle_t NA_UNUSED mh)
{
    hlog_fast(memh, "%s: memory handle %p", __func__, (void *)mh);

    return NA_SUCCESS;
}

static NA_INLINE na_size_t
na_ucx_mem_handle_get_serialize_size(na_class_t *nacl, na_mem_handle_t mh)
{
    const na_ucx_class_t *nucl = na_ucx_class_const(nacl);
    ucs_status_t status;
    void *ptr;
    const size_t hdrlen = sizeof(na_mem_handle_header_t);
    size_t paylen;

    if (hg_atomic_get32(&mh->kind) != na_ucx_mem_local) {
        NA_LOG_ERROR("non-local memory handle %p cannot be serialized",
            (void *)mh);
        return 0;   // ok for error?
    }

    status = ucp_rkey_pack(nucl->uctx, mh->handle.local.mh, &ptr, &paylen);
    if (status != UCS_OK)
        return 0;   // ok for error?
    ucp_rkey_buffer_release(ptr);

    hlog_fast(memh, "%s: memory handle %p header + payload length %zu",
        __func__, (void *)mh, hdrlen + paylen);

    return hdrlen + paylen;
}

static na_return_t
na_ucx_mem_handle_serialize(na_class_t *nacl, void *_buf, na_size_t buf_size,
    na_mem_handle_t mh)
{
    const na_ucx_class_t *nucl = na_ucx_class_const(nacl);
    char *buf = _buf;
    void *rkey;
    const size_t hdrlen = sizeof(na_mem_handle_header_t);
    na_mem_handle_header_t hdr = {
      // TBD convert to network endianness
      .base_addr = (uint64_t)(void *)mh->handle.local.buf
    , .paylen = 0
    };
    size_t paylen;
    ucs_status_t status;

    hlog_fast(memh, "%s: memory handle %p", __func__, (void *)mh);

    if (hg_atomic_get32(&mh->kind) != na_ucx_mem_local) {
        NA_LOG_ERROR("non-local memory handle %p cannot be serialized",
            (void *)mh);
        return NA_INVALID_ARG;
    }

    status = ucp_rkey_pack(nucl->uctx, mh->handle.local.mh, &rkey, &paylen);
    if (status != UCS_OK) {
        NA_LOG_ERROR("ucp_rkey_pack failed %s", ucs_status_string(status));
        return NA_PROTOCOL_ERROR;   // ok for error?
    }

    hlog_fast(memh, "%s: header + payload length %zu at %p", __func__,
        hdrlen + paylen, _buf);

    if (UINT32_MAX < paylen) {
        NA_LOG_ERROR("payload too big, %zu bytes", paylen);
        return NA_OVERFLOW;
    }
    if (buf_size < hdrlen + paylen) {
        NA_LOG_ERROR("buffer too small, %zu bytes", buf_size);
        return NA_OVERFLOW;
    }

    hdr.paylen = (uint32_t)paylen; // TBD convert to network endianness
    memcpy(buf, &hdr, hdrlen);
    memcpy(buf + hdrlen, rkey, paylen);
    ucp_rkey_buffer_release(rkey);

    return NA_SUCCESS;
}

static na_return_t
na_ucx_mem_handle_deserialize(na_class_t NA_UNUSED *nacl, na_mem_handle_t *mhp,
    const void *buf, na_size_t buf_size)
{
    na_mem_handle_header_t hdr;
    na_mem_handle_t mh;
    void *duplicate;
    const size_t hdrlen = sizeof(na_mem_handle_header_t);
    size_t paylen;

    if ((mh = zalloc(sizeof(*mh))) == NULL)
        return NA_NOMEM;

    hlog_fast(memh, "%s: memory handle %p", __func__, (void *)mh);

    if (buf_size < hdrlen) {
        NA_LOG_ERROR("buffer is shorter than a header, %zu bytes", buf_size);
        return NA_OVERFLOW;
    }

    memcpy(&hdr, buf, hdrlen);

    paylen = hdr.paylen; // TBD convert from network endianness

    hlog_fast(memh, "%s: header + payload length %zu at %p",
        __func__, hdrlen + paylen, buf);

    if (buf_size < hdrlen + paylen) {
        NA_LOG_ERROR("buffer too short, %zu bytes", buf_size);
        return NA_OVERFLOW;
    }

    if ((duplicate = memdup(buf, hdrlen + paylen)) == NULL) {
        free(mh);
        return NA_NOMEM;
    }

    hg_atomic_set32(&mh->kind, na_ucx_mem_packed_remote);
    mh->handle.packed_remote.buf = duplicate;
    mh->handle.packed_remote.buflen = hdrlen + paylen;

    *mhp = mh;
    return NA_SUCCESS;
}

static na_mem_handle_t
resolve_mem_handle_locked(ucp_ep_h ep, na_mem_handle_t mh)
{
    na_mem_handle_header_t hdr;
    unpacked_rkey_t unpacked;
    packed_rkey_t *packed = &mh->handle.packed_remote;
    ucs_status_t status;

    hlog_fast(memh, "%s: memory handle %p", __func__, (void *)mh);

    if (hg_atomic_get32(&mh->kind) != na_ucx_mem_packed_remote)
        return mh;

    memcpy(&hdr, packed->buf, sizeof(hdr));

    status = ucp_ep_rkey_unpack(ep, packed->buf + sizeof(hdr), &unpacked.rkey);
    if (status != UCS_OK) {
        NA_LOG_ERROR("ucp_rkey_pack failed %s", ucs_status_string(status));
        return NULL;
    }

    // TBD convert from network endianness
    unpacked.remote_base_addr = hdr.base_addr;

    free(packed->buf);

    mh->handle.unpacked_remote = unpacked;
    hg_atomic_set32(&mh->kind, na_ucx_mem_unpacked_remote);

    return mh;
}

static na_mem_handle_t
resolve_mem_handle(ucp_ep_h ep, na_mem_handle_t mh)
{
    if (hg_atomic_get32(&mh->kind) != na_ucx_mem_packed_remote)
        return mh;

    hg_thread_mutex_lock(&mh->unpack_lock);
    mh = resolve_mem_handle_locked(ep, mh);
    hg_thread_mutex_unlock(&mh->unpack_lock);

    return mh;
}

static na_return_t
na_ucx_copy(na_context_t *ctx, na_cb_t callback,
    void *arg, na_mem_handle_t local_mh, na_offset_t local_offset,
    na_mem_handle_t remote_mh, na_offset_t remote_offset,
    na_size_t length, na_addr_t remote_addr, na_uint8_t NA_UNUSED remote_id,
    na_op_id_t *op, bool put)
{
    const ucp_request_param_t params = {
      .op_attr_mask = UCP_OP_ATTR_FIELD_CALLBACK | UCP_OP_ATTR_FIELD_REQUEST
    , .cb = {.send = send_callback}
    , .request = op
    };
    ucp_ep_h ep;
    na_ucx_context_t *nuctx;
    address_wire_t *cache = &remote_addr->wire_cache;
    ucs_status_ptr_t request;
    unpacked_rkey_t *unpacked = &remote_mh->handle.unpacked_remote;

    hlog_fast(rdma, "%s: %s len %zu op %p",
        __func__, put ? "putting" : "getting", length, (void *)op);

    if (hg_atomic_get32(&local_mh->kind) != na_ucx_mem_local ||
        hg_atomic_get32(&remote_mh->kind) == na_ucx_mem_local) {
        hlog_fast(rdma_err,
            "%s: local/remote mem handle in remote/local argument", __func__);
        return NA_INVALID_ARG;
    }

    for (;;) {
        const address_wire_aseq_t aseq = address_wire_read_begin(cache);
        nuctx = atomic_load_explicit(&cache->ctx, memory_order_relaxed);
        ep = atomic_load_explicit(&cache->ep, memory_order_relaxed);
        if (address_wire_read_end(aseq))
            break;
    }

    /* XXX Need to verify that `ep` cannot be NULL here. */

    assert(nuctx == ctx->plugin_context);

    if ((remote_mh = resolve_mem_handle(ep, remote_mh)) == NULL)
        return NA_PROTOCOL_ERROR;

    /* TBD: verify original status */
    hg_atomic_set32(&op->status, op_s_underway);
    op->ctx.na = ctx;
    op->ctx.nu = nuctx;
    op->completion_data.callback_info.type = put ? NA_CB_PUT : NA_CB_GET;
    op->completion_data.callback = callback;
    op->completion_data.callback_info.arg = arg;

    wiring_ref_get(&nuctx->wiring, &op->ref);

    if (put) {
        request = ucp_put_nbx(
            ep, local_mh->handle.local.buf + local_offset, length,
            unpacked->remote_base_addr + remote_offset, unpacked->rkey,
            &params);
    } else {
        request = ucp_get_nbx(
            ep, local_mh->handle.local.buf + local_offset, length,
            unpacked->remote_base_addr + remote_offset, unpacked->rkey,
            &params);
    }

    if (UCS_PTR_IS_ERR(request)) {
        NA_LOG_ERROR("ucp_put_nbx: %s",
            ucs_status_string(UCS_PTR_STATUS(request)));
        hlog_fast(op_life, "%s: failed %s op %p", __func__, put ? "put" : "get",
            (void *)op);
        wiring_ref_put(&nuctx->wiring, &op->ref);
        hg_atomic_set32(&op->status, op_s_complete);
        return NA_PROTOCOL_ERROR;
    } else if (request == UCS_OK) {
        // send was immediate: queue completion
        hlog_fast(op_life, "%s: completed %s op %p", __func__,
            put ? "put" : "get", (void *)op);
        wiring_ref_put(&nuctx->wiring, &op->ref);
        hg_atomic_set32(&op->status, op_s_complete);
        op->completion_data.callback_info.ret = NA_SUCCESS;
        na_cb_completion_add(op->ctx.na, &op->completion_data);
    } else {
        hlog_fast(op_life, "%s: posted %s op %p", __func__, put ? "put" : "get",
            (void *)op);
    }

    return NA_SUCCESS;
}

static na_return_t
na_ucx_put(na_class_t NA_UNUSED *nacl, na_context_t *ctx, na_cb_t callback,
    void *arg, na_mem_handle_t local_mh, na_offset_t local_offset,
    na_mem_handle_t remote_mh, na_offset_t remote_offset,
    na_size_t length, na_addr_t remote_addr, na_uint8_t remote_id,
    na_op_id_t *op_id)
{
    return na_ucx_copy(ctx, callback, arg, local_mh, local_offset,
        remote_mh, remote_offset, length, remote_addr, remote_id, op_id, true);
}

static na_return_t
na_ucx_get(na_class_t NA_UNUSED *nacl, na_context_t *ctx, na_cb_t callback,
    void *arg, na_mem_handle_t local_mh, na_offset_t local_offset,
    na_mem_handle_t remote_mh, na_offset_t remote_offset,
    na_size_t length, na_addr_t remote_addr, na_uint8_t remote_id,
    na_op_id_t *op_id)
{
    return na_ucx_copy(ctx, callback, arg, local_mh, local_offset,
        remote_mh, remote_offset, length, remote_addr, remote_id, op_id, false);
}

#if 0
static NA_INLINE int
na_ucx_poll_get_fd(na_class_t *nacl, na_context_t *ctx)
{
    return NA_PROTOCOL_ERROR;
}

static NA_INLINE na_bool_t
na_ucx_poll_try_wait(na_class_t *nacl, na_context_t *ctx)
{
    return NA_PROTOCOL_ERROR;
}
#endif

static NA_INLINE na_size_t
na_ucx_msg_get_header_size(const na_class_t NA_UNUSED *cl)
{
    return sizeof(na_ucx_header_t);
}

static NA_INLINE na_size_t
na_ucx_msg_get_max_size(const na_class_t NA_UNUSED *cl)
{
    return NA_UCX_MSG_SIZE_MAX;
}

static NA_INLINE na_tag_t
na_ucx_msg_get_max_tag(const na_class_t *nacl)
{
    const na_ucx_class_t *nucl = na_ucx_class_const(nacl);
    const na_tag_t maxtag = (na_tag_t)MIN(NA_TAG_MAX, nucl->context.msg.tagmax);

    assert(maxtag >= 3);

    return maxtag;
}
