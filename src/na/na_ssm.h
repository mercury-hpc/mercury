/*
 * Copyright (C) 2013-2014 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#ifndef NA_SSM_H
#define NA_SSM_H

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <unistd.h>
#include <assert.h>

#include "na.h"
#include "na_private.h"
#include "na_error.h"

#include "mercury_hash_table.h"
#include "mercury_list.h"
#include "mercury_queue.h"
#include "mercury_thread.h"
#include "mercury_thread_mutex.h"
#include "mercury_thread_condition.h"
#include "mercury_time.h"

#include <ssm/dumb.h>
#include <ssm.h>
#include <ssmptcp.h>

#if (__GNUC__)
#define __likely(x)   __builtin_expect(!!(x), 1)
#define __unlikely(x) __builtin_expect(!!(x), 0)
#else
#define __likely(x)     (x)
#define __unlikely(x)   (x)
#endif

#define NA_SSM_UNEXPECTED_SIZE               1024*1024*64
#define NA_SSM_EXPECTED_SIZE                 1024*1024*64
#define NA_SSM_UNEXPECTED_BUFFERCOUNT                  64
#define NA_SSM_TAG_UNEXPECTED_OFFSET                    0
#define NA_SSM_TAG_EXPECTED_OFFSET    (((ssm_bits)1)<<62)
#define NA_SSM_TAG_RMA_OFFSET         (((ssm_bits)1)<<63)
#define NA_SSM_MAX_ADDRESS_LENGTH                      64

#define NA_SSM_NEXT_UNEXPBUF_POS(n) (((n)+(1))%(NA_SSM_UNEXPECTED_BUFFERCOUNT))

#define NA_SSM_PRIVATE_DATA(a) ((struct na_ssm_private_data *) (a)->private_data)

#define NA_SSM_MARK_OPID_COMPLETE(a)  ((a)->status = SSM_STATUS_COMPLETED)
#define NA_SSM_MARK_OPID_CANCELED(a)  ((a)->status = SSM_STATUS_CANCELED)

/* Buffers for unexpected data */
struct na_ssm_unexpected_buffer {
  char          *buf;
  ssm_me         me;
  ssm_cb_t       cb;
  ssm_mr         mr;
  ssm_bits       bits;
  ssm_status     status;
  ssm_Haddr      addr;
  uint64_t       bytes;
};

struct na_ssm_private_data {
  ssm_id       ssm;
  ssm_Itp      itp;
  int          unexpbuf_cpos;
  int          unexpbuf_rpos;
  int          unexpbuf_availpos;
  ssm_cb_t     unexpected_callback;
  ssm_me       unexpected_me;
  ssm_bits     cur_bits;
  hg_thread_mutex_t gen_matchbits;

  hg_thread_cond_t  unexp_buf_cond;
  hg_thread_mutex_t request_mutex;
  hg_thread_cond_t  comp_req_cond;

#ifdef NA_HAS_CLIENT_THREAD
  hg_thread_mutex_t finalizing_mutex;
  bool              finalizing;
  hg_thread_t       progress_service;
#endif

  hg_queue_t *opid_wait_queue;
  hg_thread_mutex_t opid_wait_queue_mutex;
  
  hg_queue_t *unexpected_msg_queue;
  hg_thread_mutex_t unexpected_msg_queue_mutex;
  hg_thread_cond_t unexpected_msg_queue_cond;
  
  hg_queue_t *unexpected_msg_complete_queue;
  hg_thread_mutex_t unexpected_msg_complete_mutex;
  hg_thread_cond_t unexpected_msg_complete_cond;
};

struct na_ssm_addr {
  ssm_Haddr addr;
};

struct na_ssm_mem_handle {
  ssm_mr         mr;
  ssm_bits       matchbits;
  void          *buf;
  unsigned long  buf_size;
  ssm_me         me;
  ssm_cb_t       cb;
  unsigned long  flag;
};

typedef int           ssm_size_t;
typedef unsigned long ssm_msg_tag_t;

typedef enum na_ssm_status {
    SSM_STATUS_INVALID     = 0,
    SSM_STATUS_INPROGRESS  = 1,
    SSM_STATUS_COMPLETED   = 2,
    SSM_STATUS_CANCELED    = 3,
} na_ssm_status_t;

struct ssm_msg_send_unexpected {
  ssm_mr            memregion;
  ssm_bits          matchbits;
};

struct ssm_msg_send_expected {
  ssm_mr            memregion;
  ssm_cb_t          callback;
  ssm_bits matchbits;
};

struct ssm_get {
  ssm_mr        memregion;
  ssm_md        memdesc;
};

struct ssm_msg_recv_expected {
  ssm_mr        memregion;
  ssm_me        matchentry;
  ssm_bits matchbits;
  void *input_buffer;
  na_size_t input_buffer_size;
};

struct ssm_msg_recv_unexpected {
  ssm_mr        memregion;
  void         *input_buffer;
  na_size_t     input_buffer_size;
};

struct na_ssm_opid {
  na_cb_type_t        requesttype;
  na_cb_t             user_callback;
  na_context_t       *user_context;
  void               *user_arg;
  struct na_ssm_private_data *ssm_data;
  struct na_cb_info  *cbinfo;
  ssm_tx              transaction;
  na_ssm_status_t     status;
  na_return_t         result;
  ssm_cb_t            ssm_callback;
  
  union {
    struct ssm_msg_send_unexpected send_unexpected;
    struct ssm_msg_send_expected send_expected;
    struct ssm_msg_recv_expected recv_expected;
    struct ssm_msg_recv_unexpected recv_unexpected;
    struct ssm_get get;
  } info;
};

#endif /* NA_SSM_H */
