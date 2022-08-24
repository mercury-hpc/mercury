/**
 * Copyright (c) 2013-2022 UChicago Argonne, LLC and The HDF Group.
 * Copyright (c) 2022 Intel Corporation.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef NA_TEST_PERF_H
#define NA_TEST_PERF_H

#include "na_test.h"

#include "mercury_param.h"
#include "mercury_poll.h"
#include "mercury_request.h" /* For convenience */
#include "mercury_time.h"

#include <stdlib.h>
#include <string.h>

/*************************************/
/* Public Type and Struct Definition */
/*************************************/

struct na_test_perf_info {
    struct na_test_info na_test_info;  /* NA test info */
    na_class_t *na_class;              /* NA class */
    na_context_t *context;             /* NA context */
    hg_poll_set_t *poll_set;           /* Poll set */
    hg_request_class_t *request_class; /* Request class */
    na_addr_t target_addr;             /* Target address */
    void *msg_unexp_buf;               /* Expected msg buffer */
    void *msg_exp_buf;                 /* Unexpected msg buffer */
    void *msg_unexp_data;              /* Plugin data */
    void *msg_exp_data;                /* Plugin data */
    na_op_id_t *msg_unexp_op_id;       /* Msg unexpected op ID */
    na_op_id_t *msg_exp_op_id;         /* Msg expected op ID */
    void *rma_buf;                     /* RMA buffer */
    void *verify_buf;                  /* Verify buffer */
    na_mem_handle_t local_handle;      /* Local handle */
    na_mem_handle_t remote_handle;     /* Remote handle */
    na_mem_handle_t verify_handle;     /* Local handle to verify buffer */
    na_op_id_t **rma_op_ids;           /* RMA op IDs */
    size_t msg_unexp_header_size;      /* Header size */
    size_t msg_exp_header_size;        /* Header size */
    size_t msg_unexp_size_max;         /* Max buffer size */
    size_t msg_exp_size_max;           /* Max buffer size */
    size_t rma_size_min;               /* Min buffer size */
    size_t rma_size_max;               /* Max buffer size */
    size_t rma_count;                  /* Buffer count */
    hg_request_t *request;             /* Request */
    int poll_fd;                       /* Poll fd */
};

struct na_test_perf_rma_info {
    int32_t expected_count; /* Expected count */
    int32_t complete_count; /* Completed count */
    hg_request_t *request;  /* Request */
};

/*****************/
/* Public Macros */
/*****************/

#define NA_TEST_PERF_TAG_LAT_INIT 0
#define NA_TEST_PERF_TAG_LAT      1
#define NA_TEST_PERF_TAG_PUT      10
#define NA_TEST_PERF_TAG_GET      20
#define NA_TEST_PERF_TAG_DONE     111

#define NA_TEST_PERF_LAT_SKIP_SMALL 100
#define NA_TEST_PERF_LAT_SKIP_LARGE 10
#define NA_TEST_PERF_BW_SKIP_SMALL  10
#define NA_TEST_PERF_BW_SKIP_LARGE  2
#define NA_TEST_PERF_LARGE_SIZE     8192

/*********************/
/* Public Prototypes */
/*********************/

#ifdef __cplusplus
extern "C" {
#endif

int
na_test_perf_request_progress(unsigned int timeout, void *arg);

int
na_test_perf_request_trigger(
    unsigned int timeout, unsigned int *flag, void *arg);

void
na_test_perf_request_complete(const struct na_cb_info *na_cb_info);

void
na_test_perf_rma_request_complete(const struct na_cb_info *na_cb_info);

na_return_t
na_test_perf_init(
    int argc, char *argv[], bool listen, struct na_test_perf_info *info);

void
na_test_perf_cleanup(struct na_test_perf_info *info);

void
na_test_perf_print_header_lat(const struct na_test_perf_info *info,
    const char *benchmark, size_t min_size);

void
na_test_perf_print_lat(
    const struct na_test_perf_info *info, size_t buf_size, hg_time_t t);

void
na_test_perf_print_header_bw(
    const struct na_test_perf_info *info, const char *benchmark);

void
na_test_perf_print_bw(
    const struct na_test_perf_info *info, size_t buf_size, hg_time_t t);

void
na_test_perf_init_data(void *buf, size_t buf_size, size_t header_size);

na_return_t
na_test_perf_verify_data(const void *buf, size_t buf_size, size_t header_size);

na_return_t
na_test_perf_mem_handle_send(
    struct na_test_perf_info *info, na_addr_t src_addr, na_tag_t tag);

na_return_t
na_test_perf_mem_handle_recv(struct na_test_perf_info *info, na_tag_t tag);

na_return_t
na_test_perf_send_finalize(struct na_test_perf_info *info);

#ifdef __cplusplus
}
#endif

#endif /* NA_TEST_PERF_H */
