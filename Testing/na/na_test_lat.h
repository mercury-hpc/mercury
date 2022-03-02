/**
 * Copyright (c) 2013-2021 UChicago Argonne, LLC and The HDF Group.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef NA_TEST_LAT_H
#define NA_TEST_LAT_H

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

struct na_test_lat_info {
    struct na_test_info na_test_info;
    na_class_t *na_class;
    na_context_t *context;
    hg_poll_set_t *poll_set;
    hg_request_class_t *request_class;
    na_addr_t target_addr;
    void *send_buf;
    void *recv_buf;
    void *send_buf_data;
    void *recv_buf_data;
    na_op_id_t *send_op_id;
    na_op_id_t *recv_op_id;
    size_t header_size;
    size_t max_buf_size;
    hg_request_t *request;
    int poll_fd;
};

/*****************/
/* Public Macros */
/*****************/

#define NA_TEST_TAG_DONE 111

/*********************/
/* Public Prototypes */
/*********************/

#ifdef __cplusplus
extern "C" {
#endif

int
na_test_lat_request_progress(unsigned int timeout, void *arg);

int
na_test_lat_request_trigger(
    unsigned int timeout, unsigned int *flag, void *arg);

int
na_test_lat_request_complete(const struct na_cb_info *na_cb_info);

na_return_t
na_test_lat_init(
    int argc, char *argv[], bool listen, struct na_test_lat_info *info);

void
na_test_lat_cleanup(struct na_test_lat_info *info);

na_return_t
na_test_lat_verify_data(const void *buf, size_t buf_size, size_t header_size);

#ifdef __cplusplus
}
#endif

#endif /* NA_TEST_LAT_H */
