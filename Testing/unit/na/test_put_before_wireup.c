/**
 * Copyright (c) 2013-2022 UChicago Argonne, LLC and The HDF Group.
 * Copyright (c) 2022-2024 Intel Corporation.
 * Copyright (c) 2024-2025 Hewlett Packard Enterprise Development LP.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*
 * Post an NA_Put() to a peer that was just looked up, before any progress, so
 * that UCX queues the put until the EP finishes wireup and completes it while
 * replaying its pending requests, then check that the data arrived.
 *
 * Only an RDMA transport defers the put, e.g.:
 *   na_test_put_before_wireup ucx+rc_v://mlx5_0:1/<ip>
 */

#include "na.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/****************/
/* Local Macros */
/****************/

#define BUF_SIZE (4096)
#define PUT_SIZE (8)

#define CHECK_NA(_call, _what)                                                 \
    do {                                                                       \
        na_return_t _ret = (_call);                                            \
        if (_ret != NA_SUCCESS) {                                              \
            fprintf(                                                           \
                stderr, "%s failed (%s)\n", _what, NA_Error_to_string(_ret));  \
            exit(EXIT_FAILURE);                                                \
        }                                                                      \
    } while (0)

/************************************/
/* Local Type and Struct Definition */
/************************************/

struct test_class {
    na_class_t *na_class;
    na_context_t *context;
};

/*******************/
/* Local Variables */
/*******************/

static struct test_class origin, target;
static bool completed;

/*---------------------------------------------------------------------------*/
static void
test_init(struct test_class *tc, const char *info)
{
    tc->na_class = NA_Initialize(info, true);
    if (tc->na_class == NULL) {
        fprintf(stderr, "NA_Initialize(%s) failed\n", info);
        exit(EXIT_FAILURE);
    }
    tc->context = NA_Context_create(tc->na_class);
    if (tc->context == NULL) {
        fprintf(stderr, "NA_Context_create() failed\n");
        exit(EXIT_FAILURE);
    }
}

/*---------------------------------------------------------------------------*/
static void
test_put_cb(const struct na_cb_info *callback_info)
{
    CHECK_NA(callback_info->ret, "NA_Put() completion");
    completed = true;
}

/*---------------------------------------------------------------------------*/
static void
test_progress(struct test_class *tc)
{
    unsigned int count;

    CHECK_NA(NA_Poll(tc->na_class, tc->context, &count), "NA_Poll()");
    NA_Trigger(tc->context, 16, &count);
}

/*---------------------------------------------------------------------------*/
static void
test_put(na_mem_handle_t *local, na_mem_handle_t *remote, size_t length,
    na_addr_t *addr)
{
    na_op_id_t *op_id = NA_Op_create(origin.na_class, NA_OP_SINGLE);

    if (op_id == NULL) {
        fprintf(stderr, "NA_Op_create() failed\n");
        exit(EXIT_FAILURE);
    }
    CHECK_NA(NA_Put(origin.na_class, origin.context, test_put_cb, NULL, local,
                 0, remote, 0, length, addr, 0, op_id),
        "NA_Put()");

    while (!completed) {
        test_progress(&origin);
        test_progress(&target);
    }
    NA_Op_destroy(origin.na_class, op_id);
}

/*---------------------------------------------------------------------------*/
static na_mem_handle_t *
test_mem_register(struct test_class *tc, void *buf)
{
    na_mem_handle_t *mem_handle;

    CHECK_NA(NA_Mem_handle_create(
                 tc->na_class, buf, BUF_SIZE, NA_MEM_READWRITE, &mem_handle),
        "NA_Mem_handle_create()");
    CHECK_NA(NA_Mem_register(tc->na_class, mem_handle, NA_MEM_TYPE_HOST, 0),
        "NA_Mem_register()");

    return mem_handle;
}

/*---------------------------------------------------------------------------*/
int
main(int argc, char *argv[])
{
    const char *info = (argc > 1) ? argv[1] : "ucx+all://127.0.0.1";
    char addr_string[256], *buf;
    size_t addr_string_len = sizeof(addr_string), buf_len, i;
    na_mem_handle_t *local_handle, *target_handle, *remote_handle;
    na_addr_t *target_self, *target_addr;
    uint8_t *local_buf, *target_buf, *expected_buf;

    test_init(&origin, info);
    test_init(&target, info);

    local_buf = malloc(BUF_SIZE);
    target_buf = malloc(BUF_SIZE);
    expected_buf = malloc(BUF_SIZE);
    if (local_buf == NULL || target_buf == NULL || expected_buf == NULL) {
        fprintf(stderr, "malloc() failed\n");
        return EXIT_FAILURE;
    }
    for (i = 0; i < BUF_SIZE; i++)
        expected_buf[i] = (uint8_t) (i * 7 + 1);
    memcpy(local_buf, expected_buf, BUF_SIZE);
    memset(target_buf, 0, BUF_SIZE);

    local_handle = test_mem_register(&origin, local_buf);
    target_handle = test_mem_register(&target, target_buf);

    /* The remote handle reaches the origin serialized, as in an RPC */
    buf_len = NA_Mem_handle_get_serialize_size(target.na_class, target_handle);
    buf = malloc(buf_len);
    if (buf == NULL) {
        fprintf(stderr, "malloc() failed\n");
        return EXIT_FAILURE;
    }
    CHECK_NA(
        NA_Mem_handle_serialize(target.na_class, buf, buf_len, target_handle),
        "NA_Mem_handle_serialize()");
    CHECK_NA(NA_Mem_handle_deserialize(
                 origin.na_class, &remote_handle, buf, buf_len),
        "NA_Mem_handle_deserialize()");

    CHECK_NA(NA_Addr_self(target.na_class, &target_self), "NA_Addr_self()");
    CHECK_NA(NA_Addr_to_string(
                 target.na_class, addr_string, &addr_string_len, target_self),
        "NA_Addr_to_string()");
    CHECK_NA(NA_Addr_lookup(origin.na_class, addr_string, &target_addr),
        "NA_Addr_lookup()");

    /* No progress yet: the put waits for the EP to finish wireup */
    test_put(local_handle, remote_handle, PUT_SIZE, target_addr);
    if (memcmp(target_buf, expected_buf, PUT_SIZE) != 0) {
        fprintf(stderr, "bad data after put\n");
        return EXIT_FAILURE;
    }

    NA_Addr_free(origin.na_class, target_addr);
    NA_Addr_free(target.na_class, target_self);
    NA_Mem_handle_free(origin.na_class, remote_handle);
    NA_Mem_deregister(origin.na_class, local_handle);
    NA_Mem_handle_free(origin.na_class, local_handle);
    NA_Mem_deregister(target.na_class, target_handle);
    NA_Mem_handle_free(target.na_class, target_handle);
    NA_Context_destroy(origin.na_class, origin.context);
    NA_Context_destroy(target.na_class, target.context);
    NA_Finalize(origin.na_class);
    NA_Finalize(target.na_class);
    free(buf);
    free(local_buf);
    free(target_buf);
    free(expected_buf);

    printf("PASS\n");

    return EXIT_SUCCESS;
}
