/*
 * Copyright (C) 2013 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#include "test_scale.h"

#include "na_mpi.h"
#include "mercury_handler.h"
#include "mercury_bulk.h"
#include "mercury_thread.h"
#include "mercury_thread_mutex.h"
#include "mercury_thread_pool.h"
#include "mercury_list.h"

#include "mercury_test_config.h"

#include <stdio.h>
#include <stdlib.h>

//#define SPAWN_REQUEST_THREAD /* want to spawn threads */
#define USE_THREAD_POOL      /* use thread pool */
#define FORCE_MPI_PROGRESS   /* want to have mpi progress */
#define TRANSFER_BULK_DATA

static hg_bool_t finalizing = 0;

#if defined(SPAWN_REQUEST_THREAD)
static hg_list_entry_t *thread_list;
#elif defined(USE_THREAD_POOL)
static hg_thread_pool_t *thread_pool = NULL;
#endif

/**
 *
 */
/*
static size_t
bla_write_check(const void *buf, size_t nbyte)
{
    int i;
    int *bulk_buf = (int*) buf;

    for (i = 0; i < (int)(nbyte / sizeof(int)); i++) {
        if (bulk_buf[i] != i) {
            printf("Error detected in bulk transfer, bulk_buf[%d] = %d, "
                    "was expecting %d!\n", i, bulk_buf[i], i);
            break;
        }
    }
    return nbyte;
}
*/

/**
 *
 */
static hg_return_t
server_finalize(hg_handle_t handle)
{
    hg_return_t ret = HG_SUCCESS;

    finalizing = 1;

    /* Free handle and send response back */
    ret = HG_Handler_start_output(handle, NULL);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not respond\n");
        return ret;
    }

    return ret;
}

/**
 *
 */
static hg_return_t
bla_open_rpc(hg_handle_t handle)
{
    hg_return_t ret = HG_SUCCESS;

    bla_open_in_t  bla_open_in_struct;
    bla_open_out_t bla_open_out_struct;


    /* Get input parameters and data */
    ret = HG_Handler_get_input(handle, &bla_open_in_struct);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not get input\n");
        return ret;
    }

    /* Free handle and send response back */
    ret = HG_Handler_start_output(handle, &bla_open_out_struct);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not start response\n");
        return ret;
    }

    return ret;
}

/**
 *
 */
static hg_return_t
bla_write_rpc(hg_handle_t handle)
{
    hg_return_t ret = HG_SUCCESS;

    bla_write_in_t  bla_write_in_struct;
    bla_write_out_t bla_write_out_struct;

    na_addr_t source = HG_Handler_get_addr(handle);
    hg_bulk_t bla_write_bulk_handle = HG_BULK_NULL;
    hg_bulk_block_t bla_write_bulk_block_handle;
    hg_bulk_request_t bla_write_bulk_request;
    size_t bla_write_nbytes;

    void *bla_write_buf;
    size_t bla_write_ret = 0;

    /* Get input parameters and data */
    ret = HG_Handler_get_input(handle, &bla_write_in_struct);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not get input\n");
        return ret;
    }

    /* Get parameters */
    bla_write_bulk_handle = bla_write_in_struct.bulk_handle;

    /* Create a new block handle to read the data */
    bla_write_nbytes = HG_Bulk_handle_get_size(bla_write_bulk_handle);

#ifdef TRANSFER_BULK_DATA
    bla_write_buf = malloc(bla_write_nbytes);

    HG_Bulk_block_handle_create(bla_write_buf, bla_write_nbytes,
            HG_BULK_READWRITE, &bla_write_bulk_block_handle);

    ret = HG_Bulk_read_all(source, bla_write_bulk_handle,
            bla_write_bulk_block_handle, &bla_write_bulk_request);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not read bulk data\n");
        return ret;
    }

    ret = HG_Bulk_wait(bla_write_bulk_request,
            HG_MAX_IDLE_TIME, HG_STATUS_IGNORE);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not complete bulk data read\n");
        return ret;
    }

    /* Free block handles */
    ret = HG_Bulk_block_handle_free(bla_write_bulk_block_handle);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not free block call\n");
        return ret;
    }

    free(bla_write_buf);
#endif

    bla_write_ret = bla_write_nbytes;

    /* Fill output structure */
    bla_write_out_struct.ret = bla_write_ret;

    /* Free handle and send response back */
    ret = HG_Handler_start_output(handle, &bla_write_out_struct);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not start response\n");
        return ret;
    }

    return ret;
}

/* Thread to handle request */
static HG_THREAD_RETURN_TYPE
bla_open_rpc_thread(void *arg)
{
    hg_handle_t handle = (hg_handle_t) arg;

    bla_open_rpc(handle);

    return NULL;
}

/* Thread to handle request */
static HG_THREAD_RETURN_TYPE
bla_write_rpc_thread(void *arg)
{
    hg_handle_t handle = (hg_handle_t) arg;

    bla_write_rpc(handle);

    return NULL;
}

/**
 *
 */
static hg_return_t
bla_open_rpc_spawn(hg_handle_t handle)
{
    hg_return_t ret = HG_SUCCESS;

#if defined(SPAWN_REQUEST_THREAD)
    hg_thread_t thread;

    hg_thread_create(&thread, bla_open_rpc_thread, handle);
    hg_list_append(&thread_list, (hg_list_value_t)thread);
#elif defined(USE_THREAD_POOL)
    hg_thread_pool_post(thread_pool, bla_open_rpc_thread, handle);
#else
    bla_open_rpc_thread(handle);
#endif

    return ret;
}

/**
 *
 */
static hg_return_t
bla_write_rpc_spawn(hg_handle_t handle)
{
    hg_return_t ret = HG_SUCCESS;

#if defined(SPAWN_REQUEST_THREAD)
    hg_thread_t thread;

    hg_thread_create(&thread, bla_write_rpc_thread, handle);
    hg_list_append(&thread_list, (hg_list_value_t)thread);
#elif defined(USE_THREAD_POOL)
    hg_thread_pool_post(thread_pool, bla_write_rpc_thread, handle);
#else
    bla_write_rpc_thread(handle);
#endif

    return ret;
}

/**
 *
 */
int
main(int argc, char *argv[])
{
    na_class_t *network_class = NULL;
    int hg_ret, na_ret;
    MPI_Comm split_comm;
    int color, global_rank, provided;
#ifdef SPAWN_REQUEST_THREAD
    hg_list_iter_t list_iterator;
#endif

    printf("# Starting server with %d threads...\n", MERCURY_TESTING_NUM_THREADS);

    /* Used by Test Driver */
    printf("# Waiting for client...\n");
    fflush(stdout);

    /* Initialize the interface */
    /* Need a MPI_THREAD_MULTIPLE level for threads */
    MPI_Init_thread(&argc, &argv, MPI_THREAD_MULTIPLE, &provided);

    MPI_Comm_rank(MPI_COMM_WORLD, &global_rank);
    /* Color is 1 for server, 2 for client */
    color = 1;
    MPI_Comm_split(MPI_COMM_WORLD, color, global_rank, &split_comm);

    network_class = NA_MPI_Init(&split_comm, MPI_INIT_SERVER_STATIC);

    hg_ret = HG_Handler_init(network_class);
    if (hg_ret != HG_SUCCESS) {
        fprintf(stderr, "Could not initialize Mercury handler\n");
        return EXIT_FAILURE;
    }

#ifdef USE_THREAD_POOL
    hg_thread_pool_init(MERCURY_TESTING_NUM_THREADS, &thread_pool);
#endif

    /* Register routine */
    MERCURY_HANDLER_REGISTER("bla_open", bla_open_rpc_spawn,
            bla_open_in_t, bla_write_out_t);
    MERCURY_HANDLER_REGISTER("bla_write", bla_write_rpc_spawn,
            bla_write_in_t, bla_write_out_t);
    MERCURY_HANDLER_REGISTER("finalize", server_finalize, void, void);

    while (!finalizing) {
        hg_status_t status;

        /* Receive new function calls */
        hg_ret = HG_Handler_process(0, &status);
        if (hg_ret == HG_SUCCESS && status) {
            /* printf("# Request processed\n"); */
        }
    }

    printf("# Finalizing...\n");

#if defined(SPAWN_REQUEST_THREAD)
    /* Wait for all threads to have joined */
    hg_list_iterate(&thread_list, &list_iterator);
    while (hg_list_iter_has_more(&list_iterator)) {
        hg_thread_t thread;

        thread = (hg_thread_t) hg_list_iter_next(&list_iterator);
        hg_thread_join(thread);
        hg_list_iter_remove(&list_iterator);
    }
#elif defined(USE_THREAD_POOL)
    hg_thread_pool_destroy(thread_pool);
#endif

    hg_ret = HG_Handler_finalize();
    if (hg_ret != HG_SUCCESS) {
        fprintf(stderr, "Could not finalize Mercury handler\n");
        return EXIT_FAILURE;
    }

    na_ret = NA_Finalize(network_class);
    if (na_ret != NA_SUCCESS) {
        fprintf(stderr, "Could not finalize NA interface\n");
        return EXIT_FAILURE;
    }

    MPI_Comm_free(&split_comm);
    MPI_Finalize();

    return EXIT_SUCCESS;
}
