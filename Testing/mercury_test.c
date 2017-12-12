/*
 * Copyright (C) 2013-2017 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#include "mercury_test.h"
#include "na_test_getopt.h"
#include "mercury_rpc_cb.h"
#ifdef HG_TESTING_HAS_CRAY_DRC
# include <mercury_test_drc.h>
#endif

#include "mercury_hl.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/****************/
/* Local Macros */
/****************/

/************************************/
/* Local Type and Struct Definition */
/************************************/

/********************/
/* Local Prototypes */
/********************/

static void
hg_test_usage(const char *execname);

static void
hg_test_parse_options(int argc, char *argv[],
    struct hg_test_info *hg_test_info);

static hg_return_t
hg_test_finalize_rpc(struct hg_test_info *hg_test_info);

static hg_return_t
hg_test_finalize_rpc_cb(const struct hg_cb_info *callback_info);

static hg_return_t
hg_test_finalize_cb(hg_handle_t handle);

static void
hg_test_register(hg_class_t *hg_class);

/*******************/
/* Local Variables */
/*******************/

extern int na_test_opt_ind_g; /* token pointer */
extern const char *na_test_opt_arg_g; /* flag argument (or value) */
extern const char *na_test_short_opt_g;
extern const struct na_test_opt na_test_opt_g[];

/* test_rpc */
hg_id_t hg_test_rpc_open_id_g = 0;
hg_id_t hg_test_rpc_open_id_no_resp_g = 0;

/* test_bulk */
hg_id_t hg_test_bulk_write_id_g = 0;

/* test_bulk_seg */
hg_id_t hg_test_bulk_seg_write_id_g = 0;

/* test_pipeline */
hg_id_t hg_test_pipeline_write_id_g = 0;

/* test_posix */
hg_id_t hg_test_posix_open_id_g = 0;
hg_id_t hg_test_posix_write_id_g = 0;
hg_id_t hg_test_posix_read_id_g = 0;
hg_id_t hg_test_posix_close_id_g = 0;

/* test_perf */
hg_id_t hg_test_perf_rpc_id_g = 0;
hg_id_t hg_test_perf_rpc_lat_id_g = 0;
hg_id_t hg_test_perf_bulk_id_g = 0;
hg_id_t hg_test_perf_bulk_write_id_g = 0;
hg_id_t hg_test_perf_bulk_read_id_g = 0;

/* test_overflow */
hg_id_t hg_test_overflow_id_g = 0;

/* test_nested */
hg_id_t hg_test_nested1_id_g = 0;
hg_id_t hg_test_nested2_id_g = 0;

/* test_finalize */
static hg_id_t hg_test_finalize_id_g = 0;

/*---------------------------------------------------------------------------*/
static void
hg_test_usage(const char *execname)
{
    na_test_usage(execname);
}

/*---------------------------------------------------------------------------*/
static void
hg_test_parse_options(int argc, char *argv[], struct hg_test_info *hg_test_info)
{
    int opt;

    /* Parse pre-init info */
    if (argc < 2) {
        hg_test_usage(argv[0]);
        exit(1);
    }

    while ((opt = na_test_getopt(argc, argv, na_test_short_opt_g,
        na_test_opt_g)) != EOF) {
        switch (opt) {
            case 'h':
                hg_test_usage(argv[0]);
                exit(1);
            case 'l':
                /* listen */
                hg_test_info->listen = NA_TRUE;
                break;
            case 'S':
                /* self */
                hg_test_info->self_forward = HG_TRUE;
                break;
            case 'a':
                /* auth service */
                hg_test_info->auth = HG_TRUE;
                break;
            default:
                break;
        }
    }
    na_test_opt_ind_g = 1;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_test_finalize_rpc(struct hg_test_info *hg_test_info)
{
    hg_request_t *request_object = NULL;
    hg_handle_t handle;
    hg_return_t ret = HG_SUCCESS;

    request_object = hg_request_create(hg_test_info->request_class);

    ret = HG_Create(hg_test_info->context, hg_test_info->target_addr,
        hg_test_finalize_id_g, &handle);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not create HG handle");
        goto done;
    }

    /* Forward call to target addr */
    ret = HG_Forward(handle, hg_test_finalize_rpc_cb, request_object, NULL);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not forward finalize call");
        goto done;
    }

    hg_request_wait(request_object, HG_MAX_IDLE_TIME, NULL);

    /* Complete */
    ret = HG_Destroy(handle);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not destroy handle");
        goto done;
    }

done:
    hg_request_destroy(request_object);

    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_test_finalize_rpc_cb(const struct hg_cb_info *callback_info)
{
    hg_request_t *request_object =
            (hg_request_t *) callback_info->arg;

    hg_request_complete(request_object);

    return HG_SUCCESS;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_test_finalize_cb(hg_handle_t handle)
{
    struct hg_test_info *hg_test_info =
        (struct hg_test_info *) HG_Class_get_data(HG_Get_info(handle)->hg_class);
    hg_return_t ret = HG_SUCCESS;

    /* Increment finalize count */
    hg_atomic_incr32(&hg_test_info->finalizing_count);

    /* Free handle and send response back */
    ret = HG_Respond(handle, NULL, NULL, NULL);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not respond");
        goto done;
    }

    ret = HG_Destroy(handle);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not destroy handle");
        goto done;
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static void
hg_test_register(hg_class_t *hg_class)
{
    /* test_rpc */
    hg_test_rpc_open_id_g = MERCURY_REGISTER(hg_class, "hg_test_rpc_open",
            rpc_open_in_t, rpc_open_out_t, hg_test_rpc_open_cb);

    /* Disable response */
    hg_test_rpc_open_id_no_resp_g = MERCURY_REGISTER(hg_class,
        "hg_test_rpc_open_no_resp", rpc_open_in_t, rpc_open_out_t,
        hg_test_rpc_open_no_resp_cb);
    HG_Registered_disable_response(hg_class, hg_test_rpc_open_id_no_resp_g,
        HG_TRUE);

    /* test_bulk */
    hg_test_bulk_write_id_g = MERCURY_REGISTER(hg_class, "hg_test_bulk_write",
            bulk_write_in_t, bulk_write_out_t, hg_test_bulk_write_cb);

    /* test_bulk_seg */
    hg_test_bulk_seg_write_id_g = MERCURY_REGISTER(hg_class,
            "hg_test_bulk_seg_write", bulk_write_in_t, bulk_write_out_t,
            hg_test_bulk_seg_write_cb);

#ifndef _WIN32
    /* test_posix */
    hg_test_posix_open_id_g = MERCURY_REGISTER(hg_class, "hg_test_posix_open",
            open_in_t, open_out_t, hg_test_posix_open_cb);
    hg_test_posix_write_id_g = MERCURY_REGISTER(hg_class, "hg_test_posix_write",
            write_in_t, write_out_t, hg_test_posix_write_cb);
    hg_test_posix_read_id_g = MERCURY_REGISTER(hg_class, "hg_test_posix_read",
            read_in_t, read_out_t, hg_test_posix_read_cb);
    hg_test_posix_close_id_g = MERCURY_REGISTER(hg_class, "hg_test_posix_close",
            close_in_t, close_out_t, hg_test_posix_close_cb);
#endif

    /* test_perf */
    hg_test_perf_rpc_id_g = MERCURY_REGISTER(hg_class, "hg_test_perf_rpc",
            void, void, hg_test_perf_rpc_cb);
    hg_test_perf_rpc_lat_id_g = MERCURY_REGISTER(hg_class,
            "hg_test_perf_rpc_lat", perf_rpc_lat_in_t, void,
            hg_test_perf_rpc_lat_cb);
    hg_test_perf_bulk_id_g = MERCURY_REGISTER(hg_class, "hg_test_perf_bulk",
            bulk_write_in_t, void, hg_test_perf_bulk_cb);
    hg_test_perf_bulk_write_id_g = hg_test_perf_bulk_id_g;
    hg_test_perf_bulk_read_id_g = MERCURY_REGISTER(hg_class,
            "hg_test_perf_bulk_read", bulk_write_in_t, void,
            hg_test_perf_bulk_read_cb);

    /* test_overflow */
    hg_test_overflow_id_g = MERCURY_REGISTER(hg_class, "hg_test_overflow",
            void, overflow_out_t, hg_test_overflow_cb);

    /* test_nested */
//    hg_test_nested1_id_g = MERCURY_REGISTER(hg_class, "hg_test_nested",
//            void, void, hg_test_nested1_cb);
//    hg_test_nested2_id_g = MERCURY_REGISTER(hg_class, "hg_test_nested_forward",
//            void, void, hg_test_nested2_cb);

    /* test_finalize */
    hg_test_finalize_id_g = MERCURY_REGISTER(hg_class, "hg_test_finalize",
            void, void, hg_test_finalize_cb);
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Test_init(int argc, char *argv[], struct hg_test_info *hg_test_info)
{
    struct hg_init_info hg_init_info;
    hg_return_t ret = HG_SUCCESS;

    /* Get HG test options */
    hg_test_parse_options(argc, argv, hg_test_info);

    if (hg_test_info->auth) {
#ifdef HG_TESTING_HAS_CRAY_DRC
        char hg_test_drc_key[NA_TEST_MAX_ADDR_NAME] = { '\0' };

        ret = hg_test_drc_acquire(argc, argv, hg_test_info);
        if (ret != HG_SUCCESS) {
            HG_LOG_ERROR("Could not acquire DRC auth key");
            goto done;
        }
        sprintf(hg_test_drc_key, "%u", hg_test_info->cookie);
        hg_test_info->na_test_info.key = strdup(hg_test_drc_key);
#endif
    }

    /* Initialize NA test layer */
    hg_test_info->na_test_info.extern_init = NA_TRUE;
    if (NA_Test_init(argc, argv, &hg_test_info->na_test_info) != NA_SUCCESS) {
        HG_LOG_ERROR("Could not initialize NA test layer");
        ret = HG_NA_ERROR;
        goto done;
    }

    memset(&hg_init_info, 0, sizeof(struct hg_init_info));

    /* Assign NA class */
    hg_init_info.na_class = hg_test_info->na_test_info.na_class;

    /* Set progress mode */
#ifdef MERCURY_TESTING_HAS_BUSY_WAIT
    hg_init_info.na_init_info.progress_mode = NA_NO_BLOCK;
#else
    hg_init_info.na_init_info.progress_mode = NA_DEFAULT;
#endif

    /* Init HG HL with init options */
    ret = HG_Hl_init_opt(NULL, 0, &hg_init_info);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not initialize HG HL");
        goto done;
    }
    hg_test_info->hg_class = HG_CLASS_DEFAULT;
    hg_test_info->context = HG_CONTEXT_DEFAULT;
    hg_test_info->request_class = HG_REQUEST_CLASS_DEFAULT;

    /* Attach test info to class */
    HG_Class_set_data(hg_test_info->hg_class, hg_test_info, NULL);

    /* Register routines */
    hg_test_register(hg_test_info->hg_class);

    if (hg_test_info->listen || hg_test_info->self_forward) {
        size_t bulk_size = 1024 * 1024 * MERCURY_TESTING_BUFFER_SIZE;
        char *buf_ptr;
        size_t i;

#ifdef MERCURY_TESTING_HAS_THREAD_POOL
        /* Create thread pool */
        hg_thread_pool_init(MERCURY_TESTING_NUM_THREADS,
            &hg_test_info->thread_pool);
        printf("# Starting server with %d threads...\n",
            MERCURY_TESTING_NUM_THREADS);

        /* Create bulk handle mutex */
        hg_thread_mutex_init(&hg_test_info->bulk_handle_mutex);
#endif

        /* Create bulk buffer that can be used for receiving data */
        HG_Bulk_create(hg_test_info->hg_class, 1, NULL,
            (hg_size_t *) &bulk_size, HG_BULK_READWRITE,
            &hg_test_info->bulk_handle);
        HG_Bulk_access(hg_test_info->bulk_handle, 0, bulk_size,
            HG_BULK_READWRITE, 1, (void **) &buf_ptr, NULL, NULL);
        for (i = 0; i < bulk_size; i++)
            buf_ptr[i] = (char) i;
    }

    if (hg_test_info->listen) {
        /* Initalize atomic variable to finalize server */
        hg_atomic_set32(&hg_test_info->finalizing_count, 0);

        /* Used by CTest Test Driver to know when to launch clients */
        MERCURY_TESTING_READY_MSG();
    } else if (hg_test_info->self_forward) {
        /* Self addr is target */
        ret = HG_Addr_self(hg_test_info->hg_class, &hg_test_info->target_addr);
        if (ret != HG_SUCCESS) {
            HG_LOG_ERROR("Could not get HG addr self");
            goto done;
        }
    } else {
        /* Look up target addr using target name info */
        ret = HG_Hl_addr_lookup_wait(hg_test_info->context,
            hg_test_info->request_class, hg_test_info->na_test_info.target_name,
            &hg_test_info->target_addr, HG_MAX_IDLE_TIME);
        if (ret != HG_SUCCESS) {
            HG_LOG_ERROR("Could not find addr for target %s",
                hg_test_info->na_test_info.target_name);
            goto done;
        }
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Test_finalize(struct hg_test_info *hg_test_info)
{
    hg_return_t ret = HG_SUCCESS;
    na_return_t na_ret;

    NA_Test_barrier(&hg_test_info->na_test_info);

    if (!hg_test_info->listen) {
        /* Send request to terminate server */
        if (hg_test_info->na_test_info.mpi_comm_rank == 0)
            hg_test_finalize_rpc(hg_test_info);

        /* Free addr id */
        ret = HG_Addr_free(hg_test_info->hg_class, hg_test_info->target_addr);
        if (ret != HG_SUCCESS) {
            HG_LOG_ERROR("Could not free addr");
            goto done;
        }
    }

    NA_Test_barrier(&hg_test_info->na_test_info);

    if (hg_test_info->listen || hg_test_info->self_forward) {
        /* Destroy bulk handle */
        HG_Bulk_free(hg_test_info->bulk_handle);

#ifdef MERCURY_TESTING_HAS_THREAD_POOL
        hg_thread_pool_destroy(hg_test_info->thread_pool);
        hg_thread_mutex_destroy(&hg_test_info->bulk_handle_mutex);
#endif
    }

    /* Finalize interface */
    ret = HG_Hl_finalize();
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not finalize HG Hl");
        goto done;
    }

    /* Finalize NA test interface */
    na_ret = NA_Test_finalize(&hg_test_info->na_test_info);
    if (na_ret != NA_SUCCESS) {
        HG_LOG_ERROR("Could not finalize NA test interface");
        ret = HG_NA_ERROR;
        goto done;
    }

    if (hg_test_info->auth) {
#ifdef HG_TESTING_HAS_CRAY_DRC
        hg_test_drc_release(hg_test_info);
#endif
    }

done:
     return ret;
}
