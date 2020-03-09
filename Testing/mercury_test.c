/*
 * Copyright (C) 2013-2019 Argonne National Laboratory, Department of Energy,
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
#ifdef HG_TEST_HAS_CRAY_DRC
# include <mercury_test_drc.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/****************/
/* Local Macros */
/****************/

/************************************/
/* Local Type and Struct Definition */
/************************************/

struct hg_test_lookup_arg {
    hg_addr_t *addr_ptr;
    hg_request_t *request;
};

/********************/
/* Local Prototypes */
/********************/

static void
hg_test_usage(const char *execname);

void
hg_test_parse_options(int argc, char *argv[],
    struct hg_test_info *hg_test_info);

static int
hg_test_request_progress(unsigned int timeout, void *arg);

static int
hg_test_request_trigger(unsigned int timeout, unsigned int *flag, void *arg);

#ifdef HG_TEST_HAS_THREAD_POOL
static hg_return_t
hg_test_handle_create_cb(hg_handle_t handle, void *arg);
#endif

static hg_return_t
hg_test_addr_lookup_cb(const struct hg_cb_info *callback_info);

static hg_return_t
hg_test_finalize_rpc(struct hg_test_info *hg_test_info, hg_uint8_t target_id);

static hg_return_t
hg_test_finalize_rpc_cb(const struct hg_cb_info *callback_info);

static hg_return_t
hg_test_finalize_cb(hg_handle_t handle);

static void
hg_test_register(hg_class_t *hg_class);

/*******************/
/* Local Variables */
/*******************/

/* Default error log mask */
#ifdef HG_HAS_VERBOSE_ERROR
unsigned int HG_TEST_LOG_MASK = HG_LOG_TYPE_ERROR | HG_LOG_TYPE_WARNING;
#endif

extern int na_test_opt_ind_g; /* token pointer */
extern const char *na_test_opt_arg_g; /* flag argument (or value) */
extern const char *na_test_short_opt_g;
extern const struct na_test_opt na_test_opt_g[];

/* test_rpc */
hg_id_t hg_test_rpc_open_id_g = 0;
hg_id_t hg_test_rpc_open_id_no_resp_g = 0;
hg_id_t hg_test_overflow_id_g = 0;
hg_id_t hg_test_cancel_rpc_id_g = 0;

/* test_bulk */
hg_id_t hg_test_bulk_write_id_g = 0;
hg_id_t hg_test_bulk_bind_write_id_g = 0;

/* test_perf */
hg_id_t hg_test_perf_rpc_id_g = 0;
hg_id_t hg_test_perf_rpc_lat_id_g = 0;
hg_id_t hg_test_perf_bulk_id_g = 0;
hg_id_t hg_test_perf_bulk_write_id_g = 0;
hg_id_t hg_test_perf_bulk_read_id_g = 0;

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
void
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
            case 'a': /* auth service */
                hg_test_info->auth = HG_TRUE;
                break;
#ifdef HG_TEST_HAS_CRAY_DRC
            case 'k': /* auth key */
                hg_test_info->credential = (uint32_t) atoi(na_test_opt_arg_g);
#endif
                break;
            case 'm': /* memory */
                hg_test_info->auto_sm = HG_TRUE;
                break;
            case 't': /* number of threads */
                hg_test_info->thread_count =
                    (unsigned int) atoi(na_test_opt_arg_g);
                break;
            default:
                break;
        }
    }
    na_test_opt_ind_g = 1;

    if (!hg_test_info->thread_count)
        hg_test_info->thread_count = HG_TEST_NUM_THREADS_DEFAULT;
}

/*---------------------------------------------------------------------------*/
static int
hg_test_request_progress(unsigned int timeout, void *arg)
{
    hg_context_t *context = (hg_context_t *) arg;
    int ret = HG_UTIL_SUCCESS;

    if (HG_Progress(context, timeout) != HG_SUCCESS)
        ret = HG_UTIL_FAIL;

    return ret;
}

/*---------------------------------------------------------------------------*/
static int
hg_test_request_trigger(unsigned int timeout, unsigned int *flag, void *arg)
{
    hg_context_t *context = (hg_context_t *) arg;
    unsigned int actual_count = 0;
    int ret = HG_UTIL_SUCCESS;

    if (HG_Trigger(context, timeout, 1, &actual_count)
            != HG_SUCCESS) ret = HG_UTIL_FAIL;
    *flag = (actual_count) ? HG_UTIL_TRUE : HG_UTIL_FALSE;

    return ret;
}

/*---------------------------------------------------------------------------*/
#ifdef HG_TEST_HAS_THREAD_POOL
static hg_return_t
hg_test_handle_create_cb(hg_handle_t handle, void *arg)
{
    struct hg_thread_work *hg_thread_work;
    hg_return_t ret = HG_SUCCESS;

    hg_thread_work = malloc(sizeof(struct hg_thread_work));
    HG_TEST_CHECK_ERROR(hg_thread_work == NULL, done, ret, HG_NOMEM_ERROR,
        "Could not allocate hg_thread_work");

    (void) arg;
    HG_Set_data(handle, hg_thread_work, free);

done:
    return ret;
}
#endif

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_test_addr_lookup_cb(const struct hg_cb_info *callback_info)
{
    struct hg_test_lookup_arg *request_args =
            (struct hg_test_lookup_arg *) callback_info->arg;

    *request_args->addr_ptr = callback_info->info.lookup.addr;

    hg_request_complete(request_args->request);

    return HG_SUCCESS;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_test_finalize_rpc(struct hg_test_info *hg_test_info, hg_uint8_t target_id)
{
    hg_request_t *request_object = NULL;
    hg_handle_t handle = HG_HANDLE_NULL;
    hg_return_t ret = HG_SUCCESS;

    request_object = hg_request_create(hg_test_info->request_class);

    ret = HG_Create(hg_test_info->context, hg_test_info->target_addr,
        hg_test_finalize_id_g, &handle);
    HG_TEST_CHECK_HG_ERROR(done, ret, "HG_Create() failed (%s)",
        HG_Error_to_string(ret));

    /* Set target ID */
    ret = HG_Set_target_id(handle, target_id);
    HG_TEST_CHECK_HG_ERROR(done, ret, "HG_Set_target_id() failed (%s)",
        HG_Error_to_string(ret));

    /* Forward call to target addr */
    ret = HG_Forward(handle, hg_test_finalize_rpc_cb, request_object, NULL);
    HG_TEST_CHECK_HG_ERROR(done, ret, "HG_Forward() failed (%s)",
        HG_Error_to_string(ret));

    hg_request_wait(request_object, HG_MAX_IDLE_TIME, NULL);

done:
    ret = HG_Destroy(handle);
    HG_TEST_CHECK_ERROR_DONE(ret != HG_SUCCESS, "HG_Destroy() failed (%s)",
        HG_Error_to_string(ret));

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
    struct hg_test_context_info *hg_test_context_info =
        (struct hg_test_context_info *) HG_Context_get_data(
            HG_Get_info(handle)->context);
    hg_return_t ret = HG_SUCCESS;

    /* Set finalize for context data */
    hg_atomic_set32(&hg_test_context_info->finalizing, 1);

    /* Free handle and send response back */
    ret = HG_Respond(handle, NULL, NULL, NULL);
    HG_TEST_CHECK_HG_ERROR(done, ret, "HG_Respond() failed (%s)",
        HG_Error_to_string(ret));

done:
    ret = HG_Destroy(handle);
    HG_TEST_CHECK_ERROR_DONE(ret != HG_SUCCESS, "HG_Destroy() failed (%s)",
        HG_Error_to_string(ret));

    return ret;
}

/*---------------------------------------------------------------------------*/
static void
hg_test_register(hg_class_t *hg_class)
{
    /* test_rpc */
    hg_test_rpc_open_id_g = MERCURY_REGISTER(hg_class, "hg_test_rpc_open",
            rpc_open_in_t, rpc_open_out_t, hg_test_rpc_open_cb);
    hg_test_rpc_open_id_no_resp_g = MERCURY_REGISTER(hg_class,
        "hg_test_rpc_open_no_resp", rpc_open_in_t, rpc_open_out_t,
        hg_test_rpc_open_no_resp_cb);

    /* Disable response */
    HG_Registered_disable_response(hg_class, hg_test_rpc_open_id_no_resp_g,
        HG_TRUE);

    hg_test_overflow_id_g = MERCURY_REGISTER(hg_class, "hg_test_overflow",
            void, overflow_out_t, hg_test_overflow_cb);
    hg_test_cancel_rpc_id_g = MERCURY_REGISTER(hg_class, "hg_test_cancel_rpc",
            void, void, hg_test_cancel_rpc_cb);


    /* test_bulk */
    hg_test_bulk_write_id_g = MERCURY_REGISTER(hg_class, "hg_test_bulk_write",
            bulk_write_in_t, bulk_write_out_t, hg_test_bulk_write_cb);
    hg_test_bulk_bind_write_id_g = MERCURY_REGISTER(hg_class,
        "hg_test_bulk_bind_write", bulk_write_in_t, bulk_bind_write_out_t,
        hg_test_bulk_bind_write_cb);

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
    struct hg_init_info hg_init_info = HG_INIT_INFO_INITIALIZER;
    struct hg_test_context_info *hg_test_context_info;
    hg_return_t ret = HG_SUCCESS;
    na_return_t na_ret;
#ifdef HG_HAS_VERBOSE_ERROR
    const char *log_level = NULL;

    /* Set log level */
    log_level = getenv("HG_TEST_LOG_LEVEL");
    if (log_level && (strcmp(log_level, "debug") == 0))
        HG_TEST_LOG_MASK |= HG_LOG_TYPE_DEBUG;
#endif

    /* Get HG test options */
    hg_test_parse_options(argc, argv, hg_test_info);

    if (hg_test_info->auth) {
#ifdef HG_TEST_HAS_CRAY_DRC
        char hg_test_drc_key[NA_TEST_MAX_ADDR_NAME] = { '\0' };

        ret = hg_test_drc_acquire(argc, argv, hg_test_info);
        HG_TEST_CHECK_HG_ERROR(done, ret, "hg_test_drc_acquire() failed (%s)",
            HG_Error_to_string(ret));

        sprintf(hg_test_drc_key, "%u", hg_test_info->cookie);
        hg_test_info->na_test_info.key = strdup(hg_test_drc_key);
#endif
    }

    /* Initialize NA test layer */
    hg_test_info->na_test_info.extern_init = NA_TRUE;
    na_ret = NA_Test_init(argc, argv, &hg_test_info->na_test_info);
    HG_TEST_CHECK_ERROR(na_ret != NA_SUCCESS, done, ret, (hg_return_t) na_ret,
        "NA_Test_init() failed (%s)",  NA_Error_to_string(na_ret));

    /* Set progress mode */
    if (hg_test_info->na_test_info.busy_wait)
        hg_init_info.na_init_info.progress_mode = NA_NO_BLOCK;

    /* Set stats */
#ifdef HG_HAS_COLLECT_STATS
    hg_init_info.stats = HG_TRUE;
#endif

    /* Set max contexts */
    if (hg_test_info->na_test_info.max_contexts)
        hg_init_info.na_init_info.max_contexts =
            hg_test_info->na_test_info.max_contexts;

    /* Set auto SM mode */
    if (hg_test_info->auto_sm)
        hg_init_info.auto_sm = HG_TRUE;

    /* Assign NA class */
    hg_init_info.na_class = hg_test_info->na_test_info.na_class;

    /* Init HG with init options */
    hg_test_info->hg_class = HG_Init_opt(NULL,
        hg_test_info->na_test_info.listen, &hg_init_info);
    HG_TEST_CHECK_ERROR(hg_test_info->hg_class == NULL, done, ret, HG_FAULT,
        "HG_Init_opt() failed (%s)");

    /* Attach test info to class */
    ret = HG_Class_set_data(hg_test_info->hg_class, hg_test_info, NULL);
    HG_TEST_CHECK_HG_ERROR(done, ret, "HG_Class_set_data() failed (%s)",
        HG_Error_to_string(ret));

#ifdef HG_TEST_HAS_THREAD_POOL
    /* Attach handle created */
    ret = HG_Class_set_handle_create_callback(hg_test_info->hg_class,
        hg_test_handle_create_cb, hg_test_info->hg_class);
    HG_TEST_CHECK_HG_ERROR(done, ret,
        "HG_Class_set_handle_create_callback() failed (%s)",
        HG_Error_to_string(ret));
#endif

    /* Set header */
    /*
    HG_Class_set_input_offset(hg_test_info->hg_class, sizeof(hg_uint64_t));
    HG_Class_set_output_offset(hg_test_info->hg_class, sizeof(hg_uint64_t));
    */

    /* Create primary context */
    hg_test_info->context = HG_Context_create(hg_test_info->hg_class);
    HG_TEST_CHECK_ERROR(hg_test_info->context == NULL, done, ret, HG_FAULT,
        "Could not create HG context");

    /* Create additional contexts (do not exceed total max contexts) */
    if (hg_test_info->na_test_info.max_contexts > 1) {
        hg_uint8_t secondary_contexts_count = (hg_uint8_t)
                        (hg_test_info->na_test_info.max_contexts - 1);
        hg_uint8_t i;

        hg_test_info->secondary_contexts = malloc(
            secondary_contexts_count * sizeof(hg_context_t *));
        HG_TEST_CHECK_ERROR(hg_test_info->secondary_contexts == NULL, done,
            ret, HG_NOMEM_ERROR, "Could not allocate secondary contexts");
        for (i = 0; i < secondary_contexts_count; i++) {
            hg_uint8_t context_id = (hg_uint8_t) (i + 1);
            hg_test_info->secondary_contexts[i] =
                HG_Context_create_id(hg_test_info->hg_class, context_id);
            HG_TEST_CHECK_ERROR(hg_test_info->secondary_contexts[i] == NULL,
                done, ret, HG_FAULT, "HG_Context_create_id() failed");

            /* Attach context info to context */
            hg_test_context_info = malloc(
                sizeof(struct hg_test_context_info));
            HG_TEST_CHECK_ERROR(hg_test_context_info == NULL, done, ret,
                HG_NOMEM_ERROR, "Could not allocate HG test context info");

            hg_atomic_init32(&hg_test_context_info->finalizing, 0);
            ret = HG_Context_set_data(hg_test_info->secondary_contexts[i],
                hg_test_context_info, free);
            HG_TEST_CHECK_HG_ERROR(done, ret, "HG_Context_set_data() failed"
                " (%s)", HG_Error_to_string(ret));
        }
    }

    /* Create request class */
    hg_test_info->request_class = hg_request_init(hg_test_request_progress,
        hg_test_request_trigger, hg_test_info->context);
    HG_TEST_CHECK_ERROR(hg_test_info->request_class == NULL, done, ret,
        HG_FAULT, "Could not create request class");

    /* Attach context info to context */
    hg_test_context_info = malloc(sizeof(struct hg_test_context_info));
    HG_TEST_CHECK_ERROR(hg_test_context_info == NULL, done, ret, HG_NOMEM_ERROR,
        "Could not allocate HG test context info");

    hg_atomic_init32(&hg_test_context_info->finalizing, 0);
    ret = HG_Context_set_data(hg_test_info->context, hg_test_context_info, free);
    HG_TEST_CHECK_HG_ERROR(done, ret, "HG_Context_set_data() failed (%s)",
        HG_Error_to_string(ret));

    /* Register routines */
    hg_test_register(hg_test_info->hg_class);

    if (hg_test_info->na_test_info.listen
        || hg_test_info->na_test_info.self_send) {
        size_t bulk_size = 1024 * 1024 * HG_TEST_BUFFER_SIZE;
        char *buf_ptr;
        size_t i;

#ifdef HG_TEST_HAS_THREAD_POOL
        /* Make sure that thread count is at least max_contexts */
        if (hg_test_info->thread_count <
            hg_test_info->na_test_info.max_contexts)
            hg_test_info->thread_count =
                hg_test_info->na_test_info.max_contexts;

        /* Create thread pool */
        hg_thread_pool_init(hg_test_info->thread_count,
            &hg_test_info->thread_pool);
        printf("# Starting server with %d threads...\n",
            hg_test_info->thread_count);

        /* Create bulk handle mutex */
        hg_thread_mutex_init(&hg_test_info->bulk_handle_mutex);
#endif
        /* Create bulk buffer that can be used for receiving data */
        ret = HG_Bulk_create(hg_test_info->hg_class, 1, NULL,
            (hg_size_t *) &bulk_size, HG_BULK_READWRITE,
            &hg_test_info->bulk_handle);
        HG_TEST_CHECK_HG_ERROR(done, ret, "HG_Bulk_create() failed (%s)",
            HG_Error_to_string(ret));

        ret = HG_Bulk_access(hg_test_info->bulk_handle, 0, bulk_size,
            HG_BULK_READWRITE, 1, (void **) &buf_ptr, NULL, NULL);
        HG_TEST_CHECK_HG_ERROR(done, ret, "HG_Bulk_access() failed (%s)",
            HG_Error_to_string(ret));
        for (i = 0; i < bulk_size; i++)
            buf_ptr[i] = (char) i;
    }

    if (hg_test_info->na_test_info.listen) {
        char addr_string[NA_TEST_MAX_ADDR_NAME];
        na_size_t addr_string_len = NA_TEST_MAX_ADDR_NAME;
        hg_addr_t self_addr;

        /* TODO only rank 0 */
        ret = HG_Addr_self(hg_test_info->hg_class, &self_addr);
        HG_TEST_CHECK_HG_ERROR(done, ret, "HG_Addr_self() failed (%s)",
            HG_Error_to_string(ret));

        ret = HG_Addr_to_string(hg_test_info->hg_class, addr_string,
            &addr_string_len, self_addr);
        HG_TEST_CHECK_HG_ERROR(done, ret, "HG_Addr_to_string() failed (%s)",
            HG_Error_to_string(ret));

        ret = HG_Addr_free(hg_test_info->hg_class, self_addr);
        HG_TEST_CHECK_HG_ERROR(done, ret, "HG_Addr_free() failed (%s)",
            HG_Error_to_string(ret));

        na_test_set_config(addr_string);

#ifdef HG_TEST_HAS_PARALLEL
        /* If static client, must wait for server to write config file */
        if (hg_test_info->na_test_info.mpi_static)
            MPI_Barrier(MPI_COMM_WORLD);
#endif

        /* Used by CTest Test Driver to know when to launch clients */
        HG_TEST_READY_MSG();
    } else if (hg_test_info->na_test_info.self_send) {
        /* Self addr is target */
        ret = HG_Addr_self(hg_test_info->hg_class, &hg_test_info->target_addr);
        HG_TEST_CHECK_HG_ERROR(done, ret, "HG_Addr_self() failed (%s)",
            HG_Error_to_string(ret));
    } else {
        char test_addr_name[NA_TEST_MAX_ADDR_NAME] = { '\0' };
        hg_request_t *request = NULL;
        unsigned int flag = 0;
        struct hg_test_lookup_arg lookup_args;

#ifdef HG_TEST_HAS_PARALLEL
        /* If static client must wait for server to write config file */
        if (hg_test_info->na_test_info.mpi_static)
            MPI_Barrier(MPI_COMM_WORLD);
#endif

        if (hg_test_info->na_test_info.mpi_comm_rank == 0)
            na_test_get_config(test_addr_name, NA_TEST_MAX_ADDR_NAME);

        /* Broadcast addr name */
        NA_Test_bcast(test_addr_name, NA_TEST_MAX_ADDR_NAME, 0,
            &hg_test_info->na_test_info);

        hg_test_info->na_test_info.target_name = strdup(test_addr_name);
        HG_TEST_CHECK_ERROR(hg_test_info->na_test_info.target_name == NULL,
            done, ret, HG_NOMEM_ERROR, "Could not dup test_addr_name");
        printf("# Target name read: %s\n",
            hg_test_info->na_test_info.target_name);

        /* Look up target addr using target name info */
        request = hg_request_create(hg_test_info->request_class);
        lookup_args.addr_ptr = &hg_test_info->target_addr;
        lookup_args.request = request;

        /* Forward call to remote addr and get a new request */
        ret = HG_Addr_lookup(hg_test_info->context, hg_test_addr_lookup_cb,
            &lookup_args, hg_test_info->na_test_info.target_name,
            HG_OP_ID_IGNORE);
        HG_TEST_CHECK_HG_ERROR(done, ret, "HG_Addr_lookup() failed (%s)",
            HG_Error_to_string(ret));

        /* Wait for request to be marked completed */
        hg_request_wait(request, HG_MAX_IDLE_TIME, &flag);
        HG_TEST_CHECK_ERROR(flag == 0, done, ret, HG_TIMEOUT,
            "Operation did not complete");

        /* Free request */
        hg_request_destroy(request);
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

    /* Client sends request to terminate server */
    if (!hg_test_info->na_test_info.listen) {
        if (hg_test_info->na_test_info.mpi_comm_rank == 0) {
            hg_uint8_t i, context_count =
                hg_test_info->na_test_info.max_contexts ?
                    hg_test_info->na_test_info.max_contexts : 1;
            for (i = 0; i < context_count; i++)
                hg_test_finalize_rpc(hg_test_info, i);
        }
    }

    NA_Test_barrier(&hg_test_info->na_test_info);

    /* Free target addr */
    if (hg_test_info->target_addr != HG_ADDR_NULL) {
        ret = HG_Addr_free(hg_test_info->hg_class, hg_test_info->target_addr);
        HG_TEST_CHECK_HG_ERROR(done, ret, "HG_Addr_free() failed (%s)",
            HG_Error_to_string(ret));
        hg_test_info->target_addr = HG_ADDR_NULL;
    }

    /* Finalize request class */
    if (hg_test_info->request_class) {
        hg_request_finalize(hg_test_info->request_class, NULL);
        hg_test_info->request_class = NULL;
    }

    /* Make sure we triggered everything */
    do {
        unsigned int actual_count;

        do {
            ret = HG_Trigger(hg_test_info->context, 0, 1, &actual_count);
        } while ((ret == HG_SUCCESS) && actual_count);
        HG_TEST_CHECK_ERROR(ret != HG_SUCCESS && ret != HG_TIMEOUT, done, ret,
            ret, "Could not trigger callback (%s)", HG_Error_to_string(ret));

        ret = HG_Progress(hg_test_info->context, 0);
    } while (ret == HG_SUCCESS);
    HG_TEST_CHECK_ERROR(ret != HG_SUCCESS && ret != HG_TIMEOUT, done, ret,
        ret, "HG_Progress failed (%s)", HG_Error_to_string(ret));

#ifdef HG_TEST_HAS_THREAD_POOL
    if (hg_test_info->thread_pool) {
        hg_thread_pool_destroy(hg_test_info->thread_pool);
        hg_test_info->thread_pool = NULL;
        hg_thread_mutex_destroy(&hg_test_info->bulk_handle_mutex);
    }
#endif

    /* Destroy secondary contexts */
    if (hg_test_info->secondary_contexts) {
        hg_uint8_t secondary_contexts_count =
            (hg_uint8_t) (hg_test_info->na_test_info.max_contexts - 1);
        hg_uint8_t i;

        for (i = 0; i < secondary_contexts_count; i++) {
            ret = HG_Context_destroy(hg_test_info->secondary_contexts[i]);
            HG_TEST_CHECK_HG_ERROR(done, ret, "HG_Context_destroy() failed"
                " (%s)", HG_Error_to_string(ret));
        }
        free(hg_test_info->secondary_contexts);
        hg_test_info->secondary_contexts = NULL;
    }

    /* Destroy context */
    if (hg_test_info->context) {
        ret = HG_Context_destroy(hg_test_info->context);
        HG_TEST_CHECK_HG_ERROR(done, ret, "HG_Context_destroy() failed"
            " (%s)", HG_Error_to_string(ret));
        hg_test_info->context = NULL;
    }

    if (hg_test_info->bulk_handle != HG_BULK_NULL) {
        /* Destroy bulk handle */
        ret = HG_Bulk_free(hg_test_info->bulk_handle);
        HG_TEST_CHECK_HG_ERROR(done, ret, "HG_Bulk_free() failed (%s)",
            HG_Error_to_string(ret));
        hg_test_info->bulk_handle = HG_BULK_NULL;
    }

    /* Finalize interface */
    if (hg_test_info->hg_class) {
        ret = HG_Finalize(hg_test_info->hg_class);
        HG_TEST_CHECK_HG_ERROR(done, ret, "HG_Finalize() failed (%s)",
            HG_Error_to_string(ret));
        hg_test_info->hg_class = NULL;
    }

    /* Finalize NA test interface */
    na_ret = NA_Test_finalize(&hg_test_info->na_test_info);
    HG_TEST_CHECK_ERROR(na_ret != NA_SUCCESS, done, ret, (hg_return_t) na_ret,
        "NA_Test_finalize() failed (%s)", NA_Error_to_string(na_ret));

    if (hg_test_info->auth) {
#ifdef HG_TEST_HAS_CRAY_DRC
        ret = hg_test_drc_release(hg_test_info);
        HG_TEST_CHECK_HG_ERROR(done, ret, "hg_test_drc_release() failed (%s)",
            HG_Error_to_string(ret));
#endif
    }

done:
     return ret;
}
