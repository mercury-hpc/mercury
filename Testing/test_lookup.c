/*
 * Copyright (C) 2013-2020 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#include "mercury_test.h"

/****************/
/* Local Macros */
/****************/

/************************************/
/* Local Type and Struct Definition */
/************************************/

#ifdef HG_TEST_HAS_THREAD_POOL
struct hg_test_thread_args {
    struct hg_test_info *hg_test_info;
    hg_thread_mutex_t test_mutex;
    hg_thread_cond_t test_cond;
    unsigned int n_threads;
};
#endif

/********************/
/* Local Prototypes */
/********************/

static hg_return_t
hg_test_rpc_lookup(hg_class_t *hg_class, const char *target_name);

/*******************/
/* Local Variables */
/*******************/

/*---------------------------------------------------------------------------*/
#ifdef HG_TEST_HAS_THREAD_POOL
static HG_THREAD_RETURN_TYPE
hg_test_lookup_thread(void *arg)
{
    struct hg_test_thread_args *hg_test_thread_args =
        (struct hg_test_thread_args *) arg;
    struct hg_test_info *hg_test_info = hg_test_thread_args->hg_test_info;
    hg_return_t hg_ret;

    /* Wait for all threads to have reached that point */
    hg_thread_mutex_lock(&hg_test_thread_args->test_mutex);
    if (++hg_test_thread_args->n_threads == HG_TEST_NUM_THREADS_DEFAULT)
        hg_thread_cond_broadcast(&hg_test_thread_args->test_cond);
    hg_thread_mutex_unlock(&hg_test_thread_args->test_mutex);

    hg_thread_mutex_lock(&hg_test_thread_args->test_mutex);
    while (hg_test_thread_args->n_threads != HG_TEST_NUM_THREADS_DEFAULT)
        hg_thread_cond_wait(
            &hg_test_thread_args->test_cond, &hg_test_thread_args->test_mutex);
    hg_thread_mutex_unlock(&hg_test_thread_args->test_mutex);

    HG_TEST_LOG_DEBUG("Now doing lookup in loop");
    hg_ret = hg_test_rpc_lookup(
        hg_test_info->hg_class, hg_test_info->na_test_info.target_name);
    HG_TEST_CHECK_ERROR_NORET(hg_ret != HG_SUCCESS, done, "lookup test failed");

done:
    return NULL;
}
#endif

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_test_rpc_lookup(hg_class_t *hg_class, const char *target_name)
{
    hg_return_t ret = HG_SUCCESS;
    hg_addr_t target_addr = HG_ADDR_NULL;
    int i;

    for (i = 0; i < 32; i++) {
        /* Forward call to remote addr and get a new request */
        ret = HG_Addr_lookup2(hg_class, target_name, &target_addr);
        HG_TEST_CHECK_HG_ERROR(
            done, ret, "HG_Addr_lookup() failed (%s)", HG_Error_to_string(ret));

        ret = HG_Addr_set_remove(hg_class, target_addr);
        HG_TEST_CHECK_HG_ERROR(error, ret, "HG_Addr_set_remove() failed (%s)",
            HG_Error_to_string(ret));

        ret = HG_Addr_free(hg_class, target_addr);
        HG_TEST_CHECK_HG_ERROR(
            error, ret, "HG_Addr_free() failed (%s)", HG_Error_to_string(ret));
        target_addr = HG_ADDR_NULL;
    }

done:
    return ret;

error:
    HG_Addr_free(hg_class, target_addr);

    return ret;
}

/*---------------------------------------------------------------------------*/
int
main(int argc, char *argv[])
{
    struct hg_test_info hg_test_info = {0};
#ifdef HG_TEST_HAS_THREAD_POOL
    struct hg_test_thread_args hg_test_thread_args;
    hg_thread_t threads[HG_TEST_NUM_THREADS_DEFAULT];
    int i;
#endif
    hg_return_t hg_ret;
    int ret = EXIT_SUCCESS;

    /* Initialize the interface */
    hg_ret = HG_Test_init(argc, argv, &hg_test_info);
    HG_TEST_CHECK_ERROR(
        hg_ret != HG_SUCCESS, done, ret, EXIT_FAILURE, "HG_Test_init() failed");

    HG_Addr_free(hg_test_info.hg_class, hg_test_info.target_addr);
    hg_test_info.target_addr = HG_ADDR_NULL;

#ifdef HG_TEST_HAS_THREAD_POOL
    hg_test_thread_args.hg_test_info = &hg_test_info;
    hg_thread_mutex_init(&hg_test_thread_args.test_mutex);
    hg_thread_cond_init(&hg_test_thread_args.test_cond);
    hg_test_thread_args.n_threads = 0;
#endif

    /* Create threads */
    HG_TEST("lookup RPC");
#ifdef HG_TEST_HAS_THREAD_POOL
    for (i = 0; i < HG_TEST_NUM_THREADS_DEFAULT; i++)
        hg_thread_create(
            &threads[i], hg_test_lookup_thread, &hg_test_thread_args);

    for (i = 0; i < HG_TEST_NUM_THREADS_DEFAULT; i++)
        hg_thread_join(threads[i]);
#else
    hg_ret = hg_test_rpc_lookup(
        hg_test_info.hg_class, hg_test_info.na_test_info.target_name);
    HG_TEST_CHECK_ERROR(
        hg_ret != HG_SUCCESS, done, ret, EXIT_FAILURE, "lookup test failed");
#endif
    HG_PASSED();

    hg_ret = HG_Addr_lookup2(hg_test_info.hg_class,
        hg_test_info.na_test_info.target_name, &hg_test_info.target_addr);
    HG_TEST_CHECK_ERROR(hg_ret != HG_SUCCESS, done, ret, EXIT_FAILURE,
        "HG_Addr_lookup() failed (%s)", HG_Error_to_string(hg_ret));

done:
    if (ret != EXIT_SUCCESS)
        HG_FAILED();

#ifdef HG_TEST_HAS_THREAD_POOL
    hg_thread_mutex_destroy(&hg_test_thread_args.test_mutex);
    hg_thread_cond_destroy(&hg_test_thread_args.test_cond);
#endif

    hg_ret = HG_Test_finalize(&hg_test_info);
    HG_TEST_CHECK_ERROR_DONE(hg_ret != HG_SUCCESS, "HG_Test_finalize() failed");

    return ret;
}
