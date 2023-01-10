/**
 * Copyright (c) 2013-2022 UChicago Argonne, LLC and The HDF Group.
 * Copyright (c) 2022 Intel Corporation.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "mercury_perf.h"

#include "mercury_thread.h"

/****************/
/* Local Macros */
/****************/

/************************************/
/* Local Type and Struct Definition */
/************************************/

/********************/
/* Local Prototypes */
/********************/

static HG_THREAD_RETURN_TYPE
hg_perf_loop_thread(void *arg);

static hg_return_t
hg_perf_loop(struct hg_perf_class_info *info);

/*******************/
/* Local Variables */
/*******************/

/*---------------------------------------------------------------------------*/
static HG_THREAD_RETURN_TYPE
hg_perf_loop_thread(void *arg)
{
    hg_thread_ret_t tret = (hg_thread_ret_t) 0;
    hg_return_t hg_ret;

    hg_ret = hg_perf_loop((struct hg_perf_class_info *) arg);
    HG_TEST_CHECK_HG_ERROR(
        done, hg_ret, "hg_perf_loop() failed (%s)", HG_Error_to_string(hg_ret));

done:
    hg_thread_exit(tret);
    return tret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_perf_loop(struct hg_perf_class_info *info)
{
    hg_return_t ret;

    do {
        unsigned int actual_count = 0;

        do {
            ret = HG_Trigger(info->context, 0, 1, &actual_count);
        } while ((ret == HG_SUCCESS) && actual_count);
        HG_TEST_CHECK_ERROR_NORET(ret != HG_SUCCESS && ret != HG_TIMEOUT, error,
            "HG_Trigger() failed (%s)", HG_Error_to_string(ret));

        if (info->done)
            break;

        ret = HG_Progress(info->context, 1000);
    } while (ret == HG_SUCCESS || ret == HG_TIMEOUT);
    HG_TEST_CHECK_ERROR_NORET(ret != HG_SUCCESS && ret != HG_TIMEOUT, error,
        "HG_Progress() failed (%s)", HG_Error_to_string(ret));

    return HG_SUCCESS;

error:
    return ret;
}

/*---------------------------------------------------------------------------*/
int
main(int argc, char *argv[])
{
    struct hg_perf_info info;
    hg_return_t hg_ret;
    hg_thread_t *progress_threads = NULL;

    /* Initialize the interface */
    hg_ret = hg_perf_init(argc, argv, true, &info);
    HG_TEST_CHECK_HG_ERROR(error, hg_ret, "hg_perf_init() failed (%s)",
        HG_Error_to_string(hg_ret));

    HG_TEST_READY_MSG();

    if (info.class_max > 1) {
        size_t i;

        progress_threads =
            (hg_thread_t *) malloc(sizeof(*progress_threads) * info.class_max);
        HG_TEST_CHECK_ERROR_NORET(progress_threads == NULL, error,
            "Could not allocate progress threads");

        for (i = 0; i < info.class_max; i++) {
            int rc = hg_thread_create(
                &progress_threads[i], hg_perf_loop_thread, &info.class_info[i]);
            HG_TEST_CHECK_ERROR_NORET(
                rc != 0, error, "hg_thread_create() failed");
        }

        for (i = 0; i < info.class_max; i++)
            hg_thread_join(progress_threads[i]);
    } else {
        hg_ret = hg_perf_loop(&info.class_info[0]);
        HG_TEST_CHECK_HG_ERROR(error, hg_ret, "hg_perf_loop() failed (%s)",
            HG_Error_to_string(hg_ret));
    }

    /* Finalize interface */
    printf("Finalizing...\n");
    hg_perf_cleanup(&info);
    free(progress_threads);

    return EXIT_SUCCESS;

error:
    hg_perf_cleanup(&info);
    free(progress_threads);

    return EXIT_FAILURE;
}
