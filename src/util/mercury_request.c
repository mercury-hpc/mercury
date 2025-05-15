/**
 * Copyright (c) 2013-2022 UChicago Argonne, LLC and The HDF Group.
 * Copyright (c) 2022-2024 Intel Corporation.
 * Copyright (c) 2024-2025 Hewlett Packard Enterprise Development LP.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "mercury_request.h"
#include "mercury_param.h"
#include "mercury_time.h"
#include "mercury_util_error.h"

#include <stdlib.h>

/****************/
/* Local Macros */
/****************/

#define HG_REQUEST_PROGRESS_TIMEOUT (500)

/************************************/
/* Local Type and Struct Definition */
/************************************/

struct hg_request_class {
    hg_request_progress_func_t progress_func;
    hg_request_trigger_func_t trigger_func;
    void *arg;
};

/********************/
/* Local Prototypes */
/********************/

/*******************/
/* Local Variables */
/*******************/

/*---------------------------------------------------------------------------*/
hg_request_class_t *
hg_request_init(hg_request_progress_func_t progress_func,
    hg_request_trigger_func_t trigger_func, void *arg)
{
    struct hg_request_class *hg_request_class = NULL;

    hg_request_class =
        (struct hg_request_class *) malloc(sizeof(struct hg_request_class));
    HG_UTIL_CHECK_ERROR_NORET(
        hg_request_class == NULL, done, "Could not allocate hg_request_class");

    hg_request_class->progress_func = progress_func;
    hg_request_class->trigger_func = trigger_func;
    hg_request_class->arg = arg;

done:
    return hg_request_class;
}

/*---------------------------------------------------------------------------*/
void
hg_request_finalize(hg_request_class_t *request_class, void **arg)
{
    if (!request_class)
        return;

    if (arg)
        *arg = request_class->arg;

    free(request_class);
}

/*---------------------------------------------------------------------------*/
hg_request_t *
hg_request_create(hg_request_class_t *request_class)
{
    struct hg_request *hg_request = NULL;

    hg_request = (struct hg_request *) malloc(sizeof(struct hg_request));
    HG_UTIL_CHECK_ERROR_NORET(
        hg_request == NULL, done, "Could not allocate hg_request");

    hg_request->request_class = request_class;
    hg_request->data = NULL;
    hg_atomic_init32(&hg_request->completed, (int32_t) false);

done:
    return hg_request;
}

/*---------------------------------------------------------------------------*/
void
hg_request_destroy(hg_request_t *request)
{
    free(request);
}

/*---------------------------------------------------------------------------*/
int
hg_request_wait(
    hg_request_t *request, unsigned int timeout_ms, unsigned int *flag)
{
    hg_time_t deadline, remaining = hg_time_from_ms(timeout_ms);
    hg_time_t now = hg_time_from_ms(0);
    bool completed = false;
    int ret = HG_UTIL_SUCCESS;

    if (timeout_ms != 0)
        hg_time_get_current_ms(&now);
    deadline = hg_time_add(now, remaining);

    do {
        unsigned int trigger_flag = 0,
                     progress_timeout = hg_time_to_ms(remaining);
        int trigger_ret;

        do {
            trigger_ret = request->request_class->trigger_func(
                0, &trigger_flag, request->request_class->arg);
        } while ((trigger_ret == HG_UTIL_SUCCESS) && trigger_flag);

        completed = (bool) hg_atomic_get32(&request->completed);
        if (completed)
            break;

        request->request_class->progress_func(
            MIN(progress_timeout, HG_REQUEST_PROGRESS_TIMEOUT),
            request->request_class->arg);

        if (timeout_ms != 0)
            hg_time_get_current_ms(&now);
        remaining = hg_time_subtract(deadline, now);
    } while (hg_time_less(now, deadline));

    if (flag)
        *flag = (unsigned int) completed;

    return ret;
}
