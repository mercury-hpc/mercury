/*
 * Copyright (C) 2013-2020 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#include "mercury_hl.h"
#include "mercury_error.h"

#include <stdlib.h>

/****************/
/* Local Macros */
/****************/

/* Environment variable names (to be removed) */
#define HG_PORT_NAME "MERCURY_PORT_NAME"

/************************************/
/* Local Type and Struct Definition */
/************************************/
struct hg_lookup_request_arg {
    hg_addr_t *addr_ptr;
    hg_request_t *request;
};

/********************/
/* Local Prototypes */
/********************/

static int
hg_hl_request_progress(unsigned int timeout, void *arg);

static int
hg_hl_request_trigger(unsigned int timeout, unsigned int *flag, void *arg);

static hg_return_t
hg_hl_addr_lookup_cb(const struct hg_cb_info *callback_info);

static hg_return_t
hg_hl_forward_cb(const struct hg_cb_info *callback_info);

static hg_return_t
hg_hl_bulk_transfer_cb(const struct hg_cb_info *callback_info);

static void
hg_hl_finalize(void);

/*******************/
/* Local Variables */
/*******************/

/* HG default */
hg_class_t *HG_CLASS_DEFAULT = NULL;
hg_context_t *HG_CONTEXT_DEFAULT = NULL;
hg_request_class_t *HG_REQUEST_CLASS_DEFAULT = NULL;

/* For convenience, register HG_Hl_finalize() */
static hg_bool_t hg_atexit_g = HG_FALSE;

/*---------------------------------------------------------------------------*/
static int
hg_hl_request_progress(unsigned int timeout, void *arg)
{
    hg_context_t *context = (hg_context_t *) arg;
    int ret = HG_UTIL_SUCCESS;

    if (HG_Progress(context, timeout) != HG_SUCCESS)
        ret = HG_UTIL_FAIL;

    return ret;
}

/*---------------------------------------------------------------------------*/
static int
hg_hl_request_trigger(unsigned int timeout, unsigned int *flag, void *arg)
{
    hg_context_t *context = (hg_context_t *) arg;
    unsigned int actual_count = 0;
    int ret = HG_UTIL_SUCCESS;

    if (HG_Trigger(context, timeout, 1, &actual_count) != HG_SUCCESS)
        ret = HG_UTIL_FAIL;
    *flag = (actual_count) ? true : false;

    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_hl_addr_lookup_cb(const struct hg_cb_info *callback_info)
{
    struct hg_lookup_request_arg *request_args =
        (struct hg_lookup_request_arg *) callback_info->arg;

    *request_args->addr_ptr = callback_info->info.lookup.addr;

    hg_request_complete(request_args->request);

    return HG_SUCCESS;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_hl_forward_cb(const struct hg_cb_info *callback_info)
{
    hg_request_t *request = (hg_request_t *) callback_info->arg;

    hg_request_complete(request);

    return HG_SUCCESS;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_hl_bulk_transfer_cb(const struct hg_cb_info *callback_info)
{
    hg_request_t *request = (hg_request_t *) callback_info->arg;

    hg_request_complete(request);

    return HG_SUCCESS;
}

/*---------------------------------------------------------------------------*/
static void
hg_hl_finalize(void)
{
    HG_Hl_finalize();
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Hl_init(const char *na_info_string, hg_bool_t na_listen)
{
    hg_return_t ret = HG_SUCCESS;

    /* First register finalize function if not set */
    if (!hg_atexit_g) {
        int rc = atexit(hg_hl_finalize);
        HG_CHECK_ERROR(
            rc != 0, done, ret, HG_INVALID_ARG, "Cannot set exit function");
        hg_atexit_g = HG_TRUE;
    }

    /* Get info string */
    if (!na_info_string) {
        na_info_string = getenv(HG_PORT_NAME);
    }
    HG_CHECK_ERROR(na_info_string == NULL, done, ret, HG_INVALID_ARG,
        HG_PORT_NAME " environment variable must be set");

    /* Initialize HG */
    if (!HG_CLASS_DEFAULT) {
        HG_CLASS_DEFAULT = HG_Init(na_info_string, na_listen);
        HG_CHECK_ERROR(HG_CLASS_DEFAULT == NULL, done, ret, HG_FAULT,
            "Could not initialize HG class");
    }

    /* Create HG context */
    if (!HG_CONTEXT_DEFAULT) {
        HG_CONTEXT_DEFAULT = HG_Context_create(HG_CLASS_DEFAULT);
        HG_CHECK_ERROR(HG_CONTEXT_DEFAULT == NULL, done, ret, HG_FAULT,
            "Could not create HG context");
    }

    /* Initialize request class */
    if (!HG_REQUEST_CLASS_DEFAULT) {
        HG_REQUEST_CLASS_DEFAULT = hg_request_init(
            hg_hl_request_progress, hg_hl_request_trigger, HG_CONTEXT_DEFAULT);
        HG_CHECK_ERROR(HG_REQUEST_CLASS_DEFAULT == NULL, done, ret, HG_FAULT,
            "Could not create HG request class");
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Hl_init_opt(const char *na_info_string, hg_bool_t na_listen,
    const struct hg_init_info *hg_init_info)
{
    hg_return_t ret = HG_SUCCESS;

    /* First register finalize function if not set */
    if (!hg_atexit_g) {
        int rc = atexit(hg_hl_finalize);
        HG_CHECK_ERROR(
            rc != 0, done, ret, HG_INVALID_ARG, "Cannot set exit function");
        hg_atexit_g = HG_TRUE;
    }

    /* Initialize HG */
    if (!HG_CLASS_DEFAULT) {
        HG_CLASS_DEFAULT = HG_Init_opt(na_info_string, na_listen, hg_init_info);
        HG_CHECK_ERROR(HG_CLASS_DEFAULT == NULL, done, ret, HG_FAULT,
            "Could not initialize HG class");
    }

    /* Create HG context */
    if (!HG_CONTEXT_DEFAULT) {
        HG_CONTEXT_DEFAULT = HG_Context_create(HG_CLASS_DEFAULT);
        HG_CHECK_ERROR(HG_CONTEXT_DEFAULT == NULL, done, ret, HG_FAULT,
            "Could not create HG context");
    }

    /* Initialize request class */
    if (!HG_REQUEST_CLASS_DEFAULT) {
        HG_REQUEST_CLASS_DEFAULT = hg_request_init(
            hg_hl_request_progress, hg_hl_request_trigger, HG_CONTEXT_DEFAULT);
        HG_CHECK_ERROR(HG_REQUEST_CLASS_DEFAULT == NULL, done, ret, HG_FAULT,
            "Could not create HG request class");
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Hl_finalize(void)
{
    hg_return_t ret = HG_SUCCESS;

    /* Finalize request class */
    if (HG_REQUEST_CLASS_DEFAULT) {
        hg_request_finalize(HG_REQUEST_CLASS_DEFAULT, NULL);
        HG_REQUEST_CLASS_DEFAULT = NULL;
    }

    /* Destroy context */
    if (HG_CONTEXT_DEFAULT) {
        ret = HG_Context_destroy(HG_CONTEXT_DEFAULT);
        HG_CHECK_HG_ERROR(done, ret, "Could not destroy HG context");
        HG_CONTEXT_DEFAULT = NULL;
    }

    /* Finalize interface */
    if (HG_CLASS_DEFAULT) {
        ret = HG_Finalize(HG_CLASS_DEFAULT);
        HG_CHECK_HG_ERROR(done, ret, "Could not finalize HG class");
        HG_CLASS_DEFAULT = NULL;
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Hl_addr_lookup_wait(hg_context_t *context, hg_request_class_t *request_class,
    const char *name, hg_addr_t *addr, unsigned int timeout)
{
    hg_request_t *request = NULL;
    hg_return_t ret = HG_SUCCESS;
    unsigned int flag = 0;
    struct hg_lookup_request_arg request_args;

    HG_CHECK_ERROR(request_class == NULL, done, ret, HG_INVALID_ARG,
        "Uninitialized request class");

    request = hg_request_create(request_class);
    request_args.addr_ptr = addr;
    request_args.request = request;

    /* Forward call to remote addr and get a new request */
    ret = HG_Addr_lookup1(
        context, hg_hl_addr_lookup_cb, &request_args, name, HG_OP_ID_IGNORE);
    HG_CHECK_HG_ERROR(done, ret, "Could not lookup address");

    /* Wait for request to be marked completed */
    hg_request_wait(request, timeout, &flag);
    HG_CHECK_ERROR(
        flag == 0, done, ret, HG_TIMEOUT, "Operation did not complete");

    /* Free request */
    hg_request_destroy(request);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Hl_forward_wait(hg_request_class_t *request_class, hg_handle_t handle,
    void *in_struct, unsigned int timeout)
{
    hg_request_t *request = NULL;
    hg_return_t ret = HG_SUCCESS;
    unsigned int flag = 0;

    HG_CHECK_ERROR(request_class == NULL, done, ret, HG_INVALID_ARG,
        "Uninitialized request class");

    request = hg_request_create(request_class);

    /* Forward call to remote addr and get a new request */
    ret = HG_Forward(handle, hg_hl_forward_cb, request, in_struct);
    HG_CHECK_HG_ERROR(done, ret, "Could not forward call");

    /* Wait for request to be marked completed */
    hg_request_wait(request, timeout, &flag);
    HG_CHECK_ERROR(
        flag == 0, done, ret, HG_TIMEOUT, "Operation did not complete");

    /* Free request */
    hg_request_destroy(request);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Hl_bulk_transfer_wait(hg_context_t *context,
    hg_request_class_t *request_class, hg_bulk_op_t op, hg_addr_t origin_addr,
    hg_bulk_t origin_handle, hg_size_t origin_offset, hg_bulk_t local_handle,
    hg_size_t local_offset, hg_size_t size, unsigned int timeout)
{
    hg_request_t *request = NULL;
    hg_return_t ret = HG_SUCCESS;
    unsigned int flag = 0;

    HG_CHECK_ERROR(request_class == NULL, done, ret, HG_INVALID_ARG,
        "Uninitialized request class");

    request = hg_request_create(request_class);

    /* Transfer bulk data */
    ret = HG_Bulk_transfer(context, hg_hl_bulk_transfer_cb, request, op,
        origin_addr, origin_handle, origin_offset, local_handle, local_offset,
        size, HG_OP_ID_IGNORE);
    HG_CHECK_HG_ERROR(done, ret, "Could not transfer data");

    /* Wait for request to be marked completed */
    hg_request_wait(request, timeout, &flag);
    HG_CHECK_ERROR(
        flag == 0, done, ret, HG_TIMEOUT, "Operation did not complete");

    /* Free request */
    hg_request_destroy(request);

done:
    return ret;
}
