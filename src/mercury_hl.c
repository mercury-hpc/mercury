/*
 * Copyright (C) 2013-2014 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#include "mercury_hl.h"
#include "mercury_request.h"
#include "mercury_error.h"

#include <stdlib.h>

/****************/
/* Local Macros */
/****************/

/************************************/
/* Local Type and Struct Definition */
/************************************/
struct hg_request_arg {
    hg_class_t *hg_class;
    hg_context_t *context;
};

/********************/
/* Local Prototypes */
/********************/
static int
hg_hl_request_progress(
        unsigned int timeout,
        void *arg
        );

static int
hg_hl_request_trigger(
        unsigned int timeout,
        unsigned int *flag,
        void *arg
        );

static hg_return_t
hg_hl_forward_cb(
        const struct hg_cb_info *callback_info
        );

static hg_return_t
hg_hl_bulk_transfer_cb(
        const struct hg_bulk_cb_info *callback_info
        );

static void
hg_hl_finalize(
        void
        );

/*******************/
/* Local Variables */
/*******************/

/* NA default */
na_class_t *NA_CLASS_DEFAULT = NULL;
na_context_t *NA_CONTEXT_DEFAULT = NULL;
na_addr_t NA_ADDR_DEFAULT = NULL;

/* HG default */
hg_class_t *HG_CLASS_DEFAULT = NULL;
hg_context_t *HG_CONTEXT_DEFAULT = NULL;

/* Internal request class associated to HG default */
static hg_request_class_t *hg_request_class_g = NULL;
static struct hg_request_arg hg_request_arg_g = {NULL, NULL};

/* For convenience, register HG_Hl_finalize() */
static hg_bool_t hg_atexit_g = HG_FALSE;

/*---------------------------------------------------------------------------*/
static int
hg_hl_request_progress(unsigned int timeout, void *arg)
{
    struct hg_request_arg *hg_request_arg = (struct hg_request_arg *) arg;
    int ret = HG_UTIL_SUCCESS;

    (void) timeout;
    /* TODO Fix timeout to 10ms for now */
    if (HG_Progress(hg_request_arg->hg_class, hg_request_arg->context,
            10) != HG_SUCCESS)
        ret = HG_UTIL_FAIL;

    return ret;
}

/*---------------------------------------------------------------------------*/
static int
hg_hl_request_trigger(unsigned int timeout, unsigned int *flag, void *arg)
{
    struct hg_request_arg *hg_request_arg = (struct hg_request_arg *) arg;
    unsigned int actual_count = 0;
    int ret = HG_UTIL_SUCCESS;

    if (HG_Trigger(hg_request_arg->hg_class, hg_request_arg->context, timeout,
            1, &actual_count) != HG_SUCCESS) ret = HG_UTIL_FAIL;
    *flag = (actual_count) ? HG_UTIL_TRUE : HG_UTIL_FALSE;

    return ret;
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
hg_hl_bulk_transfer_cb(const struct hg_bulk_cb_info *callback_info)
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
HG_Hl_init(const char *info_string, na_bool_t listen)
{
    const char *na_info_string = info_string;
    hg_return_t ret = HG_SUCCESS;

    /* First register finalize function if not set */
    if (!hg_atexit_g) {
        if (atexit(hg_hl_finalize) != 0) {
            HG_LOG_ERROR("Cannot set exit function");
            ret = HG_PROTOCOL_ERROR;
            goto done;
        }
        hg_atexit_g = HG_TRUE;
    }

    /* Get info string */
    if (!na_info_string) {
        na_info_string = getenv(HG_PORT_NAME);
    }
    if (!na_info_string) {
        HG_LOG_ERROR(HG_PORT_NAME " environment variable must be set");
        goto done;
    }

    /* Initialize NA */
    if (!NA_CLASS_DEFAULT) {
        NA_CLASS_DEFAULT = NA_Initialize(na_info_string, listen);
        if (!NA_CLASS_DEFAULT) {
            HG_LOG_ERROR("Could not initialize NA class");
            ret = HG_NA_ERROR;
            goto done;
        }
    }

    /* Create NA context */
    if (!NA_CONTEXT_DEFAULT) {
        NA_CONTEXT_DEFAULT = NA_Context_create(NA_CLASS_DEFAULT);
        if (!NA_CONTEXT_DEFAULT) {
            HG_LOG_ERROR("Could not create NA context");
            ret = HG_NA_ERROR;
            goto done;
        }
    }

    /* Initialize HG */
    if (!HG_CLASS_DEFAULT) {
        HG_CLASS_DEFAULT = HG_Init(NA_CLASS_DEFAULT, NA_CONTEXT_DEFAULT, NULL);
        if (!HG_CLASS_DEFAULT) {
            HG_LOG_ERROR("Could not initialize HG class");
            ret = HG_PROTOCOL_ERROR;
            goto done;
        }
    }

    /* Create HG context */
    if (!HG_CONTEXT_DEFAULT) {
        HG_CONTEXT_DEFAULT = HG_Context_create(HG_CLASS_DEFAULT);
        if (!HG_CONTEXT_DEFAULT) {
            HG_LOG_ERROR("Could not create HG context");
            ret = HG_PROTOCOL_ERROR;
            goto done;
        }
    }

    /* Initialize request class */
    if (!hg_request_class_g) {
        hg_request_arg_g.hg_class = HG_CLASS_DEFAULT;
        hg_request_arg_g.context = HG_CONTEXT_DEFAULT;
        hg_request_class_g = hg_request_init(hg_hl_request_progress,
                hg_hl_request_trigger, &hg_request_arg_g);
    }

    /* Lookup addr */
    if (!NA_ADDR_DEFAULT && !listen) {
        if (NA_Addr_lookup_wait(NA_CLASS_DEFAULT, na_info_string,
                &NA_ADDR_DEFAULT) != NA_SUCCESS) {
            HG_LOG_ERROR("Could not lookup addr");
            ret = HG_NA_ERROR;
            goto done;
        }
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Hl_finalize(void)
{
    hg_return_t ret = HG_SUCCESS;

    /* Free addr */
    if (NA_CLASS_DEFAULT) {
        if (NA_Addr_free(NA_CLASS_DEFAULT, NA_ADDR_DEFAULT) != NA_SUCCESS) {
            HG_LOG_ERROR("Could not free addr");
            ret = HG_NA_ERROR;
            goto done;
        }
        NA_ADDR_DEFAULT = NA_ADDR_NULL;
    }

    /* Finalize request class */
    hg_request_finalize(hg_request_class_g);
    hg_request_class_g = NULL;

    /* Destroy context */
    ret = HG_Context_destroy(HG_CONTEXT_DEFAULT);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not destroy HG context");
        goto done;
    }
    HG_CONTEXT_DEFAULT = NULL;

    /* Finalize interface */
    ret = HG_Finalize(HG_CLASS_DEFAULT);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not finalize HG class");
        goto done;
    }
    HG_CLASS_DEFAULT = NULL;

    /* Destroy context */
    if (NA_CLASS_DEFAULT && NA_Context_destroy(NA_CLASS_DEFAULT,
            NA_CONTEXT_DEFAULT) != NA_SUCCESS) {
        HG_LOG_ERROR("Could not destroy NA context");
        ret = HG_NA_ERROR;
        goto done;
    }
    NA_CONTEXT_DEFAULT = NULL;

    /* Finalize interface */
    if (NA_Finalize(NA_CLASS_DEFAULT) != NA_SUCCESS) {
        HG_LOG_ERROR("Could not finalize NA interface");
        ret = HG_NA_ERROR;
        goto done;
    }
    NA_CLASS_DEFAULT = NULL;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Hl_forward_wait(hg_handle_t handle, void *in_struct)
{
    hg_request_t *request = NULL;
    hg_return_t ret = HG_SUCCESS;
    unsigned int flag = 0;

    if (!hg_request_class_g) {
        HG_LOG_ERROR("Uninitialized request class");
        ret = HG_PROTOCOL_ERROR;
        goto done;
    }

    request = hg_request_create(hg_request_class_g);

    /* Forward call to remote addr and get a new request */
    ret = HG_Forward(handle, hg_hl_forward_cb, request, in_struct);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not forward call");
        goto done;
    }

    /* Wait for request to be marked completed */
    hg_request_wait(request, HG_MAX_IDLE_TIME, &flag);
    if (!flag) {
        HG_LOG_ERROR("Operation did not complete");
        ret = HG_TIMEOUT;
        goto done;
    }

    /* Free request */
    hg_request_destroy(request);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Hl_bulk_transfer_wait(hg_bulk_context_t *context, hg_bulk_op_t op,
        na_addr_t origin_addr, hg_bulk_t origin_handle, hg_size_t origin_offset,
        hg_bulk_t local_handle, hg_size_t local_offset, hg_size_t size)
{
    hg_request_t *request = NULL;
    hg_return_t ret = HG_SUCCESS;
    unsigned int flag = 0;

    if (!hg_request_class_g) {
        HG_LOG_ERROR("Uninitialized request class");
        ret = HG_PROTOCOL_ERROR;
        goto done;
    }

    request = hg_request_create(hg_request_class_g);

    /* Transfer bulk data */
    ret = HG_Bulk_transfer(context, hg_hl_bulk_transfer_cb, request, op,
            origin_addr, origin_handle, origin_offset, local_handle,
            local_offset, size, HG_OP_ID_IGNORE);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not transfer data");
        goto done;
    }

    /* Wait for request to be marked completed */
    hg_request_wait(request, HG_MAX_IDLE_TIME, &flag);
    if (!flag) {
        HG_LOG_ERROR("Operation did not complete");
        ret = HG_TIMEOUT;
        goto done;
    }

    /* Free request */
    hg_request_destroy(request);

done:
    return ret;
}
