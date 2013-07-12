/*
 * Copyright (C) 2013 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#include "mercury_context.h"

/*---------------------------------------------------------------------------*/
int
HG_Context_create(hg_context_t *context)
{
    return HG_SUCCESS;
}

/*---------------------------------------------------------------------------*/
unsigned int
HG_Context_get_size(hg_context_t context)
{
    return 0;
}

/*---------------------------------------------------------------------------*/
int
HG_Context_get(hg_context_t context, unsigned int max_count,
        hg_request_t array_of_requests[], unsigned int *count)
{
    return HG_SUCCESS;
}

/*---------------------------------------------------------------------------*/
int
HG_Context_free(hg_context_t context)
{
    return HG_SUCCESS;
}

/*---------------------------------------------------------------------------*/
int
HG_Context_add(hg_context_t context, hg_request_t request)
{
    return HG_SUCCESS;
}

/*---------------------------------------------------------------------------*/
int
HG_Context_remove(hg_context_t context, hg_request_t request)
{
    return HG_SUCCESS;
}

/*---------------------------------------------------------------------------*/
int
HG_Context_wait(hg_context_t context, unsigned int timeout,
        int max_count, hg_status_t array_of_statuses[], int *count)
{
    return HG_SUCCESS;
}
