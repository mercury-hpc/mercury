/*
 * Copyright (C) 2013-2017 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#ifndef MERCURY_PROC_BUF_H
#define MERCURY_PROC_BUF_H

#include "mercury_types.h"

#include <string.h>

/**
 * Copy data to buf if HG_ENCODE or buf to data if HG_DECODE and return
 * incremented pointer to buf.
 *
 * \param buf [IN/OUT]          abstract processor object
 * \param data [IN/OUT]         pointer to data
 * \param data_size [IN]        data size
 * \param op [IN]               operation type: HG_ENCODE / HG_DECODE
 *
 * \return incremented pointer to buf
 */
static HG_INLINE void *
hg_proc_buf_memcpy(void *buf, void *data, hg_size_t data_size, hg_proc_op_t op)
{
    const void *src = NULL;
    void *dest = NULL;

    if ((op != HG_ENCODE) && (op != HG_DECODE)) return NULL;
    src = (op == HG_ENCODE) ? (const void *) data : (const void *) buf;
    dest = (op == HG_ENCODE) ? buf : data;
    memcpy(dest, src, data_size);

    return ((char *) buf + data_size);
}

#endif /* MERCURY_PROC_BUF_H */
