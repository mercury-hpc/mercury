/*
 * Copyright (C) 2013-2020 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#include "mercury_util.h"

#include "mercury_util_error.h"

/*******************/
/* Local Variables */
/*******************/

/* Default error log mask */
enum hg_log_type HG_UTIL_LOG_MASK = HG_LOG_TYPE_NONE;

/*---------------------------------------------------------------------------*/
void
HG_Util_set_log_level(const char *level)
{
    /* Set log level */
    HG_UTIL_LOG_MASK = hg_log_name_to_type(level);
}
