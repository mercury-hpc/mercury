/*
 * Copyright (C) 2013 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#ifndef NA_SSM_H
#define NA_SSM_H

#include "na.h"
#include "na_error.h"

#include <ssm/dumb.h>
#include <ssm.h>
#include <ssmptcp.h>

#if (__GNUC__)
#define __likely(x)   __builtin_expect(!!(x), 1)
#define __unlikely(x) __builtin_expect(!!(x), 0)
#else
#define __likely(x)     (x)
#define __unlikely(x)   (x)
#endif




#endif /* NA_SSM_H */




