/*
 * Copyright (C) 2013 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#ifndef MERCURY_TIME_H
#define MERCURY_TIME_H

#ifdef _WIN32
#include <windows.h>
#else
#include <time.h>
#endif
typedef struct hg_time hg_time_t;
struct hg_time
{
    long tv_sec;
    long tv_usec;
};

/* Returns an elapsed time on the calling processor */
int hg_time_get_current(hg_time_t *tv);

/* Convert hg_time_t to double */
double hg_time_to_double(hg_time_t tv);

/* Convert double to hg_time_t */
hg_time_t hg_time_from_double(double d);

/* Compare time */
int hg_time_less(hg_time_t in1, hg_time_t in2);

/* Add times */
hg_time_t hg_time_add(hg_time_t in1, hg_time_t in2);

/* Subtract times */
hg_time_t hg_time_subtract(hg_time_t in1, hg_time_t in2);

#endif /* MERCURY_TIME_H */
