/*
 * Copyright (C) 2013-2014 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#ifndef MERCURY_TIME_H
#define MERCURY_TIME_H

#include "mercury_util_config.h"

typedef struct hg_time hg_time_t;
struct hg_time
{
    long tv_sec;
    long tv_usec;
};

/**
 * Get an elapsed time on the calling processor.
 *
 * \param tv [OUT]              pointer to returned time structure
 *
 * \return Non-negative on success or negative on failure
 */
HG_UTIL_EXPORT int
hg_time_get_current(hg_time_t *tv);

/**
 * Convert hg_time_t to double.
 *
 * \param tv [IN]               time structure
 *
 * \return Converted time in seconds
 */
HG_UTIL_EXPORT double
hg_time_to_double(hg_time_t tv);

/**
 * Convert double to hg_time_t.
 *
 * \param d [IN]                time in seconds
 *
 * \return Converted time structure
 */
HG_UTIL_EXPORT hg_time_t
hg_time_from_double(double d);

/**
 * Compare time values.
 *
 * \param in1 [IN]              time structure
 * \param in2 [IN]              time structure
 *
 * \return 1 if in1 < in2, 0 otherwise
 */
HG_UTIL_EXPORT int
hg_time_less(hg_time_t in1, hg_time_t in2);

/**
 * Add time values.
 *
 * \param in1 [IN]              time structure
 * \param in2 [IN]              time structure
 *
 * \return Summed time structure
 */
HG_UTIL_EXPORT hg_time_t
hg_time_add(hg_time_t in1, hg_time_t in2);

/**
 * Subtract time values.
 *
 * \param in1 [IN]              time structure
 * \param in2 [IN]              time structure
 *
 * \return Subtracted time structure
 */
HG_UTIL_EXPORT hg_time_t
hg_time_subtract(hg_time_t in1, hg_time_t in2);

/**
 * Sleep until the time specified in rqt has elapsed.
 *
 * \param reqt [IN]             time structure
 * \param rmt  [OUT]            pointer to time structure
 *
 * \return Non-negative on success or negative on failure
 */
HG_UTIL_EXPORT int
hg_time_sleep(const hg_time_t rqt, hg_time_t *rmt);

/**
 * Get a string containing current time/date stamp.
 *
 * \return Valid string or NULL on failure
 */
HG_UTIL_EXPORT char *
hg_time_stamp(void);

#endif /* MERCURY_TIME_H */
