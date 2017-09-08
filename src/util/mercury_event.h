/*
 * Copyright (C) 2013-2017 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#ifndef MERCURY_EVENT_H
#define MERCURY_EVENT_H

#include "mercury_util_config.h"

/**
 * Purpose: define an event object that can be used as an event
 * wait/notify mechanism.
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Create a new event object.
 *
 * \return file descriptor on success or negative on failure
 */
HG_UTIL_EXPORT int
hg_event_create(void);

/**
 * Destroy an event object.
 *
 * \param fd [IN]               event file descriptor
 *
 * \return Non-negative on success or negative on failure
 */
HG_UTIL_EXPORT int
hg_event_destroy(int fd);

/**
 * Notify for event.
 *
 * \param fd [IN]               event file descriptor
 *
 * \return Non-negative on success or negative on failure
 */
HG_UTIL_EXPORT int
hg_event_set(int fd);

/**
 * Get event notification.
 *
 * \param fd [IN]               event file descriptor
 * \param notified [IN]         boolean set to HG_UTIL_TRUE if event received
 *
 * \return Non-negative on success or negative on failure
 */
HG_UTIL_EXPORT int
hg_event_get(int fd, hg_util_bool_t *notified);

#ifdef __cplusplus
}
#endif

#endif /* MERCURY_EVENT_H */
