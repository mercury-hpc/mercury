/*
 * Copyright (C) 2013-2018 Argonne National Laboratory, Department of Energy,
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
#include "mercury_util_error.h"

#ifdef _WIN32

#else
# include <errno.h>
# include <string.h>
# include <unistd.h>
# if defined(HG_UTIL_HAS_SYSEVENTFD_H)
#  include <sys/eventfd.h>
#  ifndef HG_UTIL_HAS_EVENTFD_T
typedef uint64_t eventfd_t;
#  endif
# elif defined(HG_UTIL_HAS_SYSEVENT_H)
# include <sys/event.h>
/* User-defined ident */
# define HG_EVENT_IDENT 42
# endif
#endif

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
static HG_UTIL_INLINE int
hg_event_set(int fd);

/**
 * Get event notification.
 *
 * \param fd [IN]               event file descriptor
 * \param notified [IN]         boolean set to HG_UTIL_TRUE if event received
 *
 * \return Non-negative on success or negative on failure
 */
static HG_UTIL_INLINE int
hg_event_get(int fd, hg_util_bool_t *notified);

/*---------------------------------------------------------------------------*/
#if defined(_WIN32)
/* TODO */
#elif defined(HG_UTIL_HAS_SYSEVENTFD_H)
static HG_UTIL_INLINE int
hg_event_set(int fd)
{
    int ret = HG_UTIL_SUCCESS;
    eventfd_t count = 1;

#ifdef HG_UTIL_HAS_EVENTFD_T
    if (eventfd_write(fd, count) == -1) {
#else
    ssize_t s;

    s = write(fd, &count, sizeof(eventfd_t));
    if (s != sizeof(eventfd_t)) {
#endif
        if (errno == EAGAIN)
            goto done;
        HG_UTIL_LOG_ERROR("write() failed (%s)", strerror(errno));
        ret = HG_UTIL_FAIL;
        goto done;
    }

done:
    return ret;
}
#elif defined(HG_UTIL_HAS_SYSEVENT_H)
static HG_UTIL_INLINE int
hg_event_set(int fd)
{
    int ret = HG_UTIL_SUCCESS;
    struct kevent kev;
    struct timespec timeout = {0, 0};

    EV_SET(&kev, HG_EVENT_IDENT, EVFILT_USER, 0, NOTE_TRIGGER, 0, NULL);

    /* Trigger user-defined event */
    if (kevent(fd, &kev, 1, NULL, 0, &timeout) == -1) {
        HG_UTIL_LOG_ERROR("kevent() failed (%s)", strerror(errno));
        ret = HG_UTIL_FAIL;
        goto done;
    }

done:
    return ret;
}
#else
# error "Not supported on this platform."
#endif

/*---------------------------------------------------------------------------*/
#if defined(_WIN32)
#elif defined(HG_UTIL_HAS_SYSEVENTFD_H)
static HG_UTIL_INLINE int
hg_event_get(int fd, hg_util_bool_t *signaled)
{
    int ret = HG_UTIL_SUCCESS;
    hg_util_bool_t event_signal = HG_UTIL_FALSE;
    eventfd_t count = 0;

#ifdef HG_UTIL_HAS_EVENTFD_T
    if (eventfd_read(fd, &count) == -1) {
#else
    ssize_t s;

    s = read(fd, &count, sizeof(eventfd_t));
    if (s != sizeof(eventfd_t)) {
#endif
        if (errno == EAGAIN)
            goto done;
        HG_UTIL_LOG_ERROR("read() failed (%s)", strerror(errno));
        ret = HG_UTIL_FAIL;
        goto done;
    }
    event_signal = HG_UTIL_TRUE;

done:
    if (signaled && ret != HG_UTIL_FAIL)
        *signaled = event_signal;
    return ret;
}
#elif defined(HG_UTIL_HAS_SYSEVENT_H)
static HG_UTIL_INLINE int
hg_event_get(int fd, hg_util_bool_t *signaled)
{
    int ret = HG_UTIL_SUCCESS;
    hg_util_bool_t event_signal = HG_UTIL_FALSE;
    struct kevent kev;
    int nfds;
    struct timespec timeout = {0, 0};

    /* Check user-defined event */
    nfds = kevent(fd, NULL, 0, &kev, 1, &timeout);
    if (nfds == -1) {
        HG_UTIL_LOG_ERROR("kevent() failed (%s)", strerror(errno));
        ret = HG_UTIL_FAIL;
        goto done;
    }
    if (nfds > 0 && kev.ident == HG_EVENT_IDENT)
        event_signal = HG_UTIL_TRUE;

    if (signaled) *signaled = event_signal;

done:
    return ret;
}
#else
#endif

#ifdef __cplusplus
}
#endif

#endif /* MERCURY_EVENT_H */
