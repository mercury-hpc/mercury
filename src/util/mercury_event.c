/*
 * Copyright (C) 2013-2017 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#include "mercury_event.h"
#include "mercury_util_error.h"

#ifdef _WIN32

#else
#include <errno.h>
#include <string.h>
#include <unistd.h>
#if defined(HG_UTIL_HAS_SYSEVENTFD_H)
#include <sys/eventfd.h>
#ifndef HG_UTIL_HAS_EVENTFD_T
typedef uint64_t eventfd_t;
#endif
#elif defined(HG_UTIL_HAS_SYSEVENT_H)
#include <sys/event.h>
/* User-defined ident */
#define HG_EVENT_IDENT 42
#endif

#endif

/*---------------------------------------------------------------------------*/
int
hg_event_create(void)
{
    int fd = 0;
#if defined(_WIN32)

#elif defined(HG_UTIL_HAS_SYSEVENTFD_H)
    /* Create local signal event on self address */
    fd = eventfd(0, EFD_NONBLOCK | EFD_SEMAPHORE);
    if (fd == -1) {
        HG_UTIL_LOG_ERROR("eventfd() failed (%s)", strerror(errno));
        goto done;
    }
#elif defined(HG_UTIL_HAS_SYSEVENT_H)
    struct kevent kev;
    struct timespec timeout = {0, 0};

    /* Create kqueue */
    fd = kqueue();
    if (fd == -1) {
        HG_UTIL_LOG_ERROR("kqueue() failed (%s)", strerror(errno));
        goto done;
    }

    EV_SET(&kev, HG_EVENT_IDENT, EVFILT_USER, EV_ADD | EV_CLEAR, 0, 0, NULL);

    /* Add user-defined event to kqueue */
    if (kevent(fd, &kev, 1, NULL, 0, &timeout) == -1) {
        HG_UTIL_LOG_ERROR("kevent() failed (%s)", strerror(errno));
        hg_event_destroy(fd);
        fd = 0;
        goto done;
    }
#else

#endif

done:
    return fd;
}

/*---------------------------------------------------------------------------*/
int
hg_event_destroy(int fd)
{
    int ret = HG_UTIL_SUCCESS;
#if defined(_WIN32)

#else
    if (close(fd) == -1) {
        HG_UTIL_LOG_ERROR("close() failed (%s)", strerror(errno));
        ret = HG_UTIL_FAIL;
        goto done;
    }
#endif
done:
    return ret;
}

/*---------------------------------------------------------------------------*/
int
hg_event_set(int fd)
{
    int ret = HG_UTIL_SUCCESS;
#if defined(_WIN32)

#elif defined(HG_UTIL_HAS_SYSEVENTFD_H)
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
#elif defined(HG_UTIL_HAS_SYSEVENT_H)
    struct kevent kev;
    struct timespec timeout = {0, 0};

    EV_SET(&kev, HG_EVENT_IDENT, EVFILT_USER, 0, NOTE_TRIGGER, 0, NULL);

    /* Trigger user-defined event */
    if (kevent(fd, &kev, 1, NULL, 0, &timeout) == -1) {
        HG_UTIL_LOG_ERROR("kevent() failed (%s)", strerror(errno));
        ret = HG_UTIL_FAIL;
        goto done;
    }
#else

#endif

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
int
hg_event_get(int fd, hg_util_bool_t *signaled)
{
    int ret = HG_UTIL_SUCCESS;
    hg_util_bool_t event_signal = HG_UTIL_FALSE;
#if defined(_WIN32)

#elif defined(HG_UTIL_HAS_SYSEVENTFD_H)
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
#elif defined(HG_UTIL_HAS_SYSEVENT_H)
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
#else

#endif

    if (signaled) *signaled = event_signal;

done:
    return ret;
}
