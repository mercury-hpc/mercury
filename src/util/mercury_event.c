/*
 * Copyright (C) 2013-2016 Argonne National Laboratory, Department of Energy,
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
#ifdef HG_UTIL_HAS_SYSEVENTFD_H
#include <sys/eventfd.h>
#include <unistd.h>
#else

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
    uint64_t count = 1;
    ssize_t s;

    s = write(fd, &count, sizeof(uint64_t));
    if (s != sizeof(uint64_t)) {
        HG_UTIL_LOG_ERROR("write() failed (%s)", strerror(errno));
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
    uint64_t count = 1;
    ssize_t s;

    s = read(fd, &count, sizeof(uint64_t));
    if (s != sizeof(uint64_t)) {
        if (errno == EAGAIN)
            goto done;
        HG_UTIL_LOG_ERROR("read() failed (%s)", strerror(errno));
        ret = HG_UTIL_FAIL;
        goto done;
    }
    event_signal = HG_UTIL_TRUE;
#else

#endif

    if (signaled) *signaled = event_signal;

done:
    return ret;
}
