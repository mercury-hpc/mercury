/*
 * Copyright (C) 2013-2019 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#include "mercury_event.h"

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
