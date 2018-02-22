/*
 * Copyright (C) 2013-2017 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#include "mercury_poll.h"
#include "mercury_list.h"
#include "mercury_util_error.h"
#include "mercury_thread_spin.h"
#include "mercury_atomic.h"

#include <stdlib.h>

#define HG_POLL_MAX_EVENTS 64 /* TODO Make this configurable */

#if defined(_WIN32)
/* TODO */
#else
#include <errno.h>
#include <string.h>
#include <unistd.h>
#if defined(HG_UTIL_HAS_SYSEPOLL_H)
#include <sys/epoll.h>
#elif defined(HG_UTIL_HAS_SYSEVENT_H)
#include <sys/event.h>
#include <sys/time.h>
#else
#include <poll.h>
#endif
#endif /* defined(_WIN32) */

struct hg_poll_data {
#if defined(HG_UTIL_HAS_SYSEPOLL_H)
    int fd;
#elif defined(HG_UTIL_HAS_SYSEVENT_H)
    struct kevent kev;
#else
    struct pollfd pollfd;
#endif
    hg_poll_cb_t poll_cb;
    void *poll_arg;
    HG_LIST_ENTRY(hg_poll_data) entry;
};

struct hg_poll_set {
    int fd;
    hg_atomic_int32_t nfds;
    hg_poll_try_wait_cb_t try_wait_cb;
    void *try_wait_arg;
#if defined(HG_UTIL_HAS_SYSEPOLL_H) || defined(HG_UTIL_HAS_SYSEVENT_H)
    /* Nothing */
#else
    struct pollfd *poll_fds;
#endif
    HG_LIST_HEAD(hg_poll_data) poll_data_list;
    hg_thread_spin_t poll_data_list_lock;
};

/*---------------------------------------------------------------------------*/
hg_poll_set_t *
hg_poll_create(void)
{
    struct hg_poll_set *hg_poll_set = NULL;
#if defined(HG_UTIL_HAS_SYSEPOLL_H) || defined(HG_UTIL_HAS_SYSEVENT_H)
    int ret = 0;
#endif

    hg_poll_set = malloc(sizeof(struct hg_poll_set));
    if (!hg_poll_set) {
        HG_UTIL_LOG_ERROR("malloc() failed (%s)");
        goto done;
    }
#if defined(_WIN32)
    /* TODO */
#else
    HG_LIST_INIT(&hg_poll_set->poll_data_list);
    hg_thread_spin_init(&hg_poll_set->poll_data_list_lock);
    hg_atomic_init32(&hg_poll_set->nfds, 0);
    hg_poll_set->try_wait_cb = NULL;
#if defined(HG_UTIL_HAS_SYSEPOLL_H)
    ret = epoll_create1(0);
    if (ret == -1) {
        HG_UTIL_LOG_ERROR("epoll_create1() failed (%s)", strerror(errno));
        free(hg_poll_set);
        hg_poll_set = NULL;
        goto done;
    }
    hg_poll_set->fd = ret;
#elif defined(HG_UTIL_HAS_SYSEVENT_H)
    ret = kqueue();
    if (ret == -1) {
        HG_UTIL_LOG_ERROR("kqueue() failed (%s)", strerror(errno));
        free(hg_poll_set);
        hg_poll_set = NULL;
        goto done;
    }
    hg_poll_set->fd = ret;
#else
    hg_poll_set->poll_fds = malloc(sizeof(int) * HG_POLL_MAX_EVENTS);
    if (!hg_poll_set->poll_fds) {
        HG_UTIL_LOG_ERROR("malloc() failed (%s)");
        free(hg_poll_set);
        hg_poll_set = NULL;
        goto done;
    }
#endif
#endif /* defined(_WIN32) */

done:
    return hg_poll_set;
}

/*---------------------------------------------------------------------------*/
int
hg_poll_destroy(hg_poll_set_t *poll_set)
{
    int ret = HG_UTIL_SUCCESS;

    if (!poll_set)
        goto done;

#if defined(_WIN32)
    /* TODO */
#else
    if (hg_atomic_get32(&poll_set->nfds)) {
        HG_UTIL_LOG_ERROR("Poll set non empty");
        ret = HG_UTIL_FAIL;
        goto done;
    }
#if defined(HG_UTIL_HAS_SYSEPOLL_H) || defined(HG_UTIL_HAS_SYSEVENT_H)
    /* Close poll descriptor */
    if (close(poll_set->fd) == -1) {
        HG_UTIL_LOG_ERROR("close() failed (%s)", strerror(errno));
        ret = HG_UTIL_FAIL;
        goto done;
    }
#else
    free(poll_set->poll_fds);
#endif
    hg_thread_spin_destroy(&poll_set->poll_data_list_lock);
#endif /* defined(_WIN32) */
    free(poll_set);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
int
hg_poll_get_fd(hg_poll_set_t *poll_set)
{
    int fd = 0;

    if (!poll_set) {
        HG_UTIL_LOG_ERROR("NULL poll set");
        fd = HG_UTIL_FAIL;
        goto done;
    }
#if defined(_WIN32)
    /* TODO */
#elif defined(HG_UTIL_HAS_SYSEPOLL_H) || defined(HG_UTIL_HAS_SYSEVENT_H)
    fd = poll_set->fd;
#else
    /* TODO */
#endif

done:
    return fd;
}

/*---------------------------------------------------------------------------*/
int
hg_poll_set_try_wait(hg_poll_set_t *poll_set, hg_poll_try_wait_cb_t try_wait_cb,
    void *arg)
{
    int ret = HG_UTIL_SUCCESS;

    if (!poll_set) {
        HG_UTIL_LOG_ERROR("NULL poll set");
        ret = HG_UTIL_FAIL;
        goto done;
    }

    poll_set->try_wait_cb = try_wait_cb;
    poll_set->try_wait_arg = arg;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
int
hg_poll_add(hg_poll_set_t *poll_set, int fd, unsigned int flags,
    hg_poll_cb_t poll_cb, void *poll_arg)
{
    struct hg_poll_data *hg_poll_data = NULL;
    int ret = HG_UTIL_SUCCESS;

    if (!poll_set) {
        HG_UTIL_LOG_ERROR("NULL poll set");
        ret = HG_UTIL_FAIL;
        goto done;
    }

    /* Allocate poll data that can hold user data and callback */
    hg_poll_data = malloc(sizeof(struct hg_poll_data));
    if (!hg_poll_data) {
        HG_UTIL_LOG_ERROR("malloc() failed (%s)");
        goto done;
    }
    memset(hg_poll_data, 0, sizeof(struct hg_poll_data));
    hg_poll_data->poll_cb = poll_cb;
    hg_poll_data->poll_arg = poll_arg;

    if (fd > 0) {
#if defined(_WIN32)
        /* TODO */
#elif defined(HG_UTIL_HAS_SYSEPOLL_H)
        struct epoll_event ev;
        uint32_t poll_flags;

        /* Translate flags */
        switch (flags) {
            case HG_POLLIN:
                poll_flags = EPOLLIN;
                break;
            case HG_POLLOUT:
                poll_flags = EPOLLOUT;
                break;
            default:
                HG_UTIL_LOG_ERROR("Invalid flag");
                ret = HG_UTIL_FAIL;
                goto done;
        }

        hg_poll_data->fd = fd;
        ev.events = poll_flags;
        ev.data.ptr = hg_poll_data;

        if (epoll_ctl(poll_set->fd, EPOLL_CTL_ADD, fd, &ev) == -1) {
            HG_UTIL_LOG_ERROR("epoll_ctl() failed (%s)", strerror(errno));
            ret = HG_UTIL_FAIL;
            goto done;
        }
#elif defined(HG_UTIL_HAS_SYSEVENT_H)
        struct timespec timeout = {0, 0};
        int16_t poll_flags;

        /* Translate flags */
        switch (flags) {
            case HG_POLLIN:
                poll_flags = EVFILT_READ;
                break;
            case HG_POLLOUT:
                poll_flags = EVFILT_WRITE;
                break;
            default:
                HG_UTIL_LOG_ERROR("Invalid flag");
                ret = HG_UTIL_FAIL;
                goto done;
        }

        EV_SET(&hg_poll_data->kev, (uintptr_t) fd, poll_flags, EV_ADD, 0, 0, hg_poll_data);

        if (kevent(poll_set->fd, &hg_poll_data->kev, 1, NULL, 0, &timeout) == -1) {
            HG_UTIL_LOG_ERROR("kevent() failed (%s)", strerror(errno));
            ret = HG_UTIL_FAIL;
            goto done;
        }
#else
        short int poll_flags;

        /* Translate flags */
        switch (flags) {
            case HG_POLLIN:
                poll_flags = POLLIN;
                break;
            case HG_POLLOUT:
                poll_flags = POLLOUT;
                break;
            default:
                HG_UTIL_LOG_ERROR("Invalid flag");
                ret = HG_UTIL_FAIL;
                goto done;
        }

        hg_poll_data->pollfd.fd = fd;
        hg_poll_data->pollfd.events = poll_flags;
        hg_poll_data->pollfd.revents = 0;

        /* TODO limit on number of fds for now but could malloc/reallocate */
        if (poll_set->nfds + 1 > HG_POLL_MAX_EVENTS) {
            HG_UTIL_LOG_ERROR("Exceeding number of pollable file descriptors");
            ret = HG_UTIL_FAIL;
            free(hg_poll_data);
            goto done;
        }

        poll_set->poll_fds[poll_set->nfds] = hg_poll_data->pollfd;
#endif /* defined(_WIN32) */
    }
    hg_thread_spin_lock(&poll_set->poll_data_list_lock);
    HG_LIST_INSERT_HEAD(&poll_set->poll_data_list, hg_poll_data, entry);
    hg_thread_spin_unlock(&poll_set->poll_data_list_lock);
    hg_atomic_incr32(&poll_set->nfds);

done:
    if (ret != HG_UTIL_SUCCESS)
        free(hg_poll_data);
    return ret;
}

/*---------------------------------------------------------------------------*/
int
hg_poll_remove(hg_poll_set_t *poll_set, int fd)
{
    struct hg_poll_data *hg_poll_data;
    hg_util_bool_t found = HG_UTIL_FALSE;
    int ret = HG_UTIL_SUCCESS;

    if (!poll_set) {
        HG_UTIL_LOG_ERROR("NULL poll set");
        ret = HG_UTIL_FAIL;
        goto done;
    }

#if defined(_WIN32)
    /* TODO */
#elif defined(HG_UTIL_HAS_SYSEPOLL_H)
    hg_thread_spin_lock(&poll_set->poll_data_list_lock);
    HG_LIST_FOREACH(hg_poll_data, &poll_set->poll_data_list, entry) {
        if (hg_poll_data->fd == fd) {
            HG_LIST_REMOVE(hg_poll_data, entry);

            if ((fd > 0)
                && epoll_ctl(poll_set->fd, EPOLL_CTL_DEL, fd, NULL) == -1) {
                HG_UTIL_LOG_ERROR("epoll_ctl() failed (%s)", strerror(errno));
                ret = HG_UTIL_FAIL;
                hg_thread_spin_unlock(&poll_set->poll_data_list_lock);
                goto done;
            }
            free(hg_poll_data);
            found = HG_UTIL_TRUE;
            break;
        }
    }
    hg_thread_spin_unlock(&poll_set->poll_data_list_lock);
#elif defined(HG_UTIL_HAS_SYSEVENT_H)
    /* Events which are attached to file descriptors are automatically deleted
     * on the last close of the descriptor. */
    hg_thread_spin_lock(&poll_set->poll_data_list_lock);
    HG_LIST_FOREACH(hg_poll_data, &poll_set->poll_data_list, entry) {
        if ((int) hg_poll_data->kev.ident == fd) {
            HG_LIST_REMOVE(hg_poll_data, entry);

            if (fd > 0) {
                struct timespec timeout = {0, 0};

                EV_SET(&hg_poll_data->kev, (uintptr_t) fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
                if (kevent(poll_set->fd, &hg_poll_data->kev, 1, NULL, 0,
                    &timeout) == -1) {
                    HG_UTIL_LOG_ERROR("kevent() failed (%s)", strerror(errno));
                    ret = HG_UTIL_FAIL;
                    hg_thread_spin_unlock(&poll_set->poll_data_list_lock);
                    goto done;
                }
            }
            free(hg_poll_data);
            found = HG_UTIL_TRUE;
            break;
        }
    }
    hg_thread_spin_unlock(&poll_set->poll_data_list_lock);
#else
    hg_thread_spin_lock(&poll_set->poll_data_list_lock);
    HG_LIST_FOREACH(hg_poll_data, &poll_set->poll_data_list, entry) {
        if (hg_poll_data->pollfd.fd == fd) {
            unsigned int i = 0;

            HG_LIST_REMOVE(hg_poll_data, entry);
            free(hg_poll_data);
            found = HG_UTIL_TRUE;

            if (fd > 0) {
                /* Re-order poll_events */
                HG_LIST_FOREACH(hg_poll_data, &poll_set->poll_data_list, entry) {
                    poll_set->poll_fds[i] = hg_poll_data->pollfd;
                    i++;
                }
            }
            break;
        }
    }
    hg_thread_spin_unlock(&poll_set->poll_data_list_lock);
#endif
    if (!found) {
        HG_UTIL_LOG_ERROR("Could not find fd in poll_set");
        ret = HG_UTIL_FAIL;
        goto done;
    }
    hg_atomic_decr32(&poll_set->nfds);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
int
hg_poll_wait(hg_poll_set_t *poll_set, unsigned int timeout,
    hg_util_bool_t *progressed)
{
    hg_util_bool_t poll_progressed = HG_UTIL_FALSE;
    int ret = HG_UTIL_SUCCESS;

    if (!poll_set) {
        HG_UTIL_LOG_ERROR("NULL poll set");
        ret = HG_UTIL_FAIL;
        goto done;
    }

    if (timeout && (!poll_set->try_wait_cb || (poll_set->try_wait_cb
        && poll_set->try_wait_cb(poll_set->try_wait_arg))))  {
#if defined(_WIN32)

#elif defined(HG_UTIL_HAS_SYSEPOLL_H)
        struct epoll_event events[HG_POLL_MAX_EVENTS];
        int nfds, i;

        nfds = epoll_wait(poll_set->fd, events, HG_POLL_MAX_EVENTS, (int) timeout);
        if (nfds == -1 && errno != EINTR) {
            HG_UTIL_LOG_ERROR("epoll_wait() failed (%s)", strerror(errno));
            ret = HG_UTIL_FAIL;
            goto done;
        }
        for (i = 0; i < nfds; ++i) {
            struct hg_poll_data *hg_poll_data =
                (struct hg_poll_data *) events[i].data.ptr;
            if (!hg_poll_data) {
                HG_UTIL_LOG_ERROR("NULL poll data");
                ret = HG_UTIL_FAIL;
                goto done;
            }
            if (hg_poll_data->poll_cb) {
                hg_util_bool_t poll_cb_progressed = HG_UTIL_FALSE;
                int poll_ret = HG_UTIL_SUCCESS;

                poll_ret = hg_poll_data->poll_cb(
                    hg_poll_data->poll_arg, timeout, &poll_cb_progressed);
                if (poll_ret != HG_UTIL_SUCCESS) {
                    HG_UTIL_LOG_ERROR("poll cb failed");
                    ret = HG_UTIL_FAIL;
                    goto done;
                }
                poll_progressed |= poll_cb_progressed;
            }
        }
#elif defined(HG_UTIL_HAS_SYSEVENT_H)
        struct kevent events[HG_POLL_MAX_EVENTS];
        int nfds, i;
        struct timespec timeout_spec;
        ldiv_t ld;

        /* Get sec / nsec */
        ld = ldiv(timeout, 1000L);
        timeout_spec.tv_sec = ld.quot;
        timeout_spec.tv_nsec = ld.rem * 1000000L;

        nfds = kevent(poll_set->fd, NULL, 0, events, HG_POLL_MAX_EVENTS,
            &timeout_spec);
        if (nfds == -1 && errno != EINTR) {
            HG_UTIL_LOG_ERROR("kevent() failed (%s)", strerror(errno));
            ret = HG_UTIL_FAIL;
            goto done;
        }
        for (i = 0; i < nfds; ++i) {
            struct hg_poll_data *hg_poll_data =
                (struct hg_poll_data *) events[i].udata;
            if (!hg_poll_data) {
                HG_UTIL_LOG_ERROR("NULL poll data");
                ret = HG_UTIL_FAIL;
                goto done;
            }
            if (hg_poll_data->poll_cb) {
                hg_util_bool_t poll_cb_progressed = HG_UTIL_FALSE;
                int poll_ret = HG_UTIL_SUCCESS;

                poll_ret = hg_poll_data->poll_cb(
                    hg_poll_data->poll_arg, timeout, &poll_cb_progressed);
                if (poll_ret != HG_UTIL_SUCCESS) {
                    HG_UTIL_LOG_ERROR("poll cb failed");
                    ret = HG_UTIL_FAIL;
                    goto done;
                }
                poll_progressed |= poll_cb_progressed;
            }
        }
#else
        struct hg_poll_data *hg_poll_data = NULL;
        int nfds;
        unsigned int i;

        /* Reset revents */
        for (i = 0; i < poll_set->nfds; i++)
            poll_set->poll_fds[i].revents = 0;

        nfds = poll(poll_set->poll_fds, poll_set->nfds, (int) timeout);
        if (nfds == -1 && errno != EINTR) {
            HG_UTIL_LOG_ERROR("poll() failed (%s)", strerror(errno));
            ret = HG_UTIL_FAIL;
            goto done;
        }
        if (nfds > 0) {
            /* An event on one of the fds has occurred. */
            for (i = 0; i < poll_set->nfds; i++) {
                if (poll_set->poll_fds[i].revents & poll_set->poll_fds[i].events) {
                    hg_thread_spin_lock(&poll_set->poll_data_list_lock);
                    HG_LIST_FOREACH(hg_poll_data, &poll_set->poll_data_list, entry) {
                        if (hg_poll_data->pollfd.fd == poll_set->poll_fds[i].fd) {
                            hg_thread_spin_unlock(&poll_set->poll_data_list_lock);
                            break;
                        }
                    }
                    hg_thread_spin_unlock(&poll_set->poll_data_list_lock);

                    if (hg_poll_data->poll_cb) {
                        hg_util_bool_t poll_cb_progressed = HG_UTIL_FALSE;
                        int poll_ret = HG_UTIL_SUCCESS;

                        poll_ret = hg_poll_data->poll_cb(
                            hg_poll_data->poll_arg, timeout, &poll_progressed);
                        if (poll_ret != HG_UTIL_SUCCESS) {
                            HG_UTIL_LOG_ERROR("poll cb failed");
                            ret = HG_UTIL_FAIL;
                            goto done;
                        }
                        poll_progressed |= poll_cb_progressed;
                    }
                }
            }
        }
#endif
    } else {
#ifdef _WIN32

#else
        struct hg_poll_data *hg_poll_data;

        hg_thread_spin_lock(&poll_set->poll_data_list_lock);
        HG_LIST_FOREACH(hg_poll_data, &poll_set->poll_data_list, entry) {
            hg_thread_spin_unlock(&poll_set->poll_data_list_lock);
            if (hg_poll_data->poll_cb) {
                hg_util_bool_t poll_cb_progressed = HG_UTIL_FALSE;
                int poll_ret = HG_UTIL_SUCCESS;

                poll_ret = hg_poll_data->poll_cb(
                    hg_poll_data->poll_arg, 0, &poll_cb_progressed);
                if (poll_ret != HG_UTIL_SUCCESS) {
                    HG_UTIL_LOG_ERROR("poll cb failed");
                    ret = HG_UTIL_FAIL;
                    hg_thread_spin_unlock(&poll_set->poll_data_list_lock);
                    goto done;
                }
                poll_progressed |= poll_cb_progressed;
                if (poll_progressed)
                    break;
            }
            hg_thread_spin_lock(&poll_set->poll_data_list_lock);
        }
        if (!poll_progressed)
            hg_thread_spin_unlock(&poll_set->poll_data_list_lock);
#endif
    }

    if (progressed)
        *progressed = poll_progressed;

done:
    return ret;
}
