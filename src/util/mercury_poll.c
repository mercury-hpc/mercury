/*
 * Copyright (C) 2013-2016 Argonne National Laboratory, Department of Energy,
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

#include <stdlib.h>

#define HG_POLL_MAX_EVENTS 64

#if defined(_WIN32)

#else
#include <errno.h>
#include <string.h>
#ifdef HG_UTIL_HAS_SYSEPOLL_H
#include <unistd.h>

struct hg_poll_data {
    int fd;
    hg_poll_cb_t poll_cb;
    void *poll_arg;
    HG_LIST_ENTRY(hg_poll_data) entry;
};

struct hg_poll_set {
    int fd;
    unsigned int nfds;
    HG_LIST_HEAD(hg_poll_data) poll_data_list;
};
#else
struct hg_poll_data {
    struct pollfd pollfd;
    hg_poll_cb_t poll_cb;
    void *poll_arg;
    HG_LIST_ENTRY(hg_poll_data) entry;
};

struct hg_poll_set {
    nfds_t nfds;
    HG_LIST_HEAD(hg_poll_data) poll_data_list;
};
#endif
#endif

/*---------------------------------------------------------------------------*/
hg_poll_set_t *
hg_poll_create(void)
{
    struct hg_poll_set *hg_poll_set = NULL;
#ifdef HG_UTIL_HAS_SYSEPOLL_H
    int ret = 0;
#endif

    hg_poll_set = malloc(sizeof(struct hg_poll_set));
    if (!hg_poll_set) {
        HG_UTIL_LOG_ERROR("malloc() failed (%s)");
        goto done;
    }
#if defined(_WIN32)

#else
    HG_LIST_INIT(&hg_poll_set->poll_data_list);
    hg_poll_set->nfds = 0;
#ifdef HG_UTIL_HAS_SYSEPOLL_H
    ret = epoll_create1(0);
    if (ret == -1) {
        HG_UTIL_LOG_ERROR("epoll_create1() failed (%s)", strerror(errno));
        free(hg_poll_set);
        goto done;
    }
    hg_poll_set->fd = ret;
#endif
#endif

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

#else
    if (poll_set->nfds) {
        HG_UTIL_LOG_ERROR("Poll set non empty");
        ret = HG_UTIL_FAIL;
        goto done;
    }
#ifdef HG_UTIL_HAS_SYSEPOLL_H
    /* Close poll descriptor */
    if (close(poll_set->fd) == -1) {
        HG_UTIL_LOG_ERROR("close() failed (%s)", strerror(errno));
        ret = HG_UTIL_FAIL;
        goto done;
    }
#endif
#endif
    free(poll_set);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
int
hg_poll_get_fd(hg_poll_set_t *poll_set)
{
    int fd;

    if (!poll_set) {
        HG_UTIL_LOG_ERROR("NULL poll set");
        fd = HG_UTIL_FAIL;
        goto done;
    }
#if defined(_WIN32)

#elif defined(HG_UTIL_HAS_SYSEPOLL_H)
    fd = poll_set->fd;
#else

#endif

done:
    return fd;
}

/*---------------------------------------------------------------------------*/
int
hg_poll_add(hg_poll_set_t *poll_set, int fd, unsigned int flags,
    hg_poll_cb_t poll_cb, void *poll_arg)
{
    struct hg_poll_data *hg_poll_data = NULL;
#ifdef HG_UTIL_HAS_SYSEPOLL_H
    struct epoll_event ev;
#endif
    int ret = HG_UTIL_SUCCESS;

    if (!poll_set) {
        HG_UTIL_LOG_ERROR("NULL poll set");
        ret = HG_UTIL_FAIL;
        goto done;
    }

    hg_poll_data = malloc(sizeof(struct hg_poll_data));
    if (!hg_poll_data) {
        HG_UTIL_LOG_ERROR("malloc() failed (%s)");
        goto done;
    }
    hg_poll_data->poll_cb = poll_cb;
    hg_poll_data->poll_arg = poll_arg;
#if defined(_WIN32)

#elif defined(HG_UTIL_HAS_SYSEPOLL_H)
    hg_poll_data->fd = fd;
    ev.events = flags;
    ev.data.ptr = hg_poll_data;
    if (epoll_ctl(poll_set->fd, EPOLL_CTL_ADD, fd, &ev) == -1) {
        HG_UTIL_LOG_ERROR("epoll_ctl() failed (%s)", strerror(errno));
        ret = HG_UTIL_FAIL;
        goto done;
    }
#else
    hg_poll_data->pollfd.fd = fd;
    hg_poll_data->pollfd.events = (short int) flags;
    hg_poll_data->pollfd.revents = 0;
#endif
    HG_LIST_INSERT_HEAD(&poll_set->poll_data_list, hg_poll_data, entry);
    poll_set->nfds++;

done:
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

#elif defined(HG_UTIL_HAS_SYSEPOLL_H)
    if (epoll_ctl(poll_set->fd, EPOLL_CTL_DEL, fd, NULL) == -1) {
        HG_UTIL_LOG_ERROR("epoll_ctl() failed (%s)", strerror(errno));
        ret = HG_UTIL_FAIL;
        goto done;
    }
    HG_LIST_FOREACH(hg_poll_data, &poll_set->poll_data_list, entry) {
        if (hg_poll_data->fd == fd) {
            HG_LIST_REMOVE(hg_poll_data, entry);
            free(hg_poll_data);
            found = HG_UTIL_TRUE;
            break;
        }
    }
#else
    HG_LIST_FOREACH(hg_poll_data, &poll_set->poll_data_list, entry) {
        if (hg_poll_data->pollfd.fd == fd) {
            HG_LIST_REMOVE(hg_poll_data, entry);
            free(hg_poll_data);
            found = HG_UTIL_TRUE;
            break;
        }
    }
#endif
    if (!found) {
        HG_UTIL_LOG_ERROR("Could not find fd in poll_set");
        ret = HG_UTIL_FAIL;
        goto done;
    }
    poll_set->nfds--;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
int
hg_poll_wait(hg_poll_set_t *poll_set, int timeout, hg_util_bool_t *progressed)
{
    hg_util_bool_t poll_progressed = HG_UTIL_FALSE;
    int ret = HG_UTIL_SUCCESS;

    if (!poll_set) {
        HG_UTIL_LOG_ERROR("NULL poll set");
        ret = HG_UTIL_FAIL;
        goto done;
    }

    if (timeout) {
#if defined(_WIN32)

#elif defined(HG_UTIL_HAS_SYSEPOLL_H)
        struct epoll_event events[HG_POLL_MAX_EVENTS];
        int nfds, i;

        nfds = epoll_wait(poll_set->fd, events, HG_POLL_MAX_EVENTS, timeout);
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
                    hg_poll_data->poll_arg, &poll_cb_progressed);
                if (poll_ret != HG_UTIL_SUCCESS) {
                    HG_UTIL_LOG_ERROR("poll cb failed");
                    ret = HG_UTIL_FAIL;
                    goto done;
                }
                poll_progressed |= poll_cb_progressed;
            }
        }
#else
        struct pollfd pfds[HG_POLL_MAX_EVENTS];
        struct hg_poll_data *hg_poll_data = NULL;
        int nfds;
        unsigned int i = 0;

        if (poll_set->nfds > HG_POLL_MAX_EVENTS) {
            HG_UTIL_LOG_ERROR("Exceeding number of pollable file descriptors");
            ret = HG_UTIL_FAIL;
            goto done;
        }

        /* Fill pfds */
        HG_LIST_FOREACH(hg_poll_data, &poll_set->poll_data_list, entry) {
            pfds[i] = hg_poll_data->pollfd;
            i++;
        }

        nfds = poll(pfds, poll_set->nfds, timeout);
        if (nfds == -1 && errno != EINTR) {
            HG_UTIL_LOG_ERROR("poll() failed (%s)", strerror(errno));
            ret = HG_UTIL_FAIL;
            goto done;
        }
        if (nfds > 0) {
            /* An event on one of the fds has occurred. */
            for (i = 0; i < poll_set->nfds; i++) {
                if (pfds[i].revents & pfds[i].events) {
                    HG_LIST_FOREACH(hg_poll_data, &poll_set->poll_data_list, entry)
                        if (hg_poll_data->pollfd.fd == pfds[i].fd)
                            break;

                    if (hg_poll_data->poll_cb) {
                        hg_util_bool_t poll_cb_progressed = HG_UTIL_FALSE;
                        int poll_ret = HG_UTIL_SUCCESS;

                        poll_ret = hg_poll_data->poll_cb(
                            hg_poll_data->poll_arg, &poll_progressed);
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

        HG_LIST_FOREACH(hg_poll_data, &poll_set->poll_data_list, entry) {
            if (hg_poll_data->poll_cb) {
                hg_util_bool_t poll_cb_progressed = HG_UTIL_FALSE;
                int poll_ret = HG_UTIL_SUCCESS;

                poll_ret = hg_poll_data->poll_cb(
                    hg_poll_data->poll_arg, &poll_cb_progressed);
                if (poll_ret != HG_UTIL_SUCCESS) {
                    HG_UTIL_LOG_ERROR("poll cb failed");
                    ret = HG_UTIL_FAIL;
                    goto done;
                }
                poll_progressed |= poll_cb_progressed;
                if (poll_progressed)
                    break;
            }
        }
#endif
    }

    if (progressed)
        *progressed = poll_progressed;

done:
    return ret;
}
