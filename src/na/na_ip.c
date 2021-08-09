/*
 * Copyright (C) 2013-2020 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#include "na_ip.h"
#include "na_error.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netdb.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

/*---------------------------------------------------------------------------*/
na_return_t
na_ip_parse_subnet(const char *spec, na_uint32_t *netp, na_uint32_t *netmaskp)
{
    int addr[4], depth, nb;
    const char *sp;
    na_return_t ret = NA_SUCCESS;

    memset(addr, 0, sizeof(addr));

    /* parse the numbers in the address spec string */
    for (sp = spec, depth = 0; *sp && *sp != '/'; sp++) {
        if (isdigit(*sp)) {
            addr[depth] = (addr[depth] * 10) + (*sp - '0');
            NA_CHECK_ERROR(addr[depth] > 255, done, ret, NA_INVALID_ARG,
                "Malformed address");
            continue;
        }
        NA_CHECK_ERROR(*sp != '.' || !isdigit(*(sp + 1)), done, ret,
            NA_INVALID_ARG, "Malformed address");
        depth++;
        NA_CHECK_ERROR(
            depth > 3, done, ret, NA_INVALID_ARG, "Malformed address");
    }
    if (*sp == '/') {
        nb = atoi(sp + 1);
        NA_CHECK_ERROR(nb < 1 || nb > 32, done, ret, NA_INVALID_ARG,
            "Malformed subnet mask");
    } else {
        nb = (depth + 1) * 8; /* no '/'... use depth to get network bits */
    }
    /* avoid right shifting by 32... it's undefined behavior */
    *netmaskp = (nb == 32) ? 0xffffffff : ~(0xffffffff >> nb);
    *netp = (na_uint32_t) ((addr[0] << 24) | (addr[1] << 16) | (addr[2] << 8) |
                           addr[3]) &
            *netmaskp;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
na_return_t
na_ip_pref_addr(na_uint32_t net, na_uint32_t netmask, char *outstr)
{
    struct ifaddrs *ifaddr, *cur;
    struct sockaddr_in *sin;
    uint32_t cur_ipaddr;
    static uint32_t localhost = (127 << 24) | 1; /* 127.0.0.1 */
    na_return_t ret = NA_SUCCESS;
    int rc;

    rc = getifaddrs(&ifaddr);
    NA_CHECK_ERROR(rc == -1, done, ret, NA_FAULT, "getifaddrs() failed (%s)",
        strerror(errno));

    /* walk list looking for a match */
    for (cur = ifaddr; cur != NULL; cur = cur->ifa_next) {
        if ((cur->ifa_flags & IFF_UP) == 0)
            continue; /* skip interfaces that are down */
        if (cur->ifa_addr == NULL || cur->ifa_addr->sa_family != AF_INET)
            continue; /* skip interfaces w/o IP address */
        sin = (struct sockaddr_in *) cur->ifa_addr;
        cur_ipaddr = ntohl(sin->sin_addr.s_addr);
        if (netmask) {
            if ((cur_ipaddr & netmask) == net)
                break; /* got it! */
            continue;
        }
        if (cur_ipaddr != localhost)
            break; /* no net given, randomly select first !localhost addr */
    }

    NA_CHECK_ERROR(
        cur == NULL, cleanup, ret, NA_ADDRNOTAVAIL, "No match found for IP");

    rc = getnameinfo(cur->ifa_addr, sizeof(struct sockaddr_in), outstr, 16,
        NULL, 0, NI_NUMERICHOST);
    NA_CHECK_ERROR(rc != 0, cleanup, ret, NA_ADDRNOTAVAIL,
        "getnameinfo() failed (%s)", strerror(errno));

cleanup:
    freeifaddrs(ifaddr);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
na_return_t
na_ip_check_interface(const char *hostname, unsigned int port, char **ifa_name,
    struct sockaddr_storage **ss_ptr)
{
    struct ifaddrs *ifaddrs = NULL, *ifaddr;
    struct addrinfo hints, *hostname_res = NULL;
    struct sockaddr_storage *ss_addr = NULL;
    char ip_res[INET6_ADDRSTRLEN] = {'\0'}; /* To handle IPv6 addresses */
    na_return_t ret = NA_SUCCESS;
    na_bool_t found = NA_FALSE;
    int s;

    /* Allocate new sin addr to store result */
    ss_addr = calloc(1, sizeof(*ss_addr));
    NA_CHECK_SUBSYS_ERROR(cls, ss_addr == NULL, done, ret, NA_NOMEM,
        "Could not allocate sin address");

    /* Try to resolve hostname first so that we can later compare the IP */
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = 0;
    hints.ai_protocol = 0;
    s = getaddrinfo(hostname, NULL, &hints, &hostname_res);
    if (s == 0) {
        struct addrinfo *rp;

        /* Get IP */
        for (rp = hostname_res; rp != NULL; rp = rp->ai_next) {
            const char *ptr = inet_ntop(rp->ai_addr->sa_family,
                rp->ai_addr->sa_data, ip_res, INET6_ADDRSTRLEN);
            NA_CHECK_SUBSYS_ERROR(cls, ptr == NULL, done, ret, NA_ADDRNOTAVAIL,
                "IP could not be resolved");
            break;
        }
    }

    /* Check and compare interfaces */
    s = getifaddrs(&ifaddrs);
    NA_CHECK_SUBSYS_ERROR(
        cls, s == -1, done, ret, NA_ADDRNOTAVAIL, "getifaddrs() failed");

    for (ifaddr = ifaddrs; ifaddr != NULL; ifaddr = ifaddr->ifa_next) {
        char ip[INET6_ADDRSTRLEN] = {'\0'}; /* To handle IPv6 addresses */
        const char *ptr;

        if (ifaddr->ifa_addr == NULL)
            continue;

        if (ifaddr->ifa_addr->sa_family != AF_INET &&
            ifaddr->ifa_addr->sa_family != AF_INET6)
            continue;

        /* Get IP */
        ptr = inet_ntop(ifaddr->ifa_addr->sa_family, ifaddr->ifa_addr->sa_data,
            ip, INET6_ADDRSTRLEN);
        NA_CHECK_SUBSYS_ERROR(cls, ptr == NULL, done, ret, NA_ADDRNOTAVAIL,
            "IP could not be resolved for: %s", ifaddr->ifa_name);

        /* Compare hostnames / device names */
        if (strcmp(ip, ip_res) == 0 ||
            strcmp(ifaddr->ifa_name, hostname) == 0) {
            if (ifaddr->ifa_addr->sa_family == AF_INET) {
                *(struct sockaddr_in *) ss_addr =
                    *(struct sockaddr_in *) ifaddr->ifa_addr;
                ((struct sockaddr_in *) ss_addr)->sin_port =
                    htons(port & 0xffff);
            } else {
                *(struct sockaddr_in6 *) ss_addr =
                    *(struct sockaddr_in6 *) ifaddr->ifa_addr;
                ((struct sockaddr_in6 *) ss_addr)->sin6_port =
                    htons(port & 0xffff);
            }
            found = NA_TRUE;
            break;
        }
    }

    if (found) {
        if (ss_ptr)
            *ss_ptr = ss_addr;
        if (ifa_name) {
            *ifa_name = strdup(ifaddr->ifa_name);
            NA_CHECK_SUBSYS_ERROR(cls, *ifa_name == NULL, done, ret, NA_NOMEM,
                "Could not dup ifa_name");
        }
    }

done:
    if (!found || ret != NA_SUCCESS || !ss_ptr)
        free(ss_addr);
    freeifaddrs(ifaddrs);
    if (hostname_res)
        freeaddrinfo(hostname_res);

    return ret;
}