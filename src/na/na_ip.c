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

#include <ctype.h>
#include <errno.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
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
    *netp = (na_uint32_t)(
                (addr[0] << 24) | (addr[1] << 16) | (addr[2] << 8) | addr[3]) &
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
