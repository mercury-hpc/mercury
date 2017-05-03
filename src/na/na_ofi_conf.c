/* Copyright (C) 2017 Intel Corporation
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted for any purpose (including commercial purposes)
 * provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions, and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions, and the following disclaimer in the
 *    documentation and/or materials provided with the distribution.
 *
 * 3. In addition, redistributions of modified forms of the source or binary
 *    code must carry prominent notices stating that the original code was
 *    changed and the date of the change.
 *
 *  4. All publications or advertising materials mentioning features or use of
 *     this software are asked, but not required, to acknowledge that it was
 *     developed by Intel Corporation and credit the contributors.
 *
 * 5. Neither the name of Intel Corporation, nor the name of any Contributor
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "na_ofi.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <inttypes.h>

/* global NA OFI plugin configuration */
struct na_ofi_config na_ofi_conf;

static inline na_bool_t
is_integer_str(char *str)
{
    char *p;

    p = str;
    if (p == NULL || strlen(p) == 0)
        return NA_FALSE;

    while (*p != '\0') {
        if (*p <= '9' && *p >= '0') {
            p++;
            continue;
        } else {
            return NA_FALSE;
        }
    }

    return NA_TRUE;
}

na_return_t
na_ofi_config_init()
{
    char *port_str;
    char *interface;
    int port;
    struct ifaddrs *if_addrs = NULL;
    struct ifaddrs *ifa = NULL;
    void *tmp_ptr;
    const char *ip_str = NULL;
    int rc;
    na_return_t ret = NA_SUCCESS;

    interface = getenv("OFI_INTERFACE");
    if (interface != NULL && strlen(interface) > 0) {
        na_ofi_conf.noc_interface = strdup(interface);
        if (na_ofi_conf.noc_interface == NULL) {
            NA_LOG_ERROR("cannot allocate memory for noc_interface.");
            ret = NA_NOMEM_ERROR;
            goto out;
        }
    } else {
        na_ofi_conf.noc_interface = NULL;
        NA_LOG_ERROR("ENV OFI_INTERFACE not set.");
        ret = NA_INVALID_PARAM;
        goto out;
    }

    rc = getifaddrs(&if_addrs);
    if (rc != 0) {
        NA_LOG_ERROR("cannot getifaddrs, errno: %d(%s).\n",
                     errno, strerror(errno));
        ret = NA_PROTOCOL_ERROR;
        goto out;
    }

    for (ifa = if_addrs; ifa != NULL; ifa = ifa->ifa_next) {
        if (strcmp(ifa->ifa_name, na_ofi_conf.noc_interface))
            continue;
        if (ifa->ifa_addr == NULL)
            continue;
        memset(na_ofi_conf.noc_ip_str, 0, INET_ADDRSTRLEN);
        if (ifa->ifa_addr->sa_family == AF_INET) {
            /* check it is a valid IPv4 Address */
            tmp_ptr =
            &((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;
            ip_str = inet_ntop(AF_INET, tmp_ptr, na_ofi_conf.noc_ip_str,
                         INET_ADDRSTRLEN);
            if (ip_str == NULL) {
                NA_LOG_ERROR("inet_ntop failed, errno: %d(%s).\n",
                    errno, strerror(errno));
                freeifaddrs(if_addrs);
                ret = NA_PROTOCOL_ERROR;
                goto out;
            }
            if (strcmp(ip_str, "127.0.0.1") == 0) {
                continue;
            }
            /*
            NA_LOG_DEBUG("Get interface %s IPv4 Address %s\n",
                         ifa->ifa_name, na_ofi_conf.noc_ip_str);
            */
            break;
        } else if (ifa->ifa_addr->sa_family == AF_INET6) {
            /* check it is a valid IPv6 Address */
            /*
             * tmp_ptr =
             * &((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr;
             * inet_ntop(AF_INET6, tmp_ptr, na_ofi_conf.noc_ip_str,
             *           INET6_ADDRSTRLEN);
             * C_DEBUG("Get %s IPv6 Address %s\n",
             *         ifa->ifa_name, na_ofi_conf.noc_ip_str);
             */
        }
    }
    freeifaddrs(if_addrs);
    if (ip_str == NULL) {
        NA_LOG_ERROR("no IP addr found.\n");
        ret = NA_PROTOCOL_ERROR;
        goto out;
    }

    port_str = getenv("OFI_PORT");
    if (port_str == NULL || strlen(port_str) == 0) {
        na_ofi_conf.noc_port_cons = NA_FALSE;
        hg_atomic_set32(&na_ofi_conf.noc_port, 0);
        goto out;
    }
    if (is_integer_str(port_str) == NA_FALSE) {
        NA_LOG_ERROR("OFI_PORT %s invalid.", port_str);
        na_ofi_config_fini();
        ret = NA_INVALID_PARAM;
        goto out;
    }

    port = atoi(port_str);
    na_ofi_conf.noc_port_cons = NA_TRUE;
    hg_atomic_set32(&na_ofi_conf.noc_port, port - 1);

out:
    return ret;
}

void
na_ofi_config_fini()
{
    if (na_ofi_conf.noc_interface != NULL) {
        free(na_ofi_conf.noc_interface);
        na_ofi_conf.noc_interface = NULL;
    }
    na_ofi_conf.noc_port_cons = NA_FALSE;
    hg_atomic_set32(&na_ofi_conf.noc_port, 0);
}
