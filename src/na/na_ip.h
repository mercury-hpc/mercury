/**
 * Copyright (c) 2013-2021 UChicago Argonne, LLC and The HDF Group.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef NA_IP_H
#define NA_IP_H

#include "na_types.h"

#include <sys/socket.h>

/*************************************/
/* Public Type and Struct Definition */
/*************************************/

/*****************/
/* Public Macros */
/*****************/

/*********************/
/* Public Prototypes */
/*********************/

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Parse a subnet specification string.
 *
 * \param spec  [IN]    the specification string to parse
 * \param netp  [OUT]   pointer to where to put network info
 * \param maskp [OUT]   pointer to where to put the netmask info
 *
 * \return NA_SUCCESS or corresponding NA error code
 */
NA_PRIVATE na_return_t
na_ip_parse_subnet(const char *spec, na_uint32_t *netp, na_uint32_t *netmaskp);

/**
 * Get preferred ip address (based on provided subnet).
 *
 * \param net     [IN]  desired network
 * \param netmask [IN]  netmask for desired network, 0 if no preference given
 * \param outstr  [OUT] result returned here (size should at least be 16 to fit)
 *
 * \return NA_SUCCESS or corresponding NA error code
 */
NA_PRIVATE na_return_t
na_ip_pref_addr(na_uint32_t net, na_uint32_t netmask, char *outstr);

/**
 * Return interface name and sockaddr from a given hostname / port.
 *
 * \param hostname [IN]         hostname to resolve
 * \param port [IN]             port to use
 * \param ifa_name [OUT]        returned iface name
 * \param ss_ptr [OUT]          returned pointer to usable sockaddr
 *
 * \return NA_SUCCESS or corresponding NA error code
 */
NA_PRIVATE na_return_t
na_ip_check_interface(const char *hostname, unsigned int port, char **ifa_name,
    struct sockaddr_storage **ss_ptr);

#ifdef __cplusplus
}
#endif

#endif /* NA_IP_H */
