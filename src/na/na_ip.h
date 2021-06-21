/*
 * Copyright (C) 2013-2020 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#ifndef NA_IP_H
#define NA_IP_H

#include "na_types.h"

#include <netinet/in.h>

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
 * Return interface name and IPv4 address from a given hostname / port.
 *
 * \param hostname [IN]         hostname to resolve
 * \param port [IN]             port to use
 * \param ifa_name [OUT]        returned iface name
 * \param sin_addr_ptr [OUT]    returned pointer to IPv4 address
 *
 * \return NA_SUCCESS or corresponding NA error code
 */
NA_PRIVATE na_return_t
na_ip_check_interface(const char *hostname, unsigned int port, char **ifa_name,
    struct sockaddr_in **sin_addr_ptr);

#ifdef __cplusplus
}
#endif

#endif /* NA_IP_H */
