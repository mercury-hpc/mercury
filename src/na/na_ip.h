/*
 * Copyright (C) 2013-2019 Argonne National Laboratory, Department of Energy,
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

#ifdef __cplusplus
}
#endif

#endif /* NA_IP_H */
