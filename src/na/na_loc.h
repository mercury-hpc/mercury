/**
 * Copyright (c) 2013-2021 UChicago Argonne, LLC and The HDF Group.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef NA_LOC_H
#define NA_LOC_H

#include "na_types.h"

/*************************************/
/* Public Type and Struct Definition */
/*************************************/

struct na_loc_info;

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
 * Init loc info. Must be freed with na_loc_info_destroy().
 *
 * \param na_loc_info_p [OUT]   pointer to returned loc info
 *
 * \return NA_SUCCESS or corresponding NA error code
 */
NA_PRIVATE na_return_t
na_loc_info_init(struct na_loc_info **na_loc_info_p);

/**
 * Free loc info.
 *
 * \param na_loc_info [IN/OUT]  pointer to loc info
 */
NA_PRIVATE void
na_loc_info_destroy(struct na_loc_info *na_loc_info);

/**
 * Check if a process and a pci device share the same cpuset.
 *
 * \param na_loc_info [IN]      pointer to loc info
 * \param domain_id  [IN]       PCI domain ID
 * \param bus_id  [IN]          PCI bus ID
 * \param device_id  [IN]       PCI device ID
 * \param function_id  [IN]     PCI function ID
 *
 * \return true if they share the same cpu set, false otherwise
 */
NA_PRIVATE bool
na_loc_check_pcidev(const struct na_loc_info *na_loc_info,
    unsigned int domain_id, unsigned int bus_id, unsigned int device_id,
    unsigned int function_id);

#ifdef __cplusplus
}
#endif

#endif /* NA_LOC_H */
