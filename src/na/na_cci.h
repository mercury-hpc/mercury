/*
 * Copyright (C) 2013 Argonne National Laboratory, Department of Energy,
 * Copyright (C) 2014 UT-Battelle, LLC. All rights reserved.
 * Chicago Argonne, LLC and The HDF Group. All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification, and
 * redistribution, is contained in the COPYING file that can be found at the
 * root of the source code distribution tree.
 */

#ifndef NA_CCI_H
#define NA_CCI_H

#include "na.h"

#include <cci.h>

#ifdef __cplusplus
extern		"C" {
#endif

/**
 * Get port name used by server.
 *
 * \param na_class [IN]         pointer to NA class
 *
 * \return Pointer to string
 */
NA_EXPORT const char *
NA_CCI_Get_port_name(
        na_class_t *na_class
        );

#ifdef __cplusplus
}
#endif

#endif				/* NA_CCI_H */
