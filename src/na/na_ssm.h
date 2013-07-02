/*
 * Copyright (C) 2013 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#ifndef NA_SSM_H
#define NA_SSM_H

#include "na.h"


/* MPI initialization flags */

#ifdef __cplusplus
extern "C" {
#endif

/* Initialize the MPI plugin */
na_class_t *NA_SSM_Init(char *URI, char *proto, int port, int flags);



#ifdef __cplusplus
}
#endif

#endif /* NA_SSM_H */




