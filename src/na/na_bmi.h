/*
 * Copyright (C) 2013 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#ifndef NA_BMI_H
#define NA_BMI_H

#include "na.h"

#include <bmi.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Initialize the BMI plugin */
na_class_t *NA_BMI_Init(const char *method_list, const char *listen_addr, int flags);

#ifdef __cplusplus
}
#endif

#endif /* NETWORK_BMI_H */
