/*
 * Copyright (C) 2013 Argonne National Laboratory, Department of Energy,
 *                    and UChicago Argonne, LLC.
 * Copyright (C) 2013 The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#ifndef NETWORK_BMI_H
#define NETWORK_BMI_H

#include "network_abstraction.h"

#include <bmi.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Initialize the BMI plugin */
na_network_class_t *na_bmi_init(const char *method_list, const char *listen_addr, int flags);

#ifdef __cplusplus
}
#endif

#endif /* NETWORK_BMI_H */
