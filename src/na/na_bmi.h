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

/**
 * Initialize the BMI plugin.
 *
 * \param method_list [IN]      (Optional) list of available methods depend on
 *                              BMI configuration, e.g., "bmi_tcp", ...
 * \param listen_addr [IN]      (Optional) e.g., "tcp://127.0.0.1:22222"
 * \param flags [IN]            (Optional) supported flags:
 *                                - BMI_INIT_SERVER
 *                                - BMI_TCP_BIND_SPECIFIC
 *                                - BMI_AUTO_REF_COUNT
 *                                - ... see BMI header file
 *
 * \return Pointer to network class
 */
NA_EXPORT na_class_t *
NA_BMI_Init(
        const char *method_list,
        const char *listen_addr,
        int flags
        );

#ifdef __cplusplus
}
#endif

#endif /* NA_BMI_H */
