/*
 * Copyright (C) 2013 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#ifndef SHIPPER_TEST_H
#define SHIPPER_TEST_H

#include "na.h"
#include "mercury_test_config.h"

#define ION_ENV "ZOIDFS_ION_NAME" /* TODO used for compatibility with IOFSL */

#ifdef __cplusplus
extern "C" {
#endif

na_class_t *HG_Test_client_init(int argc, char *argv[], int *rank);

na_class_t *HG_Test_server_init(int argc, char *argv[], unsigned int *max_number_of_peers);

#ifdef __cplusplus
}
#endif

#endif /* SHIPPER_TEST_H */
