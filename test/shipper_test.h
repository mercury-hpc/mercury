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

#ifndef SHIPPER_TEST_H
#define SHIPPER_TEST_H

#include "network_abstraction.h"

#define ION_ENV "ZOIDFS_ION_NAME" /* TODO used for compatibility with IOFSL */

#ifdef __cplusplus
extern "C" {
#endif

na_network_class_t *shipper_test_client_init(int argc, char *argv[]);

na_network_class_t *shipper_test_server_init(int argc, char *argv[], unsigned int *max_number_of_peers);

#ifdef __cplusplus
}
#endif

#endif /* SHIPPER_TEST_H */
